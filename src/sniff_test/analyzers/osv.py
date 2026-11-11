"""Known vulnerabilities and known-malicious packages, via osv-scanner (v2).

- Python: the resolved pylock.toml per platform (already fully resolved, so --no-resolve).
- Cards: the repo's npm lockfile, from the source tree at the scanned ref.

Scoring policy for plain CVEs (dep-vuln), decided 2026-11-08 after the baseline showed
card lockfiles are almost entirely build tooling:
- Python deps: CVSS-mapped but capped at high (a CVE alone never means "do not install");
  network-vector (AV:N) CVEs are tagged inbound, so --exposure public raises them.
- Cards: dev-only packages (build tools; never in the shipped .js) get no dep-vuln;
  bundled packages are capped at medium, with no inbound tag (browser code).
- dep-malicious is critical everywhere, dev packages included: a malicious build tool
  can inject code into the bundle (the event-stream attack).

A scanned repo can ship an `osv-scanner.toml` that ignores advisories (e.g. hides a
MAL- entry). So lockfiles are copied alone into an empty directory of ours, and we always
pass our own empty `--config`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sniff_test.analyzers import _proc
from sniff_test.analyzers.python_deps import Resolution
from sniff_test.deps.reqs import normalize
from sniff_test.models import (
    AnalyzerResult,
    AnalyzerState,
    Category,
    Finding,
    Severity,
    Tag,
    Target,
    TargetKind,
)

NAME = "osv"
NPM_LOCKFILES = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
)
MALWARE_CWE = "CWE-506"  # Embedded Malicious Code: GitHub's (pre-MAL) malware advisories
_TIMEOUT = 600
_MAX_IDS = 8
_GHSA_SEVERITY = {"CRITICAL": 9.0, "HIGH": 7.0, "MODERATE": 5.0, "MEDIUM": 5.0, "LOW": 2.0}


@dataclass
class _Pkg:
    name: str
    version: str
    ecosystem: str
    vulns: dict[str, dict[str, Any]] = field(default_factory=dict)
    groups: list[dict[str, Any]] = field(default_factory=list)
    platforms: set[str] = field(default_factory=set)
    source: str = ""


def _severity_for(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def is_malicious(vuln: dict[str, Any]) -> bool:
    if str(vuln.get("id", "")).startswith("MAL-"):
        return True
    cwes = (vuln.get("database_specific") or {}).get("cwe_ids") or []
    return MALWARE_CWE in cwes


def _group_score(group: dict[str, Any], vulns: dict[str, dict[str, Any]]) -> float | None:
    try:
        return float(group.get("max_severity") or "")
    except ValueError:
        pass
    for vid in group.get("ids", []):
        label = ((vulns.get(vid) or {}).get("database_specific") or {}).get("severity")
        if isinstance(label, str) and label.upper() in _GHSA_SEVERITY:
            return _GHSA_SEVERITY[label.upper()]
    return None


def _network_vector(group: dict[str, Any], vulns: dict[str, dict[str, Any]]) -> bool:
    for vid in group.get("ids", []):
        for sev in (vulns.get(vid) or {}).get("severity") or []:
            if "AV:N" in str(sev.get("score", "")):
                return True
    return False


def _ids_text(ids: list[str]) -> str:
    more = f" (+{len(ids) - _MAX_IDS} more)" if len(ids) > _MAX_IDS else ""
    return ", ".join(ids[:_MAX_IDS]) + more


@dataclass(frozen=True)
class VulnPolicy:
    max_severity: Severity
    inbound: bool  # tag network-vector CVEs as inbound surface
    where: str  # how the package reaches the user, for the message


PYTHON_POLICY = VulnPolicy(Severity.HIGH, True, "installed into Home Assistant's Python")
NPM_POLICY = VulnPolicy(Severity.MEDIUM, False, "bundled into the card's JavaScript")


def to_findings(
    pkgs: list[_Pkg],
    file: str | None,
    skip_vulns: set[str],
    policy: VulnPolicy = PYTHON_POLICY,
    dev_only: set[tuple[str, str]] | frozenset[tuple[str, str]] = frozenset(),
) -> list[Finding]:
    """skip_vulns: names whose CVEs aren't ours to report (HA-provided).
    dev_only: (name, version) of build-only packages: malware is reported, CVEs aren't."""
    out: list[Finding] = []
    for p in sorted(pkgs, key=lambda p: (p.name, p.version)):
        evidence_base = f"{p.name}@{p.version} ({p.ecosystem})"
        plats = frozenset(p.platforms)
        mal = sorted(v for v, data in p.vulns.items() if is_malicious(data))
        if mal:
            out.append(
                Finding(
                    rule_id="dep-malicious",
                    title="Known-malicious package in the dependency tree",
                    severity=Severity.CRITICAL,
                    category=Category.DEPENDENCY,
                    message=(
                        f"{p.name} {p.version} is listed as malicious in the OSV database "
                        f"({_ids_text(mal)}). Malicious packages typically steal credentials "
                        f"or tokens. Do not install."
                    ),
                    file=file,
                    evidence=f"{evidence_base}: {_ids_text(mal)}",
                    tags=frozenset({Tag.MALWARE}),
                    analyzer=NAME,
                    platforms=plats,
                )
            )
            continue
        if p.name in skip_vulns or (p.name, p.version) in dev_only or not p.groups:
            continue
        scored = [(_group_score(g, p.vulns), g) for g in p.groups]
        best_score, best = max(scored, key=lambda sg: sg[0] if sg[0] is not None else 5.0)
        severity = _severity_for(best_score) if best_score is not None else Severity.MEDIUM
        severity = min(severity, policy.max_severity)
        ids = [g["ids"][0] for _s, g in scored if g.get("ids")]
        inbound = policy.inbound and _network_vector(best, p.vulns)
        tags = frozenset({Tag.INBOUND}) if inbound else frozenset()
        cvss = f"max CVSS {best_score:g}" if best_score is not None else "severity unknown"
        out.append(
            Finding(
                rule_id="dep-vuln",
                title="Dependency with known vulnerabilities",
                severity=severity,
                category=Category.DEPENDENCY,
                message=(
                    f"{p.name} {p.version} ({policy.where}) has {len(ids)} known "
                    f"{'vulnerability' if len(ids) == 1 else 'vulnerabilities'} ({cvss}): "
                    f"{_ids_text(ids)}. Check whether a fixed version is available."
                ),
                file=file,
                evidence=f"{evidence_base}: {_ids_text(ids)}",
                tags=tags,
                analyzer=NAME,
                platforms=plats,
            )
        )
    return out


def osv_version() -> str | None:
    exe = shutil.which("osv-scanner")
    if not exe:
        return None
    v = _proc.version([exe, "--version"])
    return v.split(":", 1)[-1].strip() if v else None


def scan_lockfile(exe: str, lockfile: Path, work: Path) -> tuple[list[_Pkg] | None, str]:
    """Run osv-scanner on one lockfile copied into isolation. (None, error) on failure."""
    iso = Path(tempfile.mkdtemp(prefix="osv-in-", dir=work))
    copy = iso / lockfile.name
    shutil.copyfile(lockfile, copy, follow_symlinks=False)
    config = work / "osv-empty-config.toml"
    config.write_text("")
    run_dir = _proc.empty_dir(work, "osv-run")
    cmd = [
        exe,
        "scan",
        "source",
        "--config",
        str(config),
        "--lockfile",
        str(copy),
        "--format",
        "json",
        "--no-resolve",
        "--verbosity",
        "error",
    ]
    try:
        proc = _proc.run(cmd, run_dir, _TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, "osv-scanner timed out"
    if proc.returncode not in (0, 1, 128):
        return None, f"osv-scanner exit {proc.returncode}: {proc.stderr.strip()[-300:]}"
    try:
        data = json.loads(proc.stdout or "{}")
    except ValueError:
        return None, f"osv-scanner produced no JSON (exit {proc.returncode})"
    pkgs: list[_Pkg] = []
    for result in data.get("results") or []:
        for entry in result.get("packages") or []:
            meta = entry.get("package") or {}
            pkgs.append(
                _Pkg(
                    name=str(meta.get("name", "")),
                    version=str(meta.get("version", "")),
                    ecosystem=str(meta.get("ecosystem", "")),
                    vulns={str(v.get("id")): v for v in entry.get("vulnerabilities") or []},
                    groups=list(entry.get("groups") or []),
                    source=lockfile.name,
                )
            )
    return pkgs, ""


def run_python(resolution: Resolution | None, work: Path) -> AnalyzerResult:
    name = f"{NAME}-python"
    if resolution is None or not resolution.lockfiles:
        return AnalyzerResult(name, AnalyzerState.NOT_APPLICABLE, detail="nothing resolved")
    exe = shutil.which("osv-scanner")
    if not exe:
        return AnalyzerResult(name, AnalyzerState.SKIPPED, detail="osv-scanner not installed")
    merged: dict[tuple[str, str], _Pkg] = {}
    errors: list[str] = []
    for plat, lockfile in sorted(resolution.lockfiles.items()):
        pkgs, err = scan_lockfile(exe, lockfile, work)
        if pkgs is None:
            errors.append(f"{plat}: {err}")
            continue
        for p in pkgs:
            p.name = normalize(p.name)
            merged.setdefault((p.name, p.version), p).platforms.add(plat)
    ha_provided = {p.name for p in resolution.packages.values() if p.ha_provided}
    findings = to_findings(list(merged.values()), "manifest.json", ha_provided)
    state = AnalyzerState.ERROR if errors else AnalyzerState.OK
    detail = f"{len(resolution.lockfiles)} lockfile(s) checked"
    if errors:
        detail += "; " + " | ".join(errors)
    return AnalyzerResult(name, state, findings, detail, tool_version=osv_version())


def npm_dev_only(lockfile: Path) -> set[tuple[str, str]]:
    """(name, version) pairs that appear in a package-lock only as dev dependencies.

    yarn.lock and pnpm-lock.yaml don't mark dev packages per entry; for those we can't
    tell, so everything is treated as bundled (and capped at medium). bun.lock has the
    dependency graph, so packages not reachable from a workspace's runtime dependencies
    are dev-only (`bun_dev_only`).
    """
    if lockfile.name == "bun.lock":
        return bun_dev_only(lockfile)
    if lockfile.name not in ("package-lock.json", "npm-shrinkwrap.json"):
        return set()
    try:
        data = json.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    flags: dict[tuple[str, str], bool] = {}  # True while every occurrence is dev-only

    def note(name: str, meta: dict[str, Any]) -> None:
        key = (name, str(meta.get("version", "")))
        is_dev = bool(meta.get("dev") or meta.get("devOptional"))
        flags[key] = flags.get(key, True) and is_dev

    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        for path, meta in packages.items():
            if path and "node_modules/" in path and isinstance(meta, dict):
                note(path.rsplit("node_modules/", 1)[-1], meta)
    else:  # lockfileVersion 1: nested "dependencies"
        stack = [data.get("dependencies") or {}]
        while stack:
            for name, meta in stack.pop().items():
                if isinstance(meta, dict):
                    note(name, meta)
                    stack.append(meta.get("dependencies") or {})
    return {k for k, dev in flags.items() if dev}


def jsonc_loads(text: str) -> Any:
    """JSON with // and /* */ comments and trailing commas (bun.lock's format)."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':  # copy a string verbatim, escapes included
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c in "]}":  # drop a trailing comma before a closer
            k = len(out) - 1
            while k >= 0 and out[k].isspace():
                k -= 1
            if k >= 0 and out[k] == ",":
                del out[k]
            out.append(c)
            i += 1
        else:
            out.append(c)
            i += 1
    return json.loads("".join(out))


def _bun_segments(key: str) -> list[str]:
    """'a/@s/b/c' -> ['a', '@s/b', 'c']: bun.lock keys are nesting paths of package names."""
    parts = key.split("/")
    segs: list[str] = []
    while parts:
        p = parts.pop(0)
        if p.startswith("@") and parts:
            p += "/" + parts.pop(0)
        segs.append(p)
    return segs


def bun_dev_only(lockfile: Path) -> set[tuple[str, str]]:
    """(name, version) pairs in a bun.lock reachable only from devDependencies.

    Entries are `"key": ["name@version", registry, {dependencies...}, integrity]`; a
    dependency of the package at key K resolves to `K/<dep>`, else to the same name one
    level up, as Node does. Unparseable files give an empty set (everything counts as
    bundled, the safe side).
    """
    try:
        data = jsonc_loads(lockfile.read_text(encoding="utf-8"))
        packages = data["packages"]
        workspaces = data.get("workspaces") or {}
    except (OSError, ValueError, KeyError, TypeError):
        return set()
    if not isinstance(packages, dict) or not isinstance(workspaces, dict):
        return set()

    def ident(entry: Any) -> tuple[str, str] | None:
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            return None
        spec = entry[0]
        at = spec.rfind("@")
        return (spec[:at], spec[at + 1 :]) if at > 0 else None

    def deps(entry: Any) -> list[str]:
        meta = (
            next((x for x in entry[1:] if isinstance(x, dict)), {})
            if isinstance(entry, list)
            else {}
        )
        names: list[str] = []
        for k in ("dependencies", "optionalDependencies", "peerDependencies"):
            if isinstance(meta.get(k), dict):
                names += list(meta[k])
        return names

    def resolve(parent: list[str], dep: str) -> str | None:
        for depth in range(len(parent), -1, -1):
            key = "/".join([*parent[:depth], dep])
            if key in packages:
                return key
        return None

    runtime: set[str] = set()
    todo: list[str] = []
    for ws in workspaces.values():
        if not isinstance(ws, dict):
            continue
        for k in ("dependencies", "optionalDependencies", "peerDependencies"):
            for dep in ws.get(k) or {}:
                if (key := resolve([], dep)) is not None:
                    todo.append(key)
    while todo:
        key = todo.pop()
        if key in runtime:
            continue
        runtime.add(key)
        segs = _bun_segments(key)
        for dep in deps(packages[key]):
            if (child := resolve(segs, dep)) is not None and child not in runtime:
                todo.append(child)
    shipped = {i for k in runtime if (i := ident(packages[k]))}
    every = {i for e in packages.values() if (i := ident(e))}
    return every - shipped


def _declares_npm_deps(source_root: Path) -> bool:
    try:
        pkg = json.loads((source_root / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(pkg, dict) and any(
        pkg.get(k) for k in ("dependencies", "devDependencies", "peerDependencies")
    )


def run_npm(target: Target, work: Path) -> AnalyzerResult:
    name = f"{NAME}-npm"
    root = target.source_root
    if target.kind is not TargetKind.PLUGIN or root is None:
        return AnalyzerResult(name, AnalyzerState.NOT_APPLICABLE)
    lockfiles = [
        root / n for n in NPM_LOCKFILES if (root / n).is_file() and not (root / n).is_symlink()
    ]
    if not lockfiles:
        if not _declares_npm_deps(root):
            return AnalyzerResult(name, AnalyzerState.NOT_APPLICABLE, detail="no npm deps")
        return AnalyzerResult(
            name,
            AnalyzerState.OK,
            [
                Finding(
                    rule_id="dep-npm-no-lockfile",
                    title="Card has npm dependencies but no lockfile",
                    severity=Severity.LOW,
                    category=Category.DEPENDENCY,
                    message=(
                        "package.json declares dependencies, but there's no package-lock.json, "
                        "yarn.lock, pnpm-lock.yaml or bun.lock, so the exact versions bundled into "
                        "the card can't be verified against known-malicious packages."
                    ),
                    file="package.json",
                    analyzer=NAME,
                )
            ],
            detail="no lockfile",
        )
    exe = shutil.which("osv-scanner")
    if not exe:
        return AnalyzerResult(name, AnalyzerState.SKIPPED, detail="osv-scanner not installed")
    findings: list[Finding] = []
    errors: list[str] = []
    for lf in lockfiles:
        pkgs, err = scan_lockfile(exe, lf, work)
        if pkgs is None:
            errors.append(f"{lf.name}: {err}")
            continue
        findings += to_findings(pkgs, lf.name, set(), NPM_POLICY, npm_dev_only(lf))
    state = AnalyzerState.ERROR if errors else AnalyzerState.OK
    detail = ", ".join(lf.name for lf in lockfiles) + (f"; {' | '.join(errors)}" if errors else "")
    return AnalyzerResult(name, state, findings, detail, tool_version=osv_version())
