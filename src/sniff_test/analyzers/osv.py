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

import contextlib
import json
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sniff_test.analyzers import _proc
from sniff_test.analyzers.python_deps import Resolution
from sniff_test.deps.reqs import normalize
from sniff_test.fetch import http
from sniff_test.models import (
    Advisory,
    AnalyzerResult,
    AnalyzerState,
    Category,
    DepFacts,
    Finding,
    Severity,
    Tag,
    Target,
    TargetKind,
    fix_phrase,
    version_key,
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


def _github_label(group: dict[str, Any], vulns: dict[str, dict[str, Any]]) -> str | None:
    """GitHub's reviewed rating (low / moderate / high / critical) of a GHSA record in the
    group, the highest if several."""
    labels = []
    for vid in group.get("ids", []):
        label = ((vulns.get(vid) or {}).get("database_specific") or {}).get("severity")
        if isinstance(label, str) and label.upper() in _GHSA_SEVERITY:
            labels.append(label.upper())
    return max(labels, key=_GHSA_SEVERITY.__getitem__) if labels else None


def _cvss(group: dict[str, Any]) -> float | None:
    try:
        return float(group.get("max_severity") or "")
    except ValueError:
        return None


def _group_score(group: dict[str, Any], vulns: dict[str, dict[str, Any]]) -> float | None:
    """GitHub's reviewed rating wins over the record's CVSS (0.7.6, user decision): the CVSS
    usually comes from the reporter, the label from GitHub's review (deepmerge
    CVE-2026-93753: reported CVSS 5.3, GitHub "low")."""
    label = _github_label(group, vulns)
    return _GHSA_SEVERITY[label] if label else _cvss(group)


def _network_vector(group: dict[str, Any], vulns: dict[str, dict[str, Any]]) -> bool:
    for vid in group.get("ids", []):
        for sev in (vulns.get(vid) or {}).get("severity") or []:
            if "AV:N" in str(sev.get("score", "")):
                return True
    return False


_IMPACT = re.compile(r"(?:^|/)(V?[CI]|S[CI]):([A-Z])")


def availability_only(group: dict[str, Any], vulns: dict[str, dict[str, Any]]) -> bool:
    """Every CVSS vector of the group's records says no confidentiality and no integrity
    impact (v3 C:N/I:N; v4 VC/VI/SC/SI all N). False when there is no vector at all."""
    seen = False
    for vid in group.get("ids", []):
        for sev in (vulns.get(vid) or {}).get("severity") or []:
            vector = str(sev.get("score", ""))
            parts = dict(_IMPACT.findall(vector))
            if not parts:
                continue
            seen = True
            if any(v != "N" for v in parts.values()):
                return False
    return seen


def _ids_text(ids: list[str]) -> str:
    more = f" (+{len(ids) - _MAX_IDS} more)" if len(ids) > _MAX_IDS else ""
    return ", ".join(ids[:_MAX_IDS]) + more


@dataclass(frozen=True)
class VulnPolicy:
    max_severity: Severity
    inbound: bool  # tag network-vector CVEs as inbound surface
    where: str  # how the package reaches the user, for the message
    # (0.14.1) cap for an advisory whose every CVSS vector says no confidentiality and no
    # integrity impact (ReDoS, DoS): in a browser that is a frozen tab
    availability_max: Severity | None = None


PYTHON_POLICY = VulnPolicy(Severity.HIGH, True, "installed into Home Assistant's Python")
# (0.14.1, user decision 2026-11-18) Browser code: rated like Python packages (GitHub's
# label, else CVSS, at most high), because a panel's or card's JavaScript runs on Home
# Assistant's own origin, where a code-execution or XSS bug can reach the user's token;
# availability-only advisories at most medium. Was capped at medium (2026-11-08).
NPM_POLICY = VulnPolicy(Severity.HIGH, False, "bundled into the card's JavaScript", Severity.MEDIUM)
# An unchanged published library an integration ships (analyzers/libraries.py).
VENDORED_POLICY = VulnPolicy(
    Severity.HIGH, False, "shipped unchanged in the app's web files", Severity.MEDIUM
)

# (0.14.0, user decision 2026-11-17) Tools that only transform code when the card is
# built: they run on the developer's machine and none of their code ends up in the
# browser bundle (checked on three real cards: no trace of them in the shipped files; the
# babel advisories seen say "users that only compile trusted code are not impacted").
# Exact names only. Not here, because their code IS copied into bundles: @babel/runtime,
# @babel/helpers, core-js, regenerator-runtime, tslib, and rollup plugins (the commonjs
# plugin writes a shim into the output). Their advisories are shown, unscored; known
# malware in them is still dep-malicious (a malicious build tool can rewrite the bundle).
NPM_BUILD_TOOLS = frozenset(
    {
        "rollup",
        "webpack",
        "esbuild",
        "vite",
        "typescript",
        "terser",
        "@babel/core",
        "@babel/parser",
        "@babel/preset-env",
    }
)


def is_build_tool(name: str) -> bool:
    return name in NPM_BUILD_TOOLS or name.startswith("@babel/plugin-transform-")


_DETAILS_MAX = 1500  # characters of an advisory's text kept for the page and the AI
Lookup = Callable[[str, str, str], tuple[str | None, str | None, int | None]]


def _same_package(a: str, b: str, ecosystem: str) -> bool:
    return normalize(a) == normalize(b) if ecosystem == "PyPI" else a.lower() == b.lower()


def fixed_for(vuln: dict[str, Any], name: str, ecosystem: str, version: str) -> str | None:
    """The first fixed version above `version` from the record's ranges; "" when the range
    holding `version` has no fix (OSV's `last_affected`, or open-ended); None when the
    record doesn't say (only an explicit version list, or no matching range)."""
    have = version_key(ecosystem, version)
    verdict: str | None = None
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if str(pkg.get("ecosystem")) != ecosystem or not _same_package(
            str(pkg.get("name", "")), name, ecosystem
        ):
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            start: tuple | None = None
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    intro = str(ev["introduced"])
                    start = ((), False) if intro == "0" else version_key(ecosystem, intro)
                elif start is not None and "fixed" in ev:
                    fx = str(ev["fixed"])
                    if start <= have < version_key(ecosystem, fx):
                        return fx
                    start = None
                elif start is not None and "last_affected" in ev:
                    if start <= have <= version_key(ecosystem, str(ev["last_affected"])):
                        verdict = ""
                    start = None
            if start is not None and start <= have:  # introduced, never fixed
                verdict = ""
    return verdict


def latest_release(
    name: str, ecosystem: str, version: str
) -> tuple[str | None, str | None, int | None]:
    """(newest final release, its date, final releases newer than `version`) from PyPI or
    the npm registry. Raises http.HttpError."""
    have = version_key(ecosystem, version)
    if ecosystem == "PyPI":
        meta = http.get_json(f"https://pypi.org/pypi/{name}/json")
        latest = str((meta.get("info") or {}).get("version") or "") or None
        dates: dict[str, str] = {}
        for v, files in (meta.get("releases") or {}).items():
            live = [f for f in files or [] if not f.get("yanked")]
            if live:
                dates[v] = min(str(f.get("upload_time_iso_8601", "")) for f in live)
    elif ecosystem == "npm":
        meta = http.get_json("https://registry.npmjs.org/" + name.replace("/", "%2F"))
        latest = str((meta.get("dist-tags") or {}).get("latest") or "") or None
        times = meta.get("time") or {}
        dates = {v: str(times.get(v, "")) for v in (meta.get("versions") or {})}
    else:
        return None, None, None
    if latest is None:
        return None, None, None
    top = version_key(ecosystem, latest)
    finals = {v for v in dates if version_key(ecosystem, v)[1]}
    behind = sum(1 for v in finals if have < version_key(ecosystem, v) <= top)
    return latest, (dates.get(latest) or "")[:10] or None, behind


_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_SSVC_WORDS = {
    "Exploitation": ("none", "poc", "active"),
    "Automatable": ("yes", "no"),
    "Technical Impact": ("partial", "total"),
}
SSVC_TIMEOUT = 10.0
SSVC_CACHE_SECONDS = 24 * 3600


def _ssvc_cache(cve: str) -> Path:
    from sniff_test import paths

    return paths.cache_root() / "ssvc" / f"{cve}.json"


def ssvc(cve: str) -> tuple[str, str, str, bool] | None:
    """(0.14.1) CISA's SSVC decision points and KEV listing for one CVE, from the CVE
    record (CISA's ADP container): (exploitation, automatable, impact, kev). None when
    the record has none or couldn't be read: then nothing is raised or explained, and
    the lookup never becomes a scan result. Answers are kept 24 hours."""
    import time

    from sniff_test import paths

    if not _CVE.match(cve):
        return None
    cache = _ssvc_cache(cve)
    try:
        data = json.loads(cache.read_text("utf-8"))
        if time.time() - float(data["t"]) < SSVC_CACHE_SECONDS:
            got = data["ssvc"]
            return tuple(got) if got else None  # type: ignore[return-value]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    try:
        rec = http.lookup_json(f"https://cveawg.mitre.org/api/cve/{cve}", SSVC_TIMEOUT)
    except http.HttpError:
        return None
    out: tuple[str, str, str, bool] | None = None
    options: dict[str, str] = {}
    kev = False
    adps = ((rec or {}).get("containers") or {}).get("adp") if isinstance(rec, dict) else None
    for adp in adps if isinstance(adps, list) else []:
        for m in (adp.get("metrics") or []) if isinstance(adp, dict) else []:
            other = m.get("other") if isinstance(m, dict) else None
            if not isinstance(other, dict):
                continue
            if other.get("type") == "kev":
                kev = True
            if other.get("type") == "ssvc":
                for opt in (other.get("content") or {}).get("options") or []:
                    if isinstance(opt, dict):
                        for k, v in opt.items():
                            if k in _SSVC_WORDS and str(v).lower() in _SSVC_WORDS[k]:
                                options[k] = str(v).lower()
    if options or kev:
        out = (
            options.get("Exploitation", ""),
            options.get("Automatable", ""),
            options.get("Technical Impact", ""),
            kev,
        )
    with contextlib.suppress(OSError):
        paths.atomic_write(cache, json.dumps({"t": time.time(), "ssvc": out}))
    return out


def _dep_facts(p: _Pkg, ids: list[str], direct: set[str] | None, lookup: Lookup | None) -> DepFacts:
    advisories = []
    for vid in ids:
        rec = p.vulns.get(vid) or {}
        aliases = tuple(str(a) for a in (rec.get("aliases") or [])[:4])
        cves = [a for a in (vid, *aliases) if _CVE.match(a)]
        # online only (`lookup` is None offline), like the newest-release facts
        found = ssvc(cves[0]) if cves and lookup is not None else None
        exploitation, automatable, impact, kev = found or ("", "", "", False)
        advisories.append(
            Advisory(
                id=vid,
                summary=str(rec.get("summary") or "")[:300],
                details=str(rec.get("details") or "")[:_DETAILS_MAX],
                fixed=fixed_for(rec, p.name, p.ecosystem, p.version),
                aliases=aliases,
                exploitation=exploitation,
                automatable=automatable,
                impact=impact,
                kev=kev,
            )
        )
    latest = date = behind = None
    error = ""
    if lookup is not None:
        try:
            latest, date, behind = lookup(p.name, p.ecosystem, p.version)
        except http.HttpError as e:
            error = str(e)[:200]
    is_direct = (
        None if direct is None else any(_same_package(p.name, d, p.ecosystem) for d in direct)
    )
    return DepFacts(p.name, p.ecosystem, p.version, tuple(advisories), is_direct,
                    latest, date, behind, error)  # fmt: skip


def facts_sentence(d: DepFacts) -> str:
    """What we checked about the fix and the newest release, in one or two sentences."""
    phrase = fix_phrase(d.ecosystem, [(a.id, a.fixed) for a in d.advisories])
    out = {
        "no fixed version yet": "OSV lists no fixed version.",
        "the advisory doesn't say which version fixes it": (
            "OSV doesn't say which version fixes it."
        ),
    }.get(phrase, phrase[0].upper() + phrase[1:] + ".")
    if d.latest:
        when = f" ({d.latest_date})" if d.latest_date else ""
        if version_key(d.ecosystem, d.version) >= version_key(d.ecosystem, d.latest):
            out += f" {d.version} is the newest release{when}."
        else:
            n = d.behind or 0
            ahead = f", {n} release{'s' if n != 1 else ''} newer than {d.version}" if n else ""
            out += f" The newest release is {d.latest}{when}{ahead}."
    return out


def to_findings(
    pkgs: list[_Pkg],
    file: str | None,
    skip_vulns: set[str],
    policy: VulnPolicy = PYTHON_POLICY,
    dev_only: set[tuple[str, str]] | frozenset[tuple[str, str]] = frozenset(),
    direct: set[str] | None = None,
    lookup: Lookup | None = None,
    build_tool: Callable[[str], bool] | None = None,
) -> list[Finding]:
    """skip_vulns: names whose CVEs aren't ours to report (HA-provided).
    dev_only: (name, version) of build-only packages: malware is reported, CVEs aren't.
    direct: names the app lists itself. lookup: the newest release (None: offline).
    build_tool: (cards) names whose advisories are shown as info, not scored."""
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
        if policy.availability_max is not None and availability_only(best, p.vulns):
            severity = min(severity, policy.availability_max)
        ids = [g["ids"][0] for _s, g in scored if g.get("ids")]
        inbound = policy.inbound and _network_vector(best, p.vulns)
        tags = frozenset({Tag.INBOUND}) if inbound else frozenset()
        label, raw = _github_label(best, p.vulns), _cvss(best)
        if label:
            cvss = f"GitHub rates it {label.lower()}" + (
                f"; CVSS {raw:g}" if raw is not None else ""
            )
        else:
            cvss = f"max CVSS {raw:g}" if raw is not None else "severity unknown"
        dep = _dep_facts(p, ids, direct, lookup)
        if build_tool is not None and build_tool(p.name):
            out.append(
                Finding(
                    rule_id="dep-build-tool-vuln",
                    title="Build tool with known vulnerabilities",
                    severity=Severity.INFO,
                    category=Category.DEPENDENCY,
                    message=(
                        f"{p.name} {p.version} has {len(ids)} known "
                        f"{'vulnerability' if len(ids) == 1 else 'vulnerabilities'} ({cvss}): "
                        f"{_ids_text(ids)}. It's a build tool: it runs on the developer's "
                        "machine when the card is built, and its code isn't part of the "
                        "card's JavaScript, so this isn't scored."
                    ),
                    file=file,
                    evidence=f"{evidence_base}: {_ids_text(ids)}",
                    analyzer=NAME,
                    platforms=plats,
                )
            )
            continue
        out.append(
            Finding(
                rule_id="dep-vuln",
                title="Dependency with known vulnerabilities",
                severity=severity,
                category=Category.DEPENDENCY,
                message=(
                    f"{p.name} {p.version} ({policy.where}) has {len(ids)} known "
                    f"{'vulnerability' if len(ids) == 1 else 'vulnerabilities'} ({cvss}): "
                    f"{_ids_text(ids)}. {facts_sentence(dep)}"
                ),
                file=file,
                evidence=f"{evidence_base}: {_ids_text(ids)}",
                tags=tags,
                analyzer=NAME,
                platforms=plats,
                dependency=dep,
            )
        )
    return out


def osv_version() -> str | None:
    exe = shutil.which("osv-scanner")
    if not exe:
        return None
    v = _proc.version([exe, "--version"], tool="osv-scanner")
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
        proc = _proc.run(cmd, run_dir, _TIMEOUT, tool="osv-scanner")
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
    if resolution is None or not resolution.lockfiles:
        return AnalyzerResult(
            f"{NAME}-python", AnalyzerState.NOT_APPLICABLE, detail="nothing resolved"
        )
    return check_python(
        resolution.lockfiles,
        {p.name for p in resolution.packages.values() if p.ha_provided},
        {r.name for r in resolution.requirements if r.name},
        work,
    )


def check_python(
    lockfiles: dict[str, Path], ha_provided: set[str], direct: set[str], work: Path
) -> AnalyzerResult:
    """osv-scanner on resolved lockfiles (platform -> pylock). Everything a check needs
    besides the files is passed in, so a stored scan's advisories can be asked again
    later from its saved lockfiles (recheck.py) with this same code."""
    name = f"{NAME}-python"
    exe = shutil.which("osv-scanner")
    if not exe:
        return AnalyzerResult(name, AnalyzerState.SKIPPED, detail="osv-scanner not installed")
    merged: dict[tuple[str, str], _Pkg] = {}
    errors: list[str] = []
    for plat, lockfile in sorted(lockfiles.items()):
        pkgs, err = scan_lockfile(exe, lockfile, work)
        if pkgs is None:
            errors.append(f"{plat}: {err}")
            continue
        for p in pkgs:
            p.name = normalize(p.name)
            merged.setdefault((p.name, p.version), p).platforms.add(plat)
    findings = to_findings(
        list(merged.values()), "manifest.json", ha_provided, direct=direct, lookup=latest_release
    )
    state = AnalyzerState.ERROR if errors else AnalyzerState.OK
    detail = f"{len(lockfiles)} lockfile(s) checked"
    if errors:
        detail += "; " + " | ".join(errors)
    return AnalyzerResult(name, state, findings, detail, tool_version=osv_version())


def npm_dev_only(lockfile: Path) -> set[tuple[str, str]]:
    """(name, version) pairs that appear in a package-lock only as dev dependencies.

    yarn.lock, pnpm-lock.yaml and bun.lock don't mark dev packages per entry, but they
    hold the dependency graph: packages not reachable from package.json's runtime
    dependencies are dev-only (`yarn_dev_only`, `pnpm_dev_only`, `bun_dev_only`; yarn and
    pnpm since 0.14.0). When a walk fails everything counts as bundled (the safe side).
    """
    if lockfile.name == "bun.lock":
        return bun_dev_only(lockfile)
    if lockfile.name == "yarn.lock":
        return yarn_dev_only(lockfile)
    if lockfile.name == "pnpm-lock.yaml":
        return pnpm_dev_only(lockfile)
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


_RUNTIME_KEYS = ("dependencies", "optionalDependencies", "peerDependencies")


def _runtime_roots(lockfile: Path) -> dict[str, str] | None:
    """package.json's runtime dependencies (name -> range) beside the lockfile."""
    try:
        pkg = json.loads((lockfile.parent / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(pkg, dict):
        return None
    out: dict[str, str] = {}
    for k in _RUNTIME_KEYS:
        if isinstance(pkg.get(k), dict):
            out.update({str(n): str(r) for n, r in pkg[k].items()})
    return out


# A dependency line: v1 `"@scope/x" "^1.2"` / `x "^1"`, berry `"@scope/x": "npm:^1"` / `x: npm:^1`
_YARN_DEP = re.compile(r"""^(?P<name>"[^"]+"|'[^']+'|[^\s:"']+):?\s+(?P<rng>.+)$""")


def _unquote(s: str) -> str:
    s = s.strip()
    return s[1:-1] if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'" else s


def _split_spec(spec: str) -> tuple[str, str] | None:
    """'@scope/name@^1.2' -> ('@scope/name', '^1.2')."""
    at = spec.find("@", 1)
    return (spec[:at], spec[at + 1 :]) if at > 0 else None


def _walk(roots: list[str], edges: dict[str, list[str]]) -> set[str]:
    seen: set[str] = set()
    todo = list(roots)
    while todo:
        key = todo.pop()
        if key not in seen:
            seen.add(key)
            todo += edges.get(key, [])
    return seen


def yarn_dev_only(lockfile: Path) -> set[tuple[str, str]]:
    """(name, version) pairs in a yarn.lock (v1 or berry) that no runtime dependency of
    package.json reaches. An entry header lists every `name@range` it answers for; a
    dependency `name range` resolves to the entry for `name@range` (berry writes the
    protocol, `npm:^1.2`). A root whose exact range isn't found takes every version of
    that name, so an odd lockfile errs towards "bundled"."""
    roots = _runtime_roots(lockfile)
    try:
        text = lockfile.read_text(encoding="utf-8")
    except OSError:
        return set()
    if roots is None:
        return set()
    entries: dict[int, dict[str, Any]] = {}
    alias: dict[str, int] = {}  # "name@range" -> entry number
    cur: dict[str, Any] | None = None
    block: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0:
            block = None
            if not line.endswith(":") or line.startswith("__metadata"):
                cur = None
                continue
            cur = {"version": None, "deps": []}
            n = len(entries)
            entries[n] = cur
            # v1 quotes each spec ("a@^1", "a@^2"); berry quotes the whole list
            # ("a@npm:^1, a@npm:^2"). Strip both kinds before reading names.
            for spec in line[:-1].split(","):
                alias[spec.strip().strip("\"'")] = n
        elif cur is None:
            continue
        elif indent == 2:
            key, _, value = line.partition(" ")
            key = key.rstrip(":")
            block = key if not value.strip() and line.endswith(":") else None
            if key == "version":
                cur["version"] = _unquote(value)
        elif indent >= 4 and block in _RUNTIME_KEYS:
            m = _YARN_DEP.match(line)
            if m is None:
                continue
            name, rng = m["name"], m["rng"]
            cur["deps"].append((_unquote(name), _unquote(rng)))
    if not entries:
        return set()

    def find(name: str, rng: str) -> list[int]:
        for key in (f"{name}@{rng}", f"{name}@npm:{rng}"):
            if key in alias:
                return [alias[key]]
        return [n for k, n in alias.items() if (s := _split_spec(k)) and s[0] == name]

    edges: dict[str, list[str]] = {}
    for n, e in entries.items():
        edges[str(n)] = [str(m) for d, r in e["deps"] for m in find(d, r)]
    start = [str(m) for name, rng in roots.items() for m in find(name, rng)]
    shipped = _walk(start, edges)

    def ident(n: int) -> tuple[str, str] | None:
        names = {s[0] for k, m in alias.items() if m == n and (s := _split_spec(k))}
        version = entries[n]["version"]
        if len(names) != 1 or not version or "use.local" in version:
            return None
        return (names.pop(), version)

    every = {i for n in entries if (i := ident(n))}
    kept = {i for n in entries if str(n) in shipped and (i := ident(n))}
    return every - kept


def _mini_yaml(text: str) -> dict[str, Any]:
    """The block mappings of a pnpm lockfile (scalars kept as text; lists and flow
    collections are kept as their text too). Not a YAML parser: enough for pnpm's
    machine-written layout, and any surprise makes the caller fall back."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith(("#", "- ")):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if line.startswith(("'", '"')):
            q = line[0]
            end = line.find(q, 1)
            if end < 0 or line[end + 1 : end + 2] != ":":
                continue
            key, value = line[1:end], line[end + 2 :].strip()
        elif ":" in line:
            key, _, value = line.partition(":")
            value = value.strip()
        else:
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if value:
            parent[key] = _unquote(value)
        else:
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
    return root


def _pnpm_version(v: Any) -> str | None:
    if isinstance(v, dict):
        v = v.get("version")
    if not isinstance(v, str) or v.startswith(("link:", "file:", "workspace:")):
        return None
    return re.sub(r"[(_].*$", "", v)


def _pnpm_key(key: str) -> tuple[str, str] | None:
    key = re.sub(r"\(.*$", "", key.lstrip("/"))
    if (s := _split_spec(key)) is not None:
        return (s[0], re.sub(r"_.*$", "", s[1]))
    name, _, version = key.rpartition("/")  # lockfile v5: /name/1.2.3
    return (name, re.sub(r"_.*$", "", version)) if name and version else None


def pnpm_dev_only(lockfile: Path) -> set[tuple[str, str]]:
    """(name, version) pairs in a pnpm-lock.yaml (v5 to v9) that the root project's
    runtime dependencies don't reach. v9 keeps the graph under `snapshots`, older
    versions under `packages`."""
    try:
        doc = _mini_yaml(lockfile.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return set()
    importers = doc.get("importers")
    project = importers.get(".") if isinstance(importers, dict) else doc
    graph = doc.get("snapshots") if isinstance(doc.get("snapshots"), dict) else None
    graph = graph if graph is not None else doc.get("packages")
    if not isinstance(project, dict) or not isinstance(graph, dict):
        return set()
    nodes: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for key, meta in graph.items():
        ident = _pnpm_key(key)
        if ident is None:
            continue
        deps: list[tuple[str, str]] = []
        for k in ("dependencies", "optionalDependencies"):
            for name, v in (meta.get(k) or {}).items() if isinstance(meta, dict) else ():
                if (ver := _pnpm_version(v)) is not None:
                    deps.append((name, ver))
        nodes.setdefault(ident, []).extend(deps)
    if not nodes:
        return set()
    roots = [
        (name, ver)
        for k in ("dependencies", "optionalDependencies")
        for name, v in (project.get(k) or {}).items()
        if isinstance(project.get(k), dict) and (ver := _pnpm_version(v)) is not None
    ]
    seen: set[tuple[str, str]] = set()
    todo = list(roots)
    while todo:
        node = todo.pop()
        if node not in seen:
            seen.add(node)
            todo += nodes.get(node, [])
    return set(nodes) - seen


def _npm_direct(source_root: Path) -> set[str] | None:
    """Names the card's package.json lists itself (runtime and build)."""
    try:
        pkg = json.loads((source_root / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(pkg, dict):
        return None
    out: set[str] = set()
    for k in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
        if isinstance(pkg.get(k), dict):
            out |= set(pkg[k])
    return out


def _declares_npm_deps(source_root: Path) -> bool:
    try:
        pkg = json.loads((source_root / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(pkg, dict) and any(
        pkg.get(k) for k in ("dependencies", "devDependencies", "peerDependencies")
    )


def npm_lockfiles(root: Path) -> list[Path]:
    return [root / n for n in NPM_LOCKFILES if (root / n).is_file() and not (root / n).is_symlink()]


def run_npm(target: Target, work: Path) -> AnalyzerResult:
    root = target.source_root
    if target.kind is not TargetKind.PLUGIN or root is None:
        return AnalyzerResult(f"{NAME}-npm", AnalyzerState.NOT_APPLICABLE)
    return check_npm(root, work)


def check_npm(root: Path, work: Path) -> AnalyzerResult:
    """The card's lockfiles (and package.json) under `root`: the source tree at the
    scanned ref, or the copies a stored scan saved (recheck.py)."""
    name = f"{NAME}-npm"
    lockfiles = npm_lockfiles(root)
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
        findings += to_findings(
            pkgs,
            lf.name,
            set(),
            NPM_POLICY,
            npm_dev_only(lf),
            direct=_npm_direct(root),
            lookup=latest_release,
            build_tool=is_build_tool,
        )
    state = AnalyzerState.ERROR if errors else AnalyzerState.OK
    detail = ", ".join(lf.name for lf in lockfiles) + (f"; {' | '.join(errors)}" if errors else "")
    return AnalyzerResult(name, state, findings, detail, tool_version=osv_version())
