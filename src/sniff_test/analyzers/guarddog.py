"""Heuristic malware checks on downloaded dependency archives, via GuardDog 3.2.

Only packages HA doesn't already provide are scanned: anything pinned in HA's
constraints is in every HA install already, and scanning it is pure noise.

Archives are downloaded (sha256-verified) and extracted by our own hardened extractor;
GuardDog only ever sees a directory. It analyzes statically and never runs the code.

GuardDog is noisy, so we keep only `threat-*` rules, with our own severity table. Its
`capability-*` rules ("makes network requests", "reads files") describe most libraries.
Heuristics never go above high: critical is reserved for proven taint paths and
known-malicious advisories. In very popular packages (the vendored top-PyPI list),
medium heuristics drop to low: there they are almost always legitimate features
(e.g. typer's shell-completion installer writing to ~/.bashrc), while high-confidence
threat rules still fire at full severity in case a popular package is hijacked.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from sniff_test.analyzers import _proc
from sniff_test.analyzers.pypi_meta import is_popular
from sniff_test.analyzers.python_deps import Resolution, ResolvedPackage, fetch_artifact
from sniff_test.analyzers.semgrep import neutralize_ignores
from sniff_test.deps.uv import Artifact
from sniff_test.models import AnalyzerResult, AnalyzerState, Category, Finding, Severity, Tag

NAME = "guarddog"
_TIMEOUT = 300
_EVIDENCE_MAX = 200

_EXFIL = frozenset(
    {
        "threat-network-exfil-messenger",
        "threat-network-exfiltration",
        "threat-network-dns-exfil",
        "threat-network-exfil-sysinfo",
        "threat-network-reverse-shell",
        "threat-runtime-keylogging",
        "threat-runtime-screencapture",
    }
)
SEVERITY: dict[str, Severity | None] = {
    **{r: Severity.HIGH for r in _EXFIL},
    "threat-runtime-obfuscation-base64exec": Severity.HIGH,
    "threat-process-download-exec": Severity.HIGH,
    "threat-process-cryptomining": Severity.HIGH,
    "threat-runtime-self-propagation": Severity.HIGH,
    "threat-process-injection-dll": Severity.HIGH,
    "threat-process-powershell-encoded": Severity.HIGH,
    "threat-setup-network-in-install": Severity.HIGH,
    "threat-filesystem-destruction": Severity.HIGH,
    "threat-runtime-obfuscation-steganography": Severity.HIGH,
    "threat-runtime-obfuscation": Severity.MEDIUM,
    "threat-runtime-obfuscation-general": Severity.MEDIUM,
    "threat-runtime-obfuscation-api": Severity.MEDIUM,
    "threat-runtime-obfuscation-import-exec": Severity.MEDIUM,
    "threat-runtime-obfuscation-dynamic-eval": Severity.MEDIUM,
    "threat-runtime-obfuscation-chr": Severity.MEDIUM,
    "threat-runtime-obfuscation-unicode": Severity.MEDIUM,
    "threat-runtime-obfuscation-hidden-code": Severity.MEDIUM,
    "threat-runtime-obfuscation-pyarmor": Severity.MEDIUM,
    "threat-runtime-obfuscation-log-suppress": Severity.MEDIUM,
    "threat-network-outbound-shady-links": Severity.MEDIUM,
    "threat-process-spawn-silent": Severity.MEDIUM,
    "threat-filesystem-autostart": Severity.MEDIUM,
    "threat-setup-suspicious-imports": Severity.MEDIUM,
    "threat-setup-import-aliasing": Severity.MEDIUM,
    "threat-process-hooks": Severity.MEDIUM,
    "threat-runtime-dynamic-loader": Severity.MEDIUM,
    # Dropped: describe ordinary libraries, or are covered better elsewhere.
    "threat-runtime-environment-read": None,
    "threat-runtime-system-info": None,
    "threat-process-sysinfo": None,
    "threat-runtime-enumeration": None,
    "threat-filesystem-read": None,
    "threat-process-memory": None,
}
_UNKNOWN_THREAT = Severity.LOW


def guarddog_version() -> str | None:
    exe = shutil.which("guarddog")
    return _proc.version([exe, "--version"]) if exe else None


def _scan(exe: str, target: Path, run_dir: Path) -> tuple[dict | None, str, bool]:
    """Returns (json, error, sandboxed)."""
    base = [exe, "pypi", "scan", str(target), "--output-format", "json"]
    sandboxed = True
    try:
        proc = _proc.run(base, run_dir, _TIMEOUT)
        if proc.returncode != 0 and "sandbox" in proc.stderr.lower():
            # No kernel sandbox here (e.g. some containers). GuardDog only parses files,
            # so fall back, but record it.
            sandboxed = False
            proc = _proc.run([*base, "--no-sandbox"], run_dir, _TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, "timed out", sandboxed
    try:
        return json.loads(proc.stdout), "", sandboxed
    except ValueError:
        return None, f"exit {proc.returncode}: {proc.stderr.strip()[-300:]}", sandboxed


def _platforms_for(art: Artifact, pkg: ResolvedPackage) -> frozenset[str]:
    for plat in ("x86_64", "aarch64"):
        if plat in art.filename:
            return frozenset({plat})
    return frozenset(pkg.platforms)


def to_findings(data: dict, pkg: ResolvedPackage, art: Artifact) -> list[Finding]:
    out: list[Finding] = []
    for rule, hits in sorted((data.get("results") or {}).items()):
        if not hits or not rule.startswith("threat-"):
            continue
        sev = SEVERITY.get(rule, _UNKNOWN_THREAT)
        if sev is None:
            continue
        if sev is Severity.MEDIUM and is_popular(pkg.name):
            sev = Severity.LOW
        hits = hits if isinstance(hits, list) else [hits]
        first = hits[0] if isinstance(hits[0], dict) else {}
        where = str(first.get("location", ""))
        match = " ".join(str(first.get("match", "")).split())[:_EVIDENCE_MAX]
        more = f" (and {len(hits) - 1} more)" if len(hits) > 1 else ""
        out.append(
            Finding(
                rule_id=f"dep-guarddog-{rule.removeprefix('threat-')}",
                title=f"Suspicious code in dependency {pkg.name}",
                severity=sev,
                category=Category.DEPENDENCY,
                message=(
                    f"GuardDog heuristic '{rule}' matched in {pkg.name} {pkg.version} "
                    f"({art.filename}) at {where}{more}: "
                    f"{str(first.get('message', '')).strip()}. Heuristic: review the code."
                ),
                file="manifest.json",
                evidence=f"{pkg.name}=={pkg.version} {where}: {match}",
                tags=frozenset({Tag.POSSIBLE}) if rule in _EXFIL else frozenset(),
                analyzer=NAME,
                platforms=_platforms_for(art, pkg),
            )
        )
    return out


def run(resolution: Resolution | None, work: Path, jobs: int | None = None) -> AnalyzerResult:
    pkgs = resolution.third_party() if resolution else []
    if not pkgs:
        return AnalyzerResult(NAME, AnalyzerState.NOT_APPLICABLE, detail="no third-party deps")
    exe = shutil.which("guarddog")
    if not exe:
        return AnalyzerResult(NAME, AnalyzerState.SKIPPED, detail="guarddog not installed")
    run_dir = _proc.empty_dir(work, "guarddog-run")

    jobs_list: list[tuple[ResolvedPackage, Artifact]] = []
    seen: set[str] = set()
    for pkg in sorted(pkgs, key=lambda p: (p.name, p.version)):
        for art in pkg.artifacts.values():
            key = art.sha256 or art.url
            if key not in seen:
                seen.add(key)
                jobs_list.append((pkg, art))

    def one(item: tuple[ResolvedPackage, Artifact]):
        _pkg, art = item
        local = fetch_artifact(art, work)
        if local is None:
            return item, None, "download/extract failed", True
        neutralize_ignores(local)
        return (item, *_scan(exe, local, run_dir))

    findings: list[Finding] = []
    errors: list[str] = []
    unsandboxed = 0
    with ThreadPoolExecutor(max_workers=max(1, min(jobs or 4, 4))) as pool:
        for (pkg, art), data, err, sandboxed in pool.map(one, jobs_list):
            unsandboxed += not sandboxed
            if data is None:
                errors.append(f"{art.filename}: {err}")
                continue
            findings += to_findings(data, pkg, art)

    # One finding per (package, rule): the same hit in each platform's wheel is one issue.
    merged: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.rule_id, (f.evidence or "").split(" ", 1)[0])
        if key in merged:
            merged[key] = replace(merged[key], platforms=merged[key].platforms | f.platforms)
        else:
            merged[key] = f
    detail = f"{len(jobs_list)} archives from {len(pkgs)} third-party packages"
    if unsandboxed:
        detail += f"; {unsandboxed} scanned without GuardDog's sandbox"
    state = AnalyzerState.OK
    if errors:
        state = AnalyzerState.ERROR
        detail += "; " + " | ".join(errors)[:500]
    return AnalyzerResult(NAME, state, list(merged.values()), detail, guarddog_version())
