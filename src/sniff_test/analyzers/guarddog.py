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

Host reputation (0.8.0, user decision 2026-11-12): `threat-network-exfiltration` fires on
how an address looks (an ending such as .xyz, a named drop-box service, a public IP),
not on a data flow. chromadb-client names `https://api.together.xyz/v1/embeddings`,
Together AI's API, and that alone was a high finding. When every address the rule matched
is a well-known service (`known.py`), the finding is kept but shown as low, under its own
rule id, saying whose address it is. See `_known_service_hits` for what "every" means.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from sniff_test import known
from sniff_test.analyzers import _proc
from sniff_test.analyzers.pypi_meta import is_popular
from sniff_test.analyzers.python_deps import Resolution, ResolvedPackage, fetch_artifact
from sniff_test.analyzers.semgrep import neutralize_ignores
from sniff_test.deps.uv import Artifact
from sniff_test.models import AnalyzerResult, AnalyzerState, Category, Finding, Severity, Tag
from sniff_test.paths import cache_root

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

_ADDRESS_SHAPE = "threat-network-exfiltration"
KNOWN_SERVICE_RULE = "dep-guarddog-network-exfiltration-known-service"
_GUARDDOG_MAX_HITS = 5  # the rule's own `max_hits`: at 5, more matches may exist unseen
_CODE_URL = re.compile(r"""https?://[^\s"'`<>)\]}]+""", re.I)


def _known_service_hits(hits: list) -> list[tuple[str, known.Service]] | None:
    """The (host, service) pairs behind an address-shape finding when **every** address
    it matched is a well-known service, else None. Deliberately strict; anything unclear
    keeps the finding high:
    - fewer hits than GuardDog's cap (at the cap, later matches were cut off unseen);
    - each hit shows its line of code, the match is a URL in that line, and every URL on
      the line (not only the matched one) has a known host;
    - the host is read the way a client would (`urlsplit`), so `https://api.together.xyz
      @evil.tk/` or a backslash trick is another host, not a known one; any userinfo
      disqualifies;
    - services where each customer gets a host of their own (`shared`) don't count, and
      neither does a bare IP or one of the drop-box names the rule also carries (those
      aren't on the list at all)."""
    if not hits or len(hits) >= _GUARDDOG_MAX_HITS:
        return None
    out: list[tuple[str, known.Service]] = []
    for hit in hits:
        if not isinstance(hit, dict):
            return None
        code, match = str(hit.get("code") or ""), str(hit.get("match") or "").strip()
        if not match.lower().startswith(("http://", "https://")) or match not in code:
            return None
        urls = _CODE_URL.findall(code)
        if not urls or "\\" in code:
            return None
        for url in urls:
            try:
                parts = urlsplit(url)
                host = parts.hostname
            except ValueError:
                return None
            if not host or "@" in parts.netloc:
                return None
            svc = known.lookup(host)
            if svc is None or svc.shared:
                return None
            if (host, svc) not in out:
                out.append((host, svc))
    return out


def guarddog_version() -> str | None:
    """Even `--version` imports the typosquat module, which refreshes the lists (so it
    needs `tool_env`: under the app's AppArmor profile the plain call would crash)."""
    exe = shutil.which("guarddog")
    return _proc.version([exe, "--version"], tool_env(exe)) if exe else None


def shipped_lists(exe: str) -> Path | None:
    """GuardDog's `resources/` folder (its vendored top-PyPI/npm lists) next to `exe`:
    the venv layout of `uv tool install` and of the app image (/opt/tools/guarddog)."""
    root = Path(exe).resolve().parent.parent
    for p in root.glob("lib/python3*/site-packages/guarddog/analyzer/metadata/resources"):
        if (p / "top_pypi_packages.json").is_file():
            return p
    return None


def tool_env(exe: str) -> dict[str, str]:
    """GuardDog's environment. Its typosquat lists expire after 30 days, and then it
    downloads fresh ones and writes them next to its own code (an unguarded `open(w+)`
    in `_get_top_packages_with_refresh`): with the shipped lists dated 2026-06 that
    happens on the first scan of every fresh container. The lists are kept in our cache
    instead (`GUARDDOG_TOP_PACKAGES_CACHE_LOCATION`), seeded from the shipped ones, so
    the tool's install is never written (the app's AppArmor profile keeps /opt read-only)
    and a refresh survives restarts like HA's constraints do. Without the shipped folder
    (an unusual install) GuardDog is left as it is."""
    shipped = shipped_lists(exe)
    if shipped is None:
        return _proc.tool_env()
    cache = cache_root() / "guarddog"
    cache.mkdir(parents=True, exist_ok=True)
    for src in shipped.glob("top_*_packages.json"):
        dst = cache / src.name
        if not dst.exists():
            shutil.copyfile(src, dst)
    return _proc.tool_env(GUARDDOG_TOP_PACKAGES_CACHE_LOCATION=str(cache))


def _scan(
    exe: str, target: Path, run_dir: Path, env: dict[str, str] | None = None
) -> tuple[dict | None, str, bool]:
    """Returns (json, error, sandboxed)."""
    base = [exe, "pypi", "scan", str(target), "--output-format", "json"]
    sandboxed = True
    try:
        proc = _proc.run(base, run_dir, _TIMEOUT, env)
        if proc.returncode != 0 and "sandbox" in proc.stderr.lower():
            # No kernel sandbox here (e.g. some containers). GuardDog only parses files,
            # so fall back, but record it.
            sandboxed = False
            proc = _proc.run([*base, "--no-sandbox"], run_dir, _TIMEOUT, env)
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
        named = _known_service_hits(hits) if rule == _ADDRESS_SHAPE else None
        if named:
            whose = "; ".join(f"{host} is {svc.label}" for host, svc in named)
            out.append(
                Finding(
                    rule_id=KNOWN_SERVICE_RULE,
                    title=f"Unusual-looking address in dependency {pkg.name}",
                    severity=Severity.LOW,
                    category=Category.DEPENDENCY,
                    message=(
                        f"GuardDog heuristic '{rule}' matched in {pkg.name} {pkg.version} "
                        f"({art.filename}) at {where}{more}: the address has an ending "
                        f"that throwaway sites often use, but {whose}. Every address the "
                        "heuristic matched is a well-known service, so this is shown as "
                        "low. The heuristic looks only at the address; it doesn't show "
                        "what is sent there."
                    ),
                    file="manifest.json",
                    evidence=f"{pkg.name}=={pkg.version} {where}: {match}",
                    analyzer=NAME,
                    platforms=_platforms_for(art, pkg),
                )
            )
            continue
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
    env = tool_env(exe)

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
        return (item, *_scan(exe, local, run_dir, env))

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
