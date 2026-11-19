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

Host reputation (0.9.0, user decision 2026-11-12): `threat-network-exfiltration` and
`threat-network-outbound-shady-links` fire on how an address looks (an ending such as
.xyz, a named service, a public IP), not on a data flow. A dependency that names
`https://api.together.xyz/v1/embeddings`, Together AI's API, gets a high finding for
that alone.
finding. The finding stays as it is; when every address behind it can be read with
certainty (`_addresses`), the finding carries them, and the panel lets the user mark
them trusted. 0.8.0 lowered such findings by itself from a shipped list of known
services; the user chose to decide per address instead (the list now only names hosts).
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

from sniff_test.analyzers import _proc
from sniff_test.analyzers.endpoints import never_trustable
from sniff_test.analyzers.pypi_meta import is_popular
from sniff_test.analyzers.python_deps import (
    Resolution,
    ResolvedPackage,
    discard_artifact,
    fetch_artifact,
)
from sniff_test.analyzers.semgrep import neutralize_ignores
from sniff_test.deps.uv import Artifact
from sniff_test.models import AnalyzerResult, AnalyzerState, Category, Finding, Severity, Tag
from sniff_test.paths import cache_root
from sniff_test.report import fingerprint
from sniff_test.trust import valid_address
from sniff_test.workspace import space_hint

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

_ADDRESS_RULES = frozenset({"threat-network-exfiltration", "threat-network-outbound-shady-links"})
_GUARDDOG_MAX_HITS = 5  # these rules' own `max_hits`: at 5, more matches may exist unseen
_CODE_URL = re.compile(r"""https?://[^\s"'`<>)\]}]+""", re.I)


def _addresses(hits: list) -> tuple[str, ...]:
    """The hosts/IPs behind an address-shape finding, when **every** one of them can be
    read with certainty; else nothing, and the finding can't be marked trusted.
    Deliberately strict:
    - fewer hits than GuardDog's cap (at the cap, later matches were cut off unseen);
    - each hit shows its line of code, the match is a URL in that line, and every URL on
      the line (not only the matched one) is counted;
    - the host is read the way a client would (`urlsplit`), so in
      `https://api.together.xyz@evil.tk/` the address is evil.tk; any userinfo or
      backslash disqualifies the finding altogether;
    - no drop box or chat webhook (`endpoints.never_trustable`): for those, knowing the
      service says nothing about who receives the data."""
    if not hits or len(hits) >= _GUARDDOG_MAX_HITS:
        return ()
    out: list[str] = []
    for hit in hits:
        if not isinstance(hit, dict):
            return ()
        code, match = str(hit.get("code") or ""), str(hit.get("match") or "").strip()
        if not match.lower().startswith(("http://", "https://")) or match not in code:
            return ()
        urls = _CODE_URL.findall(code)
        if not urls or "\\" in code:
            return ()
        for url in urls:
            try:
                parts = urlsplit(url)
                host = (parts.hostname or "").lower()
            except ValueError:
                return ()
            if not valid_address(host) or "@" in parts.netloc:
                return ()
            if never_trustable(host):
                return ()
            if host not in out:
                out.append(host)
    return tuple(out)


def guarddog_version() -> str | None:
    """Even `--version` imports the typosquat module, which refreshes the lists (so it
    needs `tool_env`: under the app's AppArmor profile the plain call would crash)."""
    exe = shutil.which("guarddog")
    return _proc.version([exe, "--version"], tool_env(exe), tool="guarddog") if exe else None


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


def _cache_dirs() -> tuple[Path, ...]:
    """GuardDog refreshes its typosquat lists into our cache (tool_env)."""
    return (cache_root() / "guarddog",)


def _scan(
    exe: str, target: Path, run_dir: Path, env: dict[str, str] | None = None
) -> tuple[dict | None, str, bool]:
    """Returns (json, error, sandboxed)."""
    base = [exe, "pypi", "scan", str(target), "--output-format", "json"]
    sandboxed = True
    try:
        proc = _proc.run(base, run_dir, _TIMEOUT, env, tool="guarddog", write=_cache_dirs())
        if proc.returncode != 0 and "sandbox" in proc.stderr.lower():
            # No kernel sandbox here (e.g. some containers). GuardDog only parses files,
            # so fall back, but record it.
            sandboxed = False
            proc = _proc.run([*base, "--no-sandbox"], run_dir, _TIMEOUT, env, tool="guarddog",
                             write=_cache_dirs())  # fmt: skip
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


def _file_hash(art: Artifact, where: str) -> str:
    """sha256 of the file GuardDog flagged, inside the unpacked archive ("" if unknown)."""
    if art.local is None or not where:
        return ""
    rel = where.rsplit(":", 1)[0] if where.rsplit(":", 1)[-1].isdigit() else where
    base = art.local.resolve()
    path = (base / rel).resolve() if not Path(rel).is_absolute() else Path(rel).resolve()
    try:
        path.relative_to(base)
    except ValueError:
        return ""
    return fingerprint.file_content(path)


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
                # (0.14.0) the package and the flagged file's content, not its version:
                # an accepted hit stays accepted until that file changes
                fingerprint=fingerprint.other(rule, pkg.name, _file_hash(art, where)),
                tags=frozenset({Tag.POSSIBLE}) if rule in _EXFIL else frozenset(),
                analyzer=NAME,
                platforms=_platforms_for(art, pkg),
                addresses=_addresses(hits) if rule in _ADDRESS_RULES else (),
            )
        )
    return out


LAST_PASS_MAX = 10  # files retried once more at the end; beyond that the network is down


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
        """Fetch, scan and turn into findings (which read the unpacked files), then free
        the archive's space at once (#22)."""
        pkg, art = item
        local = fetch_artifact(art, work)
        if local is None:
            return item, None, "fetch failed", True
        neutralize_ignores(local)
        data, err, sandboxed = _scan(exe, local, run_dir, env)
        found = to_findings(data, pkg, art) if data is not None else None
        discard_artifact(art, work)
        return item, found, err, sandboxed

    findings: list[Finding] = []
    errors: list[str] = []
    problems: list[dict] = []
    unsandboxed = 0
    failed: list[tuple[ResolvedPackage, Artifact]] = []

    def take(results) -> None:
        nonlocal unsandboxed
        for (pkg, art), data, err, sandboxed in results:
            unsandboxed += not sandboxed
            if data is None and err == "fetch failed":
                failed.append((pkg, art))
                continue
            if data is None:
                errors.append(f"{art.filename}: {err}")
                continue
            findings.extend(data)

    with ThreadPoolExecutor(max_workers=max(1, min(jobs or 4, 4))) as pool:
        take(pool.map(one, jobs_list))
    # (0.14.0) one last pass over what still failed, after everything else had its time
    if failed:
        again, failed = failed[:LAST_PASS_MAX], failed[LAST_PASS_MAX:]
        take(map(one, again))
    for _pkg, art in failed:
        problem = art.failure or {"file": art.filename, "kind": "other", "error": "fetch failed"}
        problems.append(problem)
        errors.append(f"{art.filename}: {problem.get('kind')}: {problem.get('error')}")

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
        # (#22) a full temp folder first, in plain words, then the tools' own messages
        detail += space_hint(" ".join(errors), work) + "; " + " | ".join(errors)[:500]
    return AnalyzerResult(
        NAME, state, list(merged.values()), detail, guarddog_version(), problems=problems
    )
