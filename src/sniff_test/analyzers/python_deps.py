"""Resolve an integration's Python dependency tree the way Home Assistant would install it.

`uv pip compile` against HA's constraints, for the platforms of the official (Alpine,
musl) image, using PyPI plus HA's own wheel index with HA's index strategy.

Safety:
- `--no-build` (uv's alias for `--only-binary :all:`): uv never builds an sdist to read
  its metadata, so no `setup.py` / build backend from the scanned tree ever runs;
- only validated PEP 508 lines reach the requirements file (no `-e`, `--index-url`, ...);
- `--no-config`, a scrubbed environment, an empty cwd, and a dedicated uv cache that
  has never built anything (uv reuses cached *built* wheels otherwise).

When resolution fails we find the culprit, record it, exclude it, and resolve again, so
one bad package can't hide the rest of the tree from the later analyzers.
"""

from __future__ import annotations

import email.parser
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from sniff_test.analyzers import _proc
from sniff_test.deps import reqs, uv
from sniff_test.deps.ha_env import HAEnv
from sniff_test.deps.uv import Artifact, parse_pylock
from sniff_test.fetch import http
from sniff_test.models import (
    AnalyzerResult,
    AnalyzerState,
    Category,
    Finding,
    Severity,
    Target,
    TargetKind,
)
from sniff_test.paths import cache_root
from sniff_test.workspace import UnsafeArchiveError, extract, single_top_dir

NAME = "python-deps"
PYPI_JSON = "https://pypi.org/pypi/{name}/json"
_MAX_ROUNDS = 12

_RX_NOT_FOUND = re.compile(r"Because (\S+?) was not found in the package registry")
_RX_SDIST_ONLY = re.compile(r"Wheels are required for `([^`]+)`")
_RX_NO_WHEELS = re.compile(r"(\S+?)==(\S+?) has no usable wheels")
_RX_YOU_REQUIRE = re.compile(r"you require ([A-Za-z0-9][A-Za-z0-9._-]*)")
_RX_CAUSE = re.compile(r"cause:\s*(.+)")


@dataclass
class ResolvedPackage:
    name: str
    version: str
    platforms: set[str] = field(default_factory=set)
    artifacts: dict[str, Artifact] = field(default_factory=dict)  # keyed by filename
    direct: bool = False
    ha_provided: bool = False
    sdist_only: bool = False


@dataclass
class Resolution:
    requirements: list[reqs.Requirement] = field(default_factory=list)
    packages: dict[tuple[str, str], ResolvedPackage] = field(default_factory=dict)
    lockfiles: dict[str, Path] = field(default_factory=dict)  # platform -> pylock.toml

    def third_party(self) -> list[ResolvedPackage]:
        """Packages not already present in every HA install."""
        return [p for p in self.packages.values() if not p.ha_provided]


@dataclass
class _Culprit:
    name: str
    reason: str  # not_found | sdist_only | conflict
    version: str | None
    cause: str


def manifest_requirements(target: Target) -> list[object] | None:
    try:
        data = json.loads((target.root / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    value = data.get("requirements") if isinstance(data, dict) else None
    return value if isinstance(value, list) else None


def uv_version() -> str | None:
    exe = uv.exe()
    v = _proc.version([exe, "--version"]) if exe else None
    return v.split()[1] if v and len(v.split()) > 1 else v  # "uv 0.13.7 (Homebrew ...)"


def find_culprit(stderr: str) -> _Culprit | None:
    m = _RX_CAUSE.search(stderr)
    cause = m.group(1).strip() if m else stderr.strip()[-300:]
    if m := _RX_NOT_FOUND.search(stderr):
        return _Culprit(reqs.normalize(m.group(1)), "not_found", None, cause)
    if m := _RX_SDIST_ONLY.search(stderr):
        name = reqs.normalize(m.group(1))
        version = None
        for nm, ver in _RX_NO_WHEELS.findall(stderr):
            if reqs.normalize(nm) == name:
                version = ver
        return _Culprit(name, "sdist_only", version, cause)
    if m := _RX_YOU_REQUIRE.search(stderr):
        return _Culprit(reqs.normalize(m.group(1)), "conflict", None, cause)
    return None


# --- sdist handling ---------------------------------------------------------------------


def _pypi_sdist(name: str, version: str | None) -> tuple[str, Artifact] | None:
    try:
        meta = http.get_json(PYPI_JSON.format(name=name))
    except http.HttpError:
        return None
    version = version or str(meta.get("info", {}).get("version") or "")
    for f in meta.get("releases", {}).get(version, []):
        if f.get("packagetype") == "sdist" and not f.get("yanked"):
            return version, Artifact(
                url=str(f["url"]),
                filename=str(f["filename"]),
                sha256=(f.get("digests") or {}).get("sha256"),
                kind="sdist",
            )
    return None


def fetch_artifact(art: Artifact, work: Path) -> Path | None:
    """Download and safely extract a distribution. Never builds or imports anything."""
    if art.local:
        return art.local
    dl = work / "dists"
    dl.mkdir(exist_ok=True)
    key = (art.sha256 or re.sub(r"[^A-Za-z0-9]", "_", art.filename))[:32]
    archive = dl / f"{key}-{re.sub(r'[^A-Za-z0-9._-]', '_', art.filename)}"
    dest = dl / f"{key}.d"
    try:
        if not archive.exists():
            http.download(art.url, archive, art.sha256)
        if not dest.exists():
            dest.mkdir()
            extract(archive, dest)
    except (http.HttpError, UnsafeArchiveError, OSError):
        return None
    art.local = dest
    return dest


def static_requires(sdist_dir: Path) -> list[str]:
    """Requires-Dist from an sdist's PKG-INFO (or egg-info), read as text. Best effort:
    for old sdists, setup.py may compute dependencies we can't see without running it."""
    root = single_top_dir(sdist_dir)
    candidates = [root / "PKG-INFO", *sorted(root.glob("*.egg-info/requires.txt"))]
    for path in candidates:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if path.name == "PKG-INFO":
            msg = email.parser.Parser().parsestr(text, headersonly=True)
            found = [str(v) for v in msg.get_all("Requires-Dist") or []]
            if found:
                return [r for r in found if "extra" not in r.split(";", 1)[-1]]
        else:
            lines = []
            for line in text.splitlines():
                if line.startswith("["):  # extras / conditional sections
                    break
                if line.strip():
                    lines.append(line.strip())
            return lines
    return []


# --- main -------------------------------------------------------------------------------


def _finding(rule: str, title: str, sev: Severity, msg: str, evidence: str, plats) -> Finding:
    return Finding(
        rule_id=rule,
        title=title,
        severity=sev,
        category=Category.DEPENDENCY,
        message=msg,
        file="manifest.json",
        evidence=evidence,
        analyzer=NAME,
        platforms=frozenset(plats),
    )


def _culprit_finding(c: _Culprit, plats: set[str]) -> Finding:
    if c.reason == "not_found":
        msg = (
            f"'{c.name}' was not found on PyPI or HA's wheel index, so Home Assistant would "
            f"fail to install this integration. Packages that disappear from PyPI are often "
            f"removed malware; a misspelled name may be a typosquat that doesn't exist yet."
        )
    else:
        msg = (
            f"'{c.name}' can't be resolved together with Home Assistant's pinned packages "
            f"(see evidence), so HA would fail to install this integration's requirements. "
            f"Its dependency tree was not checked."
        )
    return _finding(
        "dep-unresolvable",
        "Dependency can't be installed",
        Severity.MEDIUM,
        msg,
        f"{c.name}: {c.cause}",
        plats,
    )


def run(target: Target, work: Path, env: HAEnv | None) -> tuple[AnalyzerResult, Resolution | None]:
    if target.kind is not TargetKind.INTEGRATION:
        return AnalyzerResult(NAME, AnalyzerState.NOT_APPLICABLE), None
    raw = manifest_requirements(target)
    parsed = [reqs.parse(r) for r in raw or []]
    resolution = Resolution(requirements=parsed)
    plain = [r for r in parsed if r.kind is reqs.ReqKind.PLAIN]
    if not plain:
        detail = "no installable requirements in manifest.json"
        return AnalyzerResult(NAME, AnalyzerState.NOT_APPLICABLE, detail=detail), resolution
    exe = uv.exe()
    if not exe:
        return AnalyzerResult(NAME, AnalyzerState.SKIPPED, detail="uv not installed"), resolution
    version = uv_version()
    if env is None:
        detail = "Home Assistant constraints unavailable (offline?)"
        return (
            AnalyzerResult(NAME, AnalyzerState.SKIPPED, detail=detail, tool_version=version),
            resolution,
        )

    run_dir = _proc.empty_dir(work, "uv-run")
    deps_dir = _proc.empty_dir(work, "deps")
    direct = {r.name for r in plain}
    culprits: dict[tuple[str, str], tuple[_Culprit, set[str]]] = {}
    sdists: dict[tuple[str, str], tuple[Artifact, set[str]]] = {}
    errors: list[str] = []

    for plat in uv.PLATFORMS:
        lines = [r.raw for r in plain]
        excluded: list[str] = []
        for _round in range(_MAX_ROUNDS):
            req_file = deps_dir / f"requirements.{plat}.txt"
            req_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            excludes = deps_dir / f"excludes.{plat}.txt"
            excludes.write_text("".join(f"{n}\n" for n in excluded), encoding="utf-8")
            out = deps_dir / f"pylock.{plat}.toml"
            out.unlink(missing_ok=True)
            try:
                proc = uv.compile_lock(
                    exe,
                    req_file,
                    out,
                    constraints=env.constraints_path,
                    python_version=env.python_version,
                    platform=plat,
                    cache_dir=cache_root() / "uv",
                    run_dir=run_dir,
                    excludes=excludes,
                )
            except subprocess.TimeoutExpired:
                errors.append(f"{plat}: uv timed out")
                break
            if proc.returncode == 0 and out.is_file():
                resolution.lockfiles[plat] = out
                for name, ver, arts in parse_pylock(out):
                    pkg = resolution.packages.setdefault(
                        (name, ver), ResolvedPackage(name, ver, direct=name in direct)
                    )
                    pkg.platforms.add(plat)
                    for a in arts:
                        pkg.artifacts.setdefault(a.filename, a)
                break
            culprit = find_culprit(proc.stderr)
            if culprit is None or culprit.name in excluded:
                errors.append(f"{plat}: {proc.stderr.strip()[-400:]}")
                break
            excluded.append(culprit.name)
            if culprit.reason != "sdist_only":
                key = (culprit.name, culprit.reason)
                culprits.setdefault(key, (culprit, set()))[1].add(plat)
                continue
            # sdist only: fetch it (never build) for GuardDog, and resolve what it declares.
            pinned = next((r.pinned for r in plain if r.name == culprit.name), None)
            got = _pypi_sdist(culprit.name, culprit.version or pinned)
            if got is None:
                key = (culprit.name, "sdist_only")
                culprits.setdefault(key, (culprit, set()))[1].add(plat)
                continue
            sver, art = got
            sdists.setdefault((culprit.name, sver), (art, set()))[1].add(plat)
            local = fetch_artifact(art, work)
            for dep in static_requires(local) if local else []:
                r = reqs.parse(dep)
                if r.kind is reqs.ReqKind.PLAIN and r.name not in excluded:
                    lines.append(r.raw)
        else:
            errors.append(f"{plat}: gave up after {_MAX_ROUNDS} resolution rounds")

    findings: list[Finding] = []
    for (_name, _reason), (c, plats) in sorted(culprits.items()):
        findings.append(_culprit_finding(c, plats))
    for (name, ver), (art, plats) in sorted(sdists.items()):
        pkg = resolution.packages.setdefault(
            (name, ver), ResolvedPackage(name, ver, direct=name in direct)
        )
        pkg.platforms |= plats
        pkg.sdist_only = True
        pkg.artifacts.setdefault(art.filename, art)
        findings.append(
            _finding(
                "dep-sdist-only",
                "Dependency has no wheel: HA builds it from source on your box",
                Severity.LOW,
                f"{name} {ver} has no prebuilt wheel for "
                f"{', '.join(sorted(plats))}, so HA would build it from source during "
                f"install, running its setup code. Sniff Test downloaded the source archive "
                f"without building it; its declared dependencies were resolved as best "
                f"we can without running setup code.",
                f"{name}=={ver}",
                plats,
            )
        )

    for pkg in resolution.packages.values():
        pkg.ha_provided = not pkg.sdist_only and env.is_ha_provided(
            pkg.name, pkg.version, pkg.platforms
        )
    n = len(resolution.packages)
    third = len(resolution.third_party())
    detail = f"{n} packages resolved ({third} not provided by HA {env.version})"
    state = AnalyzerState.OK
    if errors:
        state = AnalyzerState.ERROR
        detail += "; resolution incomplete: " + " | ".join(errors)[:600]
    return (
        AnalyzerResult(NAME, state, findings=findings, detail=detail, tool_version=version),
        resolution,
    )
