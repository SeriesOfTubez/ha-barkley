"""Package-metadata checks: typosquats, non-index requirements, brand-new packages.

The typosquat check works offline from the name alone. A typosquat may not exist on
PyPI (yet, or any more), so it can't depend on resolution or the PyPI API.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from functools import cache
from importlib import resources

from sniff_test.analyzers import osv
from sniff_test.analyzers.python_deps import PYPI_JSON, Resolution
from sniff_test.deps import reqs
from sniff_test.deps.ha_env import HAEnv
from sniff_test.fetch import http
from sniff_test.models import (
    AnalyzerResult,
    AnalyzerState,
    Category,
    Finding,
    Severity,
    Tag,
    version_key,
)

NAME = "pypi-meta"
NEW_PACKAGE_DAYS = 30
# Squat targets: the most-downloaded projects (plus HA's constraint names). Anything in
# the full list counts as popular in its own right and is never flagged. Tuned on HA's
# requirements_all.txt (1190 real libraries): top-1000 targets gave 0 false positives
# and caught every planted typo; top-5000 flagged 9 legitimate libraries.
_TARGET_COUNT = 1000
_MIN_TARGET_LEN = 5  # short names have too many legitimate one-edit neighbours


@cache
def _top_packages() -> tuple[str, ...]:
    text = (resources.files("sniff_test") / "data" / "top_pypi.txt").read_text("utf-8")
    return tuple(ln.strip() for ln in text.splitlines() if ln.strip() and ln[0] != "#")


@cache
def _top_set() -> frozenset[str]:
    return frozenset(_top_packages())


def is_popular(name: str) -> bool:
    return reqs.normalize(name) in _top_set()


def _osa_distance(a: str, b: str, limit: int) -> int:
    """Optimal string alignment distance (Levenshtein + adjacent transpositions)."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit and min(prev) >= limit:  # transpositions reach back one row
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _squashed(name: str) -> str:
    return name.replace("-", "")


def typosquat_target(
    name: str, known: frozenset[str] = frozenset(), extra_targets: tuple[str, ...] = ()
) -> str | None:
    """Return the popular package `name` looks like an imitation of, else None."""
    name = reqs.normalize(name)
    top = _top_packages()
    if name in known or name in _top_set():
        return None
    for target in (*top[:_TARGET_COUNT], *extra_targets):
        if len(target) < _MIN_TARGET_LEN:
            continue
        if _squashed(name) == _squashed(target):  # python-dateutil vs pythondateutil
            return target
        limit = 2 if len(target) >= 10 else 1
        if _osa_distance(name, target, limit) <= limit:
            return target
    return None


def _first_upload(meta: dict) -> datetime | None:
    times = [
        f.get("upload_time_iso_8601")
        for files in (meta.get("releases") or {}).values()
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    if not times:
        return None
    return min(datetime.fromisoformat(t.replace("Z", "+00:00")) for t in times)


def versions_behind(meta: dict, version: str, pinned: str | None = None) -> dict | None:
    """(0.15, his decision 2026-11-21) Context for a package line, from the PyPI JSON the
    scan already reads: the newest release, its date, how many final releases (not yanked)
    are newer than the one installed, and whether Home Assistant's own pin is the one
    installed (then it holds the app at that version). Never a finding."""
    newest, date, newer = osv.latest_from_meta(meta, "PyPI", version)
    if not newest:
        return None
    out: dict = {"newest": newest[:40], "newer": newer}
    if date:
        out["newest_date"] = date
    if pinned and newer and version_key("PyPI", pinned) == version_key("PyPI", version):
        out["held_by_ha"] = True
    return out


def _f(rule: str, title: str, sev: Severity, msg: str, evidence: str, **kw) -> Finding:
    return Finding(
        rule_id=rule,
        title=title,
        severity=sev,
        category=Category.DEPENDENCY,
        message=msg,
        file="manifest.json",
        evidence=evidence,
        analyzer=NAME,
        **kw,
    )


_GITHUB_OWNER = re.compile(r"^https?://(?:www\.)?github\.com/([A-Za-z0-9-]{1,39})(?:/|$)", re.I)
_PROJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}")


def owner_tie(name: str, version: str | None, owner: str | None) -> str | None:
    """(0.15, his decision 2026-11-22) How a package is tied to the app's owner on GitHub:
    "attested" when PyPI's provenance record for one of its files names a GitHub workflow
    in that owner's account (PyPI checks it when the file is uploaded), "link" when only
    the project's own links point there (anyone can type a link), else None. Lookups that
    fail say nothing (never a result)."""
    if not owner or not _PROJECT.fullmatch(name):
        return None
    try:
        meta = http.lookup_json(PYPI_JSON.format(name=name), 10.0)
    except http.HttpError:
        return None
    if not isinstance(meta, dict):
        return None
    info = meta.get("info") if isinstance(meta.get("info"), dict) else {}
    ver = version if version and version in (meta.get("releases") or {}) else info.get("version")
    files = ((meta.get("releases") or {}).get(ver) or []) if ver else []
    want = owner.lower()
    for f in [x for x in files if isinstance(x, dict)][:4]:
        fname = str(f.get("filename") or "")
        if not _PROJECT.fullmatch(fname):
            continue
        try:
            prov = http.lookup_json(
                f"https://pypi.org/integrity/{name}/{ver}/{fname}/provenance", 10.0
            )
        except http.HttpError:
            continue
        for b in (prov or {}).get("attestation_bundles") or []:
            pub = b.get("publisher") if isinstance(b, dict) else None
            repo = str((pub or {}).get("repository") or "")
            if (pub or {}).get("kind") == "GitHub" and repo.split("/", 1)[0].lower() == want:
                return "attested"
    links = [str(v) for v in (info.get("project_urls") or {}).values()] + [
        str(info.get("home_page") or "")
    ]
    if any((m := _GITHUB_OWNER.match(u)) and m.group(1).lower() == want for u in links):
        return "link"
    return None


TIED_RULE = "dep-lookalike-own"


def _tied(name: str, target: str, tie: str, owner: str, plats: set[str]) -> Finding:
    """A lookalike name tied to the app's owner: a note when PyPI's provenance says the
    owner's GitHub published it; medium when only a link says so."""
    if tie == "attested":
        return _f(
            TIED_RULE,
            "Package name close to a popular one, published by this app's owner",
            Severity.INFO,
            f"'{name}' is one typo away from the popular package '{target}'. PyPI's record "
            f"of how it was published names a GitHub workflow in {owner[:39]}'s account, the "
            "owner of this app, so it's their own library, not an imitation.",
            f"{name} ~ {target}",
            platforms=frozenset(plats),
        )
    return _f(
        "dep-typosquat",
        "Possible typosquat of a popular package",
        Severity.MEDIUM,
        f"'{name}' is one typo away from the popular package '{target}'. Its PyPI page links "
        f"to {owner[:39]}'s GitHub account, the owner of this app. Anyone can type a link, "
        "so that doesn't prove who published it.",
        f"{name} ~ {target}",
        tags=frozenset({Tag.POSSIBLE}),
        platforms=frozenset(plats),
    )


def run(
    requirements: list[reqs.Requirement],
    resolution: Resolution | None,
    env: HAEnv | None,
    online: bool = True,
    now: datetime | None = None,
    owner: str | None = None,
) -> AnalyzerResult:
    if not requirements:
        return AnalyzerResult(NAME, AnalyzerState.NOT_APPLICABLE)
    known = env.known_names() if env else frozenset()
    ha_targets = tuple(sorted(env.constraints)) if env else ()
    findings: list[Finding] = []

    for r in requirements:
        if r.kind is reqs.ReqKind.URL:
            findings.append(
                _f(
                    "dep-vcs-or-url-requirement",
                    "Requirement bypasses PyPI (VCS / URL / path)",
                    Severity.HIGH,
                    "This requirement installs code straight from a URL or repository instead "
                    "of a package index. What it points at can change at any time without a "
                    "new release, and it wasn't resolved or checked by Barkley.",
                    r.raw,
                )
            )
        elif r.kind is reqs.ReqKind.INVALID:
            option_like = r.raw.lstrip().startswith("-")
            findings.append(
                _f(
                    "dep-invalid-requirement",
                    "Malformed or option-like requirement",
                    Severity.HIGH if option_like else Severity.MEDIUM,
                    "This manifest requirement isn't a plain package requirement"
                    + (
                        ". It looks like an installer option, which could change where or "
                        "how packages are installed."
                        if option_like
                        else "; it wasn't resolved or checked."
                    ),
                    r.raw,
                )
            )

    # Typosquats: the manifest's own names (offline), plus resolved transitive names.
    names: dict[str, set[str]] = {}
    for r in requirements:
        if r.name:
            names.setdefault(r.name, set())
    if resolution:
        for p in resolution.third_party():
            names.setdefault(p.name, set()).update(p.platforms)
    versions = {p.name: p.version for p in resolution.third_party()} if resolution else {}
    for name, plats in sorted(names.items()):
        if (target := typosquat_target(name, known, ha_targets)) is not None:
            tie = owner_tie(name, versions.get(name), owner) if online else None
            if tie is not None:
                findings.append(_tied(name, target, tie, owner or "", plats))
                continue
            findings.append(
                _f(
                    "dep-typosquat",
                    "Possible typosquat of a popular package",
                    Severity.HIGH,
                    f"'{name}' is one typo away from the popular package '{target}'. "
                    f"Typosquats imitate well-known names to get installed by mistake.",
                    f"{name} ~ {target}",
                    tags=frozenset({Tag.POSSIBLE}),
                    platforms=frozenset(plats),
                )
            )

    state, detail = AnalyzerState.OK, "names checked offline"
    if resolution and online:
        now = now or datetime.now(UTC)
        cutoff = now - timedelta(days=NEW_PACKAGE_DAYS)
        failures = 0
        seen: set[str] = set()
        for p in resolution.third_party():
            if p.name in seen:
                continue
            seen.add(p.name)
            try:
                meta = http.get_json(PYPI_JSON.format(name=p.name))
            except http.NotFoundError:
                continue  # served only by HA's wheel index
            except http.HttpError:
                failures += 1
                continue
            pin = env.constraints.get(reqs.normalize(p.name)) if env else None
            behind = versions_behind(meta, p.version, pin)
            if behind is not None:  # every platform's copy of this package
                for q in resolution.packages.values():
                    if q.name == p.name:
                        q.behind = behind
            first = _first_upload(meta)
            if first and first > cutoff:
                findings.append(
                    _f(
                        "dep-very-new-package",
                        f"Dependency first published under {NEW_PACKAGE_DAYS} days ago",
                        Severity.MEDIUM,
                        f"{p.name} was first uploaded to PyPI on {first:%Y-%m-%d}. Brand-new "
                        f"packages have no track record; most malicious packages are "
                        f"caught and removed within days of upload.",
                        f"{p.name}=={p.version}",
                        platforms=frozenset(p.platforms),
                    )
                )
        detail = f"{len(seen)} packages checked on PyPI"
        if failures:
            state = AnalyzerState.ERROR
            detail += f"; {failures} PyPI lookups failed"
    elif resolution is None or not online:
        detail = "names checked offline only (no PyPI age check)"
    return AnalyzerResult(NAME, state, findings=findings, detail=detail)
