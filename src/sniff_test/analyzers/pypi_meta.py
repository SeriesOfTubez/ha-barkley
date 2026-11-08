"""Package-metadata checks: typosquats, non-index requirements, brand-new packages.

The typosquat check works offline from the name alone. A typosquat may not exist on
PyPI (yet, or any more), so it can't depend on resolution or the PyPI API.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from functools import cache
from importlib import resources

from sniff_test.analyzers.python_deps import PYPI_JSON, Resolution
from sniff_test.deps import reqs
from sniff_test.deps.ha_env import HAEnv
from sniff_test.fetch import http
from sniff_test.models import AnalyzerResult, AnalyzerState, Category, Finding, Severity, Tag

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


def run(
    requirements: list[reqs.Requirement],
    resolution: Resolution | None,
    env: HAEnv | None,
    online: bool = True,
    now: datetime | None = None,
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
                    "new release, and it wasn't resolved or checked by Sniff Test.",
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
    for name, plats in sorted(names.items()):
        if (target := typosquat_target(name, known, ha_targets)) is not None:
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
