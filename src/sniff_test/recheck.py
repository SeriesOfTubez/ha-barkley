"""Advisories asked again for a stored scan (0.10.0).

A stored scan is reused for as long as the app stays at that version, so an advisory
published after the scan (a new CVE, or a package newly listed as malicious) never
showed until someone sniffed again. A re-check asks OSV again about exactly the packages
the scan resolved, and nothing else:

- The scan saves its lockfiles next to the report (`capture`, `Store.save(inputs=)`):
  the pylock per platform for an integration, the card's npm lockfile and package.json.
  They are text from the scan, some of it from the scanned repo: stored as data, only
  ever parsed, and handed to osv-scanner the way the scan did (copied alone into an
  empty folder of ours, our own empty config).
- `recheck` writes them into a fresh workspace and runs the same `osv.check_python` /
  `osv.check_npm` as the scan. No code is fetched, nothing else is scanned again, GitHub
  is not asked anything.
- Nothing stored is edited. When the advisories differ, `apply` builds a **new** report
  from the stored one: the osv findings replaced, the score computed by `scoring.score`
  from the findings (the same call the scanner makes), and every section that points at
  findings brought in line. The caller saves it as a new scan entry; the old one stays.
- A re-check that couldn't ask OSV raises `RecheckError` and changes nothing: an
  unreachable service is never a result.

"Differ" means the set of (finding, severity) pairs: a finding's id covers its rule,
package, version and advisory ids. The newest-release facts in a finding's text refresh
only when that set changes (or on a fresh sniff): a new upstream release alone is not a
reason for a new entry and a notification.
"""

from __future__ import annotations

import copy
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sniff_test import trust
from sniff_test.analyzers import osv
from sniff_test.analyzers.python_deps import Resolution
from sniff_test.models import AnalyzerResult, AnalyzerState, Target, TargetKind
from sniff_test.report.graph import _DEP_NAME, _pep503
from sniff_test.report.json_report import finding_json, sanitize_untrusted
from sniff_test.scoring import Exposure, apply_exposure
from sniff_test.workspace import workspace

INPUTS_VERSION = 1
KEY = "_recheck_inputs"  # how a scan function hands the inputs to Store.save; never stored
MAX_FILE = 8 * 1024 * 1024  # a lockfile larger than this isn't saved (no re-check)
MAX_TOTAL = 24 * 1024 * 1024
_PYLOCK = re.compile(r"^pylock(\.[A-Za-z0-9._-]{1,60})?\.toml$")
_PLATFORM = re.compile(r"^[A-Za-z0-9._-]{1,60}$")
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class RecheckError(Exception):
    """OSV couldn't be asked (or the saved inputs are unusable). Nothing changes."""


def _read(path: Path) -> str | None:
    try:
        if path.is_symlink() or path.stat().st_size > MAX_FILE:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def capture(target: Target, resolution: Resolution | None) -> dict[str, Any] | None:
    """What a later re-check needs, read while the scan's workspace still exists. None:
    nothing to ask OSV about, or a file is too large or unreadable (then this scan can't
    be re-checked, and the panel says so)."""
    if target.kind is TargetKind.INTEGRATION:
        if resolution is None or not resolution.lockfiles:
            return None
        files: dict[str, dict[str, str]] = {}
        for plat, path in sorted(resolution.lockfiles.items()):
            text = _read(path)
            if text is None or not _PYLOCK.match(path.name) or not _PLATFORM.match(plat):
                return None
            files[plat] = {"name": path.name, "text": text}
        out: dict[str, Any] = {
            "version": INPUTS_VERSION,
            "ecosystem": "PyPI",
            "lockfiles": files,
            "ha_provided": sorted({p.name for p in resolution.packages.values() if p.ha_provided}),
            "direct": sorted({r.name for r in resolution.requirements if r.name}),
        }
    else:
        root = target.source_root
        if root is None:
            return None
        files = {}
        for lf in osv.npm_lockfiles(root):
            text = _read(lf)
            if text is None:
                return None
            files[lf.name] = {"name": lf.name, "text": text}
        if not files:
            return None
        out = {
            "version": INPUTS_VERSION,
            "ecosystem": "npm",
            "lockfiles": files,
            "package_json": _read(root / "package.json"),
        }
    size = sum(len(f["text"]) for f in files.values()) + len(out.get("package_json") or "")
    return out if size <= MAX_TOTAL else None


def packages(inputs: dict[str, Any]) -> int:
    """How many lockfiles a saved input set holds (for a status line)."""
    files = inputs.get("lockfiles")
    return len(files) if isinstance(files, dict) else 0


def run(inputs: dict[str, Any], work: Path) -> AnalyzerResult:
    """osv-scanner on the saved lockfiles, written into `work` (an empty folder of ours)."""
    files = inputs.get("lockfiles")
    if inputs.get("version") != INPUTS_VERSION or not isinstance(files, dict) or not files:
        raise RecheckError("the saved package list isn't one this version can read")
    eco = inputs.get("ecosystem")
    src = work / "recheck-in"
    src.mkdir()
    if eco == "PyPI":
        paths: dict[str, Path] = {}
        for i, (plat, f) in enumerate(sorted(files.items())):
            name, text = str(f.get("name", "")), f.get("text")
            if not _PLATFORM.match(str(plat)) or not _PYLOCK.match(name):
                raise RecheckError("the saved package list has an unexpected file name")
            if not isinstance(text, str):
                raise RecheckError("the saved package list is damaged")
            d = src / str(i)
            d.mkdir()
            (d / name).write_text(text, encoding="utf-8")
            paths[str(plat)] = d / name
        return osv.check_python(
            paths,
            {str(n) for n in inputs.get("ha_provided") or []},
            {str(n) for n in inputs.get("direct") or []},
            work,
        )
    if eco == "npm":
        for name, f in files.items():
            text = f.get("text")
            if name not in osv.NPM_LOCKFILES or not isinstance(text, str):
                raise RecheckError("the saved package list has an unexpected file name")
            (src / name).write_text(text, encoding="utf-8")
        pkg = inputs.get("package_json")
        if isinstance(pkg, str):
            (src / "package.json").write_text(pkg, encoding="utf-8")
        return osv.check_npm(src, work)
    raise RecheckError("the saved package list names no known ecosystem")


def _signature(findings: list[dict[str, Any]]) -> set[tuple[str, str]]:
    return {(str(f["id"]), str(f["severity"])) for f in findings}


def _order(f: dict[str, Any]) -> tuple[int, str, str, int]:
    return (
        -_SEVERITY_ORDER.get(str(f["severity"]), 0),
        str(f["rule_id"]),
        str(f.get("file") or ""),
        int(f.get("line") or 0),
    )


def _brief_entry(f: dict[str, Any]) -> dict[str, Any]:
    """One finding as `json_report.ai_brief` writes it, from its stored form."""
    file, line = f.get("file"), f.get("line")
    return {
        "id": f["id"],
        "rule_id": f["rule_id"],
        "severity": f["severity"],
        "title": f["title"],
        "message": f["message"],
        "location_untrusted": sanitize_untrusted(f"{file}:{line}" if file and line else file, 200),
        "evidence_untrusted": f.get("evidence") or "",
        "platforms": list(f.get("platforms") or []),
    }


def _dep_key(f: dict[str, Any]) -> str | None:
    """The package a dependency finding is about, as the graph keys it."""
    if f.get("category") != "dependency" or not f.get("evidence"):
        return None
    m = _DEP_NAME.match(str(f["evidence"]))
    return _pep503(m[1]) if m else None


def _relink(graph: dict[str, Any], gone: set[str], new: list[dict[str, Any]]) -> None:
    """Package edges point at the findings about that package (graph._add_packages)."""
    by_pkg: dict[str, list[str]] = {}
    for f in new:
        key = _dep_key(f)
        if key:
            by_pkg.setdefault(key, []).append(str(f["id"]))
    for e in graph.get("edges", []):
        ids = [i for i in e.get("finding_ids", []) if i not in gone]
        target = str(e.get("target", ""))
        if e.get("relation") in ("depends_on", "bundles") and target.startswith("package:"):
            name = target.split("/", 1)[-1]
            ids += by_pkg.get(_pep503(name), [])
        if ids or "finding_ids" in e:
            e["finding_ids"] = sorted(set(ids))


def _recontext(
    context: dict[str, Any] | None, old: list[dict[str, Any]], new: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Where the app uses a package doesn't change with its advisories: a new finding
    about a package takes over the old finding's item; a package that had no finding
    before gets an item marked `unread` (the code isn't here to look through)."""
    if not isinstance(context, dict) or not isinstance(context.get("items"), dict):
        return context
    items = dict(context["items"])
    by_pkg: dict[tuple[str, str], Any] = {}
    for f in old:
        item = items.pop(str(f["id"]), None)
        dep = f.get("dependency")
        if item is not None and isinstance(dep, dict):
            by_pkg[(str(dep.get("package")), str(dep.get("ecosystem")))] = item
    for f in new:
        dep = f.get("dependency")
        if f.get("rule_id") != "dep-vuln" or not isinstance(dep, dict):
            continue
        pkg = (str(dep.get("package")), str(dep.get("ecosystem")))
        # `unread`: nobody looked for where the app uses it (the page says so, instead of
        # "couldn't find where it's used", which would be a claim we didn't check)
        items[str(f["id"])] = by_pkg.get(pkg) or {
            "kind": "dependency",
            "package": pkg[0],
            "snippet": None,
            "unread": True,
        }
    return {**context, "items": items}


def apply(
    report: dict[str, Any],
    new: list[dict[str, Any]],
    result: AnalyzerResult,
    of: int,
    code_scanned_at: str,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """The stored report with its osv findings replaced by `new` (in report form), or
    None when they are the same findings at the same severities. `of`: the scan id the
    stored report has; `code_scanned_at`: when its code was sniffed."""
    old = [f for f in report.get("findings", []) if f.get("analyzer") == osv.NAME]
    if _signature(old) == _signature(new):
        return None
    out = copy.deepcopy(report)
    keep = [f for f in out["findings"] if f.get("analyzer") != osv.NAME]
    findings = sorted(keep + copy.deepcopy(new), key=_order)
    r = trust.rescore(
        [(str(f["id"]), str(f["rule_id"]), str(f["severity"])) for f in findings],
        bool(out.get("complete")),
    )
    counts: dict[str, int] = {}
    for f in findings:
        counts[str(f["severity"])] = counts.get(str(f["severity"]), 0) + 1
    out.update(
        findings=findings,
        score=r.score,
        raw_score=r.raw_score,
        verdict={"key": r.verdict_key, "label": r.verdict_label},
        caps_applied=r.caps,
        score_breakdown=r.breakdown,
        counts=counts,
    )
    entry = {
        "name": result.name,
        "state": str(result.state),
        "detail": result.detail,
        "tool_version": result.tool_version,
        "findings": len(result.findings),
    }
    out["analyzers"] = [
        entry if a.get("name") == result.name else a for a in out.get("analyzers", [])
    ]
    gone = {str(f["id"]) for f in old} - {str(f["id"]) for f in new}
    if isinstance(out.get("graph"), dict):
        _relink(out["graph"], gone, new)
    hyg = out.get("hygiene")
    if isinstance(hyg, dict) and "dependabot_but_known_vulns" in hyg:
        eco = "pip" if (out.get("target") or {}).get("kind") == "integration" else "npm"
        hyg["dependabot_but_known_vulns"] = bool(
            hyg.get("dependabot")
            and eco in hyg["dependabot"]
            and any(f["rule_id"] == "dep-vuln" for f in findings)
        )
    brief = out.get("ai_brief")
    if isinstance(brief, dict):
        had = {str(b.get("id")): b for b in brief.get("findings", [])}
        fresh = {str(f["id"]) for f in new}
        brief["score"] = r.score
        brief["verdict"] = r.verdict_label
        brief["findings"] = [
            had[str(f["id"])]
            if str(f["id"]) in had and str(f["id"]) not in fresh
            else _brief_entry(f)
            for f in findings
        ]
    out["context"] = _recontext(out.get("context"), old, new)
    prior = report.get("recheck") if isinstance(report.get("recheck"), dict) else {}
    out["recheck"] = {
        "of": of,
        "code_scanned_at": prior.get("code_scanned_at") or code_scanned_at,
        "at": (now or datetime.now(UTC)).isoformat(timespec="seconds"),
    }
    return out


def recheck(
    report: dict[str, Any], inputs: dict[str, Any], of: int, code_scanned_at: str
) -> dict[str, Any] | None:
    """Ask OSV again about a stored scan's packages. A new report when the advisories
    changed, None when they didn't. Raises RecheckError when OSV couldn't be asked."""
    with workspace() as ws:
        result = run(inputs, ws)
    if result.state is not AnalyzerState.OK:
        raise RecheckError(f"{result.name} {result.state}: {result.detail}"[:300])
    findings = apply_exposure(result.findings, Exposure(str(report.get("exposure", "local"))))
    return apply(report, [finding_json(f) for f in findings], result, of, code_scanned_at)
