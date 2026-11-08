"""Orchestrates one scan: fetch -> analyzers -> scoring."""

from __future__ import annotations

from collections.abc import Callable

from sniff_test.analyzers import semgrep
from sniff_test.fetch.hacs import fetch
from sniff_test.models import AnalyzerResult, AnalyzerState, Finding, TargetKind
from sniff_test.report.json_report import ScanResult
from sniff_test.scoring import Exposure, apply_exposure, score
from sniff_test.workspace import workspace


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop exact duplicates, apply `supersedes`, then collapse same-line overlaps.

    e.g. `exec(b64decode(x))` hits both py-b64-exec (critical) and py-eval-exec (high);
    reporting both is noise. Keep the most severe finding(s) for each line+category.
    Findings in different categories on the same line are all kept.
    """
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.id, f)
    superseded = {
        (f.file, f.line, rule)
        for f in unique.values()
        if f.file and f.line
        for rule in f.supersedes
    }
    unique = {k: f for k, f in unique.items() if (f.file, f.line, f.rule_id) not in superseded}
    best: dict[tuple[str, int, str], int] = {}
    for f in unique.values():
        if f.file and f.line:
            key = (f.file, f.line, str(f.category))
            best[key] = max(best.get(key, -1), int(f.severity))
    return [
        f
        for f in unique.values()
        if not (f.file and f.line) or f.severity == best[(f.file, f.line, str(f.category))]
    ]


def scan(
    source: str,
    ref: str | None = None,
    exposure: Exposure = Exposure.LOCAL,
    kind: TargetKind | None = None,
    keep_workspace: bool = False,
    jobs: int | None = None,
    progress: Callable[[str], None] | None = None,
) -> ScanResult:
    say = progress or (lambda _msg: None)
    with workspace(keep=keep_workspace) as ws:
        say("fetching")
        target = fetch(source, ws, ref=ref, kind=kind)
        say("semgrep")
        results: list[AnalyzerResult] = [semgrep.run(target, ws, jobs=jobs)]

        findings = list(target.notes)
        for r in results:
            findings.extend(r.findings)
        findings = apply_exposure(_dedupe(findings), exposure)
        complete = all(r.state in (AnalyzerState.OK, AnalyzerState.NOT_APPLICABLE) for r in results)
        return ScanResult(
            target=target,
            exposure=exposure,
            analyzers=results,
            findings=findings,
            score=score(findings, complete),
        )
