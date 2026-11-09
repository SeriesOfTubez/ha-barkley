"""Orchestrates one scan: fetch -> analyzers -> scoring."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from sniff_test.analyzers import (
    bytecode,
    correlate,
    endpoints,
    guarddog,
    osv,
    pypi_meta,
    python_deps,
    repo_signals,
    semgrep,
)
from sniff_test.deps import ha_env
from sniff_test.fetch.hacs import fetch
from sniff_test.models import AnalyzerResult, AnalyzerState, Fact, Finding, Target, TargetKind
from sniff_test.report import graph
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


def _dependency_analyzers(
    target: Target,
    ws: Path,
    ha_version: str | None,
    offline: bool,
    jobs: int | None,
    say: Callable[[str], None],
) -> tuple[list[AnalyzerResult], python_deps.Resolution | None, ha_env.HAEnv | None]:
    if target.kind is TargetKind.PLUGIN:
        say("osv (npm)")
        if offline:
            return [AnalyzerResult("osv-npm", AnalyzerState.SKIPPED, detail="offline")], None, None
        return [osv.run_npm(target, ws)], None, None

    env, env_error = None, "offline"
    if not offline:
        say("home assistant constraints")
        try:
            env = ha_env.load(ha_version)
        except ha_env.HAEnvError as e:
            env_error = str(e)
    say("resolving dependencies")
    deps_result, resolution = python_deps.run(target, ws, env)
    if env is None and deps_result.state is AnalyzerState.SKIPPED:
        deps_result.detail = env_error
    elif env is not None:
        deps_result.detail = f"HA {env.version}, Python {env.python_version}: {deps_result.detail}"
    requirements = resolution.requirements if resolution else []
    say("package metadata")
    results = [deps_result, pypi_meta.run(requirements, resolution, env, online=not offline)]
    if resolution and resolution.lockfiles:
        say("osv (python)")
        results.append(osv.run_python(resolution, ws))
        say("guarddog")
        results.append(guarddog.run(resolution, ws, jobs=jobs))
    return results, resolution, env


def scan(
    source: str,
    ref: str | None = None,
    exposure: Exposure = Exposure.LOCAL,
    kind: TargetKind | None = None,
    keep_workspace: bool = False,
    jobs: int | None = None,
    progress: Callable[[str], None] | None = None,
    ha_version: str | None = None,
    offline: bool = False,
) -> ScanResult:
    say = progress or (lambda _msg: None)
    with workspace(keep=keep_workspace) as ws:
        say("fetching")
        target = fetch(source, ws, ref=ref, kind=kind)
        say("semgrep")
        results: list[AnalyzerResult] = [semgrep.run(target, ws, jobs=jobs)]
        say("endpoints")
        results.append(endpoints.run(target))
        say("repo signals")
        repo_result, provenance = repo_signals.run(target)
        results.append(repo_result)
        dep_results, resolution, env = _dependency_analyzers(
            target, ws, ha_version, offline, jobs, say
        )
        results += dep_results
        if target.kind is TargetKind.INTEGRATION:
            say("bytecode")
            results.append(bytecode.run(target, env.python_version if env else None))

        findings = list(target.notes)
        facts: list[Fact] = []
        for r in results:
            findings.extend(r.findings)
            facts.extend(r.facts)
        findings += correlate.correlate(findings, facts, target.root)
        findings = apply_exposure(_dedupe(findings), exposure)
        complete = all(r.state in (AnalyzerState.OK, AnalyzerState.NOT_APPLICABLE) for r in results)
        result = ScanResult(
            target=target,
            exposure=exposure,
            analyzers=results,
            findings=findings,
            score=score(findings, complete),
            facts=facts,
            provenance=provenance,
            resolution=resolution,
            ha_version=env.version if env else None,
        )
        # Built while the workspace still exists: it reads manifests and parses files.
        result.graph = graph.build(result)
        return result
