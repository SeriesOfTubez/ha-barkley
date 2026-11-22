"""Orchestrates one scan: fetch -> analyzers -> scoring."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from pathlib import Path

from sniff_test import cpu, logic, recheck, scancache, sources
from sniff_test.analyzers import (
    bytecode,
    correlate,
    endpoints,
    js_requests,
    libraries,
    osv,
    py_env,
    py_group,
    py_pages,
    py_precision,
    py_requests,
    pypi_meta,
    python_deps,
    repo_hygiene,
    repo_signals,
    semgrep,
    telemetry,
)
from sniff_test.analyzers.py_resolve import Resolver
from sniff_test.deps import ha_env
from sniff_test.fetch.hacs import fetch
from sniff_test.models import (
    AnalyzerResult,
    AnalyzerState,
    Fact,
    Finding,
    Tag,
    Target,
    TargetKind,
)
from sniff_test.report import context, fingerprint, graph
from sniff_test.report.json_report import ScanResult, finding_json
from sniff_test.scoring import Exposure, Policy, apply_exposure, score
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
    return results, resolution, env


DYNAMIC_IMPORT = "py-dynamic-import"


def loadable_tests(findings: list[Finding], tests: frozenset[str]) -> frozenset[str]:
    """(0.15, his decision 2026-11-21) Test files stay test files only while nothing could
    load them: a computed import in the app's own code (the module name worked out while
    it runs, which Barkley can't follow) could name one, so then none is set aside."""
    if any(f.rule_id == DYNAMIC_IMPORT and f.file not in tests for f in findings):
        return frozenset()
    return tests


def _label_test_code(findings: list[Finding], target: Target) -> list[Finding]:
    """(0.14.0) Tag findings in test files no runtime module imports (py_precision).
    (0.15) A tagged finding is left out of the readings and of "What it can do"; the panel
    lists it apart (shown.py)."""
    tests = loadable_tests(findings, py_precision.test_only_files(Resolver(target.root)))
    return [
        dataclasses.replace(f, tags=f.tags | {Tag.TEST_CODE}) if f.file in tests else f
        for f in findings
    ]


_DEP_RULES = ("dep-vuln", "dep-malicious", "dep-build-tool-vuln")


def _fingerprints(findings: list[Finding], target: Target) -> list[Finding]:
    """(0.14.0) report/fingerprint.py, for every finding that doesn't have one yet (the
    JavaScript ones come from semgrep.py)."""
    texts: dict[str, str | None] = {}
    out = []
    for f in findings:
        if f.fingerprint:
            out.append(f)
            continue
        if f.rule_id in _DEP_RULES:
            fp = fingerprint.dependency(f.rule_id, f.evidence or f.message)
        elif f.file and f.file.endswith(".py"):
            if f.file not in texts:
                p = (target.root / f.file).resolve()
                try:
                    p.relative_to(target.root.resolve())
                    texts[f.file] = p.read_text("utf-8", "replace") if p.is_file() else None
                except (OSError, ValueError):
                    texts[f.file] = None
            text = texts[f.file]
            fp = (
                fingerprint.python(f.rule_id, text, f.line)
                if text is not None
                else fingerprint.other(f.rule_id, f.evidence, f.message)
            )
        else:
            fp = fingerprint.other(f.rule_id, f.evidence, f.message)
        out.append(dataclasses.replace(f, fingerprint=fp))
    return out


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
    recognise_libraries: bool = True,
    cache_mb: int = 0,
) -> ScanResult:
    say = progress or (lambda _msg: None)
    with workspace(keep=keep_workspace) as ws:
        say("fetching")
        target = fetch(source, ws, ref=ref, kind=kind)
        # (0.14.1) unchanged published libraries (analyzers/libraries.py): set aside while
        # the code is read, put back before anything compares files
        if offline:
            libs = libraries.Result(
                AnalyzerResult(libraries.NAME, AnalyzerState.NOT_APPLICABLE, detail="offline")
            )
        else:
            say("published libraries")
            libs = libraries.recognise(target, ws, enabled=recognise_libraries)
        with libraries.set_aside(target.root, libs.aside, ws):
            say("semgrep")
            # (0.14.1) answers for code already read (scancache); 0 MB: off
            cache = scancache.Cache(logic.key(), cache_mb) if cache_mb > 0 else None
            results: list[AnalyzerResult] = [semgrep.run(target, ws, jobs=jobs, cache=cache)]
            if cache is not None:
                cache.prune()
            say("endpoints")
            results.append(endpoints.run(target))
        results.append(libs.analyzer)
        say("repo signals")
        repo_result, provenance = repo_signals.run(target)
        results.append(repo_result)
        say("repo habits")
        hygiene = repo_hygiene.run(target, offline=offline)
        dep_results, resolution, env = _dependency_analyzers(
            target, ws, ha_version, offline, jobs, say
        )
        results += dep_results
        if target.kind is TargetKind.INTEGRATION:
            say("usage reporting")
            results.append(telemetry.run(target))
            say("bytecode")
            results.append(bytecode.run(target, env.python_version if env else None))

        findings = list(target.notes)
        facts: list[Fact] = []
        for r in results:
            findings.extend(r.findings)
            facts.extend(r.facts)
        # (0.15) the requests are read first: a pairing needs a site the code really calls
        # (an address it couldn't read may be any host the code names: then every one counts)
        if target.kind is TargetKind.INTEGRATION:
            py_reqs = py_requests.requests_in(target.root)
            reqs = py_reqs
            called: set[str] | None = {r.host for r in py_reqs if r.host}
        else:
            js_reqs = js_requests.requests_in(target.root)
            reqs = js_reqs[0]
            called = {r.host for r in js_reqs[0] if r.host} | set(js_reqs[1])
        if any(r.host is None for r in reqs):
            called = None
        findings += correlate.correlate(findings, facts, target.root, called)
        if target.kind is TargetKind.INTEGRATION:
            findings = _label_test_code(findings, target)
        findings = apply_exposure(_dedupe(findings), exposure)
        # (#19) one "What it can do" finding per Python function (py_group)
        findings = py_group.group(findings, target.root)
        findings = py_pages.annotate(findings, target.root)  # (0.15) login-free pages
        findings = _fingerprints(findings, target)
        for r in results:  # (#18) a tool that can't load on this CPU: say why and the fix
            if r.state is AnalyzerState.ERROR and r.detail:
                r.detail = cpu.explain(r.detail)
        complete = all(r.state in (AnalyzerState.OK, AnalyzerState.NOT_APPLICABLE) for r in results)
        result = ScanResult(
            target=target,
            exposure=exposure,
            analyzers=results,
            findings=findings,
            score=score(findings, complete, Policy(exposure=exposure)),
            facts=facts,
            provenance=provenance,
            hygiene=hygiene,
            resolution=resolution,
            ha_version=env.version if env else None,
            libraries=libs.libraries,
            library_lookups=libs.lookups,
            logic=logic.key(),
            cache=(
                {
                    "files": cache.stats.files,
                    "hits": cache.stats.hits,
                    "saved_secs": round(cache.stats.saved, 1),
                }
                if cache is not None
                else None
            ),
        )
        # Built while the workspace still exists: it reads manifests and parses files.
        result.graph = graph.build(result)
        if target.kind is TargetKind.INTEGRATION:
            say("web requests")  # (0.15) the method and what each call carries; never scored
            tests = loadable_tests(findings, py_precision.test_only_files(
                Resolver(target.root), also=py_precision.looks_like_a_script
            ))  # fmt: skip
            result.requests = py_requests.summary(py_reqs, tests)
            # (0.15) which environment variables it reads and sets, by name
            result.environment = py_env.summary(py_env.uses_in(target.root))
        else:
            say("web requests")  # (0.15) a card's built file: fetch calls and map-tile sites
            result.requests = js_requests.summary(*js_reqs)
        result.inputs = recheck.capture(target, resolution) if not offline else None
        result.context = context.build(
            target.root,
            [finding_json(f) for f in findings],
            result.graph,
            source_root=target.source_root,
            places=[(f.kind, f.file, f.line) for f in facts if f.file and f.line],
            # (0.12.0) the original of a Home Assistant function the app replaces: one file
            # of HA's own source at this scan's release (deps.ha_env.source_file)
            ha_version=env.version if env else None,
            ha_source=(lambda path: ha_env.source_file(env.version, path)) if env else None,
        )
        # (0.11.0) the app's own Python, so the AI can be shown more of it on request
        result.source, result.context["source"] = sources.capture(target)
        return result
