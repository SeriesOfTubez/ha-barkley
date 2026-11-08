"""Run Semgrep with the bundled HA rules against the install root."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from importlib import resources
from pathlib import Path
from typing import Any

from sniff_test.models import (
    AnalyzerResult,
    AnalyzerState,
    Category,
    Finding,
    Severity,
    Tag,
    Target,
)

NAME = "semgrep"
_EVIDENCE_MAX = 300
_PROCESS_TIMEOUT = 900
# Files whose presence in the scanned tree could make Semgrep skip targets.
_IGNORE_FILES = (".semgrepignore", ".gitignore")


def rules_dir() -> Path:
    dev = Path(__file__).resolve().parents[3] / "rules"
    if dev.is_dir():
        return dev
    return Path(str(resources.files("sniff_test") / "rules"))


def _neutralize_ignores(root: Path) -> None:
    """Hostile repos can ship ignore files to hide payloads from the scanner.

    Delete every ignore file in our extracted copy, then drop an empty .semgrepignore at
    the root so Semgrep's built-in default ignores (tests/, *.min.js, ...) don't apply.
    """
    for name in _IGNORE_FILES:
        for p in root.rglob(name):
            if p.is_file() and not p.is_symlink():
                p.unlink()
    (root / ".semgrepignore").write_text("")


def _tool_env() -> dict[str, str]:
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    return env


def _version(exe: str) -> str | None:
    try:
        out = subprocess.run(
            [exe, "--version"], capture_output=True, text=True, timeout=60, env=_tool_env()
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = [ln for ln in out.stdout.splitlines() if ln.strip()]
    return lines[-1].strip() if lines else None


def _evidence(path: Path, start: int, end: int) -> str:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            lines = [ln.rstrip("\n") for i, ln in enumerate(fh, 1) if start <= i <= end]
    except OSError:
        return ""
    text = "\n".join(lines).strip()
    return text[:_EVIDENCE_MAX] + ("…" if len(text) > _EVIDENCE_MAX else "")


def _evidence_at(path: Path, line: int, col: int) -> str:
    """For minified files a 'line' can be megabytes; take a window around the match."""
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for i, ln in enumerate(fh, 1):
                if i == line:
                    lo = max(0, col - 1 - 80)
                    snippet = ln[lo : lo + _EVIDENCE_MAX].strip()
                    return ("…" if lo else "") + snippet
    except OSError:
        pass
    return ""


def to_finding(result: dict[str, Any], root: Path) -> Finding:
    extra = result.get("extra", {})
    meta = (extra.get("metadata") or {}).get("sniff") or {}
    abs_path = Path(result["path"])
    try:
        rel = abs_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        rel = abs_path.name
    start, end = result["start"]["line"], result["end"]["line"]
    evidence = (
        _evidence(abs_path, start, min(end, start + 3))
        if result["end"]["line"] - start < 20
        else ""
    )
    if len(evidence) >= _EVIDENCE_MAX:  # long/minified line: window around the column
        evidence = _evidence_at(abs_path, start, result["start"].get("col", 1))
    return Finding(
        rule_id=result["check_id"].rsplit(".", 1)[-1],
        title=meta.get("title", result["check_id"]),
        severity=Severity.parse(meta.get("severity", "medium")),
        category=Category(meta.get("category", "code_exec")),
        message=" ".join(str(extra.get("message", "")).split()),
        file=rel,
        line=start,
        evidence=evidence,
        tags=frozenset(Tag(t) for t in meta.get("tags", [])),
        analyzer=NAME,
    )


def _is_own_storage(f: Finding, domain: str | None) -> bool:
    """An integration reading .storage/<its own domain>... is not interesting."""
    if f.rule_id != "ha-raw-storage-access" or not f.evidence:
        return False
    ev = f.evidence.replace("\\", "/")
    own = [".storage/{DOMAIN}", '".storage", DOMAIN', "'.storage', DOMAIN"]
    if domain:
        own += [f".storage/{domain}", f'".storage", "{domain}', f"'.storage', '{domain}"]
    return any(marker in ev for marker in own)


def _parse_error_findings(errors: list[dict[str, Any]], root: Path) -> list[Finding]:
    """Python that Semgrep can't parse can't be checked by it either; surface that."""
    out: list[Finding] = []
    seen: set[str] = set()
    for err in errors:
        path = err.get("path")
        if not path or not str(path).endswith(".py") or "Syntax" not in str(err.get("type")):
            continue
        try:
            rel = Path(path).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = Path(path).name
        if rel in seen:
            continue
        seen.add(rel)
        out.append(
            Finding(
                rule_id="scan-parse-error",
                title="Python file could not be fully parsed",
                severity=Severity.LOW,
                category=Category.CODE_EXEC,
                message=(
                    "Semgrep could not parse this file, so its rules could not check all "
                    "of it. Review manually."
                ),
                file=rel,
                analyzer=NAME,
            )
        )
    return out


def run(target: Target, work: Path, jobs: int | None = None) -> AnalyzerResult:
    exe = shutil.which("semgrep")
    if not exe:
        return AnalyzerResult(NAME, AnalyzerState.SKIPPED, detail="semgrep not installed")
    version = _version(exe)
    root = target.root.resolve()
    _neutralize_ignores(root)
    run_dir = work / "semgrep-run"
    run_dir.mkdir(exist_ok=True)
    cmd = [
        exe,
        "scan",
        "--config",
        str(rules_dir()),
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--no-rewrite-rule-ids",
        "--max-target-bytes",
        "50000000",
        "--timeout",
        "120",
        "--quiet",
    ]
    if jobs:
        cmd += ["--jobs", str(jobs)]
    cmd.append(str(root))
    try:
        proc = subprocess.run(
            cmd,
            cwd=run_dir,  # never run from inside the scanned tree
            capture_output=True,
            text=True,
            timeout=_PROCESS_TIMEOUT,
            env=_tool_env(),
        )
    except subprocess.TimeoutExpired:
        return AnalyzerResult(
            NAME, AnalyzerState.ERROR, detail="semgrep timed out", tool_version=version
        )
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return AnalyzerResult(
            NAME,
            AnalyzerState.ERROR,
            detail=f"semgrep exit {proc.returncode}: {proc.stderr.strip()[-500:]}",
            tool_version=version,
        )
    findings = [to_finding(r, root) for r in data.get("results", [])]
    findings = [f for f in findings if not _is_own_storage(f, target.domain)]
    errors = data.get("errors", [])
    findings += _parse_error_findings(errors, root)
    timeouts = [e for e in errors if "Timeout" in str(e.get("type"))]
    state = AnalyzerState.OK
    detail = f"{len(data.get('paths', {}).get('scanned', []))} files scanned"
    if timeouts:
        state = AnalyzerState.ERROR
        detail += f"; {len(timeouts)} rule timeouts (scan incomplete)"
    return AnalyzerResult(NAME, state, findings=findings, detail=detail, tool_version=version)
