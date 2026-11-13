"""Run Semgrep with the bundled HA rules against the install root."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
from importlib import resources
from pathlib import Path
from typing import Any

from sniff_test.analyzers import py_tamper
from sniff_test.models import (
    AnalyzerResult,
    AnalyzerState,
    Category,
    Evidence,
    Fact,
    Finding,
    Ring,
    Severity,
    Tag,
    Target,
)

NAME = "semgrep"
_EVIDENCE_MAX = 300
_PROCESS_TIMEOUT = 900
# Files whose presence in the scanned tree could make Semgrep skip targets.
_IGNORE_FILES = (".semgrepignore", ".gitignore")
_JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# Rewrites applied to OUR extracted copy so Semgrep sees all of the code. Checked on
# Semgrep 1.181 (2026-11-08) and again on 1.185 (2026-11-13, unchanged): it treats
# `<!--` and `-->` as the start of a line comment
# *anywhere* on a line (the classic-script HTML-comment rule, and wider than it), so in
# `x = n-->0; fetch(u)` or `a<!--b; fetch(u)` the fetch is silently invisible: 0
# results, 0 errors. HA loads cards as ES modules, where neither is a comment: `a<!--b`
# is `a < !(--b)` and `n-->0` is `n-- > 0`. Inserting a space keeps the meaning in code
# and only adds a space inside strings, regexes and comments, so it can't hide anything.
# It also covers lit-html's `/-->/g`, which made Semgrep drop all of mushroom.js (M3).
_JS_PARSE_FIXES = ((re.compile(r"<!--"), "< !--"), (re.compile(r"-->"), "-- >"))


def rules_dir() -> Path:
    dev = Path(__file__).resolve().parents[3] / "rules"
    if dev.is_dir():
        return dev
    return Path(str(resources.files("sniff_test") / "rules"))


def neutralize_ignores(root: Path) -> None:
    """Hostile repos can ship ignore files to hide payloads from the scanner.

    Delete every ignore file in our extracted copy, then drop an empty .semgrepignore at
    the root so Semgrep's built-in default ignores (tests/, *.min.js, ...) don't apply.
    """
    for name in _IGNORE_FILES:
        for p in root.rglob(name):
            if p.is_file() and not p.is_symlink():
                p.unlink()
    (root / ".semgrepignore").write_text("")


def normalize_js(root: Path, pristine: dict[str, str] | None = None) -> int:
    """Apply _JS_PARSE_FIXES to every JS file under root. Returns files changed.

    The rewrite is in place, so the sha256 of each changed file's original bytes goes
    into `pristine` (root-relative path). Anything comparing bytes with what HACS
    installs (repo_signals.compare_card_asset) must use those: comparing our rewritten
    copy made identical bundles look different (power-flow-card-plus v0.4.0, Helios).
    """
    changed = 0
    for p in root.rglob("*"):
        if p.suffix not in _JS_SUFFIXES or not p.is_file() or p.is_symlink():
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        text = data.decode("utf-8", errors="surrogateescape")
        new = text
        for rx, repl in _JS_PARSE_FIXES:
            new = rx.sub(repl, new)
        if new != text:
            if pristine is not None:
                rel = p.relative_to(root).as_posix()
                pristine.setdefault(rel, hashlib.sha256(data).hexdigest())
            p.write_text(new, encoding="utf-8", errors="surrogateescape")
            changed += 1
    return changed


def _tool_env() -> dict[str, str]:
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    return env


def failure_detail(proc: subprocess.CompletedProcess[str]) -> str:
    """Why semgrep produced no JSON: exit code or signal, then the most telling output."""
    rc = proc.returncode
    head = f"semgrep exit {rc}" if rc >= 0 else f"semgrep killed by signal {-rc}"
    if rc == -9:
        head += " (out of memory?)"
    err, out = (proc.stderr or "").strip(), (proc.stdout or "").strip()
    if err:
        return f"{head}: {err[-500:]}"
    if out:
        return f"{head}; stdout: {out[:300]}"
    return f"{head}, no output (run `sniff-test doctor` or open /doctor in the panel)"


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
        supersedes=frozenset(meta.get("supersedes", [])),
    )


_KEY_MAX = 120
_PY_LITERAL = re.compile(r"""^[rRbBuU]?(["'])(.*)\1$""", re.S)
_PY_FSTRING = re.compile(r"""^[fF][rR]?(["'])(.*)\1$""", re.S)
_JS_LITERAL = re.compile(r"""^(["'])(.*)\1$|^`([^`$]*)`$""", re.S)
_DOTTED = re.compile(r"^[A-Za-z_][\w.]*$")
_CTOR = re.compile(r"^([A-Za-z_][\w.]*)\(.*\)$", re.S)


def _clean_part(part: str, domain: str | None, js: bool) -> str:
    """One interpolated metavariable -> a readable key part.

    String literals keep their value; Python constants (EVENT_HOMEASSISTANT_STOP,
    DOMAIN) keep their name; anything computed (or any JS identifier, which is
    minified in bundles) becomes `*`.
    """
    part = part.strip()
    if js:
        m = _JS_LITERAL.match(part)
        return (m[2] if m[2] is not None else m[3]) if m else "*"
    if m := _PY_LITERAL.match(part):
        return m[2]
    if m := _PY_FSTRING.match(part):
        return m[2]
    if part in ("DOMAIN", "self.domain") and domain:
        return domain
    if m := _CTOR.match(part):  # register_view(AcmeView()) -> AcmeView
        part = m[1]
    return part if _DOTTED.match(part) else "*"


def _clean_key(text: str, domain: str | None, js: bool) -> str:
    """Interpolated message (`DOMAIN|"refresh"`) -> node key (`acme.refresh`)."""
    parts = [_clean_part(p, domain, js) for p in text.split("|")]
    key = ".".join(parts)
    return _CONTROL.sub("", key)[:_KEY_MAX] or "*"


def to_fact(result: dict[str, Any], root: Path, domain: str | None) -> Fact | None:
    """An inventory rule hit -> a neutral Fact (None if it isn't an inventory rule)."""
    extra = result.get("extra", {})
    inv = ((extra.get("metadata") or {}).get("sniff") or {}).get("inventory")
    if not isinstance(inv, dict):
        return None
    try:
        rel = Path(result["path"]).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        rel = Path(result["path"]).name
    js = Path(result["path"]).suffix in _JS_SUFFIXES
    # DOMAIN is only safely "our" domain when registering; calls often use another
    # component's imported DOMAIN constant.
    own = domain if inv.get("relation") == "registers" else None
    value = _clean_key(str(extra.get("message", "")), own, js)
    attrs: dict[str, Any] = {}
    if inv.get("outbound"):
        attrs["outbound"] = True
    if fixed := inv.get("key"):
        raw = " ".join(str(extra.get("message", "")).split())
        if raw != str(fixed):  # the message interpolated something: keep it as a value
            attrs["values"] = [value]
        value = str(fixed)
    return Fact(
        ring=Ring(inv["ring"]),
        kind=str(inv["kind"]),
        key=value,
        relation=str(inv["relation"]),
        evidence=Evidence.POSSIBLE,
        file=rel,
        line=result["start"]["line"],
        attrs=attrs,
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


def _only_rebinds_names(f: Finding, root: Path, trees: dict[str, Any]) -> bool:
    """`ha-monkeypatch` matched an assignment that only binds local names.

    After `from homeassistant import config_entries`, Semgrep resolves a later local
    `config_entries = hass.config_entries.async_entries(DOMAIN)` to
    `homeassistant.config_entries` and matches `$OBJ.$ATTR = $V` (Bambu Lab v2.3.0).
    Rebinding a name changes nothing outside the function. We parse the file (never
    run it) and drop the hit only when every assignment starting on that line targets
    bare names; chained `x = homeassistant.y = v` keeps it, as does a parse failure.
    """
    if f.rule_id != "ha-monkeypatch" or not f.file or not f.line:
        return False
    if f.file not in trees:
        try:
            trees[f.file] = ast.parse((root / f.file).read_bytes())
        except (OSError, SyntaxError, ValueError, RecursionError, MemoryError):
            trees[f.file] = None
    tree = trees[f.file]
    if tree is None:
        return False

    def names_only(t: ast.expr) -> bool:
        if isinstance(t, ast.Name):
            return True
        if isinstance(t, (ast.Tuple, ast.List)):
            return all(names_only(e) for e in t.elts)
        if isinstance(t, ast.Starred):
            return names_only(t.value)
        return False

    stmts = [
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and n.lineno == f.line
    ]
    if not stmts:
        return False  # setattr(...) or something we don't recognise: keep it
    targets = [t for n in stmts for t in (n.targets if isinstance(n, ast.Assign) else [n.target])]
    return all(names_only(t) for t in targets)


def _is_parse_error(err: dict[str, Any]) -> bool:
    # Full failures are "Syntax error"; recovered ones are ["PartialParsing", spans].
    kind = err.get("type")
    name = kind[0] if isinstance(kind, list) and kind else str(kind)
    return "Syntax" in str(name) or name == "PartialParsing"


def _parse_error_findings(errors: list[dict[str, Any]], root: Path) -> list[Finding]:
    """Python that Semgrep can't parse can't be checked by it either; surface that."""
    out: list[Finding] = []
    seen: set[str] = set()
    for err in errors:
        path = err.get("path")
        suffix = Path(str(path)).suffix if path else ""
        if not path or suffix not in {".py"} | _JS_SUFFIXES or not _is_parse_error(err):
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
                title=f"{'Python' if suffix == '.py' else 'JavaScript'} file could not be "
                "fully parsed",
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
    neutralize_ignores(root)
    normalize_js(root, target.pristine_sha256)
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
            NAME, AnalyzerState.ERROR, detail=failure_detail(proc), tool_version=version
        )
    findings: list[Finding] = []
    facts: list[Fact] = []
    for r in data.get("results", []):
        if (fact := to_fact(r, root, target.domain)) is not None:
            facts.append(fact)
        else:
            findings.append(to_finding(r, root))
    trees: dict[str, Any] = {}
    findings = [
        f
        for f in findings
        if not _is_own_storage(f, target.domain) and not _only_rebinds_names(f, root, trees)
    ]
    # The assignment forms the ha-monkeypatch rule can't see (chained, `+=`, aliased
    # from-imports, ...), from the same parsed trees. Skips lines Semgrep kept.
    flagged = {(f.file, f.line) for f in findings if f.rule_id == py_tamper.RULE_ID and f.file}
    findings += py_tamper.find(root, flagged, trees)
    errors = data.get("errors", [])
    findings += _parse_error_findings(errors, root)
    timeouts = [e for e in errors if "Timeout" in str(e.get("type"))]
    state = AnalyzerState.OK
    detail = f"{len(data.get('paths', {}).get('scanned', []))} files scanned"
    if timeouts:
        state = AnalyzerState.ERROR
        detail += f"; {len(timeouts)} rule timeouts (scan incomplete)"
    return AnalyzerResult(
        NAME, state, findings=findings, detail=detail, tool_version=version, facts=facts
    )
