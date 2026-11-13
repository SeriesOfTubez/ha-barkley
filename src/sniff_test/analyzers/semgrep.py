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
    RULE_FILE_NOT_CHECKED,
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
#
# Two more, found on 1.185 (2026-11-13) and both meaning-preserving in code:
# - `n?.5:1` (a conditional whose first branch is a decimal such as `.5`): Semgrep reads
#   `?.` as optional chaining and skips a few characters (PartialParsing: Bubble-Card,
#   Helios, Bambu Lab's card, HACS's chunks). ECMAScript says `?.` is never optional
#   chaining before a digit, so `? .5` is the same expression.
# - `new as(a, -1)`: a class minified to the name `as` (or `satisfies`), TypeScript's
#   operator words. Together with an arrow function whose body is a function called on
#   the spot (`t => function(){...}()`), neither of Semgrep's JavaScript parsers gets
#   through and NO rule runs on the file ("Syntax error": HACS 2.0.5's 1.65 MB chunk
#   1117, CodeMirror). `new (as)(a, -1)` constructs the same class and parses.
# Like the first two, inside a string, regex or comment they only add a space or a pair
# of brackets to our copy.
_JS_PARSE_FIXES = (
    (re.compile(r"<!--"), "< !--"),
    (re.compile(r"-->"), "-- >"),
    (re.compile(r"\?\.(?=[0-9])"), "? ."),
    (re.compile(r"\bnew(\s+)(as|satisfies)(\s*)\("), r"new\1(\2)\3("),
)


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


# Semgrep's error types for a file it gave up on entirely: no rule ran on it. A recovered
# parse is ["PartialParsing", spans], and the spans say how much was skipped: a few
# characters on real bundles (`n?.5:1`), but it can be the whole file (seen on 1.185:
# one span from the first to the last byte, 0 results). Names read from
# semgrep_output_v1 (1.185.0).
_UNREAD_TYPES = {"Lexical error", "Syntax error", "Other syntax error", "AST builder error"}
# A partial parse that skipped at least this share of the file counts as unread.
_UNREAD_SHARE = 0.5
# A file the engine dropped for a reason another run may not hit: the scan didn't finish.
_GAVE_UP_TYPES = {"Fatal error", "Out of memory", "Stack overflow"}
# Type declarations: nothing in them runs, in the browser or anywhere else.
_DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")


def _error_type(err: dict[str, Any]) -> str:
    kind = err.get("type")
    return str(kind[0] if isinstance(kind, list) and kind else kind)


def _skipped_chars(err: dict[str, Any]) -> int | None:
    """Characters a PartialParsing error skipped, or None when the spans don't say."""
    kind = err.get("type")
    spans = kind[1] if isinstance(kind, list) and len(kind) > 1 else None
    if not isinstance(spans, list) or not spans:
        return None
    total = 0
    for sp in spans:
        try:
            n = int(sp["end"]["offset"]) - int(sp["start"]["offset"])
        except (KeyError, TypeError, ValueError):
            return None
        if n < 0:
            return None
        total += n
    return total


def _parse_failure(err: dict[str, Any], size: int | None = None) -> str | None:
    """ "unread" (no rule ran on the file, or on most of it), "partial" (a gap; the rest
    was checked) or None. `size` is the file's length in characters, when known."""
    name = _error_type(err)
    if name in _UNREAD_TYPES:
        return "unread"
    if name != "PartialParsing":
        return None
    skipped = _skipped_chars(err)
    if skipped is None:  # no usable spans: we can't say the rest was read
        return "unread"
    if size is not None and skipped >= max(1, size) * _UNREAD_SHARE:
        return "unread"
    return "partial"


def _chars(path: Path) -> int | None:
    try:
        return len(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None


def _parse_error_findings(errors: list[dict[str, Any]], root: Path) -> list[Finding]:
    """Code Semgrep can't parse can't be checked by it either; surface that.

    A file it couldn't read at all, or skipped most of, is `scan-file-not-checked` (medium,
    and the score is capped: see scoring). A file it read with small gaps stays
    `scan-parse-error` (low), as does a type-declaration file, which never runs.
    """
    worst: dict[str, tuple[str, str]] = {}  # rel -> (failure, suffix), "unread" wins
    for err in errors:
        path = err.get("path")
        suffix = Path(str(path)).suffix if path else ""
        if not path or suffix not in {".py"} | _JS_SUFFIXES:
            continue
        failure = _parse_failure(err, _chars(Path(path)))
        if not failure:
            continue
        try:
            rel = Path(path).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = Path(path).name
        if rel.endswith(_DECLARATION_SUFFIXES):
            failure = "partial"
        if rel not in worst or failure == "unread":
            worst[rel] = (failure, suffix)
    out: list[Finding] = []
    for rel, (failure, suffix) in worst.items():
        lang = "Python" if suffix == ".py" else "JavaScript"
        if failure == "unread":
            out.append(
                Finding(
                    rule_id=RULE_FILE_NOT_CHECKED,
                    title=f"{lang} file could not be parsed at all",
                    severity=Severity.MEDIUM,
                    category=Category.CODE_EXEC,
                    message=(
                        "Semgrep could not parse this file, so its rules checked none (or "
                        "almost none) of it. Review manually."
                    ),
                    file=rel,
                    analyzer=NAME,
                )
            )
            continue
        out.append(
            Finding(
                rule_id="scan-parse-error",
                title=f"{lang} file could not be fully parsed",
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


def _unfinished(errors: list[dict[str, Any]]) -> tuple[int, int]:
    """(rule timeouts, files the engine gave up on): either leaves the scan incomplete."""
    names = [_error_type(e) for e in errors]
    return (
        sum("Timeout" in n for n in names),
        sum(n in _GAVE_UP_TYPES for n in names),
    )


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
    state = AnalyzerState.OK
    detail = f"{len(data.get('paths', {}).get('scanned', []))} files scanned"
    timeouts, gave_up = _unfinished(errors)
    if timeouts:
        state = AnalyzerState.ERROR
        detail += f"; {timeouts} rule timeouts (scan incomplete)"
    if gave_up:
        state = AnalyzerState.ERROR
        detail += f"; the engine gave up on {gave_up} files (scan incomplete)"
    return AnalyzerResult(
        NAME, state, findings=findings, detail=detail, tool_version=version, facts=facts
    )
