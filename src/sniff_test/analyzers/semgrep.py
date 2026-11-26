"""Run Semgrep with the bundled HA rules against the install root."""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import re
import shutil
import subprocess
from importlib import resources
from pathlib import Path
from typing import Any

from sniff_test import scancache
from sniff_test.analyzers import (
    _proc,
    js_fold,
    js_loader,
    js_settings,
    js_wrapper,
    py_precision,
    py_tamper,
)
from sniff_test.analyzers.py_resolve import Resolver
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
    TargetKind,
)
from sniff_test.report import fingerprint

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
# It also covers lit-html's `/-->/g`, which made Semgrep drop a whole card bundle (M3).
#
# Two more, found on 1.185 (2026-11-13) and both meaning-preserving in code:
# - `n?.5:1` (a conditional whose first branch is a decimal such as `.5`): Semgrep reads
#   `?.` as optional chaining and skips a few characters (PartialParsing, seen in
#   four real bundles). ECMAScript says `?.` is never optional
#   chaining before a digit, so `? .5` is the same expression.
# - `new as(a, -1)`: a class minified to the name `as` (or `satisfies`), TypeScript's
#   operator words. Together with an arrow function whose body is a function called on
#   the spot (`t => function(){...}()`), neither of Semgrep's JavaScript parsers gets
#   through and NO rule runs on the file ("Syntax error": HACS 2.0.5's 1.65 MB chunk
#   1117, CodeMirror). `new (as)(a, -1)` constructs the same class and parses.
# Like the first two, inside a string, regex or comment they only add a space or a pair
# of brackets to our copy.
#
# (0.15.0, 2026-11-20) Class static blocks (ES2022, `class C { static { ... } }`): neither
# Semgrep 1.185 nor 1.186 parses them, not even an empty one (no upstream issue found).
# A real card's 1.77 MB map chunk lost about 2% of its code to parser recovery around 11
# of them, and a rule matched nothing inside one. `static {` becomes `static
# __sniff_static_block() {`: a static method that is never called, in the same class,
# with the same body and the same `this`, so every rule reads the body. In code,
# `static` followed by `{` on the same line is only ever a static block (anything else is
# a syntax error, and `static` is reserved in modules); a property (`a.static{`), a
# private name (`#static`) or a longer word (`isstatic{`) is left alone by the
# lookbehind. Only spaces or tabs may sit between: across a newline a classic script can
# read `static` as a variable, so that form is left as it is (still reported as code
# Barkley couldn't read, never hidden). Inside a string, regex or comment it only adds a
# name and brackets to our copy. Linear: a fixed lookbehind and one run of blanks.
_JS_PARSE_FIXES = (
    (re.compile(r"<!--"), "< !--"),
    (re.compile(r"-->"), "-- >"),
    (re.compile(r"\?\.(?=[0-9])"), "? ."),
    (re.compile(r"\bnew(\s+)(as|satisfies)(\s*)\("), r"new\1(\2)\3("),
    (re.compile(r"(?<![\w$.#])static([ \t]*)\{"), r"static __sniff_static_block()\1{"),
)


def rules_dir() -> Path:
    dev = Path(__file__).resolve().parents[3] / "rules"
    if dev.is_dir():
        return dev
    return Path(str(resources.files("sniff_test") / "rules"))


def rules_const_dir() -> Path:
    """(0.14.0) The second pass's rules (shipped inside the package)."""
    return Path(str(resources.files("sniff_test") / "rules_const"))


class _ScanFailed(Exception):
    """Semgrep produced no JSON; the message says why."""


def _rule_id(result: dict[str, Any]) -> str:
    """A result's rule id; a rule with `sniff.alias` reports as the rule it copies."""
    meta = ((result.get("extra") or {}).get("metadata") or {}).get("sniff") or {}
    return str(meta.get("alias") or result["check_id"].rsplit(".", 1)[-1])


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
    copy made identical bundles look different (seen on two real cards).
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
    env = {k: v for k, v in _proc.tool_env().items() if k in keep}
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
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sniff-test-version-") as d:
        try:
            out = _proc.run([exe, "--version"], Path(d), 60, _tool_env(), tool="semgrep")
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
    """For minified files a 'line' can be megabytes; take a window around the match.
    (0.15) Semgrep's column counts bytes: each character of more than one byte before the
    match (`…`, `°`, an emoji in a bundled label) would push a window cut by characters
    to the right of it, so the column is turned into a character index first."""
    try:
        with path.open("rb") as fh:
            for i, raw in enumerate(fh, 1):
                if i == line:
                    at = len(raw[: max(0, col - 1)].decode("utf-8", "replace"))
                    ln = raw.decode("utf-8", "replace")
                    lo = max(0, at - 80)
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
        rule_id=_rule_id(result),
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
    `homeassistant.config_entries` and matches `$OBJ.$ATTR = $V` (seen on a real integration).
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


def _put_back(findings: list[Finding], trees: dict[str, Any]) -> list[Finding]:
    """(0.15, #32) py_tamper.temporary for the `ha-monkeypatch` lines Semgrep matched:
    a line that puts a saved original back is dropped, and a patch the same function
    undoes says so. Uses the trees `_only_rebinds_names` parsed (never run)."""
    out: list[Finding] = []
    for f in findings:
        tree = trees.get(f.file) if f.rule_id == py_tamper.RULE_ID and f.file else None
        if tree is None:
            out.append(f)
            continue
        restores, undone = py_tamper.temporary(tree)
        if f.line in restores:
            continue
        if f.line in undone and py_tamper.PUT_BACK not in f.message:
            f = dataclasses.replace(f, message=f"{f.message} {py_tamper.PUT_BACK}")
        out.append(f)
    return out


def _precise(findings: list[Finding], root: Path, target: Target) -> list[Finding]:
    """(0.14.0) analyzers/py_precision: whose config entries, which .storage file, which
    packages. Fixed-list package installs go to Target.runtime_requirements."""
    res = Resolver(root)
    out: list[Finding] = []
    # (0.15) a send whose literal address is the Supervisor on this box isn't off-box
    local = {f.id for f in findings if py_precision.supervisor_only(f, res)}
    for f in findings:
        if f.id in local:
            continue
        if (url := py_precision.supervisor_token_stays(f, res)) is not None:
            out.append(py_precision.sent_to_supervisor(f, url))
            continue
        if py_precision.entry_finding_dropped(f, res, target.domain):
            continue
        if py_precision.secrets_dropped(f, res):
            continue
        if py_precision.pickle_of_stored(f, res):
            out.append(py_precision.stored_pickle(f))  # (0.15) a habit, not hidden code
            continue
        if (key := py_precision.own_secret_key(f, res)) is not None:
            out.append(py_precision.reads_own_secret(f, key))  # (0.15) one named entry
            continue
        if py_precision.supervisor_presence_only(f, res):
            continue
        if f.rule_id == "ha-raw-storage-access":
            level = py_precision.storage_level(f, res, target.domain)
            if (
                level is None
                and f.file
                and res.tree(f.file) is None
                and _is_own_storage(f, target.domain)
            ):
                level = py_precision.own_storage(f)  # unparseable file: the old text check
            out.append(level or f)
            continue
        if (checked := py_precision.token_check_only(f, res)) is not None:
            out.append(checked)  # (#21) a token check, not a reach into the auth store
            continue
        if (listed := py_precision.pip_listed(f, res)) is not None:
            out.append(listed[0])
            for spec in listed[1]:
                if spec not in target.runtime_requirements:
                    target.runtime_requirements.append(spec)
            continue
        out.append(f)
    return out


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


def _precise_cached(
    hits: list[js_wrapper.Hit],
    root: Path,
    runner: js_wrapper.Runner,
    card: bool,
    cache: scancache.Cache | None,
) -> set[int]:
    """js_wrapper.precise, kept for the whole app: the key is every file of the app (its
    scope check also reads HTML and Python) and every token hit, so any change reads
    everything again."""
    if cache is None or not cache.on:
        return js_wrapper.precise(hits, root, runner, card=card)
    h = hashlib.sha256(b"card" if card else b"integration")
    try:
        for p in sorted(root.rglob("*")):
            if p.is_file() and not p.is_symlink():
                h.update(p.relative_to(root).as_posix().encode() + b"\0")
                h.update(hashlib.sha256(p.read_bytes()).digest())
    except OSError:
        return js_wrapper.precise(hits, root, runner, card=card)
    spots = sorted({(x.path.resolve().relative_to(root).as_posix(), x.start, x.end) for x in hits})
    h.update(json.dumps(spots).encode())
    key = h.hexdigest()
    got = cache.get("js_wrapper", key)
    if got is not None and isinstance(got.get("dropped"), list):
        dropped = {tuple(d) for d in got["dropped"] if isinstance(d, list) and len(d) == 3}
        cache.stats.saved += float(got.get("secs") or 0)
        return {
            id(x.finding)
            for x in hits
            if (x.path.resolve().relative_to(root).as_posix(), x.start, x.end) in dropped
        }
    started = scancache.now()
    ids = js_wrapper.precise(hits, root, runner, card=card)
    dropped_spots = sorted(
        {
            (x.path.resolve().relative_to(root).as_posix(), x.start, x.end)
            for x in hits
            if id(x.finding) in ids
        }
    )
    cache.put("js_wrapper", key, {"dropped": dropped_spots, "secs": scancache.now() - started})
    return ids


_PARSE_TYPES = _UNREAD_TYPES | {"PartialParsing"}
# More files than this aren't listed on Semgrep's command line one by one: the app is
# read as one folder, without the cache (a command line has a size limit).
_MAX_LISTED = 3000


def _cacheable(errors: list[dict[str, Any]]) -> bool:
    """A file's answer can be kept only if every error is a parse error, which repeats
    exactly on the same bytes (a timeout or a crash may not: "try again")."""
    return all(_error_type(e) in _PARSE_TYPES for e in errors)


def _key_path(r: dict[str, Any]) -> str:
    return str(Path(str(r.get("path", ""))).resolve())


# (0.15) Python 3.14 (PEP 758) lets `except A, B, C:` drop the parentheses. Semgrep
# 1.185 and 1.186 fail on that clause when something else in the file (a `match`, a PEP
# 695 `type` alias or generic) sends it to its fallback parser, which takes one comma
# only (upstream issue 12079), and skip the rules for that part of the file: 6 of 360
# real integrations. Semgrep reads the files with the parentheses added (every line stays
# where it was), and the original bytes are put back as soon as it is done.
_BARE_EXCEPT = re.compile(r"^[ \t]*+except\*?[ \t]++[^(\s:#][^:\n,]*+,", re.M)
_MAX_PY_BYTES = 5_000_000


def _parenthesize_excepts(text: str) -> str | None:
    """`text` with each bare multi-name `except` clause in parentheses; None when the
    tokenizer can't read it. Tokenizing only reads the text, it never runs it."""
    import io
    import tokenize

    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError, ValueError):
        return None
    edits: list[tuple[int, int, int]] = []  # (row, col of first name, col of ":")
    starts_line = True
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if t.type in (tokenize.NL, tokenize.COMMENT):
            i += 1
            continue
        if starts_line and t.type == tokenize.NAME and t.string == "except":
            j = i + 1
            if j < n and toks[j].type == tokenize.OP and toks[j].string == "*":
                j += 1
            first = toks[j] if j < n else None
            depth, comma, named, k = 0, False, False, j
            while k < n:
                u = toks[k]
                if u.type == tokenize.OP and u.string in "([{":
                    depth += 1
                elif u.type == tokenize.OP and u.string in ")]}":
                    depth -= 1
                elif depth == 0 and u.type == tokenize.OP and u.string == ",":
                    comma = True
                elif depth == 0 and u.type == tokenize.NAME and u.string == "as":
                    named = True
                elif u.type == tokenize.NEWLINE or (
                    depth == 0 and u.type == tokenize.OP and u.string == ":"
                ):
                    break
                k += 1
            if (
                k < n
                and first is not None
                and comma
                and not named
                and toks[k].string == ":"
                and not (first.type == tokenize.OP and first.string == "(")
                and first.start[0] == toks[k].start[0]
            ):
                edits.append((first.start[0], first.start[1], toks[k].start[1]))
            i = k
        starts_line = t.type in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT)
        i += 1
    if not edits:
        return text
    lines = text.splitlines(keepends=True)
    for row, a, b in sorted(edits, reverse=True):
        line = lines[row - 1]
        lines[row - 1] = line[:a] + "(" + line[a:b].rstrip() + ")" + line[b:]
    return "".join(lines)


def normalize_py(root: Path) -> dict[Path, bytes]:
    """Parenthesize bare multi-name `except` clauses for Semgrep (see _BARE_EXCEPT).
    Returns the original bytes of each file it changed, to be put back."""
    saved: dict[Path, bytes] = {}
    for p in root.rglob("*.py"):
        if not p.is_file() or p.is_symlink():
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if len(data) > _MAX_PY_BYTES:
            continue
        text = data.decode("utf-8", errors="surrogateescape")
        if not _BARE_EXCEPT.search(text):
            continue
        new = _parenthesize_excepts(text)
        if new is not None and new != text:
            saved[p] = data
            p.write_text(new, encoding="utf-8", errors="surrogateescape")
    return saved


def run(
    target: Target,
    work: Path,
    jobs: int | None = None,
    cache: scancache.Cache | None = None,
) -> AnalyzerResult:
    saved = normalize_py(target.root.resolve())
    try:
        return _run(target, work, jobs, cache)
    finally:
        for path, data in saved.items():
            path.write_bytes(data)


def _run(
    target: Target,
    work: Path,
    jobs: int | None = None,
    cache: scancache.Cache | None = None,
) -> AnalyzerResult:
    exe = shutil.which("semgrep")
    if not exe:
        return AnalyzerResult(NAME, AnalyzerState.SKIPPED, detail="semgrep not installed")
    version = _version(exe)
    root = target.root.resolve()
    neutralize_ignores(root)
    normalize_js(root, target.pristine_sha256)
    run_dir = work / "semgrep-run"
    run_dir.mkdir(exist_ok=True)

    def scan(config: Path, targets: list[Path], timed: bool = False) -> dict[str, Any]:
        cmd = [
            exe,
            "scan",
            "--config",
            str(config),
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
        if timed:
            cmd.append("--time")  # per-file times, for the cache's "about N s saved"
        cmd += [str(p) for p in targets]
        # never run from inside the scanned tree; sandboxed, with no network at all
        proc = _proc.run(cmd, run_dir, _PROCESS_TIMEOUT, _tool_env(), tool="semgrep",
                         read=(config,))  # fmt: skip
        try:
            return json.loads(proc.stdout)
        except ValueError:
            raise _ScanFailed(failure_detail(proc)) from None

    mirrors = [0]

    def scan_uncached(
        config: Path, targets: list[Path], miss: list[Path], some_hit: bool
    ) -> dict[str, Any]:
        """Semgrep on the files the cache didn't answer, read the way a plain scan reads
        them: with nothing cached, the same targets; with some cached, a folder target
        is replaced by a mirror folder holding only the others (copies in the run
        folder, with the same empty .semgrepignore). Semgrep reads a list of files given
        one by one noticeably slower than a folder (38 s against 31 s on a real card)."""
        if not some_hit:
            return scan(config, targets, timed=True)
        if not (len(targets) == 1 and targets[0].is_dir()):
            return scan(config, miss, timed=True)
        mirrors[0] += 1
        mirror = (run_dir / f"uncached-{mirrors[0]}").resolve()
        for f in miss:
            dst = mirror / f.relative_to(root)
            dst.parent.mkdir(parents=True, exist_ok=True)
            # a copy, not a hard link: the app's AppArmor profile grants no link
            # permission, and a denied call would show in the audit log
            shutil.copyfile(f, dst)
        (mirror / ".semgrepignore").write_text("")  # Semgrep's default ignores stay off
        data = scan(config, [mirror], timed=True)

        def back(value: Any) -> Any:
            try:
                return str(root / Path(str(value)).resolve().relative_to(mirror))
            except ValueError:
                return value

        for item in [*data.get("results", []), *data.get("errors", [])]:
            if item.get("path"):
                item["path"] = back(item["path"])
        paths_ = data.get("paths") or {}
        paths_["scanned"] = [back(x) for x in paths_.get("scanned") or []]
        for x in paths_.get("skipped") or []:
            if isinstance(x, dict) and x.get("path"):
                x["path"] = back(x["path"])
        for t in (data.get("time") or {}).get("targets") or []:
            if t.get("path"):
                t["path"] = back(t["path"])
        shutil.rmtree(mirror, ignore_errors=True)
        return data

    def cached(config: Path, targets: list[Path], count: bool = False) -> dict[str, Any]:
        """scan(), with each file's answer kept and reused (scancache). The merged output
        has the same results, errors and scanned paths a single run would give."""
        if cache is None or not cache.on:
            return scan(config, targets)
        files: list[Path] = []
        for t in targets:
            if t.is_dir():
                files += [p for p in sorted(t.rglob("*")) if p.is_file() and not p.is_symlink()
                          and p.name != ".semgrepignore"]  # fmt: skip
            else:
                files.append(t)
        if len(files) > _MAX_LISTED:
            return scan(config, targets)
        keys: dict[str, tuple[Path, str]] = {}
        hit: dict[Path, dict[str, Any]] = {}
        for f in files:
            try:
                k = scancache.file_key(config.name, f.relative_to(root).as_posix(), f.read_bytes())
            except (OSError, ValueError):
                return scan(config, targets)
            keys[str(f.resolve())] = (f, k)
            got = cache.get("semgrep", k)
            if got is not None:
                hit[f] = got
        miss = [f for f in files if f not in hit]
        if count:  # the "N of M files" line counts the main pass's files once
            cache.stats.files += len(files)
            cache.stats.hits += len(hit)
        out: dict[str, Any] = {"results": [], "errors": [], "paths": {"scanned": []}}
        if miss:
            started = scancache.now()
            out = scan_uncached(config, targets, miss, bool(hit))
            wall = scancache.now() - started
            out.setdefault("results", [])
            out.setdefault("errors", [])
            out.setdefault("paths", {}).setdefault("scanned", [])
            general = [e for e in out["errors"] if not e.get("path")]
            per: dict[str, dict[str, Any]] = {
                str(f.resolve()): {"results": [], "errors": [], "scanned": False, "secs": 0.0}
                for f in miss
            }
            for r in out["results"]:
                if (entry := per.get(_key_path(r))) is not None:
                    entry["results"].append(r)
            for e in out["errors"]:
                if e.get("path") and (entry := per.get(_key_path(e))) is not None:
                    entry["errors"].append(e)
            for sp in out["paths"]["scanned"]:
                if (entry := per.get(str(Path(sp).resolve()))) is not None:
                    entry["scanned"] = True
            for t in (out.get("time") or {}).get("targets") or []:
                if (entry := per.get(str(Path(str(t.get("path", ""))).resolve()))) is not None:
                    rt = t.get("run_time", 0)
                    entry["secs"] = float(sum(rt) if isinstance(rt, list) else rt or 0)
            # Semgrep's per-file times add up over its parallel jobs: share the run's
            # wall-clock time out by them, so "about N saved" never says more than it took
            busy = sum(e["secs"] for e in per.values())
            for entry in per.values():
                entry["secs"] = round(wall * entry["secs"] / busy, 3) if busy else 0.0
            skipped = {
                str(Path(str(x.get("path", ""))).resolve())
                for x in out["paths"].get("skipped") or []
                if isinstance(x, dict)
            }
            if not general:
                for abs_path, entry in per.items():
                    if abs_path in skipped or not _cacheable(entry["errors"]):
                        continue
                    rel = keys[abs_path][0].relative_to(root).as_posix()
                    cache.put("semgrep", keys[abs_path][1], {
                        "results": [{**r, "path": rel} for r in entry["results"]],
                        "errors": [{**e, "path": rel} for e in entry["errors"]],
                        "scanned": entry["scanned"], "secs": entry["secs"],
                    })  # fmt: skip
        for f, got in hit.items():
            here = str(f)
            out["results"] += [{**r, "path": here} for r in got.get("results", [])]
            out["errors"] += [{**e, "path": here} for e in got.get("errors", [])]
            if got.get("scanned"):
                out["paths"]["scanned"].append(here)
            cache.stats.saved += float(got.get("secs") or 0)
        return out

    try:
        data = cached(rules_dir(), [root], count=True)
        # (0.14.0) Second pass, JavaScript only: the constant-propagation copy of the
        # token rule (Semgrep mixes two taint rules' propagation settings in one run).
        # Names built from pieces (analyzers/js_fold.py) are written back in place and
        # both passes run again on those files.
        js = js_fold.js_files(root)
        fold = js_fold.analyse(js, root)
        # Only files that can hold a token source (every source pattern names one of
        # js_fold.TOKEN_HINTS; a name built from pieces is in fold.rewrites, which both
        # passes read again below). A real 1.6 MB card bundle without them: no second parse.
        need = [p for p in js if p not in fold.rewrites and js_fold.may_hold_token(p)]
        data2 = cached(rules_const_dir(), need) if need else {"results": [], "errors": []}
        if fold.rewrites:
            originals = {p: p.read_bytes() for p in fold.rewrites}
            try:
                for p, b in fold.rewrites.items():
                    p.write_bytes(b)
                files = sorted(fold.rewrites)
                again, again2 = cached(rules_dir(), files), cached(rules_const_dir(), files)
            finally:
                for p, b in originals.items():
                    p.write_bytes(b)
            redone = {str(p.resolve()) for p in files}

            def keep(d: dict[str, Any]) -> list[dict[str, Any]]:
                return [
                    r for r in d.get("results", []) if str(Path(r["path"]).resolve()) not in redone
                ]

            data["results"] = keep(data) + again.get("results", [])
            data2["results"] = keep(data2) + again2.get("results", [])
            data["errors"] = [
                e for e in data.get("errors", [])
                if str(Path(str(e.get("path", ""))).resolve()) not in redone
            ] + again.get("errors", [])  # fmt: skip
    except subprocess.TimeoutExpired:
        return AnalyzerResult(
            NAME, AnalyzerState.ERROR, detail="semgrep timed out", tool_version=version
        )
    except _ScanFailed as e:
        return AnalyzerResult(NAME, AnalyzerState.ERROR, detail=str(e), tool_version=version)
    # One list: the second pass's token findings (aliased to card-token-exfil), once per
    # place; its parse errors repeat the first pass's and aren't counted twice.
    seen = {(_rule_id(r), r["path"], r["start"]["offset"]) for r in data.get("results", [])}
    for r in data2.get("results", []):
        key = (_rule_id(r), r["path"], r["start"]["offset"])
        if key in seen:
            continue
        seen.add(key)
        data["results"].append(r)
    data["errors"] = data.get("errors", []) + [
        e
        for e in data2.get("errors", [])
        if _error_type(e) != "Syntax error" and "PartialParsing" not in str(e.get("type"))
    ]
    findings: list[Finding] = []
    facts: list[Fact] = []
    token_hits: list[js_wrapper.Hit] = []
    eval_hits: list[js_loader.Hit] = []
    for r in data.get("results", []):
        if (fact := to_fact(r, root, target.domain)) is not None:
            facts.append(fact)
        else:
            f = to_finding(r, root)
            if f.file and Path(f.file).suffix in js_wrapper._JS:
                raw = (root / f.file).read_bytes()
                start = js_wrapper.char_offset(raw, r["start"]["offset"])
                end = js_wrapper.char_offset(raw, r["end"]["offset"])
                text = raw.decode("utf-8", "replace")
                f = dataclasses.replace(
                    f, fingerprint=fingerprint.javascript(f.rule_id, text, start, end)
                )
                if f.rule_id == js_wrapper.RULE:
                    token_hits.append(js_wrapper.Hit(f, root / f.file, start, end))
                elif f.rule_id == "card-eval-remote":
                    eval_hits.append(js_loader.Hit(f, root / f.file, start))
            findings.append(f)
    if token_hits:  # (0.14.0) same-origin URLs the rule can't prove (js_wrapper)
        runner = js_wrapper.semgrep_runner(exe, root, run_dir, _tool_env(), _proc.run)
        card = target.kind is TargetKind.PLUGIN
        same_origin = _precise_cached(token_hits, root, runner, card, cache)
        findings = [f for f in findings if id(f) not in same_origin]
        # (0.15) a path from the card's own settings, with a "/" default or none: a note
        notes = js_settings.settings_note(
            [h for h in token_hits if id(h.finding) not in same_origin]
        )
        findings = [js_settings.as_note(f, *notes[id(f)]) if id(f) in notes else f
                    for f in findings]  # fmt: skip
    if eval_hits:  # (0.15) a loader: a door graded by the addresses it can be handed
        loader_ids = js_loader.loaders(eval_hits, root)
        if loader_ids:
            findings = [js_loader.as_note(f) if id(f) in loader_ids else f for f in findings]
            remote = ("card-remote-script", "card-remote-pinned")
            known = {f.evidence for f in findings if f.rule_id in remote}
            findings += [f for f in js_loader.script_addresses(root) if f.evidence not in known]
    findings += fold.findings
    trees: dict[str, Any] = {}
    findings = [f for f in findings if not _only_rebinds_names(f, root, trees)]
    findings = _put_back(findings, trees)
    findings = _precise(findings, root, target)
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
