"""Code around a finding, port or unknown address, for "Explain in context" (0.7.0).

Built by the scanner while the workspace still exists (it's deleted when `scan()`
returns), so the code is exactly what the Marketplace installs. Files are read as text and
Python is parsed with `ast` and `tokenize`; nothing is ever run or imported.

Each snippet is the code the question is about, not just the flagged line:
- Python: the enclosing function. A module-level line brings the functions that use the
  names it assigns: in the same file (HomGar's `TELEMETRY_URL = "https://…/ping"` at
  `telemetry.py:36` brings `async_maybe_ping`, which posts to it), else in files that
  import the name with a relative import (`from .const import TELEMETRY`). Then, budget
  permitting, one hop to the functions those call, in the same file or imported from a
  sibling module (`from .helpers import upload`): that's where "what gets sent" usually
  is. Only relative imports inside the scanned package are followed, never the whole repo.
- Other files (cards): lines around the location. A minified line is cut to a window of
  characters around the host or evidence.

Snippets are capped (lines, characters, count, total) and stored in the report under
`context`. The text is from the scanned repo and so untrusted: it goes to the AI only
inside a nonce-delimited block (report.ai_context), and the panel shows it escaped.
For the citation check, each snippet records per file which of its lines aren't code
(comment-only and docstring lines) and where a trailing comment starts.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import jsbeautifier

from sniff_test.analyzers.endpoints import UNEXPLAINED

CONTEXT_VERSION = 2  # 2: windows on long lines are reformatted (0.7.2)
MAX_LINES = 150  # per snippet
MAX_CHARS = 12_000  # per snippet
MAX_ITEMS = 40  # per report
MAX_TOTAL = 300_000  # characters per report
MAX_FILE = 2_000_000  # bytes read from one file
MAX_PY_FILES = 300  # files parsed per report when looking for importers
LONG_LINE = 400  # longer lines are cut (minified bundles)
WINDOW = 1_200  # characters each side of the hint on a long line (shared by its windows)
MIN_WINDOW = 300  # characters each side, at least, when a line has several windows
MAX_WINDOWS = 5  # windows on one long line
TEXT_RADIUS = 25  # lines each side for non-Python files
FUNC_WINDOW = 50  # lines each side of the location inside a very long function
HOST_CLASSES = UNEXPLAINED | {"messaging"}  # "unknown addresses": no docs or name explain them
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


@dataclass(frozen=True)
class Item:
    id: str  # finding id or graph edge id
    kind: str  # finding | host | port
    file: str
    line: int
    hints: tuple[str, ...] = ()  # text to centre a cut line on (host, evidence, names)


def items(findings: Iterable[dict[str, Any]], graph: dict[str, Any] | None) -> list[Item]:
    """What gets a button, most important first: findings (one per rule, as the page
    groups them; dependency findings have no code of the app's own), then unknown
    addresses, then ports."""
    order = ["critical", "high", "medium", "low", "info"]
    out: list[Item] = []
    seen_rules: set[str] = set()
    findings = list(findings)
    for f in sorted(findings, key=lambda f: order.index(f.get("severity", "info"))):
        if f["rule_id"] in seen_rules:
            continue
        seen_rules.add(f["rule_id"])
        if f.get("file") and f.get("line") and f.get("category") != "dependency":
            # Every occurrence on the same line (a minified bundle: Bambu's 5 token uses
            # are all on line 87) gets its own window.
            same = [
                x.get("evidence") or ""
                for x in findings
                if x["rule_id"] == f["rule_id"]
                and x.get("file") == f["file"]
                and x.get("line") == f["line"]
            ]
            hints = tuple(dict.fromkeys([f.get("evidence") or "", *same]))[:MAX_WINDOWS]
            out.append(Item(f["id"], "finding", f["file"], int(f["line"]), hints))
    g = graph or {}
    nodes = {n["id"]: n for n in g.get("nodes", [])}
    hosts, ports = [], []
    for edge in g.get("edges", []):
        sample = next((s for s in edge.get("samples", []) if s.get("line")), None)
        if not sample or edge.get("source") != g.get("subject"):
            continue
        attrs = edge.get("attrs", {})
        if edge["relation"] == "connects_to" and attrs.get("class") in HOST_CLASSES:
            label = nodes.get(edge["target"], {}).get("label", "")
            hosts.append(Item(edge["id"], "host", sample["file"], int(sample["line"]), (label,)))
        elif edge["relation"] == "uses_port":
            hint = (attrs.get("names") or [""])[0]
            ports.append(Item(edge["id"], "port", sample["file"], int(sample["line"]), (hint,)))
    return out + sorted(hosts, key=lambda i: i.hints) + ports


def build(root: Path, findings: list[dict[str, Any]], graph: dict[str, Any] | None) -> dict:
    """The report's `context` section: {"version", "snippets": {sid: …}, "items": {id: …}}."""
    tree = _Tree(root)
    snippets: dict[str, dict[str, Any]] = {}
    by_key: dict[str, str] = {}
    out_items: dict[str, dict[str, Any]] = {}
    total = 0
    for it in items(findings, graph):
        if len(out_items) >= MAX_ITEMS:
            break
        snip = snippet(tree, it.file, it.line, it.hints)
        if snip is None:
            continue
        key = repr(
            [(s.get("line"), s["file"], s["start"], s.get("col", 0)) for s in snip["segments"]]
        )
        sid = by_key.get(key)
        if sid is None:
            size = sum(len(c) for s in snip["segments"] for c in s["code"])
            if total + size > MAX_TOTAL:
                continue
            total += size
            sid = f"s{len(snippets) + 1}"
            snippets[sid] = snip
            by_key[key] = sid
        out_items[it.id] = {"kind": it.kind, "file": it.file, "line": it.line, "snippet": sid}
    return {"version": CONTEXT_VERSION, "snippets": snippets, "items": out_items}


# --- reading files ----------------------------------------------------------------------------


def _clean(line: str) -> str:
    return _CONTROL.sub("", line)  # tabs kept: comment columns come from tokenize


@dataclass
class _Py:
    rel: str
    lines: list[str]
    tree: ast.Module
    funcs: list[ast.FunctionDef | ast.AsyncFunctionDef]
    noncode: set[int]
    comment_col: dict[int, int]
    imports: dict[str, tuple[str, str]]  # local name -> (file rel, name there), relative only


@dataclass
class _Tree:
    root: Path
    _text: dict[str, str | None] = field(default_factory=dict)
    _py: dict[str, _Py | None] = field(default_factory=dict)

    def text(self, rel: str) -> str | None:
        if rel not in self._text:
            self._text[rel] = _read(self.root, rel)
        return self._text[rel]

    def py(self, rel: str) -> _Py | None:
        if rel not in self._py:
            self._py[rel] = self._parse(rel)
        return self._py[rel]

    def _parse(self, rel: str) -> _Py | None:
        text = self.text(rel)
        if text is None:
            return None
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return None  # e.g. syntax newer than our Python: a line window instead
        funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
        noncode, cc = _python_noncode(text, tree)
        return _Py(rel, text.splitlines(), tree, funcs, noncode, cc, self._imports(rel, tree))

    def _imports(self, rel: str, tree: ast.Module) -> dict[str, tuple[str, str]]:
        out: dict[str, tuple[str, str]] = {}
        own = f"custom_components.{self.root.name}"
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if node.level:
                target = self.module_file(rel, node.level, node.module)
            elif node.module and (node.module == own or node.module.startswith(own + ".")):
                # `from custom_components.<this domain>.x import n`: the same package
                sub = node.module[len(own) + 1 :] or None
                target = self.module_file("__init__.py", 1, sub)
            else:
                continue
            if target is None:
                continue
            for alias in node.names:
                if alias.name != "*":
                    out[alias.asname or alias.name] = (target, alias.name)
        return out

    def module_file(self, rel: str, level: int, module: str | None) -> str | None:
        """`from ..x.y import n` in `rel` -> the file inside the scanned root, if any."""
        pkg = PurePosixPath(rel).parent
        for _ in range(level - 1):
            if pkg == PurePosixPath("."):
                return None  # above the scanned package
            pkg = pkg.parent
        parts = module.split(".") if module else []
        base = pkg.joinpath(*parts) if parts else pkg
        for cand in (f"{base}.py", f"{base}/__init__.py"):
            cand = cand.removeprefix("./")
            if self.text(cand) is not None:
                return cand
        return None

    def py_files(self) -> list[str]:
        out = []
        try:
            for p in sorted(self.root.rglob("*.py")):
                if not p.is_symlink() and p.is_file():
                    out.append(p.relative_to(self.root).as_posix())
                if len(out) >= MAX_PY_FILES:
                    break
        except OSError:
            pass
        return out


def _read(root: Path, rel: str) -> str | None:
    try:
        base = root.resolve()
        path = (root / rel).resolve()
        if not path.is_relative_to(base) or (root / rel).is_symlink() or not path.is_file():
            return None
        with path.open("rb") as fh:
            data = fh.read(MAX_FILE)
    except (OSError, ValueError):
        return None
    return data.decode("utf-8", "replace")


def snippet(
    tree: _Tree | Path, rel: str, line: int, hints: str | tuple[str, ...] = ()
) -> dict[str, Any] | None:
    if isinstance(hints, str):
        hints = (hints,)
    if isinstance(tree, Path):
        tree = _Tree(tree)
    text = tree.text(rel)
    if text is None:
        return None
    lines = text.splitlines()
    if not 1 <= line <= len(lines):
        return None
    if rel.endswith(".py"):
        py = tree.py(rel)
        if py is not None:
            return _python(tree, py, line)
    return _text(rel, lines, line, hints)


# --- Python -----------------------------------------------------------------------------------


def _span(node: ast.AST) -> tuple[int, int]:
    start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
    return start, node.end_lineno or node.lineno


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _called(node: ast.AST) -> set[str]:
    """Names it may call: `f(…)`, `self.f(…)`/`cls.f(…)`."""
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            fn = n.func
            if isinstance(fn, ast.Name):
                out.add(fn.id)
            elif (
                isinstance(fn, ast.Attribute)
                and isinstance(fn.value, ast.Name)
                and fn.value.id in ("self", "cls")
            ):
                out.add(fn.attr)
    return out


def _assigned_names(stmt: ast.stmt) -> set[str]:
    targets: list[ast.expr] = []
    if isinstance(stmt, ast.Assign):
        targets = stmt.targets
    elif isinstance(stmt, ast.AnnAssign | ast.AugAssign):
        targets = [stmt.target]
    return {n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)}


def _python(tree: _Tree, py: _Py, line: int) -> dict[str, Any]:
    spans: list[tuple[str, int, int]] = []  # (file, first, last) in priority order
    primary: list[tuple[_Py, ast.AST]] = []
    around = [f for f in py.funcs if _span(f)[0] <= line <= _span(f)[1]]
    if around:
        f = max(around, key=lambda f: _span(f)[0])  # innermost
        a, b = _span(f)
        if b - a + 1 > 2 * FUNC_WINDOW:
            head_end = f.body[0].lineno - 1 if f.body else a
            spans.append((py.rel, a, max(a, head_end)))
            spans.append((py.rel, max(a, line - FUNC_WINDOW), min(b, line + FUNC_WINDOW)))
        else:
            spans.append((py.rel, a, b))
        primary.append((py, f))
    else:
        stmt = next(
            (
                s
                for s in ast.walk(py.tree)
                if isinstance(s, ast.stmt)
                and not isinstance(s, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
                and s.lineno <= line <= (s.end_lineno or s.lineno)
            ),
            None,
        )
        if stmt is None:
            spans.append((py.rel, max(1, line - 5), min(len(py.lines), line + 5)))
        else:
            a, b = stmt.lineno, stmt.end_lineno or stmt.lineno
            spans.append((py.rel, a, min(b, a + 9)))
            keys = _keys_on(stmt, line)
            for user_py, f in _users(tree, py, _assigned_names(stmt), keys)[:2]:
                spans.append((user_py.rel, *_span(f)))
                primary.append((user_py, f))
    for p_py, p in primary:
        for name in sorted(_called(p)):
            hit = _resolve(tree, p_py, name)
            if hit is not None and hit[1] is not p:
                spans.append((hit[0].rel, *_span(hit[1])))
    return _finish(tree, py.rel, _fit(spans), "python")


MAX_SOURCES = 24  # module-level names followed per snippet


def _module_derived(py: _Py, names: set[str], keys: frozenset[str]) -> set[str]:
    """Module-level names assigned from `names` (`LOGIN = urljoin(BASE, "/login")`).

    A name reached only through an attribute (`DOMAIN = CURRENT_BRAND.domain`) counts
    only if the attribute is one of `keys`, the keywords on the flagged line (EG4's
    `default_base_url="https://…"`): else every user of `DOMAIN` would come along.
    """
    out = set()
    for stmt in py.tree.body:
        if not isinstance(stmt, ast.Assign | ast.AnnAssign) or stmt.value is None:
            continue
        used = names & _names_in(stmt.value)
        if not used:
            continue
        attrs = {
            n.attr
            for n in ast.walk(stmt.value)
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in used
        }
        bare = any(
            isinstance(n, ast.Name) and n.id in used and not _is_attr_base(stmt.value, n)
            for n in ast.walk(stmt.value)
        )
        if bare or attrs & keys:
            out |= _assigned_names(stmt) - names
    return out


def _is_attr_base(tree: ast.AST, name: ast.Name) -> bool:
    return any(isinstance(n, ast.Attribute) and n.value is name for n in ast.walk(tree))


def _keys_on(stmt: ast.stmt, line: int) -> frozenset[str]:
    """Keyword-argument names and string dict keys on one line of a statement."""
    out = set()
    for n in ast.walk(stmt):
        if isinstance(n, ast.keyword) and n.arg and getattr(n.value, "lineno", 0) == line:
            out.add(n.arg)
        elif isinstance(n, ast.Dict):
            for k in n.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.lineno == line:
                    out.add(k.value)
    return frozenset(out)


def _users(
    tree: _Tree, py: _Py, names: set[str], keys: frozenset[str] = frozenset()
) -> list[tuple[_Py, ast.AST]]:
    """Functions using a module-level name, following it the way code does: through
    module-level names derived from it (Daikin's `DAIKIN_API_URL_BASE` is only used by
    `DAIKIN_API_URL_LOGIN = urljoin(DAIKIN_API_URL_BASE, …)`) and through relative imports,
    re-exports included (EG4's `const/__init__.py` re-exports `BRAND_EG4` from
    `const/brand.py`). Breadth first, nearest users first; bounded by MAX_SOURCES."""
    if not names:
        return []
    out: list[tuple[_Py, ast.AST]] = []
    seen_funcs: set[int] = set()
    queue: list[tuple[_Py, frozenset[str]]] = [(py, frozenset(names))]
    seen: set[tuple[str, str]] = {(py.rel, n) for n in names}
    files = None
    while queue and len(out) < 2 and len(seen) <= MAX_SOURCES:
        cur, cur_names = queue.pop(0)
        for f in sorted(cur.funcs, key=lambda f: f.lineno):
            if set(cur_names) & _names_in(f) and id(f) not in seen_funcs:
                seen_funcs.add(id(f))
                out.append((cur, f))
        derived = {
            n for n in _module_derived(cur, set(cur_names), keys) if (cur.rel, n) not in seen
        }
        if derived:
            seen |= {(cur.rel, n) for n in derived}
            queue.append((cur, frozenset(derived)))
        if files is None:
            files = tree.py_files()
        for rel in files:
            other = tree.py(rel) if rel != cur.rel else None
            if other is None:
                continue
            local = {
                a
                for a, (src, name) in other.imports.items()
                if src == cur.rel and name in cur_names and (rel, a) not in seen
            }
            if local:
                seen |= {(rel, a) for a in local}
                queue.append((other, frozenset(local)))
    return out[:2]


def _resolve(tree: _Tree, py: _Py, name: str) -> tuple[_Py, ast.AST] | None:
    """A function called by name: defined in this file, or imported from a sibling."""
    for f in py.funcs:
        if f.name == name:
            return py, f
    src = py.imports.get(name)
    if src is not None:
        other = tree.py(src[0])
        if other is not None:
            for f in other.funcs:
                if f.name == src[1] and f.col_offset == 0:
                    return other, f
    return None


def _fit(spans: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    """Keep spans in priority order while they fit MAX_LINES, the first always (cut to
    size); then merge overlaps. The first span's file comes first."""
    kept: list[tuple[str, int, int]] = []
    used = 0
    for f, a, b in spans:
        n = b - a + 1
        if used + n > MAX_LINES:
            if not kept:
                kept.append((f, a, a + MAX_LINES - 1))
                used = MAX_LINES
            continue
        kept.append((f, a, b))
        used += n
    first = kept[0][0] if kept else ""
    merged: list[tuple[str, int, int]] = []
    for f, a, b in sorted(kept, key=lambda s: (s[0] != first, s[0], s[1])):
        if merged and merged[-1][0] == f and a <= merged[-1][2] + 1:
            merged[-1] = (f, merged[-1][1], max(merged[-1][2], b))
        else:
            merged.append((f, a, b))
    return merged


def _python_noncode(text: str, tree: ast.AST) -> tuple[set[int], dict[int, int]]:
    """(lines that aren't code: comment-only or docstring, {line: column a comment starts})."""
    noncode: set[int] = set()
    comment_col: dict[int, int] = {}
    code_lines: set[int] = set()
    skip = (tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER)
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                comment_col[tok.start[0]] = tok.start[1]
            elif tok.type not in skip:
                code_lines.update(range(tok.start[0], tok.end[0] + 1))
    except (tokenize.TokenError, SyntaxError):
        pass
    noncode |= {ln for ln in comment_col if ln not in code_lines}
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list):
            continue
        for stmt in body:
            if (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
            ):
                noncode.update(range(stmt.lineno, (stmt.end_lineno or stmt.lineno) + 1))
    return noncode, comment_col


# --- other text (cards) -----------------------------------------------------------------------


_JS_OPTS = jsbeautifier.default_options()
_JS_OPTS.indent_size = 2
_JS_OPTS.wrap_line_length = 0
_JS_OPTS.preserve_newlines = False
# Never set: `editorconfig` (jsbeautifier only reads .editorconfig files from its command
# line, which we don't use; beautify() formats the string it's given and nothing else).
PART_RADIUS = 15  # formatted lines each side of an occurrence
_WS = re.compile(r"\s+")
_formatted_cache: dict[int, list[str] | None] = {}


def reformat(line: str) -> list[str] | None:
    """A whole minified line laid out one statement per line, or None if formatting
    changed anything but whitespace (then the raw window is used: the AI must read the
    shipped code, never our rewrite of it). The whole line is formatted, from its real
    start, because a window cut at an arbitrary character can begin inside a string, and
    the formatter then reads strings as code (it turned "/api/bambu_lab/print_history"
    into " / api / bambu_lab / print_history "). Formatting only: jsbeautifier tokenizes
    text and runs nothing. Bambu's 209 KB line takes 0.2 s."""
    key = hash(line)
    if key in _formatted_cache:
        return _formatted_cache[key]
    try:
        text = jsbeautifier.beautify(line, _JS_OPTS)
    except Exception:
        text = None
    out = None
    if text is not None and _WS.sub("", text) == _WS.sub("", line):
        out = [_clean(x.rstrip()) for x in text.splitlines()]
    if len(_formatted_cache) > 64:
        _formatted_cache.clear()
    _formatted_cache[key] = out
    return out


def _formatted_line_of(formatted: list[str], nonspace: int) -> int:
    """1-based formatted line holding the `nonspace`-th non-whitespace character."""
    seen = 0
    for i, text in enumerate(formatted, 1):
        seen += len(_WS.sub("", text))
        if seen > nonspace:
            return i
    return len(formatted)


def find_hint(target: str, hint: str) -> int:
    """Where `hint` is in `target`, -1 if nowhere. Evidence is stored cut, with "…" at
    either end (`…tch("/api/bambu_lab/print_history",…`), so the marks are dropped and,
    failing a full match, shorter pieces from its start are tried."""
    for piece in (p.strip() for p in hint.split("…")):
        if len(piece) < 8:
            continue
        for n in (len(piece), 80, 40, 20):
            if n <= len(piece):
                col = target.find(piece[:n])
                if col >= 0:
                    return col
    return -1


def _text(rel: str, lines: list[str], line: int, hints: tuple[str, ...]) -> dict[str, Any]:
    target = lines[line - 1]
    if len(target) > LONG_LINE:
        cols = sorted({c for c in (find_hint(target, h) for h in hints if h) if c >= 0})
        if not cols:
            cols = [len(target) // 2]
        formatted = reformat(target)
        if formatted is not None:
            part = f"{rel}#L{line}"
            rows = [_formatted_line_of(formatted, len(_WS.sub("", target[:c]))) for c in cols]
            spans: list[list[int]] = []
            for r in rows:
                a, b = max(1, r - PART_RADIUS), min(len(formatted), r + PART_RADIUS)
                if spans and a <= spans[-1][1] + 1:
                    spans[-1][1] = max(spans[-1][1], b)
                else:
                    spans.append([a, b])
            segs = []
            for a, b in spans:
                code = [x if len(x) <= LONG_LINE else x[:LONG_LINE] + " …"
                        for x in formatted[a - 1 : b]]  # fmt: skip
                segs.append({"file": part, "start": a, "code": code, "line": line})
            shown = {n for g in segs for n in range(g["start"], g["start"] + len(g["code"]))}
            noncode = sorted(
                n for n in shown if formatted[n - 1].strip().startswith(("//", "/*", "*"))
            )
            return {"file": rel, "lang": "text", "segments": segs,
                    "noncode": {part: noncode}, "comment_col": {}}  # fmt: skip
        side = max(MIN_WINDOW, WINDOW // len(cols))
        raw: list[list[int]] = []
        for c in cols:
            a, b = max(0, c - side), min(len(target), c + side)
            if raw and a <= raw[-1][1]:
                raw[-1][1] = max(raw[-1][1], b)
            else:
                raw.append([a, b])
        segs = [
            {"file": rel, "start": line, "col": a, "end": b, "code": [_clean(target[a:b])]}
            for a, b in raw
        ]
        return {"file": rel, "lang": "text", "segments": segs, "noncode": {}, "comment_col": {}}
    a, b = max(1, line - TEXT_RADIUS), min(len(lines), line + TEXT_RADIUS)
    noncode = {
        n
        for n in range(a, b + 1)
        if lines[n - 1].strip().startswith(("//", "/*", "*", "<!--", "#"))
    }
    return _segments(rel, "text", [(rel, a, b)], {rel: lines}, {rel: (noncode, {})})


def _finish(
    tree: _Tree, first: str, spans: list[tuple[str, int, int]], lang: str
) -> dict[str, Any]:
    lines, nc = {}, {}
    for f, _a, _b in spans:
        py = tree.py(f)
        if py is not None:
            lines[f] = py.lines
            nc[f] = (py.noncode, py.comment_col)
    return _segments(first, lang, [s for s in spans if s[0] in lines], lines, nc)


def _segments(
    first: str,
    lang: str,
    spans: list[tuple[str, int, int]],
    lines: dict[str, list[str]],
    noncode: dict[str, tuple[set[int], dict[int, int]]],
) -> dict[str, Any]:
    segments = []
    chars = 0
    for f, a, b in spans:
        code = []
        for n in range(a, min(b, len(lines[f])) + 1):
            text = _clean(lines[f][n - 1])
            if len(text) > LONG_LINE:
                text = text[:LONG_LINE] + " …"
            if chars + len(text) > MAX_CHARS:
                break
            chars += len(text) + 1
            code.append(text)
        if code:
            segments.append({"file": f, "start": a, "code": code})
        if chars >= MAX_CHARS:
            break
    shown: dict[str, set[int]] = {}
    for s in segments:
        shown.setdefault(s["file"], set()).update(range(s["start"], s["start"] + len(s["code"])))
    return {
        "file": first,
        "lang": lang,
        "segments": segments,
        "noncode": {f: sorted(n for n in noncode[f][0] if n in rows) for f, rows in shown.items()},
        "comment_col": {
            f: {str(n): c for n, c in sorted(noncode[f][1].items()) if n in rows}
            for f, rows in shown.items()
        },
    }


def line_text(snip: dict[str, Any], file: str, n: int) -> str | None:
    """The code we sent for file:n (None if not sent). A cut line is its windows, joined."""
    parts = []
    for s in snip.get("segments", []):
        i = n - int(s["start"])
        if s.get("file") == file and 0 <= i < len(s["code"]):
            parts.append(s["code"][i])
    return "\n".join(parts) if parts else None


def code_part(snip: dict[str, Any], file: str, n: int) -> str | None:
    """file:n without its trailing comment; "" for a comment-only or docstring line."""
    text = line_text(snip, file, n)
    if text is None:
        return None
    if n in set(snip.get("noncode", {}).get(file, [])):
        return ""
    col = snip.get("comment_col", {}).get(file, {}).get(str(n))
    return text[:col] if isinstance(col, int) else text


def files(snip: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for s in snip.get("segments", []):
        if s["file"] not in out:
            out.append(s["file"])
    return out


def line_count(snip: dict[str, Any]) -> int:
    return sum(len(s["code"]) for s in snip.get("segments", []))
