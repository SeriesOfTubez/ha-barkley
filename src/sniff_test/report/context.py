"""Code around a finding, port or unknown address, for "Explain in context" (0.7.0).

Built by the scanner while the workspace still exists (it's deleted when `scan()`
returns), so the code is exactly what the Marketplace installs. Files are read as text and
Python is parsed with `ast` and `tokenize`; nothing is ever run or imported.

Each snippet is the code the question is about, not just the flagged line:
- Python: the enclosing function. A module-level line brings the functions that use the
  names it assigns: in the same file (`TELEMETRY_URL = "https://…/ping"` in a
  `telemetry.py` brings `async_maybe_ping`, which posts to it), else in files that
  import the name with a relative import (`from .const import TELEMETRY`). Then, budget
  permitting, one hop to the functions those call, in the same file or imported from a
  sibling module (`from .helpers import upload`): that's where "what gets sent" usually
  is. Only relative imports inside the scanned package are followed, never the whole repo.
  Since 0.11.0 the snippet also brings what the reader otherwise has to ask for: the
  import statements and module-level constants behind the names it uses, the functions
  and classes of the app it *refers to* without calling them (an app assigns a function of
  its own to a method of one of Home Assistant's built-in integrations: the question is
  what that function does), those named on the flagged statement first and
  cut to fit rather than left out.
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
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import jsbeautifier

from sniff_test.analyzers import py_tamper
from sniff_test.analyzers.endpoints import UNEXPLAINED
from sniff_test.report import compare

# 2: long lines reformatted (0.7.2); 3: dependency items (0.7.4); 4: imports, constants,
# referenced functions and classes, `patch` on a monkeypatch item, `source` (0.11.0);
# 5: `patch.compare` and `patch.inside`, `readme` (0.12.0)
CONTEXT_VERSION = 5
MAX_LINES = 150  # per snippet, without the header lines
MAX_CHARS = 16_000  # per snippet
HEADER_LINES = 40  # more lines per snippet for imports and module-level constants
CONST_LINES = 10  # of one module-level assignment
CLASS_HEAD = 40  # lines of a class that is only referred to
MIN_CUT = 10  # a span that may be cut is left out when fewer lines than this are free
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
MAX_JS_FILES = 400  # card source files searched for a package's imports
MAX_USES = 6  # places a dependency is used, per snippet
DEP_RADIUS = 6  # lines each side of a use in a card's source
_SKIP_DIRS = {"node_modules", "dist", "build", ".git", "coverage", "test", "tests",
              "__tests__", "docs", "examples", "demo"}  # fmt: skip
_JS_EXT = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
HOST_CLASSES = UNEXPLAINED | {"messaging"}  # "unknown addresses": no docs or name explain them
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


@dataclass(frozen=True)
class Item:
    id: str  # finding id or graph edge id
    kind: str  # finding | host | port | dependency
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
    deps: list[Item] = []
    for f in sorted(findings, key=lambda f: order.index(f.get("severity", "info"))):
        dep = f.get("dependency")
        if f["rule_id"] == "dep-vuln" and isinstance(dep, dict):
            # (0.7.4) where the app's own code uses the package; one item per package
            hint = (str(dep.get("package", "")), str(dep.get("ecosystem", "")))
            deps.append(Item(f["id"], "dependency", "", 0, hint))
            continue
        if f["rule_id"] in seen_rules:
            continue
        seen_rules.add(f["rule_id"])
        if f.get("file") and f.get("line") and f.get("category") != "dependency":
            # Every occurrence on the same line (a minified bundle: five token uses, all
            # on one line) gets its own window.
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
    return out + deps + sorted(hosts, key=lambda i: i.hints) + ports


def build(
    root: Path,
    findings: list[dict[str, Any]],
    graph: dict[str, Any] | None,
    source_root: Path | None = None,
    *,
    places: list[tuple[str, str, int]] | None = None,
    ha_version: str | None = None,
    ha_source: Callable[[str], str | None] | None = None,
) -> dict:
    """The report's `context` section: {"version", "snippets": {sid: …}, "items": {id: …},
    "readme": …}. source_root: the repo at the ref, where a card's own (unbundled) source
    and the README live. places: (kind, file, line) of every address and port the scan
    listed. ha_version, ha_source(path): the scan's Home Assistant release and a reader for
    one file of it (report.compare); without them nothing is compared and the item says so."""
    tree = _Tree(root)
    src = _Tree(source_root) if source_root is not None else tree
    snippets: dict[str, dict[str, Any]] = {}
    by_key: dict[str, str] = {}
    out_items: dict[str, dict[str, Any]] = {}
    patches = {f["id"] for f in findings if f.get("rule_id") == py_tamper.RULE_ID}
    budget = [compare.MAX_FETCH]  # Home Assistant files this scan may still ask GitHub for
    total = 0
    for it in items(findings, graph):
        if len(out_items) >= MAX_ITEMS:
            break
        if it.kind == "dependency":
            package, ecosystem = it.hints
            snip = dependency_usage(tree if ecosystem == "PyPI" else src, package, ecosystem)
            if snip is None:  # no button; the page says we couldn't find where it's used
                out_items[it.id] = {"kind": "dependency", "package": package, "snippet": None}
                continue
        else:
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
        if it.kind == "dependency":
            first = snip["segments"][0]
            out_items[it.id] = {"kind": "dependency", "package": it.hints[0], "file": first["file"],
                                "line": first["start"], "snippet": sid}  # fmt: skip
        else:
            out_items[it.id] = {"kind": it.kind, "file": it.file, "line": it.line, "snippet": sid}
            if it.kind == "finding" and it.id in patches:
                fact, repl = _patch(tree, it.file, it.line)
                if fact:
                    out_items[it.id]["patch"] = fact
                    cmp = compare.compare(fact, repl, ha_version, ha_source, budget)
                    if cmp:
                        fact["compare"] = cmp
                    if repl:
                        a, b = _span(repl[2])
                        fact["inside"] = compare.inside(
                            repl[0], a, b, it.id, findings, places or []
                        )
    out = {"version": CONTEXT_VERSION, "snippets": snippets, "items": out_items}
    doc = readme(source_root)
    if doc:
        out["readme"] = doc
    return out


# --- what the app says it does (0.12.0) -------------------------------------------------------

README_LINES = 80
README_CHARS = 6_000
README_LINE = 300  # characters kept of one line (badge and image lines run long)
_README_NAMES = ("readme.md", "readme.rst", "readme.txt")


def readme(source_root: Path | None) -> dict[str, Any] | None:
    """The head of the repository's README: what the app says it does. Written by whoever
    published the app, so it is untrusted like the code: shown escaped, sent to the AI only
    inside a nonce-delimited block, and never evidence of what the code does."""
    if source_root is None:
        return None
    try:
        names = {p.name.lower(): p.name for p in source_root.iterdir() if not p.is_symlink()}
    except OSError:
        return None
    name = next((names[n] for n in _README_NAMES if n in names), None)
    if name is None or not re.fullmatch(r"[A-Za-z0-9_.\-]{1,40}", name):
        return None
    text = _read(source_root, name)
    if not text or not text.strip():
        return None
    lines = text.splitlines()
    code: list[str] = []
    chars = 0
    for raw in lines[:README_LINES]:
        line = _clean(raw).rstrip()
        if len(line) > README_LINE:
            line = line[:README_LINE] + " …"
        if chars + len(line) > README_CHARS:
            break
        chars += len(line) + 1
        code.append(line)
    while code and not code[-1].strip():
        code.pop()
    if not code:
        return None
    return {"file": name, "start": 1, "code": code, "total": len(lines)}


# --- what a monkeypatch replaces (0.11.0) -----------------------------------------------------

_STDLIB = ("socket", "ssl", "builtins", "http.client")


def origin(resolved: str) -> str:
    """Whose code a patched object is, in plain words, from its import path alone."""
    m = re.match(r"homeassistant\.components\.(\w+)", resolved)
    if m:
        return f"Home Assistant's built-in {m[1]} integration"
    if resolved == "HomeAssistant" or resolved.startswith("homeassistant"):
        return "Home Assistant's own code"
    if re.match(r"(self\.)?_?hass\.", resolved):
        return "the running Home Assistant"
    if any(resolved == x or resolved.startswith(x + ".") for x in _STDLIB):
        return "Python's standard library"
    if resolved.split(".")[0] in ("aiohttp", "ClientSession", "TCPConnector"):
        return "aiohttp, the network library Home Assistant uses"
    return f"the {resolved.split('.')[0]} network library"


def patch_fact(tree: _Tree, rel: str, line: int) -> dict[str, Any] | None:
    """For a `ha-monkeypatch` finding: what is replaced, whose it is, and with what. Read
    from the syntax tree the way analyzers.py_tamper resolves the object (imports, local
    shadowing); nothing is run. None when the line holds no such assignment."""
    return _patch(tree, rel, line)[0]


def _patch(
    tree: _Tree, rel: str, line: int
) -> tuple[dict[str, Any] | None, tuple[str, list[str], ast.AST] | None]:
    """(the patch fact, the replacement when the app defines it as a function: its file,
    that file's lines and the function's node)."""
    py = tree.py(rel)
    if py is None:
        return None, None
    hits = {ln: res for ln, res in py_tamper.check_tree(py.tree)}
    resolved = hits.get(line)
    if resolved is None:
        return None, None
    repl = None
    fact: dict[str, Any] = {"object": resolved[:200], "origin": origin(resolved)}
    for node in ast.walk(py.tree):
        if not isinstance(node, ast.Assign) or node.lineno != line:
            continue
        target = next(
            (t for t in node.targets if isinstance(t, ast.Attribute) and t.lineno == line), None
        )
        if target is None:
            continue
        fact["attr"] = target.attr[:100]
        if isinstance(node.value, ast.Name):
            fact["replacement"] = node.value.id[:100]
            hit = _resolve_def(tree, py, node.value.id)
            if hit is not None:
                fact["replacement_at"] = [hit[0].rel, _span(hit[1])[0]]
                if isinstance(hit[1], ast.FunctionDef | ast.AsyncFunctionDef):
                    repl = (hit[0].rel, hit[0].lines, hit[1])
        break
    return fact, repl


# --- where the app uses a dependency (0.7.4) --------------------------------------------------


def py_modules(package: str) -> set[str]:
    """Import names a PyPI distribution likely provides: python-jose -> jose, PyJWT -> jwt."""
    n = re.sub(r"[-.]+", "_", package.lower())
    out = {n}
    for prefix in ("python_", "py_", "py"):
        if n.startswith(prefix) and len(n) > len(prefix) + 1:
            out.add(n[len(prefix) :])
    for suffix in ("_python", "_py"):
        if n.endswith(suffix):
            out.add(n[: -len(suffix)])
    return out


def dependency_usage(tree: _Tree, package: str, ecosystem: str) -> dict[str, Any] | None:
    """The app's own lines that import the package and use what they import, or None."""
    if ecosystem == "PyPI":
        return _py_usage(tree, py_modules(package))
    if ecosystem == "npm":
        return _js_usage(tree, package)
    return None


def _enclosing_span(py: _Py, line: int) -> tuple[int, int]:
    best: tuple[int, int] | None = None
    for fn in py.funcs:
        a, b = _span(fn)
        if a <= line <= b and (best is None or b - a < best[1] - best[0]):
            best = (a, b)
    if best is None or best[1] - best[0] > 2 * FUNC_WINDOW:
        return max(1, line - DEP_RADIUS), min(len(py.lines), line + DEP_RADIUS)
    return best


def _py_usage(tree: _Tree, modules: set[str]) -> dict[str, Any] | None:
    spans: list[tuple[str, int, int]] = []
    uses = 0
    for rel in tree.py_files():
        py = tree.py(rel)
        if py is None:
            continue
        bound: set[str] = set()
        for node in ast.walk(py.tree):
            if isinstance(node, ast.Import):
                for al in node.names:
                    if al.name.split(".")[0] in modules:
                        bound.add(al.asname or al.name.split(".")[0])
                        spans.append((rel, node.lineno, node.end_lineno or node.lineno))
            elif (
                isinstance(node, ast.ImportFrom)
                and not node.level
                and node.module
                and node.module.split(".")[0] in modules
            ):
                bound |= {al.asname or al.name for al in node.names if al.name != "*"}
                spans.append((rel, node.lineno, node.end_lineno or node.lineno))
        if not bound:
            continue
        lines = sorted({n.lineno for n in ast.walk(py.tree)
                        if isinstance(n, ast.Name) and n.id in bound
                        and isinstance(n.ctx, ast.Load)})  # fmt: skip
        for line in lines:
            if uses >= MAX_USES:
                break
            a, b = _enclosing_span(py, line)
            spans.append((rel, a, b))
            uses += 1
    if not spans:
        return None
    spans = _fit(spans)
    return _finish(tree, spans[0][0], spans, "python")


def _js_files(tree: _Tree) -> list[str]:
    out: list[str] = []
    try:
        for p in sorted(tree.root.rglob("*")):
            rel = p.relative_to(tree.root)
            if any(part in _SKIP_DIRS for part in rel.parts[:-1]) or p.is_symlink():
                continue
            if p.suffix in _JS_EXT and not p.name.endswith((".min.js", ".d.ts")) and p.is_file():
                out.append(rel.as_posix())
                if len(out) >= MAX_JS_FILES:
                    break
    except OSError:
        pass
    return out


def _js_import(package: str) -> re.Pattern[str]:
    spec = re.escape(package) + r"(?:/[^'\"`]*)?"
    return re.compile(
        r"(?:import\s+(?P<what>[\w$*\s{},]+?)\s+from\s*|import\s*\(\s*|require\s*\(\s*)"
        rf"['\"`]{spec}['\"`]"
    )


def _js_bound(text: str, m: re.Match[str]) -> set[str]:
    """Local names an import binds: `x`, `{a as b}`, `* as ns`, `const {a: b} = require(…)`."""
    what = m.group("what")
    if what is None:  # require()/import(): look at what it's assigned to
        head = text[max(0, m.start() - 120) : m.start()]
        a = re.search(r"(?:const|let|var)\s+([\w$]+|\{[^}]*\})\s*=\s*(?:await\s+)?$", head)
        what = a.group(1) if a else ""
    names: set[str] = set()
    for part in re.split(r"[,{}]", what):
        part = part.strip()
        if not part:
            continue
        local = re.split(r"\s+as\s+|\s*:\s*", part)[-1].strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", local):
            names.add(local)
    return names


def _js_usage(tree: _Tree, package: str) -> dict[str, Any] | None:
    pattern = _js_import(package)
    spans: list[tuple[str, int, int]] = []
    found: dict[str, list[str]] = {}
    uses = 0
    for rel in _js_files(tree):
        text = tree.text(rel)
        if text is None or package not in text:
            continue
        lines = text.splitlines()
        if any(len(x) > LONG_LINE for x in lines[:50]):
            continue  # a bundle: names are gone; the source files are what we read
        hits = list(pattern.finditer(text))
        if not hits:
            continue
        found[rel] = lines
        bound: set[str] = set()
        for m in hits:
            n = text.count("\n", 0, m.start()) + 1
            spans.append((rel, n, n))
            bound |= _js_bound(text, m)
        imports = {text.count("\n", 0, m.start()) + 1 for m in hits}
        if bound:
            word = re.compile(
                r"(?<![\w$.])(?:" + "|".join(map(re.escape, sorted(bound))) + r")(?![\w$])"
            )
            for i, line in enumerate(lines, 1):
                if uses >= MAX_USES:
                    break
                if i not in imports and word.search(line):
                    spans.append((rel, max(1, i - DEP_RADIUS), min(len(lines), i + DEP_RADIUS)))
                    uses += 1
    if not spans:
        return None
    spans = _fit(spans)
    noncode = {
        f: ({n for n, x in enumerate(ls, 1) if x.strip().startswith(("//", "/*", "*"))}, {})
        for f, ls in found.items()
    }
    return _segments(spans[0][0], "text", spans, found, noncode)


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
    defs: dict[str, ast.AST] = field(default_factory=dict)  # module-level functions, classes
    consts: list[tuple[set[str], int, int]] = field(default_factory=list)  # module-level assigns
    import_spans: list[tuple[set[str], int, int]] = field(default_factory=list)  # every import


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
        py = _Py(rel, text.splitlines(), tree, funcs, noncode, cc, self._imports(rel, tree))
        for stmt in tree.body:
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                py.defs.setdefault(stmt.name, stmt)
            elif isinstance(stmt, ast.Assign | ast.AnnAssign):
                names = _assigned_names(stmt)
                if names:
                    py.consts.append((names, stmt.lineno, stmt.end_lineno or stmt.lineno))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                bound = {(a.asname or a.name).split(".")[0] for a in node.names if a.name != "*"}
                py.import_spans.append((bound, node.lineno, node.end_lineno or node.lineno))
        py.import_spans.sort(key=lambda s: s[1])
        return py

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

    def py_files(self, limit: int = MAX_PY_FILES) -> list[str]:
        out = []
        try:
            for p in sorted(self.root.rglob("*.py")):
                if not p.is_symlink() and p.is_file():
                    out.append(p.relative_to(self.root).as_posix())
                if len(out) >= limit:
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
    own = {id(p) for _py, p in primary}
    cut: set[tuple[str, int, int]] = set()
    # What the flagged statement itself names comes first, and is cut to fit, never left
    # out: a monkeypatch's replacement function, a callback handed to a registration.
    flagged = _statement_at(primary[0][1], line) if around else None
    if flagged is not None:
        for name in _loads(flagged):
            hit = _resolve_def(tree, py, name)
            if hit is not None and id(hit[1]) not in own and not _holds(hit[1], own):
                span = (hit[0].rel, *_span(hit[1]))
                spans.append(span)
                cut.add(span)
    for p_py, p in primary:
        for name in sorted(_called(p)):
            hit = _resolve(tree, p_py, name)
            if hit is not None and hit[1] is not p:
                spans.append((hit[0].rel, *_span(hit[1])))
    # Then what it refers to without calling: functions whole, classes by their first lines.
    for p_py, p in primary:
        for name in _loads(p):
            hit = _resolve_def(tree, p_py, name)
            if hit is None or id(hit[1]) in own or _holds(hit[1], own):
                continue
            a, b = _span(hit[1])
            if isinstance(hit[1], ast.ClassDef):
                b = min(b, a + CLASS_HEAD - 1)
            spans.append((hit[0].rel, a, b))
    kept = _budget(list(dict.fromkeys(spans)), frozenset(cut))
    # gap 3: the header's lines sit a blank line or two apart; one block reads better
    return _finish(tree, py.rel, _merge(kept + _header(tree, kept), gap=3), "python")


def _loads(node: ast.AST) -> list[str]:
    """Names a piece of code reads, in the order they appear."""
    found = sorted(
        (n.lineno, n.col_offset, n.id)
        for n in ast.walk(node)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    )
    return list(dict.fromkeys(name for _l, _c, name in found))


def _statement_at(func: ast.AST, line: int) -> ast.stmt | None:
    """The smallest statement inside `func` that covers `line`."""
    best: ast.stmt | None = None
    for n in ast.walk(func):
        if n is func or not isinstance(n, ast.stmt):
            continue
        a, b = n.lineno, n.end_lineno or n.lineno
        if a <= line <= b and (
            best is None or b - a < (best.end_lineno or best.lineno) - best.lineno
        ):
            best = n
    return best


def _holds(node: ast.AST, ids: set[int]) -> bool:
    return any(id(n) in ids for n in ast.walk(node))


def _resolve_def(tree: _Tree, py: _Py, name: str) -> tuple[_Py, ast.AST] | None:
    """A module-level function or class of the app a name refers to: defined in this
    file, or imported from a sibling module (relative imports only, like `_resolve`)."""
    node = py.defs.get(name)
    if node is not None:
        return py, node
    src = py.imports.get(name)
    if src is not None:
        other = tree.py(src[0])
        if other is not None and src[1] in other.defs:
            return other, other.defs[src[1]]
    return None


def _header(tree: _Tree, kept: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    """Import statements and module-level constants behind the names the kept code uses,
    so "where does `ReolinkVODMediaSource` come from?" is answered by the snippet. The
    first file's first; whole statements only, within HEADER_LINES."""
    rows: dict[str, set[int]] = {}
    for f, a, b in kept:
        rows.setdefault(f, set()).update(range(a, b + 1))
    imports: list[tuple[str, int, int]] = []
    consts: list[tuple[str, int, int]] = []
    for f, shown in rows.items():
        py = tree.py(f)
        if py is None:
            continue
        used = {n.id for n in ast.walk(py.tree) if isinstance(n, ast.Name) and n.lineno in shown}
        for names, a, b in py.import_spans:
            if names & used and not shown.issuperset(range(a, b + 1)):
                imports.append((f, a, b))
        for names, a, b in py.consts:
            if names & used and a not in shown:
                consts.append((f, a, min(b, a + CONST_LINES - 1)))
    out: list[tuple[str, int, int]] = []
    left = HEADER_LINES
    for f, a, b in imports + consts:
        if b - a + 1 <= left:
            out.append((f, a, b))
            left -= b - a + 1
    return out


MAX_SOURCES = 24  # module-level names followed per snippet


def _module_derived(py: _Py, names: set[str], keys: frozenset[str]) -> set[str]:
    """Module-level names assigned from `names` (`LOGIN = urljoin(BASE, "/login")`).

    A name reached only through an attribute (`DOMAIN = CURRENT_BRAND.domain`) counts
    only if the attribute is one of `keys`, the keywords on the flagged line (such as
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
    module-level names derived from it (`API_URL_BASE` is only used by
    `API_URL_LOGIN = urljoin(API_URL_BASE, …)`) and through relative imports,
    re-exports included (a `const/__init__.py` that re-exports a name from
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
    return _merge(_budget(spans))


def _budget(
    spans: list[tuple[str, int, int]],
    cut: frozenset[tuple[str, int, int]] = frozenset(),
    limit: int = MAX_LINES,
) -> list[tuple[str, int, int]]:
    """Spans in priority order while they fit `limit` lines. The first is always kept
    (cut to size); one in `cut` is shortened to the lines left when it doesn't fit."""
    kept: list[tuple[str, int, int]] = []
    used = 0
    for f, a, b in spans:
        n = b - a + 1
        if used + n > limit:
            left = limit - used
            if not kept:
                kept.append((f, a, a + limit - 1))
                used = limit
            elif (f, a, b) in cut and left >= MIN_CUT:
                kept.append((f, a, a + left - 1))
                used = limit
            continue
        kept.append((f, a, b))
        used += n
    return kept


def _merge(kept: list[tuple[str, int, int]], gap: int = 1) -> list[tuple[str, int, int]]:
    """Overlapping spans joined (and those up to `gap` - 1 lines apart); first file first."""
    first = kept[0][0] if kept else ""
    merged: list[tuple[str, int, int]] = []
    for f, a, b in sorted(kept, key=lambda s: (s[0] != first, s[0], s[1])):
        if merged and merged[-1][0] == f and a <= merged[-1][2] + gap:
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
    the formatter then reads strings as code (it turned "/api/some_domain/print_history"
    into " / api / some_domain / print_history "). Formatting only: jsbeautifier tokenizes
    text and runs nothing. A 209 KB line takes 0.2 s."""
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
    either end (`…tch("/api/some_domain/print_history",…`), so the marks are dropped and,
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
    max_chars: int = MAX_CHARS,
) -> dict[str, Any]:
    segments = []
    chars = 0
    for f, a, b in spans:
        code = []
        for n in range(a, min(b, len(lines[f])) + 1):
            text = _clean(lines[f][n - 1])
            if len(text) > LONG_LINE:
                text = text[:LONG_LINE] + " …"
            if chars + len(text) > max_chars:
                break
            chars += len(text) + 1
            code.append(text)
        if code:
            segments.append({"file": f, "start": a, "code": code})
        if chars >= max_chars:
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


# --- more code, from the stored source (0.11.0) -----------------------------------------------

MORE_LINES = 150  # lines added in the one follow-up round
MORE_CHARS = 12_000


def shown_rows(snip: dict[str, Any]) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for s in snip.get("segments", []):
        if "line" in s or "col" in s:
            continue  # a reformatted or cut long line: not file rows
        out.setdefault(s["file"], set()).update(range(s["start"], s["start"] + len(s["code"])))
    return out


def more(
    snip: dict[str, Any], files: dict[str, dict[str, Any]], spans: list[tuple[str, int, int]]
) -> dict[str, Any] | None:
    """The lines of `spans` the snippet doesn't have yet, as segments in the snippet's own
    format, read from the stored source (sources.capture: text, non-code lines and comment
    columns per file, all computed during the scan). Spans come in the order asked; each
    is cut to the lines left of MORE_LINES. Nothing is parsed here."""
    have = shown_rows(snip)
    lines: dict[str, list[str]] = {}
    noncode: dict[str, tuple[set[int], dict[int, int]]] = {}
    want: list[tuple[str, int, int]] = []
    left = MORE_LINES
    for f, a, b in spans:
        entry = files.get(f)
        if not isinstance(entry, dict) or not isinstance(entry.get("text"), str):
            continue
        if f not in lines:
            lines[f] = entry["text"].splitlines()
            cc = entry.get("comment_col") or {}
            noncode[f] = (
                {int(n) for n in entry.get("noncode") or []},
                {int(k): int(v) for k, v in cc.items()},
            )
        run: list[int] = []
        for n in [*range(max(1, a), min(b, len(lines[f])) + 1), 0]:
            if n and n not in have.get(f, set()) and left > 0:
                run.append(n)
                left -= 1
                have.setdefault(f, set()).add(n)
            elif run:
                want.append((f, run[0], run[-1]))
                run = []
    if not want:
        return None
    out = _segments(want[0][0], "python", _merge(want), lines, noncode, MORE_CHARS)
    return out if out["segments"] else None


def merged(snip: dict[str, Any], extra: dict[str, Any] | None) -> dict[str, Any]:
    """The snippet plus the added segments: what the second request sends and what its
    answer's citations are checked against. The stored snippet itself is never changed."""
    if not extra:
        return snip
    noncode = {f: list(v) for f, v in (snip.get("noncode") or {}).items()}
    cols = {f: dict(v) for f, v in (snip.get("comment_col") or {}).items()}
    for f, v in (extra.get("noncode") or {}).items():
        noncode[f] = sorted({*noncode.get(f, []), *v})
    for f, v in (extra.get("comment_col") or {}).items():
        cols[f] = {**cols.get(f, {}), **v}
    return {
        **snip,
        "segments": [*snip.get("segments", []), *extra.get("segments", [])],
        "noncode": noncode,
        "comment_col": cols,
    }
