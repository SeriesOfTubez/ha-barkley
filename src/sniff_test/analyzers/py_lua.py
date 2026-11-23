"""(0.15, his decision 2026-11-23) An integration that runs Lua code through `lupa`, the
Python package that embeds a Lua interpreter: where that Lua comes from and what it can
reach.

What lupa does out of the box (read in lupa 2.8's own source, `_lupa.pyx`): `LuaRuntime()`
opens every Lua standard library (`luaL_openlibs`, so `os.execute` and `io.popen` run
programs) and, with `register_eval=True` and `register_builtins=True` as the defaults, gives
the Lua `python.eval` and `python.builtins`. Its README: "Any Lupa deployment that allows
untrusted Lua code to be executed should disable the access to Python's builtin
functions". Even with both switched off, an object handed to Lua leads back to Python's
classes unless an `attribute_filter` (or `attribute_handlers`) guards attribute access.

For every runtime the app makes, Barkley notes whether Python is still within reach (both
switches off and a filter set: not), and whether the app's own Lua text removes `os` and
`io`. For every piece of Lua it runs (`execute`, `eval`, `compile`, and `dofile`,
`loadfile`, `require` inside that text or through `globals()`), where it comes from:

- **downloaded**: the path given to `dofile` leads back (py_flow.Tracer.source) to a file
  the app writes with what a web request answered, or the code is a web answer itself;
- **shipped**: a `.lua` file of that name is in the release;
- **packed**: the app packs Lua in its code (analyzers/packed) and names that file;
- **in its code**: Lua text written in its Python;
- **unknown**: a file it picks while it runs that Barkley couldn't follow.

Only Lua it downloads counts (his decision: like a card's code loaded from another site,
Exposure 5 when the version is decided while it runs; `py-lua-download`), unless the app
closes both ways out. Everything else is a fact under "Code it gets while it runs".
Parse only: nothing is imported or run, and the Lua text is only searched.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sniff_test.analyzers import packed, py_flow
from sniff_test.models import Category, Finding, Severity

NAME = "lua"
RULE = "py-lua-download"
VERSION = 1

DOWNLOADED, SHIPPED, PACKED, IN_CODE, UNKNOWN = (
    "downloaded", "shipped", "packed", "in-code", "unknown")  # fmt: skip
SOURCES = (DOWNLOADED, SHIPPED, PACKED, IN_CODE, UNKNOWN)

_MAX_FILES = 3000
_MAX_PY = 2_000_000  # bytes of one Python file
_MAX_TEXT = 100_000  # characters of one piece of Lua text searched
_MAX_RUNS = 20
_MAX_LUA_FILES = 2000
_NAME_MAX = 80
# lupa's LuaRuntime(encoding, source_encoding, attribute_filter, attribute_handlers,
# register_eval, unpack_returned_tuples, register_builtins, …)
_POSITION = {"attribute_filter": 2, "attribute_handlers": 3, "register_eval": 4,
             "register_builtins": 6}  # fmt: skip
_RUNS = frozenset({"execute", "eval", "compile"})
_LOADS = frozenset({"dofile", "loadfile", "require"})
_HOLE = "\x00"  # stands for an f-string's {value} in the Lua text
# `dofile("x.lua")`, `loadfile "x"`, `dofile(<hole 3>)`: bounded pieces, linear
_FILE_LOAD = re.compile(
    r"\b(?:dofile|loadfile)\s{0,20}\(?\s{0,20}(?:\[\[|[\"'])?"
    r"(\x00(\d{1,4})\x00|[^\"'\]\)\s\x00]{1,200})"
)
_REQUIRE = re.compile(r"\brequire\s{0,20}\(?\s{0,20}[\"']([A-Za-z0-9_.\-]{1,80})[\"']")
_OS_OFF = re.compile(r"(?:^|[^\w.])os\s{0,20}=\s{0,20}nil\b")
_IO_OFF = re.compile(r"(?:^|[^\w.])io\s{0,20}=\s{0,20}nil\b")
_PLAIN = re.compile(r"^[A-Za-z0-9_.\-/]{1,200}$")


@dataclass
class Runtime:
    file: str
    line: int
    python: str  # "open" | "closed" | "unknown" (options Barkley couldn't read)
    system: str = "open"  # "closed" when the app's Lua sets os and io to nil
    defaults: bool = False  # made with no options at all: lupa's out-of-the-box settings

    def as_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "python": self.python,
                "system": self.system, "defaults": self.defaults}  # fmt: skip


@dataclass
class Run:
    file: str
    line: int
    source: str
    name: str = ""  # the Lua file or module, when the code names it (plain-checked)
    origins: list[dict[str, str]] = field(default_factory=list)  # where the download is from
    at: list[str] = field(default_factory=list)  # "file:line" of the downloading request

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"file": self.file, "line": self.line, "source": self.source}
        if self.name:
            d["name"] = self.name
        if self.origins:
            d["from"] = self.origins
        if self.at:
            d["at"] = self.at
        return d


@dataclass
class Result:
    runtimes: list[Runtime] = field(default_factory=list)
    runs: list[Run] = field(default_factory=list)

    def section(self) -> dict[str, Any] | None:
        if not self.runtimes and not self.runs:
            return None
        return {"version": VERSION,
                "runtimes": [r.as_dict() for r in self.runtimes[:_MAX_RUNS]],
                "runs": [r.as_dict() for r in self.runs[:_MAX_RUNS]]}  # fmt: skip

    def open_ways(self) -> bool:
        """Whether the Lua can reach Python or run programs: lupa's defaults, unless every
        runtime the app makes closes both."""
        if not self.runtimes:
            return True
        return any(r.python != "closed" or r.system != "closed" for r in self.runtimes)


def _plain(text: str) -> str:
    t = text.strip()[:_NAME_MAX]
    return t if _PLAIN.match(t) else ""


def _const(x: ast.expr | None) -> object:
    return x.value if isinstance(x, ast.Constant) else ...


@dataclass
class _File:
    rel: str
    tree: ast.Module
    mods: set[str] = field(default_factory=set)  # names bound to lupa or one of its modules
    classes: set[str] = field(default_factory=set)  # names bound to LuaRuntime
    names: set[str] = field(default_factory=set)  # locals holding a runtime
    attrs: set[str] = field(default_factory=set)  # self.<attr> holding a runtime


def _imports(f: _File) -> None:
    for node in ast.walk(f.tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "lupa" or a.name.startswith("lupa."):
                    f.mods.add(a.asname or "lupa")
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            mod = node.module or ""
            if mod == "lupa" or mod.startswith("lupa."):
                for a in node.names:
                    (f.classes if a.name == "LuaRuntime" else f.mods).add(a.asname or a.name)


def _is_runtime(f: _File, x: ast.expr) -> bool:
    if not isinstance(x, ast.Call):
        return False
    fn = x.func
    if isinstance(fn, ast.Name):
        return fn.id in f.classes
    if isinstance(fn, ast.Attribute) and fn.attr == "LuaRuntime":
        head = fn.value
        while isinstance(head, ast.Attribute):
            head = head.value
        return isinstance(head, ast.Name) and head.id in f.mods
    return False


def _python(call: ast.Call) -> str:
    """Whether a LuaRuntime(…) call leaves Python within the Lua's reach."""
    if any(k.arg is None for k in call.keywords) or any(
        isinstance(a, ast.Starred) for a in call.args
    ):
        return "unknown"  # **options or *args: Barkley can't read them

    def opt(name: str) -> ast.expr | None:
        for k in call.keywords:
            if k.arg == name:
                return k.value
        i = _POSITION[name]
        return call.args[i] if len(call.args) > i else None

    off = all(_const(opt(n)) is False for n in ("register_eval", "register_builtins"))
    guarded = any(
        (v := opt(n)) is not None and _const(v) is not None
        for n in ("attribute_filter", "attribute_handlers")
    )
    return "closed" if off and guarded else "open"


class _Walk(ast.NodeVisitor):
    """Each call with the function and class it sits in."""

    def __init__(self) -> None:
        self.fn: ast.AST | None = None
        self.cls: ast.ClassDef | None = None
        self.calls: list[tuple[ast.Call, ast.AST | None, ast.ClassDef | None]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        cls, fn = self.cls, self.fn
        self.cls, self.fn = node, None
        self.generic_visit(node)
        self.cls, self.fn = cls, fn

    def _func(self, node: ast.AST) -> None:
        fn = self.fn
        self.fn = node
        self.generic_visit(node)
        self.fn = fn

    visit_FunctionDef = _func
    visit_AsyncFunctionDef = _func

    def visit_Call(self, node: ast.Call) -> None:
        if len(self.calls) < 20000:
            self.calls.append((node, self.fn, self.cls))
        self.generic_visit(node)


def _holds_runtime(f: _File, recv: ast.expr) -> bool:
    if _is_runtime(f, recv):
        return True
    if isinstance(recv, ast.Name):
        return recv.id in f.names
    if isinstance(recv, ast.Attribute) and isinstance(recv.value, ast.Name):
        return recv.value.id in ("self", "cls") and recv.attr in f.attrs
    return False


def _text(x: ast.expr) -> tuple[str, list[ast.expr]] | None:
    """Lua text written in the code: a string, or an f-string with each {value} as a
    numbered hole."""
    if isinstance(x, ast.Constant) and isinstance(x.value, str):
        return x.value[:_MAX_TEXT], []
    if isinstance(x, ast.JoinedStr):
        parts, holes = [], []
        for v in x.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value.replace(_HOLE, ""))
            elif isinstance(v, ast.FormattedValue):
                parts.append(f"{_HOLE}{len(holes)}{_HOLE}")
                holes.append(v.value)
        return "".join(parts)[:_MAX_TEXT], holes
    return None


def _read_path(x: ast.expr) -> ast.expr | None:
    """The path of `open(p).read()`, `Path(p).read_text()`, `p.read_text()`."""
    if not (isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute)):
        return None
    recv, attr = x.func.value, x.func.attr
    if attr == "read" and isinstance(recv, ast.Call) and py_flow._call_name(recv) == "open":
        return recv.args[0] if recv.args else None
    if attr in ("read_text", "read_bytes"):
        if isinstance(recv, ast.Call) and py_flow._call_name(recv) == "Path" and recv.args:
            return recv.args[0]
        return recv
    return None


class _Reader:
    def __init__(self, root: Path, packed_lua: int):
        from sniff_test.analyzers import py_requests

        self.root = root
        self.packed_lua = packed_lua
        self.reader = py_requests.Reader(root)
        self.tracer = py_flow.Tracer(self.reader)
        self._lua_names: set[str] | None = None
        self._py_text: list[str] | None = None

    def lua_names(self) -> set[str]:
        """Names of the .lua files in the release."""
        if self._lua_names is None:
            self._lua_names = set()
            for n, p in enumerate(sorted(self.root.rglob("*.lua"))):
                if n >= _MAX_LUA_FILES:
                    break
                if packed.FOLDER not in p.parts:
                    self._lua_names.add(p.name.lower())
        return self._lua_names

    def named_in_code(self, base: str) -> bool:
        """Whether the app's Python spells out this file name (where it writes packed Lua)."""
        if self._py_text is None:
            self._py_text = []
            for n, p in enumerate(sorted(self.root.rglob("*.py"))):
                if n >= _MAX_FILES:
                    break
                try:
                    if p.is_symlink() or p.stat().st_size > _MAX_PY:
                        continue
                    self._py_text.append(p.read_text("utf-8", "replace"))
                except OSError:
                    continue
        # "cjson.lua", 'cjson.lua' or a path ending in it ("/lua/cjson.lua")
        rx = re.compile(r"[\"'/\\]" + re.escape(base) + r"[\"']")
        return any(rx.search(t) for t in self._py_text)

    def by_name(self, run: Run, base: str) -> Run:
        base = base.lower()
        if base in self.lua_names():
            run.source = SHIPPED
        elif self.packed_lua and self.named_in_code(base):
            run.source = PACKED
        return run

    def path(self, run: Run, x: ast.expr, sc: Any) -> Run:
        """Where the file at path `x` comes from."""
        if isinstance(x, ast.Constant) and isinstance(x.value, str):
            run.name = _plain(Path(x.value).name)
            return self.by_name(run, Path(x.value).name)
        origins, downloads = self.tracer.source(x, sc)
        if origins and all(o.kind == py_flow.DOWNLOADED for o in origins):
            run.source = DOWNLOADED
            self.where(run, downloads)
        return run

    def where(self, run: Run, downloads: list[tuple[ast.Call, Any]]) -> None:
        seen: set[tuple[str, ...]] = set()
        for call, sc in downloads[:6]:
            run.at.append(f"{sc.rel}:{call.lineno}")
            url = call.args[0] if call.args else next(
                (k.value for k in call.keywords if k.arg == "url"), None)  # fmt: skip
            for o in self.tracer.address(url, sc):
                d = o.as_dict()
                key = tuple(sorted(d.items()))
                if key not in seen and len(run.origins) < 6:
                    seen.add(key)
                    run.origins.append(d)
        run.at = sorted(set(run.at))[:6]

    def code(self, f: _File, call: ast.Call, arg: ast.expr, sc: Any) -> list[Run]:
        """The pieces of Lua one execute/eval/compile call runs."""
        here = (f.rel, call.lineno)
        value = arg
        fn = sc.func
        if isinstance(arg, ast.Name) and fn is not None:
            vals = self.tracer._local_values(fn).get(arg.id) or []
            if len(vals) == 1:
                value = vals[0]
        got = _text(value)
        if got is None:
            req = self.tracer._from_web(value, fn) if fn is not None else None
            if req is not None:  # the code is a web answer itself
                run = Run(*here, DOWNLOADED)
                self.where(run, [(req, sc)])
                return [run]
            p = _read_path(value)
            if p is not None:
                return [self.path(Run(*here, UNKNOWN), p, sc)]
            return [Run(*here, UNKNOWN)]
        text, holes = got
        out: list[Run] = []
        for m in _FILE_LOAD.finditer(text):
            run = Run(*here, UNKNOWN)
            if m[2] is not None:
                i = int(m[2])
                if i < len(holes):
                    out.append(self.path(run, holes[i], sc))
                else:
                    out.append(run)
            else:
                run.name = _plain(Path(m[1]).name)
                out.append(self.by_name(run, Path(m[1]).name))
        for m in _REQUIRE.finditer(text):
            base = m[1].replace(".", "/").rsplit("/", 1)[-1] + ".lua"
            run = Run(*here, UNKNOWN, name=_plain(m[1]))
            out.append(self.by_name(run, base))
        if not out and text.strip() and _HOLE not in text:
            out.append(Run(*here, IN_CODE))
        return out


def read(root: Path, packed_lua: int = 0) -> Result:
    """The Lua runtimes an integration makes and the Lua they run (see the module text).
    `packed_lua`: Lua pieces analyzers/packed unpacked from its code."""
    from sniff_test.analyzers import py_requests

    out = Result()
    files: list[_File] = []
    for n, p in enumerate(sorted(root.rglob("*.py"))):
        if n >= _MAX_FILES:
            break
        rel = p.relative_to(root).as_posix()
        if py_flow._TEST_FILE.search(rel) or packed.FOLDER in p.parts:
            continue
        try:
            if p.is_symlink() or p.stat().st_size > _MAX_PY:
                continue
            if "lupa" not in p.read_text("utf-8", "replace"):
                continue
        except OSError:
            continue
        files.append(_File(rel, ast.Module(body=[], type_ignores=[])))
    if not files:
        return out
    rd = _Reader(root, packed_lua)
    for f in files:
        tree = rd.reader.module(f.rel).tree
        if tree is None:
            continue
        f.tree = tree
        _imports(f)
        if not (f.mods or f.classes):
            continue
        walk = _Walk()
        try:
            walk.visit(tree)
        except RecursionError:
            continue
        here: list[Runtime] = []
        for node in ast.walk(tree):  # what holds a runtime: `rt = LuaRuntime()`, self.rt
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                if not _is_runtime(f, node.value):
                    continue
                ts = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in ts:
                    if isinstance(t, ast.Name):
                        f.names.add(t.id)
                    elif isinstance(t, ast.Attribute):
                        f.attrs.add(t.attr)
        for call, _fn, _cls in walk.calls:
            if _is_runtime(f, call):
                bare = not call.args and not call.keywords
                here.append(Runtime(f.rel, call.lineno, _python(call), defaults=bare))
        lua_texts: list[str] = []
        for call, fn, cls in walk.calls:
            func = call.func
            if not (isinstance(func, ast.Attribute) and call.args):
                continue
            sc = py_requests._Scope(f.rel, fn, cls)
            recv = func.value
            if func.attr in _RUNS and _holds_runtime(f, recv):
                got = _text(call.args[0])
                if got is not None:
                    lua_texts.append(got[0])
                if len(out.runs) < _MAX_RUNS:
                    out.runs += rd.code(f, call, call.args[0], sc)
            elif (
                func.attr in _LOADS
                and isinstance(recv, ast.Call)
                and isinstance(recv.func, ast.Attribute)
                and recv.func.attr == "globals"
                and _holds_runtime(f, recv.func.value)
                and len(out.runs) < _MAX_RUNS
            ):  # rt.globals().dofile(path), rt.globals().require("name")
                run = Run(f.rel, call.lineno, UNKNOWN)
                if func.attr == "require":
                    name = _const(call.args[0])
                    if isinstance(name, str):
                        run.name = _plain(name)
                        rd.by_name(run, name.replace(".", "/").rsplit("/", 1)[-1] + ".lua")
                    out.runs.append(run)
                else:
                    out.runs.append(rd.path(run, call.args[0], sc))
        closed = any(_OS_OFF.search(t) for t in lua_texts) and any(
            _IO_OFF.search(t) for t in lua_texts
        )
        for r in here:
            r.system = "closed" if closed else "open"
        out.runtimes += here
    out.runs = out.runs[:_MAX_RUNS]
    return out


def ways_words(res: Result | dict[str, Any]) -> str:
    """ "can use Python and run programs" (or one of them) for the runtimes found; from a
    Result or a stored `lua` section."""
    rts = res.runtimes if isinstance(res, Result) else [
        Runtime("", 0, str(r.get("python")), str(r.get("system")))
        for r in res.get("runtimes") or [] if isinstance(r, dict)
    ]  # fmt: skip
    py = not rts or any(r.python != "closed" for r in rts)
    system = not rts or any(r.system != "closed" for r in rts)
    if py and system:
        return "can use Python and run programs"
    return "can use Python" if py else "can run programs"


def findings(res: Result) -> list[Finding]:
    """One `py-lua-download` per place that runs Lua it downloads, unless every runtime
    closes both ways out (then it stays a fact)."""
    if not res.open_ways():
        return []
    can = ways_words(res)
    out: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for r in res.runs:
        if r.source != DOWNLOADED or (r.file, r.line) in seen:
            continue
        seen.add((r.file, r.line))
        out.append(Finding(
            rule_id=RULE,
            title="Runs Lua code it downloads",
            severity=Severity.MEDIUM,
            category=Category.CODE_EXEC,
            message=("While it runs, the app downloads Lua code and runs it with the lupa "
                     f"package. Its Lua runner {can}, so that code can do anything the app "
                     "can. Barkley never sees that code."),
            file=r.file,
            line=r.line,
            analyzer=NAME,
        ))  # fmt: skip
    return out
