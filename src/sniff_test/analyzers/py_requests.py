"""(0.15, his yes 2026-11-20) How the app's Python sends web requests: the method of each
call, the site when the code spells it out, and what the call puts into the body, the
headers and the address.

A fact about the code, never scored and never a reason to call anything safe: a GET
carries data too (in the address, the query or a header), so the method alone says
nothing about what leaves.

What counts as a request: a call named get/post/put/patch/delete/head/options or
`request(method, url)` (aiohttp, requests, httpx and Home Assistant's shared sessions all
look like this), and `urlopen`. The address is followed through string constants: module
and class constants (also `from .const import X`), a local name assigned once, an
attribute the class sets once (`self._base = BASE_URL`), f-strings, `+`, `%s`,
`.format()`, `urljoin` and yarl's `/`. Whatever can't be followed (a parameter, a
setting) is kept as its name, so `f"{BASE}/users/{user_id}"` gives the site and
"user_id goes into the address".

- A request whose address starts with a site in the code is listed under that site.
- One whose address is built while the app runs (the usual case for a device on your
  network or a server you entered at setup) is counted apart, and only when the call
  looks like a web request (`_SESSION` below), so a dictionary's `.get()` isn't one.

Names of body fields, headers and query fields are read from a dict literal at the call
(or a local name assigned one); they are text from the scanned code: capped here, escaped
where shown. Values are never recorded.

Parse only: `ast.parse` of the app's files; nothing is imported or run.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VERSION = 1
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
_CALLS = {m.lower(): m for m in METHODS}
_MAX_FILE = 5 * 1024 * 1024
_MAX_FILES = 3000
_MAX_NAMES = 12  # names kept per part of one request
_NAME_MAX = 60
_MAX_SHAPES = 20  # distinct request shapes kept per site
_MAX_SITES = 200
_MAX_AT = 3
_DEPTH = 8
_URL_MAX = 2000
_BUDGET = 4000  # steps the reader may take to follow one address
_MAX_TERMS = 500  # terms of one `a + b + …` chain
_GAP = "\x00"  # stands for a piece the code fills in while it runs

_HOST = re.compile(r"^(https?)://([A-Za-z0-9.\-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])(?::(\d{1,5}))?")
_PLAIN = re.compile(r"^[A-Za-z0-9_.\-\[\] ]{1,60}$")
# what a web request is called on, when the address isn't in the code
_SESSION = re.compile(r"(?i)sess|client|requests$|httpx$|aiohttp$|^http$|_http$|websession")
_REQ_KW = frozenset(
    {"json", "data", "params", "headers", "timeout", "ssl", "verify", "allow_redirects", "auth"}
)
_URLISH = re.compile(r"(?i)url|uri|endpoint|href")
_BODY_KW = ("json", "data", "content", "files")
_STRIP = frozenset({"rstrip", "lstrip", "strip", "removesuffix", "removeprefix", "lower"})


@dataclass(frozen=True)
class Request:
    host: str | None  # None: the address is built while the app runs
    method: str  # one of METHODS, or "" when the code picks it while running
    file: str
    line: int
    # each: None = not sent; a tuple of field names (empty: sent, names not in the call)
    body: tuple[str, ...] | None = None
    headers: tuple[str, ...] | None = None
    query: tuple[str, ...] | None = None
    address: tuple[str, ...] = ()  # names the code puts into the address after the site
    auth: bool = False  # an `auth=` argument (a login for the site)
    more: bool = False  # `**kwargs`: the caller can add a body, headers or anything else
    scheme: str = ""
    port: int | None = None

    @property
    def shape(self) -> tuple:
        return (
            self.method,
            self.body,
            self.headers,
            self.query,
            self.address,
            self.auth,
            self.more,
        )


Piece = str | tuple[str]  # text, or (name,) for a piece filled in while running


def _label(node: ast.AST) -> str:
    """A short name for an expression that can't be followed: `user_id`, `self.token`."""
    try:
        text = ast.unparse(node)
    except (ValueError, RecursionError, AttributeError):
        return ""
    text = text.removeprefix("self.").removeprefix("cls.")
    text = text[:-2] if text.endswith("()") else text
    return text if _PLAIN.match(text) else ""


@dataclass
class _Module:
    assigns: dict[str, ast.expr] = field(default_factory=dict)
    imports: dict[str, tuple[str, str]] = field(default_factory=dict)
    tree: ast.Module | None = None


class _Scope:
    """What a name means where a call stands: the function's own single assignments, the
    class's constants and single `self.x = …` assignments, then the module."""

    def __init__(self, rel: str, func: ast.AST | None, cls: ast.ClassDef | None):
        self.rel, self.func, self.cls = rel, func, cls
        self._locals: dict[str, ast.expr | None] | None = None
        self._attrs: dict[str, ast.expr | None] | None = None

    def local(self, name: str) -> ast.expr | None:
        if self._locals is None:
            self._locals = _single_assigns(self.func, attr=False) if self.func else {}
        return self._locals.get(name)

    def attr(self, name: str) -> ast.expr | None:
        if self._attrs is None:
            self._attrs = _single_assigns(self.cls, attr=True) if self.cls else {}
            if self.cls is not None:
                for node in self.cls.body:  # class-level constants
                    if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                        ts = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for t in ts:
                            if isinstance(t, ast.Name) and t.id not in self._attrs:
                                self._attrs[t.id] = node.value
        return self._attrs.get(name)


def _single_assigns(scope: ast.AST, attr: bool) -> dict[str, ast.expr | None]:
    """name -> its value, for names assigned exactly once in `scope` (None: more than once,
    so it isn't followed). attr: `self.x = …` inside a class; else plain local names."""
    out: dict[str, ast.expr | None] = {}
    for node in ast.walk(scope):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
        elif isinstance(node, (ast.AugAssign, ast.NamedExpr, ast.For, ast.AsyncFor)):
            targets, value = [node.target], None
        else:
            continue
        for t in targets:
            for sub in ast.walk(t) if isinstance(t, (ast.Tuple, ast.List)) else [t]:
                if attr:
                    ok = (isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name)
                          and sub.value.id in ("self", "cls"))  # fmt: skip
                    name = sub.attr if ok else None
                else:
                    name = sub.id if isinstance(sub, ast.Name) else None
                if name is None:
                    continue
                whole = sub is t and value is not None
                out[name] = value if whole and name not in out else None
    return out


class Reader:
    def __init__(self, root: Path):
        self.root = root
        self._mods: dict[str, _Module] = {}
        self._left = _BUDGET

    def module(self, rel: str) -> _Module:
        if rel in self._mods:
            return self._mods[rel]
        mod = self._mods[rel] = _Module()  # a cycle sees an empty module
        p = self.root / rel
        try:
            if p.is_symlink() or not p.is_file() or p.stat().st_size > _MAX_FILE:
                return mod
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError, ValueError, RecursionError, MemoryError):
            return mod
        mod.tree = tree
        here = Path(rel).parent
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        mod.assigns[t.id] = node.value
            elif isinstance(node, ast.ImportFrom) and node.level >= 1:
                base = here
                for _ in range(node.level - 1):
                    base = base.parent
                for a in node.names:
                    if node.module:
                        target = (base / (node.module.replace(".", "/") + ".py")).as_posix()
                        pkg = (base / node.module.replace(".", "/") / "__init__.py").as_posix()
                        if not (self.root / target).is_file() and (self.root / pkg).is_file():
                            target = pkg
                    else:  # `from . import const`: a module, not a value
                        continue
                    mod.imports[a.asname or a.name] = (target, a.name)
        return mod

    # --- the address ------------------------------------------------------------------

    def address(self, expr: ast.expr | None, sc: _Scope) -> list[Piece]:
        """`pieces` with a fresh budget: one request can't make the reader do more than
        _BUDGET steps, however the code's names refer to each other."""
        self._left = _BUDGET
        return self.pieces(expr, sc)

    def pieces(self, expr: ast.expr | None, sc: _Scope, depth: int = 0) -> list[Piece]:
        """The string an expression makes, as text and gaps. Never raises."""
        if expr is None:
            return [("",)]
        self._left -= 1
        if depth > _DEPTH or self._left < 0:
            return [(_label(expr),)]
        d = depth + 1
        if isinstance(expr, ast.Constant):
            if isinstance(expr.value, str):
                return [expr.value[:_URL_MAX]]
            if isinstance(expr.value, (int, float)) and not isinstance(expr.value, bool):
                return [str(expr.value)]
            return [("",)]
        if isinstance(expr, ast.Name):
            mod = self.module(sc.rel)
            value = sc.local(expr.id)
            if value is not None and not _mentions(value, expr.id):
                return self.pieces(value, sc, d)
            if sc.func is not None and expr.id in (sc._locals or {}):
                return [(expr.id,)]  # assigned more than once here
            if expr.id in mod.assigns and not _is_param(sc.func, expr.id):
                return self.pieces(mod.assigns[expr.id], _Scope(sc.rel, None, None), d)
            if expr.id in mod.imports and not _is_param(sc.func, expr.id):
                target, name = mod.imports[expr.id]
                other = self.module(target)
                if name in other.assigns:
                    return self.pieces(other.assigns[name], _Scope(target, None, None), d)
                if name in other.imports:
                    return self.pieces(ast.Name(id=name, ctx=ast.Load()),
                                       _Scope(target, None, None), d)  # fmt: skip
            return [(expr.id,)]
        if isinstance(expr, ast.Attribute):
            if isinstance(expr.value, ast.Name) and expr.value.id in ("self", "cls"):
                value = sc.attr(expr.attr)
                if value is not None:
                    return self.pieces(value, _Scope(sc.rel, _owner(sc.cls, value), sc.cls), d)
            elif isinstance(expr.value, ast.Name):  # `const.BASE_URL` after `from . import const`
                got = self._module_attr(sc.rel, expr.value.id, expr.attr, d)
                if got is not None:
                    return got
            return [(_label(expr),)]
        if isinstance(expr, ast.JoinedStr):
            out: list[Piece] = []
            for v in expr.values:
                if isinstance(v, ast.FormattedValue):
                    out += self.pieces(v.value, sc, d)
                else:
                    out += self.pieces(v, sc, d)
            return out
        if isinstance(expr, ast.BinOp):
            if isinstance(expr.op, ast.Add):
                terms: list[ast.expr] = []  # a + b + c + …: one level, however long
                node: ast.expr = expr
                while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    terms.append(node.right)
                    node = node.left
                    if len(terms) > _MAX_TERMS:
                        return [(_label(expr),)]
                out_add: list[Piece] = []
                for term in [node, *reversed(terms)]:
                    out_add += self.pieces(term, sc, d)
                return out_add
            if isinstance(expr.op, ast.Div):  # yarl: URL(base) / "path"
                return [*self.pieces(expr.left, sc, d), "/", *self.pieces(expr.right, sc, d)]
            if isinstance(expr.op, ast.Mod):
                left = self.pieces(expr.left, sc, d)
                if len(left) == 1 and isinstance(left[0], str):
                    args = expr.right.elts if isinstance(expr.right, ast.Tuple) else [expr.right]
                    return self._fill(re.split(r"%[sdr]", left[0]), list(args), {}, sc, d)
            return [(_label(expr),)]
        if isinstance(expr, ast.Call):
            f = expr.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if isinstance(f, ast.Attribute) and name == "format":
                base = self.pieces(f.value, sc, d)
                if len(base) == 1 and isinstance(base[0], str):
                    kw = {k.arg: k.value for k in expr.keywords if k.arg}
                    return self._format(base[0], list(expr.args), kw, sc, d)
            elif isinstance(f, ast.Attribute) and name in _STRIP:
                return self.pieces(f.value, sc, d)
            elif name in ("str", "URL") and len(expr.args) == 1 and not expr.keywords:
                return self.pieces(expr.args[0], sc, d)
            elif name == "urljoin" and len(expr.args) == 2:
                return self.pieces(expr.args[0], sc, d) + self.pieces(expr.args[1], sc, d)
            return [(_label(expr),)]
        return [(_label(expr),)]

    def _module_attr(self, rel: str, mod_name: str, attr: str, depth: int) -> list[Piece] | None:
        tree = self.module(rel).tree
        if tree is None:
            return None
        here = Path(rel).parent
        for node in tree.body:
            if not isinstance(node, ast.ImportFrom) or node.level < 1:
                continue
            base = here
            for _ in range(node.level - 1):
                base = base.parent
            for a in node.names:
                if (a.asname or a.name) != mod_name:
                    continue
                stem = base / node.module.replace(".", "/") if node.module else base
                target = (stem / (a.name + ".py")).as_posix()
                other = self.module(target)
                if attr in other.assigns:
                    return self.pieces(other.assigns[attr], _Scope(target, None, None), depth)
        return None

    def _fill(
        self,
        texts: list[str],
        args: list[ast.expr],
        kw: dict[str, ast.expr],
        sc: _Scope,
        depth: int,
    ) -> list[Piece]:
        out: list[Piece] = []
        for i, text in enumerate(texts):
            out.append(text)
            if i < len(texts) - 1:
                out += self.pieces(args[i], sc, depth) if i < len(args) else [("",)]
        return out

    def _format(
        self, text: str, args: list[ast.expr], kw: dict[str, ast.expr], sc: _Scope, depth: int
    ) -> list[Piece]:
        out: list[Piece] = []
        auto = 0
        # split on {…} fields; `{{` and `}}` are rare in addresses and left as they are
        for i, part in enumerate(re.split(r"\{([A-Za-z0-9_]{0,40})\}", text)):
            if i % 2 == 0:
                out.append(part)
                continue
            if part == "" or part.isdigit():
                idx = int(part) if part else auto
                auto += part == ""
                out += self.pieces(args[idx], sc, depth) if idx < len(args) else [("",)]
            else:
                out += self.pieces(kw[part], sc, depth) if part in kw else [(part,)]
        return out


def _mentions(value: ast.expr, name: str) -> bool:
    """`url = url + "/x"`: a name defined from itself can't be followed."""
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(value))


def _is_param(func: ast.AST | None, name: str) -> bool:
    if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return False
    a = func.args
    every = [*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg]
    return any(x is not None and x.arg == name for x in every)


def _owner(cls: ast.ClassDef | None, value: ast.expr) -> ast.AST | None:
    """The method of `cls` that holds `value` (so its locals and parameters apply)."""
    if cls is None:
        return None
    for node in cls.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for sub in ast.walk(node):
                if sub is value:
                    return node
    return None


def _site(pieces: list[Piece]) -> tuple[str | None, str, int | None, tuple[str, ...]]:
    """(host, scheme, port, names put into the address after the site). host None: the
    address doesn't start with a site the code spells out."""
    text = "".join(p if isinstance(p, str) else _GAP for p in pieces)[:_URL_MAX].strip()
    m = _HOST.match(text)
    names: list[str] = []
    if not m or text[m.end() : m.end() + 1] not in ("", "/", "?", "#"):
        return None, "", None, ()
    host = m[2].lower().rstrip(".")
    if not host or host.startswith((".", "-")) or ".." in host:
        return None, "", None, ()
    seen = 0
    for p in pieces:
        if isinstance(p, str):
            seen += len(p)
        else:
            seen += 1
            if seen > m.end() and p[0] and p[0] not in names:
                names.append(p[0][:_NAME_MAX])
    port = int(m[3]) if m[3] and 0 < int(m[3]) < 65536 else None
    return host, m[1].lower(), port, tuple(names[:_MAX_NAMES])


def _field_names(expr: ast.expr | None, sc: _Scope) -> tuple[str, ...] | None:
    """Keys of a dict literal (also `dict(a=…)`, or a local name assigned one): the names
    of what is sent. () when something is sent but its names aren't in the code here."""
    if expr is None or (isinstance(expr, ast.Constant) and expr.value is None):
        return None
    if isinstance(expr, ast.Name) and sc.func is not None:
        value = sc.local(expr.id)
        if value is not None and not isinstance(value, ast.Name):
            return _field_names(value, sc)
        return ()
    names: list[str] = []
    if isinstance(expr, ast.Dict):
        for k in expr.keys:
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                names.append(k.value)
    elif isinstance(expr, ast.Call) and getattr(expr.func, "id", "") == "dict":
        names += [k.arg for k in expr.keywords if k.arg]
    out = []
    for n in names:
        n = n.strip()[:_NAME_MAX]
        if n and _PLAIN.match(n) and n not in out:
            out.append(n)
    return tuple(out[:_MAX_NAMES])


def _receiver(func: ast.expr) -> str:
    """The last name of what the call is made on: `self._session.post` -> `_session`."""
    if not isinstance(func, ast.Attribute):
        return ""
    v = func.value
    while isinstance(v, (ast.Call, ast.Await)):  # async_get_clientsession(hass).get(…)
        v = v.func if isinstance(v, ast.Call) else v.value
    if isinstance(v, ast.Attribute):
        return v.attr
    return v.id if isinstance(v, ast.Name) else ""


def _looks_like_request(call: ast.Call, url: ast.expr | None) -> bool:
    if not _SESSION.search(_receiver(call.func)):
        return False
    if any(k.arg in _REQ_KW for k in call.keywords):
        return True
    if isinstance(url, ast.JoinedStr):
        return True
    return bool(url is not None and _URLISH.search(_label(url)))


def _kw(call: ast.Call | list[ast.keyword] | None, name: str) -> ast.expr | None:
    kws = call.keywords if isinstance(call, ast.Call) else call or []
    return next((k.value for k in kws if k.arg == name), None)


def _method_of(expr: ast.expr | None, reader: Reader, sc: _Scope) -> str:
    got = reader.address(expr, sc)
    if len(got) == 1 and isinstance(got[0], str) and got[0].upper() in METHODS:
        return got[0].upper()
    return ""


class ScopeVisitor(ast.NodeVisitor):
    """Walks one file keeping track of the function and class a node stands in, so names
    can be followed from there (also used by py_env)."""

    def __init__(self, reader: Reader, rel: str):
        self.reader, self.rel = reader, rel
        self.func: ast.AST | None = None
        self.cls: ast.ClassDef | None = None
        self.scopes: dict[tuple[int, int], _Scope] = {}

    def text(self, expr: ast.expr | None) -> str | None:
        """The string an expression is, when the code spells all of it out."""
        got = self.reader.address(expr, self._scope())
        if got and all(isinstance(p, str) for p in got):
            return "".join(got)  # type: ignore[arg-type]
        return None

    def _scope(self) -> _Scope:
        key = (id(self.func), id(self.cls))
        if key not in self.scopes:
            self.scopes[key] = _Scope(self.rel, self.func, self.cls)
        return self.scopes[key]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        cls, func = self.cls, self.func
        self.cls, self.func = node, None
        self.generic_visit(node)
        self.cls, self.func = cls, func

    def _visit_func(self, node: ast.AST) -> None:
        func = self.func
        self.func = node
        self.generic_visit(node)
        self.func = func

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func


class _Visitor(ScopeVisitor):
    def __init__(self, reader: Reader, rel: str):
        super().__init__(reader, rel)
        self.out: list[Request] = []

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
        sc = self._scope()
        url: ast.expr | None
        body_kw: ast.expr | None = None
        kws = list(node.keywords)
        if name in _CALLS and isinstance(f, ast.Attribute):
            method = _CALLS[name]
            url = node.args[0] if node.args else _kw(node, "url")
        elif name == "request" and isinstance(f, ast.Attribute):
            m = node.args[0] if node.args else _kw(node, "method")
            method = _method_of(m, self.reader, sc)
            url = node.args[1] if len(node.args) > 1 else _kw(node, "url")
        elif name == "urlopen":
            url = node.args[0] if node.args else _kw(node, "url")
            body_kw = node.args[1] if len(node.args) > 1 else _kw(node, "data")
            inner = url
            if isinstance(inner, ast.Name) and (v := sc.local(inner.id)) is not None:
                inner = v
            called = getattr(inner, "func", None)
            if isinstance(inner, ast.Call) and "Request" in (
                getattr(called, "attr", ""),
                getattr(called, "id", ""),
            ):  # urllib.request.Request(url, data=…, headers=…, method=…): read as one call
                kws = [*inner.keywords, *kws]
                url = inner.args[0] if inner.args else _kw(inner, "url")
                body_kw = body_kw or (inner.args[1] if len(inner.args) > 1 else _kw(inner, "data"))
            m = _method_of(_kw(kws, "method"), self.reader, sc)
            method = m or ("POST" if _field_names(body_kw, sc) is not None else "GET")
        else:
            return
        if url is None:
            return
        host, scheme, port, address = _site(self.reader.address(url, sc))
        if host is None and name != "urlopen" and not _looks_like_request(node, url):
            return
        body = None
        for k in _BODY_KW:
            got = _field_names(_kw(kws, k), sc)
            if got is not None:
                body = tuple(dict.fromkeys((body or ()) + got))[:_MAX_NAMES]
        if name == "urlopen" and body_kw is not None:
            body = _field_names(body_kw, sc)
        self.out.append(
            Request(
                host=host,
                method=method,
                file=self.rel,
                line=node.lineno,
                body=body,
                headers=_field_names(_kw(kws, "headers"), sc),
                query=_field_names(_kw(kws, "params"), sc),
                address=address,
                auth=_kw(kws, "auth") is not None,
                more=any(k.arg is None for k in kws),
                scheme=scheme,
                port=port,
            )
        )


def requests_in(root: Path) -> list[Request]:
    """Every web request call in the app's Python files, in file and line order."""
    reader = Reader(root)
    out: list[Request] = []
    n = 0
    for p in sorted(root.rglob("*.py")):
        if n >= _MAX_FILES:
            break
        n += 1
        try:
            rel = p.relative_to(root).as_posix()
        except ValueError:
            continue
        tree = reader.module(rel).tree
        if tree is None:
            continue
        v = _Visitor(reader, rel)
        try:
            v.visit(tree)
        except RecursionError:
            continue
        out += v.out
    return sorted(out, key=lambda r: (r.file, r.line, r.method))


def _names(v: tuple[str, ...] | None) -> list[str] | None:
    return None if v is None else list(v)


def _shapes(reqs: list[Request]) -> list[dict[str, Any]]:
    """One entry per distinct request shape: the method, what it carries, how often and
    where (the first three places)."""
    by: dict[tuple, dict[str, Any]] = {}
    for r in reqs:
        d = by.get(r.shape)
        if d is None:
            if len(by) >= _MAX_SHAPES:
                continue
            d = by[r.shape] = {
                "method": r.method,
                "body": _names(r.body),
                "headers": _names(r.headers),
                "query": _names(r.query),
                "address": list(r.address),
                "auth": r.auth,
                "more": r.more,
                "count": 0,
                "at": [],
            }
        d["count"] += 1
        if len(d["at"]) < _MAX_AT:
            d["at"].append(f"{r.file}:{r.line}")
    return list(by.values())


def summary(reqs: list[Request]) -> dict[str, Any] | None:
    """The report's `requests` section, or None when the code makes no request Barkley
    can read. `sites`: host -> shapes; `elsewhere`: shapes of requests whose address is
    built while the app runs. Field names and address names are untrusted text."""
    if not reqs:
        return None
    sites: dict[str, list[Request]] = {}
    for r in reqs:
        if r.host is not None and (r.host in sites or len(sites) < _MAX_SITES):
            sites.setdefault(r.host, []).append(r)
    return {
        "version": VERSION,
        "sites": {h: _shapes(rs) for h, rs in sorted(sites.items())},
        "elsewhere": _shapes([r for r in reqs if r.host is None]),
        "total": len(reqs),
    }
