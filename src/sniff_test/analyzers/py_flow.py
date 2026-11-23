"""(0.15, his yes 2026-11-22) Where an address built while the app runs comes from, and
where the app's own logins go. Context only: never scored, never a reason to call
anything safe.

Both questions are answered by reading backward from a request (py_requests finds them):

- **The address.** When the code doesn't spell out the site, Barkley follows the piece the
  address starts with (`f"http://{self._host}/api"` -> `self._host`) back to where it is
  set: what was saved when you set the app up (`entry.data[CONF_HOST]`, the setup form's
  `user_input`, a YAML `config`), a device found on your network
  (`async_step_zeroconf(discovery_info)`), Home Assistant's own address (`get_url(hass)`),
  a list of sites in the code (`SERVERS[region]`), or a server's answer
  (`(await resp.json())["url"]`, with the site that answered when the code names it).
  Anything else is "couldn't tell".
- **The logins.** Every value a request carries (address, body, headers, query, `auth=`) is
  followed the same way; a setup field whose name is a login (password, token, API key…)
  that reaches the request is one of "your logins for this app" going there, and a token
  read from a server's answer is "the token the answer from <site> gives it".

How a value is followed: a local name (every assignment of it in the function, also `for`
targets and `with … as`), a parameter (each call of the function in the app: `self.f(…)`,
`f(…)`, a function handed to `hass.async_add_executor_job(f, …)` or `partial(f, …)`, a
class's constructor for `__init__` (also a subclass without its own), a method name only one
function of the app has), `self.x` (every `self.x = …` in the class or an own base class;
`self.coordinator` from Home Assistant's CoordinatorEntity), an attribute of the app's own
object (`api.base_url` where `api = Api(…)`; dataclass fields by position), what the app
keeps in `hass.data[…]` or `entry.runtime_data`, module constants (also imported from the
app's own modules), dict literals and `{**spread}`, f-strings, `+`, `%`, `.format()`,
`urljoin`, `URL.build(host=…)`, `str()`, and the app's own functions (what they return).

Each question has a step budget (and a limit on function boundaries crossed), so a hostile
file can't make the reader work longer than that; anything past it is "couldn't tell".
Answers worked out in full are reused within a scan. Parse only: `ast` on the app's files;
nothing is imported or run.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sniff_test.analyzers import py_resolve

if TYPE_CHECKING:
    from sniff_test.analyzers.py_requests import Reader, _Scope

VERSION = 1
BUDGET = 3000  # steps one question may take
_DEPTH = 40  # nesting of one question
_HOPS = 4  # function boundaries crossed in one question
_MAX_ORIGINS = 6  # kept per question
_MAX_CALLS = 20000  # calls indexed per app
_MAX_FILES = 3000
_FAN = 12  # callers, assignments or returns followed per step
_KEY_MAX = 40

# kinds of origin, in the order the page lists them
ANSWER, SETUP, DISCOVERY, HA, LIST, SITE, UNKNOWN = (
    "answer", "setup", "discovery", "ha", "list", "site", "unknown")  # fmt: skip
KINDS = (ANSWER, SETUP, DISCOVERY, HA, LIST, SITE, UNKNOWN)
# containers: not an address themselves; reading a key of one gives the origin
_ENTRY, _DATA, _RESPONSE, _FOUND, _LISTED = "_entry", "_data", "_response", "_found", "_listed"
_OBJ, _STORE, _LIB, _REL, _PARAM, _DICT = "_obj", "_store", "_lib", "_rel", "_param", "_dict"
_BASE_KW = ("base_url", "base_uri", "baseurl")  # a session that adds its own site
_FIELD = re.compile(r"\{([A-Za-z0-9_]{0,40})(?:![rsa])?(?::[^{}]{0,20})?\}")

# Packages that aren't "a library the login is handed to": Python's own, Home Assistant,
# and the web clients whose requests py_requests already reads where the app calls them.
_NOT_LIB = frozenset({*sys.stdlib_module_names, "homeassistant", "custom_components",
                      "aiohttp", "requests", "httpx", "urllib3", "yarl", "voluptuous",
                      "async_timeout", "attr", "attrs", "pydantic",
                      "typing_extensions"})  # fmt: skip
# an argument that hands over an address
# calls whose positional arguments may be where to connect (a class, or connect/login…);
# a signing or hashing helper given a URL isn't handed somewhere to connect to
_CONNECTS = re.compile(r"(?i)connect|login|log_in|auth|client|session|open|create|setup|start")
_TYPE_NAME = re.compile(r"(?<![\w.])([A-Z][A-Za-z0-9_]{0,60})(?![\w(\[])")
_SESSION_SENDS = frozenset({"headers", "auth", "cookies"})
ADDRESS_ARG = re.compile(r"(?i)url|uri|host|server|endpoint|address|domain|base")
_MAX_HANDOFFS = 60
_HANDOFF_BUDGET = 600  # steps per call looked at for a hand-off
_HANDOFF_TOTAL = 150_000  # steps for all of an app's hand-offs
# words an argument must contain before it is followed (a cheap first look: the setup
# data, a login's name, an address's name, `self.` / a local that may hold one)
_ARG_WORDS = re.compile(
    r"(?i)pass|pw|token|secret|key|cred|auth|login|user|mail|entry|data|config|input|self\."
    r"|url|uri|host|server|endpoint|address|http"
)

# A setup field holding a login. Matched against the whole field name (lower case).
LOGIN_FIELD = re.compile(
    r"(?:^|_)(?:pass(?:word|wd|code|phrase)?|pwd|pin|token|secret|api_?key|apikey|key"
    r"|access_?key|auth(?:_?key|_?token|_?code)?|credentials?|cookie|session_?id)$"
)
# who you are, sent with a login (shown only beside one)
ID_FIELD = re.compile(r"(?:^|_)(?:user(?:name)?|e_?mail|login|account|user_?id|client_?id)$")
# a key of a server's answer that holds a login token
TOKEN_KEY = re.compile(
    r"(?i)token|jwt|session|sid$|cookie|auth|bearer|ticket|^key$|api_?key|secret|password"
)

_HA_FUNCS = frozenset({"get_url", "async_get_url"})  # Home Assistant's own address
_HA_ATTRS = frozenset({"internal_url", "external_url", "base_url"})
_ENTRIES = frozenset({"async_get_entry", "async_entries", "async_loaded_entries"})
# config-flow steps whose first argument is what discovery found
_DISCOVERY_STEP = re.compile(
    r"^async_step_(?:zeroconf|ssdp|dhcp|homekit|mqtt|usb|bluetooth|hassio|discovery"
    r"|integration_discovery)$"
)
_DISCOVERY_NAME = re.compile(r"(?i)^(?:discovery_info|service_info|discovery)$")
_ENTRY_NAME = re.compile(r"(?i)(?:^|_)(?:config_)?entry$")
_ENTRY_ATTRS = frozenset({"config_entry", "entry", "_entry", "_config_entry"})
_YAML_SETUP = re.compile(r"^(?:async_)?(?:setup|setup_platform|get_scanner|get_service)$")
_REQUEST_CALLS = frozenset({"get", "post", "put", "patch", "delete", "head", "options",
                            "request", "urlopen", "ws_connect"})  # fmt: skip
_READ_BODY = frozenset({"json", "text", "read"})
_PASS = frozenset({"str", "URL", "strip", "rstrip", "lstrip", "lower", "removesuffix",
                   "removeprefix", "with_path", "join", "encode", "decode", "dict", "copy",
                   "deepcopy", "MappingProxyType"})  # fmt: skip
# Calls whose result still holds what they were given: encodings, hashes, login objects
# and text builders. Any other function's result (a library's answer, a lookup) is not
# taken to carry its arguments (the hand check of 2026-11-22: an upload's returned
# content hash isn't the secret that signed the upload).
_CARRIES = frozenset(
    {
        "b64encode",
        "urlsafe_b64encode",
        "standard_b64encode",
        "b32encode",
        "hexlify",
        "encode",
        "decode",
        "hexdigest",
        "digest",
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha512",
        "new",
        "pbkdf2_hmac",
        "BasicAuth",
        "HTTPBasicAuth",
        "HTTPDigestAuth",
        "DigestAuth",
        "quote",
        "quote_plus",
        "urlencode",
        "dumps",
        "str",
        "bytes",
        "bytearray",
        "format",
        "join",
        "strip",
        "lower",
        "upper",
        "replace",
        "dict",
        "tuple",
        "list",
        "copy",
        "update_wrapper",
        "Headers",
        "CIMultiDict",
        "MultiDict",
        "FormData",
        "Request",
    }
)
_CARRIES_SELF = frozenset({"encode", "decode", "hexdigest", "digest", "format", "join",
                           "strip", "lower", "upper", "replace", "copy"})  # fmt: skip
# a function handed over to be called later: (call name, where the function is)
_HANDED = {"async_add_executor_job": 0, "add_executor_job": 0, "partial": 0, "to_thread": 0,
           "run_in_executor": 1, "async_add_job": 0}  # fmt: skip
_TEST_FILE = re.compile(r"(?:^|/)(?:tests?/|test_[^/]*\.py$|[^/]*_test\.py$|conftest\.py$)")
_HOST = re.compile(r"^(?:https?|wss?)://([A-Za-z0-9.\-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])")
_SCHEME_ONLY = re.compile(r"^(?:(?:https?|wss?)://)?$")


@dataclass(frozen=True, order=True)
class Origin:
    kind: str
    detail: str = ""  # setup/answer/discovery: the field or key; list/site: hosts (",")
    site: str = ""  # answer: the site that answered ("" when the code doesn't say)

    def as_dict(self) -> dict[str, str]:
        d = {"kind": self.kind}
        if self.detail:
            d["detail"] = self.detail
        if self.site:
            d["site"] = self.site
        return d


_UNK = Origin(UNKNOWN)


def _host(text: str) -> str:
    m = _HOST.match(text.strip())
    return m[1].lower().rstrip(".") if m else ""


def _short(x: ast.expr) -> str:
    """The text of a short argument (names only; a long one is cut)."""
    try:
        return ast.unparse(x)[:200]
    except (ValueError, RecursionError):
        return ""


_BARE = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.){1,8}([A-Za-z]{2,24}))(?::\d{1,5})?$")
_FILE_EXT = frozenset(
    "json py js mjs html htm xml txt yaml yml php cgi asp aspx jsp csv png jpg jpeg gif svg css "
    "ico md toml ini cfg log zip gz pem crt key".split()
)


def _bare_host(text: str) -> str:
    """A host name written without "https://" ("api.vendor.example", "meter.example.ca"), not a
    file name ("config.json")."""
    m = _BARE.match(text.strip())
    if m is None or m[2].lower() in _FILE_EXT:
        return ""
    return m[1].lower()


def _call_name(call: ast.Call) -> str:
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


def _tail(x: ast.expr) -> str:
    """`self._entry` -> "_entry"; `hass` -> "hass"."""
    if isinstance(x, ast.Attribute):
        return x.attr
    return x.id if isinstance(x, ast.Name) else ""


def _params(fn: ast.AST) -> list[str]:
    a = fn.args  # type: ignore[attr-defined]
    return [x.arg for x in [*a.posonlyargs, *a.args, *a.kwonlyargs]]


def _is_param(fn: ast.AST | None, name: str) -> bool:
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return False
    a = fn.args
    every = [*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg]
    return any(x is not None and x.arg == name for x in every)


def _annotation(fn: ast.AST, name: str) -> str:
    a = fn.args  # type: ignore[attr-defined]
    for x in [*a.posonlyargs, *a.args, *a.kwonlyargs]:
        if x.arg == name and x.annotation is not None:
            try:
                return ast.unparse(x.annotation)[:80]
            except (ValueError, RecursionError):
                return ""
    return ""


def _bound(call: ast.Call, params: list[str], name: str) -> ast.expr | None:
    """What `call` passes for parameter `name` (`params`: positional order, no self)."""
    for k in call.keywords:
        if k.arg == name:
            return k.value
    try:
        i = params.index(name)
    except ValueError:
        return None
    for j, a in enumerate(call.args):
        if isinstance(a, ast.Starred):
            return None
        if j == i:
            return a
    return None


def _default(fn: ast.AST, name: str) -> ast.expr | None:
    a = fn.args  # type: ignore[attr-defined]
    pos = [*a.posonlyargs, *a.args]
    for x, dv in zip(pos[len(pos) - len(a.defaults) :], a.defaults, strict=False):
        if x.arg == name:
            return dv
    for x, dv in zip(a.kwonlyargs, a.kw_defaults, strict=False):
        if x.arg == name:
            return dv
    return None


def _store_root(t: ast.expr) -> tuple[str, list[ast.expr | None]]:
    """("hass.data", the keys on the way) when an assignment target sits in
    `hass.data[…]` (also `hass.data.setdefault(DOMAIN, {})[…]`); ("runtime_data", […]) for
    `entry.runtime_data`; ("", []) otherwise. A key is None when it isn't a subscript or a
    `setdefault` (then any key matches it)."""
    keys: list[ast.expr | None] = []
    node: ast.expr = t
    for _ in range(12):
        if isinstance(node, ast.Attribute) and node.attr == "runtime_data":
            return "runtime_data", keys[::-1]
        if isinstance(node, ast.Subscript):
            keys.append(node.slice)
            node = node.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "setdefault" and node.args:
                keys.append(node.args[0])
            else:
                keys.append(None)
            node = node.func.value
        elif isinstance(node, ast.Attribute) and node.attr == "data":
            return ("hass.data", keys[::-1]) if _tail(node.value) == "hass" else ("", [])
        else:
            return "", []
    return "", []


@dataclass
class _Def:
    rel: str
    fn: ast.AST
    cls: ast.ClassDef | None


@dataclass
class _Site:
    rel: str
    call: ast.Call
    fn: ast.AST | None
    cls: ast.ClassDef | None


@dataclass
class _Index(ast.NodeVisitor):
    """Every function, class and call of the app, by name, and what it keeps in
    `hass.data` / `entry.runtime_data` (one walk per file)."""

    funcs: dict[str, list[_Def]] = field(default_factory=dict)
    classes: dict[str, list[tuple[str, ast.ClassDef]]] = field(default_factory=dict)
    calls: dict[str, list[_Site]] = field(default_factory=dict)
    stores: dict[str, list[_Site | tuple[str, ast.expr, ast.AST | None, ast.ClassDef | None]]] = (
        field(default_factory=dict))  # fmt: skip
    libs: dict[str, dict[str, str]] = field(default_factory=dict)  # file -> name -> package
    own: str = ""  # (py_library) the library being read: its imports of itself aren't a library
    aliases: dict[str, set[str]] = field(default_factory=dict)  # name -> `import name as X` names
    n: int = 0
    rel: str = ""
    fn: ast.AST | None = None
    cls: ast.ClassDef | None = None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.classes.setdefault(node.name, []).append((self.rel, node))
        cls, fn = self.cls, self.fn
        self.cls, self.fn = node, None
        self.generic_visit(node)
        self.cls, self.fn = cls, fn

    def _func(self, node: ast.AST) -> None:
        self.funcs.setdefault(node.name, []).append(  # type: ignore[attr-defined]
            _Def(self.rel, node, self.cls if self.fn is None else None)
        )
        fn = self.fn
        self.fn = node
        self.generic_visit(node)
        self.fn = fn

    visit_FunctionDef = _func
    visit_AsyncFunctionDef = _func

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            top = a.name.split(".")[0]
            if top not in _NOT_LIB and top != self.own:
                self.libs.setdefault(self.rel, {})[a.asname or top] = top

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for a in node.names:  # `from .api import Client as API`: `API(…)` calls Client
            if a.asname and a.asname != a.name and len(self.aliases) < _MAX_CALLS:
                self.aliases.setdefault(a.name, set()).add(a.asname)
        top = (node.module or "").split(".")[0]
        if node.level == 0 and top and top not in _NOT_LIB and top != self.own:
            for a in node.names:
                if a.name != "*":
                    self.libs.setdefault(self.rel, {})[a.asname or a.name] = top

    def visit_Assign(self, node: ast.Assign) -> None:
        for t in node.targets:
            root, keys = _store_root(t)
            if root:
                self.stores.setdefault(root, []).append(
                    (self.rel, node.value, self.fn, self.cls, keys)
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self.n < _MAX_CALLS:
            self.n += 1
            name = _call_name(node)
            self.calls.setdefault(name, []).append(_Site(self.rel, node, self.fn, self.cls))
            at = _HANDED.get(name)
            if at is not None and len(node.args) > at:
                ref = node.args[at]  # a function handed over: called with what follows it
                if isinstance(ref, (ast.Name, ast.Attribute)):
                    call = ast.copy_location(
                        ast.Call(func=ref, args=node.args[at + 1 :], keywords=node.keywords), node
                    )
                    self.calls.setdefault(_tail(ref), []).append(
                        _Site(self.rel, call, self.fn, self.cls)
                    )
        self.generic_visit(node)


class Tracer:
    """Follows values backward in one app. One instance per scan (it caches each file's
    assignments, the app's index and answers worked out in full)."""

    def __init__(self, reader: Reader):
        self.reader = reader
        self.res = py_resolve.Resolver(reader.root, getattr(reader, "package", None))
        self._index: _Index | None = None
        self._locals: dict[int, dict[str, list[ast.expr]]] = {}
        self._dict_at: dict[int, tuple[ast.Dict, _Scope]] = {}
        self._wr: dict[tuple[int, bool], dict[str, list[tuple[ast.expr | None, ast.expr]]]] = {}
        self._attrs: dict[int, dict[str, list[tuple[ast.expr, ast.AST | None]]]] = {}
        self._left = BUDGET
        self._hops = 0
        self._busy: set[tuple[ast.AST, bool, ast.AST | None]] = set()
        self._memo: dict[tuple[ast.AST, bool, object, object, object], frozenset[Origin]] = {}
        self._cuts = 0
        self._stop: ast.AST | None = None  # a wrapper whose parameters each call fills in
        # (py_library) inside a library: the functions the app calls, whose parameters hold
        # what the app passed in
        self.entries: list[Entry] = []
        self.gave_up: list[tuple[str, ast.AST]] | None = None  # (why, where): for measuring

    def _cut(self, why: str) -> None:
        self._cuts += 1
        if self.gave_up is not None and len(self.gave_up) < 20000:
            self.gave_up.append((f"cut: {why}", ast.Pass()))

    def _unk(self, x: ast.AST, why: str) -> set[Origin]:
        if self.gave_up is not None and len(self.gave_up) < 20000:
            self.gave_up.append((why, x))
        return {_UNK}

    def _scope(self, rel: str, fn: ast.AST | None, cls: ast.ClassDef | None) -> _Scope:
        from sniff_test.analyzers.py_requests import _Scope

        return _Scope(rel, fn, cls)

    # --- the app's index -----------------------------------------------------------------

    def index(self) -> _Index:
        if self._index is None:
            ix = _Index()
            ix.own = getattr(self.reader, "package", None) or ""
            n = 0
            for p in sorted(self.reader.root.rglob("*.py")):
                if n >= _MAX_FILES:
                    break
                n += 1
                try:
                    rel = p.relative_to(self.reader.root).as_posix()
                except ValueError:
                    continue
                if _TEST_FILE.search(rel):
                    continue  # test scripts: Home Assistant never runs them
                tree = self.reader.module(rel).tree
                if tree is None:
                    continue
                ix.rel, ix.fn, ix.cls = rel, None, None
                try:
                    ix.visit(tree)
                except RecursionError:
                    continue
            self._index = ix
        return self._index

    def _class(self, name: str) -> tuple[str, ast.ClassDef] | None:
        got = self.index().classes.get(name, [])
        return got[0] if len(got) == 1 else None

    # --- questions -----------------------------------------------------------------------

    def address(
        self,
        expr: ast.expr | None,
        sc: _Scope,
        budget: int = BUDGET,
        receiver: ast.expr | None = None,
    ) -> list[Origin]:
        """Where the address `expr` comes from (its leading piece). `receiver`: what the
        request is called on; when the address is a path (`"/api/x"`), a session made
        with `base_url=` gives the site."""
        if expr is None:
            return [_UNK]
        self._left, self._hops, self._busy = budget, 0, set()
        got = self._t(expr, sc, True, 0)
        if receiver is not None and not {o.kind for o in got} - {_REL, UNKNOWN}:
            base = self._session_base(receiver, sc, 0)
            if base:
                got = base
        for o in [o for o in got if o.kind == _DICT]:
            if (hit := self._dict_at.get(int(o.detail))) is not None:
                got = (got - {o}) | self._values(hit[0], hit[1], True, 0)
        sites = sorted({o.detail for o in got if o.kind == SITE})
        if len(sites) > 1:  # one of several sites in the code
            got = {o for o in got if o.kind != SITE} | {Origin(LIST, ",".join(sites)[:400])}
        got = {o if not o.kind.startswith("_") else _UNK for o in got} or {_UNK}
        if len(got) > 1:
            got.discard(_UNK)  # one path known: say that one, not "couldn't tell" too
        return sorted(got, key=lambda o: (KINDS.index(o.kind), o))[:_MAX_ORIGINS]

    def carried(
        self, exprs: list[ast.expr | None], sc: _Scope, budget: int = BUDGET
    ) -> list[Origin]:
        """Where every piece of the values a request carries comes from."""
        return self.carried_in(exprs, sc, None, budget)[0]

    def carried_in(
        self,
        exprs: list[ast.expr | None],
        sc: _Scope,
        wrapper: ast.AST | None,
        budget: int = BUDGET,
        receiver: ast.expr | None = None,
    ) -> tuple[list[Origin], tuple[str, ...]]:
        """`carried`, for a request inside `wrapper` (the app's own function each call of
        which is read as a request): the wrapper's parameters are left open, and their
        names are returned so each call can fill in what it passes. (Pooling every
        caller's values made a shared helper carry the login call's password on every
        call: the hand check of 2026-11-22.)"""
        out: set[Origin] = set()
        self._left, self._hops, self._busy = budget, 0, set()
        self._stop = wrapper
        try:
            for x in exprs:
                if x is not None:
                    out |= self._t(x, sc, False, 0)
            if receiver is not None:  # what the session itself sends every time
                out |= self._session_sends(receiver, sc)
        finally:
            self._stop = None
        params = tuple(sorted({o.detail for o in out if o.kind == _PARAM}))
        return sorted(o for o in out if not o.kind.startswith("_")), params

    # --- the walk ------------------------------------------------------------------------

    def _t(self, x: ast.expr, sc: _Scope, lead: bool, depth: int) -> set[Origin]:
        self._left -= 1
        if self._left < 0 or depth > _DEPTH:
            self._cut("budget")
            return {_UNK}
        # keyed by the nodes themselves, not id(): a node built here (a format string's
        # piece, a loop's item) can be freed, and a new one could then reuse its id
        mk = (x, lead, sc.func, sc.cls, self._stop)
        if (hit := self._memo.get(mk)) is not None:
            return set(hit)
        key = (x, lead, sc.func)
        if key in self._busy:
            self._cut("cycle")
            return set()  # a value defined from itself: the other paths say where it's from
        self._busy.add(key)
        cuts = self._cuts
        try:
            got = self._step(x, sc, lead, depth + 1)
        except RecursionError:
            self._cut("recursion")
            return {_UNK}
        finally:
            self._busy.discard(key)
        if self._cuts == cuts:
            self._memo[mk] = frozenset(got)
        return got

    def _step(self, x: ast.expr, sc: _Scope, lead: bool, d: int) -> set[Origin]:
        if isinstance(x, ast.Constant):
            if isinstance(x.value, str) and (h := _host(x.value)):
                return {Origin(SITE, h)}
            if lead and isinstance(x.value, str) and (h := _bare_host(x.value)):
                return {Origin(SITE, h)}  # "api.vendor.example", put after "https://" elsewhere
            if lead and isinstance(x.value, str) and x.value.strip():
                return {Origin(_REL)}  # a path: the site is added elsewhere (a session)
            return set()  # fixed text: comes from nowhere
        if isinstance(x, (ast.JoinedStr, ast.BinOp)):
            return self._joined(x, sc, lead, d)
        if isinstance(x, (ast.Await, ast.NamedExpr, ast.Starred)):
            return self._t(x.value, sc, lead, d)
        if isinstance(x, (ast.IfExp, ast.BoolOp)):
            parts = [x.body, x.orelse] if isinstance(x, ast.IfExp) else list(x.values)
            out: set[Origin] = set()
            for p in parts:
                out |= self._t(p, sc, lead, d)
            return out
        if isinstance(x, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            return self._literal(x, sc, lead, d)
        if isinstance(x, ast.Subscript):
            return self._read_key(x.value, self._key(x.slice, sc), sc, lead, d)
        if isinstance(x, ast.Attribute):
            return self._attribute(x, sc, lead, d)
        if isinstance(x, ast.Name):
            return self._name(x.id, sc, lead, d)
        if isinstance(x, ast.Call):
            return self._call(x, sc, lead, d)
        return self._unk(x, type(x).__name__)

    def _key(self, node: ast.expr | None, sc: _Scope) -> str:
        """The key a subscript or `.get()` reads: a literal, a constant's value, or a
        `CONF_X` name as Home Assistant spells it (`CONF_PASSWORD` -> "password")."""
        if node is None:
            return ""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value[:_KEY_MAX]
        name = node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", "")
        try:
            got = self.res.ha_const(sc.rel, node) or self.res.value(sc.rel, node)
        except RecursionError:
            got = None
        if got:
            return got[:_KEY_MAX]
        if isinstance(name, str) and name.startswith("CONF_"):
            return name.removeprefix("CONF_").lower()[:_KEY_MAX]
        return ""

    def _session_made(
        self, receiver: ast.expr, sc: _Scope, hops: int = 0
    ) -> list[tuple[ast.Call, _Scope]]:
        """The calls that make the session a request is sent on: the receiver itself, a
        local name or `self.<attr>` it was set to, or what an own method that hands it out
        returns (`session = await self._get_session()`), a few steps back."""
        values: list[tuple[ast.expr, _Scope]] = []
        if isinstance(receiver, ast.Call):
            values = [(receiver, sc)]
        elif isinstance(receiver, ast.Name) and sc.func is not None:
            values = [(v, sc) for v in self._local_values(sc.func).get(receiver.id, [])[:_FAN]]
        elif isinstance(receiver, ast.Attribute) and _tail(receiver.value) in ("self", "cls"):
            got = self._class_attr(sc.cls, receiver.attr, sc.rel)[:_FAN]
            values = [(v, self._scope(rel, fn, cls)) for v, fn, rel, cls in got]
        out: list[tuple[ast.Call, _Scope]] = []
        for v, vsc in values:
            while isinstance(v, ast.Await):
                v = v.value
            if not isinstance(v, ast.Call):
                if hops < 3 and isinstance(v, (ast.Name, ast.Attribute)):
                    out += self._session_made(v, vsc, hops + 1)
                continue
            own = self._own_def(v, vsc) if hops < 3 else None
            if own is None:
                out.append((v, vsc))
                continue
            osc = self._scope(own.rel, own.fn, own.cls)
            for r in [n for n in ast.walk(own.fn) if isinstance(n, ast.Return)][:_FAN]:
                if r.value is not None:
                    out += self._session_made(r.value, osc, hops + 1)
        return out[:_FAN]

    def _session_base(self, receiver: ast.expr, sc: _Scope, d: int) -> set[Origin]:
        """The site a session adds to paths: `ClientSession(base_url=X)` (also
        `httpx.AsyncClient(base_url=X)`) where the receiver is made."""
        out: set[Origin] = set()
        for v, vsc in self._session_made(receiver, sc):
            kw = next((k.value for k in v.keywords if k.arg in _BASE_KW), None)
            if kw is not None:
                out |= self._t(kw, vsc, True, d)
        return {o for o in out if o.kind not in (_REL, UNKNOWN)}

    def _session_sends(self, receiver: ast.expr, sc: _Scope) -> set[Origin]:
        """(0.15) What a session sends with every request on it: the headers, login and
        cookies it was made with (`ClientSession(headers={"Authorization": …})`)."""
        out: set[Origin] = set()
        for v, vsc in self._session_made(receiver, sc):
            for k in v.keywords:
                if k.arg in _SESSION_SENDS:
                    out |= self._t(k.value, vsc, False, 0)
        return out

    def _format_parts(self, text: str, x: ast.Call | None, args: list[ast.expr]) -> list[ast.expr]:
        """A format string's pieces in order: its text and what fills each field
        (`"%s/me" % base`, `"{}/api/{id}".format(base, id=…)`)."""
        out: list[ast.expr] = []
        if x is None:  # % formatting
            pieces = re.split(r"%[sdr]", text[:2000])
            for i, piece in enumerate(pieces):
                out.append(ast.Constant(value=piece))
                if i < len(pieces) - 1:
                    out.append(args[i] if i < len(args) else ast.Constant(value=""))
            return out
        kw = {k.arg: k.value for k in x.keywords if k.arg}
        auto = 0
        for i, piece in enumerate(_FIELD.split(text[:2000])):
            if i % 2 == 0:
                out.append(ast.Constant(value=piece))
                continue
            if piece == "" or piece.isdigit():
                idx = int(piece) if piece else auto
                auto += piece == ""
                out.append(args[idx] if idx < len(args) else ast.Constant(value=""))
            else:
                out.append(kw.get(piece, ast.Constant(value="")))
        return out

    def _text_of(self, x: ast.expr, sc: _Scope) -> str | None:
        if isinstance(x, ast.Constant) and isinstance(x.value, str):
            return x.value
        try:
            return self.res.value(sc.rel, x)
        except RecursionError:
            return None

    def _joined(self, x: ast.expr, sc: _Scope, lead: bool, d: int) -> set[Origin]:
        parts: list[ast.expr] = []
        if isinstance(x, ast.JoinedStr):
            parts = [v.value if isinstance(v, ast.FormattedValue) else v for v in x.values]
        elif isinstance(x, ast.BinOp) and isinstance(x.op, ast.Add):
            node: ast.expr = x
            terms: list[ast.expr] = []
            while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                terms.append(node.right)
                node = node.left
                if len(terms) > 500:
                    return self._unk(x, "long sum")
            parts = [node, *reversed(terms)]
        elif isinstance(x, ast.BinOp) and isinstance(x.op, (ast.Mod, ast.Div)):
            args = x.right.elts if isinstance(x.right, ast.Tuple) else [x.right]
            text = self._text_of(x.left, sc) if isinstance(x.op, ast.Mod) else None
            parts = self._format_parts(text, None, args) if text is not None else [x.left, *args]
        else:
            return self._unk(x, "operator")
        return self._parts(parts, sc, lead, d)

    def _parts(self, parts: list[ast.expr], sc: _Scope, lead: bool, d: int) -> set[Origin]:
        if not lead:
            out: set[Origin] = set()
            for p in parts:
                out |= self._t(p, sc, False, d)
            return out
        for p in parts:  # the first piece that isn't just "http://"
            if isinstance(p, ast.Constant) and isinstance(p.value, str):
                if _SCHEME_ONLY.match(p.value.strip()):
                    continue
                if h := _host(p.value):
                    return {Origin(SITE, h)}
                return {Origin(_REL)}  # a path: the site is added elsewhere (a session)
            return self._t(p, sc, True, d)
        return {_UNK}

    def _literal(self, x: ast.expr, sc: _Scope, lead: bool, d: int) -> set[Origin]:
        if lead and isinstance(x, ast.Dict):
            # a dict stays a dict until a key of it is read (`data.get(CONF_IP)` where the
            # caller passes `{CONF_IP: …, CONF_PASSWORD: …}`): one key, one value
            self._dict_at[id(x)] = (x, sc)
            return {Origin(_DICT, str(id(x)))}
        return self._values(x, sc, lead, d)

    def _values(self, x: ast.expr, sc: _Scope, lead: bool, d: int) -> set[Origin]:
        values = list(x.values if isinstance(x, ast.Dict) else x.elts)  # type: ignore[attr-defined]
        out: set[Origin] = set()
        for v in values[:200]:
            if v is not None:
                out |= self._t(v, sc, lead, d)
        if lead:  # a list of sites in the code: the address is one of them
            sites = sorted({s for o in out if o.kind in (SITE, LIST) for s in o.detail.split(",")})
            if sites and all(o.kind in (SITE, LIST) for o in out):
                return {Origin(_LISTED, ",".join(sites)[:400])}
        return out

    # --- reading a key or an attribute of something ----------------------------------------

    def _dicts(self, base: ast.expr, sc: _Scope) -> list[tuple[ast.Dict, _Scope]]:
        """The dict literals `base` is (itself, or a name every assignment of which is one)."""
        if isinstance(base, ast.Dict):
            return [(base, sc)]
        if isinstance(base, ast.Name):
            values = self._local_values(sc.func).get(base.id) if sc.func is not None else None
            if values is None and base.id in self.reader.module(sc.rel).assigns:
                values, sc = (
                    [self.reader.module(sc.rel).assigns[base.id]],
                    self._scope(sc.rel, None, None),
                )
            if values and all(isinstance(v, ast.Dict) for v in values):
                return [(v, sc) for v in values[:_FAN]]  # type: ignore[misc]
        return []

    def _read_key(self, base: ast.expr, key: str, sc: _Scope, lead: bool, d: int) -> set[Origin]:
        self._left -= 1  # its own steps count too (`d = {**d, …}` reads itself)
        if self._left < 0 or d > _DEPTH:
            self._cut("budget")
            return {_UNK}
        d += 1
        if isinstance(base, ast.Name) and sc.func is not None:
            wrote = self._writes(sc.func, False).get(base.id, [])
            hits = [v for k, v in wrote if k is not None and key and self._key(k, sc) == key]
            written: set[Origin] = set()
            for v in hits[:_FAN]:  # `d[KEY] = v` … `d[KEY]`: one more value it can have
                written |= self._t(v, sc, lead, d)
            if written:
                rest = self._read_key_as_made(base, key, sc, lead, d)
                return (written | rest) - ({_UNK} if rest - {_UNK} or written - {_UNK} else set())
        return self._read_key_as_made(base, key, sc, lead, d)

    def _read_key_as_made(
        self, base: ast.expr, key: str, sc: _Scope, lead: bool, d: int
    ) -> set[Origin]:
        """`_read_key` without the writes made into `base` after it was made."""
        literal = self._dicts(base, sc)
        if literal and key:
            out: set[Origin] = set()
            for dct, dsc in literal:
                for k, v in zip(dct.keys, dct.values, strict=False):
                    if k is None:  # {**other}: the key may be in there
                        if (isinstance(v, ast.Name) and isinstance(base, ast.Name)
                                and v.id == base.id and _is_param(dsc.func, v.id)):  # fmt: skip
                            # `data = {**data, …}`: the parameter it came in as
                            got_p = self._param(dsc.func, v.id, dsc, True, d)  # type: ignore[arg-type]
                            out |= self._map_key(got_p, key, lead, d)
                        else:
                            out |= self._read_key(v, key, dsc, lead, d)
                    elif self._key(k, dsc) == key:
                        out |= self._t(v, dsc, lead, d)
            return out  # a key the dict doesn't hold (or one only a spread may hold)
        return self._map_key(self._container(base, sc, d), key, lead, d)

    def _map_key(self, got: set[Origin], key: str, lead: bool, d: int) -> set[Origin]:
        """What reading `key` of something whose origins are `got` gives."""
        out: set[Origin] = set()
        for o in got:
            if o.kind == _DATA or (o.kind == SETUP and not o.detail):
                out.add(Origin(SETUP, key))
            elif o.kind == SETUP:  # entry.data[CONF_DEVICE]["x"]: the setup field stays
                out.add(o)
            elif o.kind in (_RESPONSE, ANSWER):
                out.add(Origin(ANSWER, key or o.detail, o.site))
            elif o.kind == _FOUND or (o.kind == DISCOVERY and not o.detail):
                out.add(Origin(DISCOVERY, key))
            elif o.kind == DISCOVERY:
                out.add(o)
            elif o.kind in (_LISTED, LIST):
                out.add(Origin(LIST, o.detail))
            elif o.kind == _ENTRY:
                out.add(o if not key else _UNK)  # `for entry in entries`: still an entry
            elif o.kind == _OBJ:
                out |= self._obj_attr(o.detail, key, lead, d)
            elif o.kind == _DICT and (hit := self._dict_at.get(int(o.detail))) is not None:
                dct, dsc = hit
                if key:
                    out |= self._read_key(dct, key, dsc, lead, d)
                else:  # a key known only while running: any of its values
                    out |= {Origin(LIST, v.detail) if v.kind == _LISTED else v
                            for v in self._values(dct, dsc, lead, d)}  # fmt: skip
            elif o.kind == _STORE:
                out |= self._stored(o.detail, key, lead, d)
                out.discard(_UNK)
            else:
                out.add(o)
        return out

    def _container(self, base: ast.expr, sc: _Scope, d: int) -> set[Origin]:
        """What `base` is when the code reads a key of it."""
        if (
            isinstance(base, ast.Call)
            and _call_name(base) == "get"
            and base.args
            and isinstance(base.func, ast.Attribute)
        ):  # `entry.data.get(CONF_X, {})["y"]`
            return self._read_key(base.func.value, self._key(base.args[0], sc), sc, True, d)
        return self._t(base, sc, True, d)

    def _attribute(self, x: ast.Attribute, sc: _Scope, lead: bool, d: int) -> set[Origin]:
        v = x.value
        if isinstance(v, ast.Name) and v.id in ("self", "cls"):
            return self._self_attr(x.attr, sc, lead, d)
        if x.attr in ("data", "options"):
            if _tail(v) == "hass" and x.attr == "data":
                return {Origin(_STORE, "hass.data")}
            if _ENTRY_NAME.search(_tail(v)) or any(
                o.kind == _ENTRY for o in self._t(v, sc, True, d)
            ):
                return {Origin(_DATA)}
        if x.attr == "runtime_data":
            return {Origin(_STORE, "runtime_data")}
        if (x.attr in _HA_ATTRS and _tail(v) in ("config", "api")) or (
            x.attr == "api" and _tail(v) == "config"
        ):
            return {Origin(HA)}
        if x.attr in _ENTRY_ATTRS:
            return {Origin(_ENTRY)}
        if isinstance(v, ast.Name) and v.id in self.reader.module(sc.rel).imports:
            got = self.reader._module_attr(sc.rel, v.id, x.attr, 0)
            if got is not None and all(isinstance(p, str) for p in got):
                h = _host("".join(got))  # type: ignore[arg-type]
                return {Origin(SITE, h)} if h else set()
        return self._read_key(v, x.attr, sc, lead, d)

    def _self_attr(self, attr: str, sc: _Scope, lead: bool, d: int) -> set[Origin]:
        for e in self.entries:  # (py_library) a field of a dataclass the app made
            got = e.field(sc.cls, attr, lead)
            if got is not None:
                return set(got)
        values = self._class_attr(sc.cls, attr, sc.rel)
        if not values:
            if attr in _ENTRY_ATTRS:
                return {Origin(_ENTRY)}
            if attr == "hass":
                return self._unk(sc.cls or ast.Pass(), "hass")
            return self._unk(sc.cls or ast.Pass(), f"self.{attr}: not set in the class")
        out: set[Origin] = set()
        for value, fn, rel, cls in values[:_FAN]:
            out |= self._t(value, self._scope(rel, fn, cls), lead, d)
        if not lead and sc.cls is not None:
            for _k, v in self._writes(sc.cls, True).get(attr, [])[:_FAN]:
                out |= self._t(v, self._scope(sc.rel, None, sc.cls), lead, d)
        return out

    def _class_attr(
        self, cls: ast.ClassDef | None, attr: str, rel: str, depth: int = 0
    ) -> list[tuple[ast.expr, ast.AST | None, str, ast.ClassDef]]:
        """Every value `self.<attr>` gets in `cls` (or, when it sets none, in an own base
        class; Home Assistant's CoordinatorEntity keeps the first argument of
        `super().__init__` as `self.coordinator`)."""
        if cls is None or depth > 4:
            return []
        got = [(v, fn, rel, cls) for v, fn in self._attr_values(cls).get(attr, [])]
        if got:
            return got
        for b in cls.bases:
            name = _tail(b)
            if attr == "coordinator" and name.endswith("CoordinatorEntity"):
                for fn in cls.body:
                    if (
                        isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and fn.name == "__init__"
                    ):
                        for c in ast.walk(fn):
                            if (isinstance(c, ast.Call) and _call_name(c) == "__init__"
                                    and isinstance(c.func, ast.Attribute)
                                    and isinstance(c.func.value, ast.Call)
                                    and _call_name(c.func.value) == "super"):  # fmt: skip
                                arg = _bound(c, ["coordinator"], "coordinator")
                                if arg is not None:
                                    got.append((arg, fn, rel, cls))
                if got:
                    return got
            own = self._class(name)
            if own is not None and own[1] is not cls:
                got += self._class_attr(own[1], attr, own[0], depth + 1)
        return got

    def _attr_values(self, cls: ast.ClassDef) -> dict[str, list[tuple[ast.expr, ast.AST | None]]]:
        got = self._attrs.get(id(cls))
        if got is None:
            got = {}
            for node in cls.body:  # class constants
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                    ts = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for t in ts:
                        if isinstance(t, ast.Name):
                            got.setdefault(t.id, []).append((node.value, None))
            for fn in cls.body:
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for node in ast.walk(fn):
                    if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                        ts = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for t in ts:
                            if (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                                    and t.value.id in ("self", "cls")):  # fmt: skip
                                got.setdefault(t.attr, []).append((node.value, fn))
            self._attrs[id(cls)] = got
        return got

    def _obj_attr(self, cls_name: str, attr: str, lead: bool, d: int) -> set[Origin]:
        """`obj.attr` where `obj` is one of the app's own objects: what the class sets
        `self.attr` to, a property's return, or (a dataclass) the constructor's argument."""
        found = self._class(cls_name)
        if found is None or not attr:
            return self._unk(ast.Pass(), f"object {cls_name}.{attr}")
        rel, cls = found
        for node in cls.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == attr:
                return self._returns(_Def(rel, node, cls), lead, d)
        values = self._class_attr(cls, attr, rel)
        if values:
            return self._self_attr(attr, self._scope(rel, None, cls), lead, d)
        fields = [n.target.id for n in cls.body
                  if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)]  # fmt: skip
        if attr in fields and self._hops < _HOPS:  # a dataclass or NamedTuple field
            out: set[Origin] = set()
            self._hops += 1
            try:
                for s in self.index().calls.get(cls.name, [])[:_FAN]:
                    arg = _bound(s.call, fields, attr)
                    if arg is not None:
                        out |= self._t(arg, self._scope(s.rel, s.fn, s.cls), lead, d)
            finally:
                self._hops -= 1
            return out or self._unk(cls, f"field {cls_name}.{attr}")
        return self._unk(cls, f"object {cls_name}.{attr}")

    def _stored(self, where: str, key: str, lead: bool, d: int) -> set[Origin]:
        """What the app keeps in `hass.data[…]` or `entry.runtime_data`, read with `key`
        after the keys in `where` ("root\x1fkey\x1fkey…"; "" = a key known only while
        running). Only values written under the same keys answer: a value written
        exactly there, or a dict or object written higher up and read on from there; a
        value written deeper keeps the store open for the next key. (One setting per key,
        `hass.data[DOMAIN][CONF_SECRET] = …`, made every read of `hass.data` carry the
        secret: the hand check of 2026-11-22.)"""
        root, *path = where.split("\x1f")
        path = ["" if p == "\x00" else p for p in path] + [key]
        out: set[Origin] = set()
        deeper = False
        for rel, value, fn, cls, raw in self.index().stores.get(root, [])[: _FAN * 2]:  # type: ignore[misc]
            vsc = self._scope(rel, fn, cls)
            keys = ["" if k is None else self._key(k, vsc) for k in raw]
            n = min(len(keys), len(path))
            if any(a and b and a != b for a, b in zip(keys[:n], path[:n], strict=True)):
                continue  # written under another key
            if len(keys) > len(path):
                deeper = True
                continue
            if len(keys) == len(path):
                out |= self._t(value, vsc, lead, d)
                continue
            got = {Origin(_DICT, str(id(value)))} if isinstance(value, ast.Dict) else None
            if got is not None:
                self._dict_at[id(value)] = (value, vsc)  # type: ignore[assignment]
            else:
                got = self._t(value, vsc, True, d)
            for k in path[len(keys) :]:  # read on from the value written higher up
                got = self._map_key(got, k, True, d)
            out |= got
        if deeper:
            out.add(Origin(_STORE, "\x1f".join([root, *[p or "\x00" for p in path]])))
        return out or {_UNK}

    # --- names ---------------------------------------------------------------------------

    def _local_values(self, fn: ast.AST) -> dict[str, list[ast.expr]]:
        got = self._locals.get(id(fn))
        if got is None:
            got = {}
            for node in ast.walk(fn):
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                    if node.value is None:
                        continue
                    ts = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for t in ts:
                        if isinstance(t, ast.Name):
                            got.setdefault(t.id, []).append(node.value)
                        elif isinstance(t, (ast.Tuple, ast.List)):
                            v = node.value
                            pair = isinstance(v, (ast.Tuple, ast.List)) and len(v.elts) == len(
                                t.elts
                            )
                            for i, e in enumerate(t.elts):  # `a, b = x`: each comes from x
                                if isinstance(e, ast.Name):  # `a, b = x, y`: a from x
                                    got.setdefault(e.id, []).append(v.elts[i] if pair else v)  # type: ignore[union-attr]
                elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                    item = ast.Subscript(value=node.iter, slice=ast.Constant(value=""))
                    for e in ast.walk(node.target):
                        if isinstance(e, ast.Name):
                            got.setdefault(e.id, []).append(item)
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    for w in node.items:
                        if isinstance(w.optional_vars, ast.Name):
                            got.setdefault(w.optional_vars.id, []).append(w.context_expr)
            self._locals[id(fn)] = got
        return got

    def _writes(
        self, scope: ast.AST, attr: bool
    ) -> dict[str, list[tuple[ast.expr | None, ast.expr]]]:
        """Values written into a dict or list after it is made, by its name (`attr`:
        `self.x`): `d[k] = v`, `d.update(v)`, `d.setdefault(k, v)`, `l.append(v)`."""
        key = (id(scope), attr)
        got = self._wr.get(key)
        if got is None:
            got = {}

            def name_of(x: ast.expr) -> str:
                if attr:
                    ok = isinstance(x, ast.Attribute) and _tail(x.value) in ("self", "cls")
                    return x.attr if ok else ""  # type: ignore[union-attr]
                return x.id if isinstance(x, ast.Name) else ""

            for node in ast.walk(scope):
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Subscript) and (n := name_of(t.value)):
                            got.setdefault(n, []).append((t.slice, node.value))
                elif (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("update", "setdefault", "append", "extend", "add")
                    and node.args
                    and (n := name_of(node.func.value))
                ):
                    if node.func.attr == "setdefault" and len(node.args) > 1:
                        got.setdefault(n, []).append((node.args[0], node.args[1]))
                    else:
                        got.setdefault(n, []).append((None, node.args[0]))
            self._wr[key] = got
        return got

    def _name(self, name: str, sc: _Scope, lead: bool, d: int) -> set[Origin]:
        fn = sc.func
        if fn is not None:
            values = list(self._local_values(fn).get(name) or [])
            if values and not lead:  # what it carries includes what was written into it
                values += [v for _k, v in self._writes(fn, False).get(name, [])]
            if values:
                out: set[Origin] = set()
                for v in values[:_FAN]:
                    out |= self._t(v, sc, lead, d)
                return out
            if name in ("self", "cls") and sc.cls is not None and _is_param(fn, name):
                return {Origin(_OBJ, sc.cls.name)}  # the object passes itself on (`API(self)`)
            if _is_param(fn, name):
                return self._param(fn, name, sc, lead, d)
        mod = self.reader.module(sc.rel)
        if name in mod.assigns:
            return self._t(mod.assigns[name], self._scope(sc.rel, None, None), lead, d)
        if name in mod.imports:
            target, orig = mod.imports[name]
            other = self.reader.module(target)
            if orig in other.assigns:
                return self._t(other.assigns[orig], self._scope(target, None, None), lead, d)
        if self._class(name) is not None:
            return {Origin(_OBJ, name)}  # the class itself (its class attributes)
        return self._unk(fn or ast.Pass(), f"name {name}")

    def _param(self, fn: ast.AST, name: str, sc: _Scope, lead: bool, d: int) -> set[Origin]:
        for e in self.entries:  # (py_library) what the app passed for this parameter
            got = e.value(fn, sc, name, lead)
            if got is not None:
                return set(got) if got else self._from_default(fn, name, sc, lead, d)
        if fn is self._stop:
            return {Origin(_PARAM, name)}  # each call of the wrapper says what it passes
        fname = getattr(fn, "name", "")
        params = _params(fn)
        first = next((p for p in params if p not in ("self", "cls")), "")
        ann = _annotation(fn, name)
        if _DISCOVERY_STEP.match(fname) and name == first:
            return {Origin(_FOUND)}
        if name == "user_input" or (fname.startswith("async_step_") and name == first):
            return {Origin(_DATA)}  # what you typed into the setup form
        if name == "config" and (_YAML_SETUP.match(fname) or "ConfigType" in ann):
            return {Origin(_DATA)}  # what you wrote in configuration.yaml
        if _DISCOVERY_NAME.match(name) or "ServiceInfo" in ann or "DiscoveryInfo" in ann:
            return {Origin(_FOUND)}
        if "ConfigEntry" in ann or (_ENTRY_NAME.search(name) and not ann):
            return {Origin(_ENTRY)}
        if name == "hass":
            return self._unk(fn, "hass")
        if self._hops >= _HOPS:
            self._cut("hops")
            return {_UNK}
        sites = self._callers(fn, sc)
        if not sites:
            # `api: Client` with no caller in this code: one of its own Client objects
            typed = {t for t in _TYPE_NAME.findall(ann) if self._class(t) is not None}
            if typed and len(typed) <= 2:
                return {Origin(_OBJ, t) for t in typed}
            default = _default(fn, name)
            if default is not None and not (
                isinstance(default, ast.Constant) and default.value is None
            ):
                return self._t(default, sc, lead, d)
            return self._unk(fn, f"no caller of {fname}({name})")
        self._hops += 1
        out: set[Origin] = set()
        try:
            method = sc.cls is not None and params[:1] in (["self"], ["cls"])
            pos = params[1:] if method else params
            for s in sites[:_FAN]:
                arg = _bound(s.call, pos, name)
                if arg is None:
                    default = _default(fn, name)
                    if default is not None:
                        out |= self._t(default, sc, lead, d)
                    continue
                out |= self._t(arg, self._scope(s.rel, s.fn, s.cls), lead, d)
        finally:
            self._hops -= 1
        return out or self._unk(fn, f"callers pass nothing for {name}")

    def _from_default(self, fn: ast.AST, name: str, sc: _Scope, lead: bool, d: int) -> set[Origin]:
        default = _default(fn, name)
        if default is None or (isinstance(default, ast.Constant) and default.value is None):
            return self._unk(fn, f"the app passes nothing for {name}")
        return self._t(default, sc, lead, d)

    def _callers(self, fn: ast.AST, sc: _Scope) -> list[_Site]:
        ix = self.index()
        fname = getattr(fn, "name", "")
        if fname == "__init__" and sc.cls is not None:
            if self._class(sc.cls.name) is None:
                return []
            names = [sc.cls.name, *[  # subclasses that keep this constructor
                c.name for lst in ix.classes.values() for _r, c in lst
                if any(_tail(b) == sc.cls.name for b in c.bases)
                and not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and n.name == "__init__" for n in c.body)
            ][:_FAN]]  # fmt: skip
            names += [a for n in names for a in sorted(ix.aliases.get(n, ()))[:_FAN]]
            # a subclass's `super().__init__(…)` (or `Base.__init__(self, …)`)
            supers = [s for s in ix.calls.get("__init__", [])
                      if s.cls is not None and isinstance(s.call.func, ast.Attribute)
                      and any(_tail(b) == sc.cls.name for b in s.cls.bases)
                      and ((isinstance(s.call.func.value, ast.Call)
                            and _call_name(s.call.func.value) == "super")
                           or _tail(s.call.func.value) == sc.cls.name)][:_FAN]  # fmt: skip
            return [s for n in names for s in ix.calls.get(n, [])] + supers
        defs = ix.funcs.get(fname, [])
        if len(defs) != 1 or fname.startswith("__"):
            # the name is defined more than once: only calls on `self` in the same class,
            # or for a module-level function, plain calls of the name (`login(self)` beside a
            # method `login`; `x.login()` is a method)
            if sc.cls is None:
                if fname.startswith("__"):
                    return []
                return [s for s in ix.calls.get(fname, [])
                        if isinstance(s.call.func, ast.Name)][:_FAN * 4]  # fmt: skip
            return [s for s in ix.calls.get(fname, []) if s.cls is sc.cls
                    and isinstance(s.call.func, ast.Attribute)
                    and getattr(s.call.func.value, "id", "") in ("self", "cls")]  # fmt: skip
        return list(ix.calls.get(fname, []))

    # --- calls ---------------------------------------------------------------------------

    def _call(self, x: ast.Call, sc: _Scope, lead: bool, d: int) -> set[Origin]:
        name = _call_name(x)
        f = x.func
        if name in _HA_FUNCS and not self.index().funcs.get(name):
            return {Origin(HA)}
        if name in _ENTRIES:
            return {Origin(_ENTRY)}
        is_request = (name in _REQUEST_CALLS and isinstance(f, ast.Attribute)) or name == "urlopen"
        if is_request and (site := self._request_site(x, sc, d)) is not None:
            return {Origin(_RESPONSE, "", site)}
        if name in _READ_BODY and isinstance(f, ast.Attribute):
            got = self._t(f.value, sc, True, d)
            if any(o.kind == _RESPONSE for o in got):
                return {o for o in got if o.kind == _RESPONSE}
            return got if not lead else {o if o.kind != SITE else _UNK for o in got}
        if name in ("get", "getattr", "pop", "setdefault") and x.args:
            obj, k = (x.args[0], x.args[1] if len(x.args) > 1 else None) if name == "getattr" \
                else (f.value if isinstance(f, ast.Attribute) else None, x.args[0])  # fmt: skip
            if obj is not None:
                got = self._read_key(obj, self._key(k, sc), sc, lead, d)
                rest = x.args[2:] if name == "getattr" else x.args[1:]
                for extra in rest[:1]:  # the default
                    got |= self._t(extra, sc, lead, d)
                return got
        if name == "format" and isinstance(f, ast.Attribute):
            text = self._text_of(f.value, sc)
            if text is not None:
                return self._parts(self._format_parts(text, x, list(x.args)), sc, lead, d)
        if name == "cast" and len(x.args) == 2:  # typing.cast(T, value) is the value
            return self._t(x.args[1], sc, lead, d)
        if name == "loads" and x.args:  # json.loads(await resp.text())
            return self._t(x.args[0], sc, lead, d)
        if name == "build" and isinstance(f, ast.Attribute) and _tail(f.value) == "URL":
            host = next((k.value for k in x.keywords if k.arg == "host"), None)
            return self._t(host, sc, lead, d) if host is not None else self._unk(x, "URL.build")
        if name == "urljoin" and x.args and lead:
            return self._t(x.args[0], sc, True, d)
        if name in _PASS:
            method = isinstance(f, ast.Attribute) and name not in ("str", "URL", "dict", "deepcopy")
            base = f.value if method else None  # type: ignore[union-attr]
            arg = base if base is not None else (x.args[0] if x.args else None)
            if name == "join" and base is not None and x.args:
                # "/".join([...]) is its list; URL(base).join(URL(path)) and
                # self.base_url.join(path) start with the base
                url = (_call_name(base) in ("URL", "build") if isinstance(base, ast.Call)
                       else bool(ADDRESS_ARG.search(_tail(base))))  # fmt: skip
                if not url:
                    arg = x.args[0]
            if arg is None:
                return set()
            return self._t(arg, sc, lead, d)
        own = self._own_def(x, sc)
        if own is not None:
            got = self._returns(own, lead, d)
            if any(o.kind == _RESPONSE and not o.site for o in got):
                site = self._site_passed(x, own, sc)  # a helper that takes the address
                got = {Origin(_RESPONSE, o.detail, site) if o.kind == _RESPONSE and not o.site
                       else o for o in got}  # fmt: skip
            return got
        if self._class(name) is not None:
            return {Origin(_OBJ, name)}  # one of the app's own objects
        if lib := self.library(x, sc):
            return {Origin(_LIB, lib)}  # made by a library
        if lead:
            return self._unk(x, f"call {name}")
        if name not in _CARRIES:  # another function's answer isn't what it was given
            return set()
        out: set[Origin] = set()  # an encoding or a wrapper of these values
        for a in [*x.args, *(k.value for k in x.keywords)][:_FAN]:
            out |= self._t(a, sc, False, d)
        if isinstance(f, ast.Attribute) and name in _CARRIES_SELF:
            out |= self._t(f.value, sc, False, d)
        return out

    def library(self, x: ast.Call, sc: _Scope) -> str:
        """The library package a call goes to (`VendorClient(…)` after `from vendor_api
        import VendorClient`, `vendor_api.Client(…)`), else ""."""
        libs = self.index().libs.get(sc.rel) or {}
        f = x.func
        head = f
        while isinstance(head, ast.Attribute):
            head = head.value
        if isinstance(head, ast.Name) and head.id in libs:
            return libs[head.id]
        return ""

    def handoffs(self) -> list[Handoff]:
        """Calls that give a library one of the app's setup logins or an address: the
        library does the connecting, and Barkley doesn't read inside libraries, so this is
        where following them ends. A call to a method of an object a library made counts
        too (`self.client.login(password)` after `self.client = VendorClient(…)`)."""
        from sniff_test.analyzers import py_requests

        ix = self.index()
        out: dict[tuple[str, str], Handoff] = {}
        left = _HANDOFF_TOTAL
        for sites in ix.calls.values():
            for s in sites:
                if len(out) >= _MAX_HANDOFFS or left <= 0:
                    break
                x = s.call
                if not (x.args or x.keywords) or _call_name(x) in _REQUEST_CALLS:
                    continue
                if not isinstance(x.func, ast.Attribute) and not isinstance(x.func, ast.Name):
                    continue
                sc = self._scope(s.rel, s.fn, s.cls)
                args = [*x.args, *(k.value for k in x.keywords)]
                words = " ".join([*(k.arg or "" for k in x.keywords),
                                  *(_short(a) for a in args[:_FAN])])  # fmt: skip
                if not _ARG_WORDS.search(words):
                    continue
                lib = self.library(x, sc)
                if not lib:
                    if not isinstance(x.func, ast.Attribute) or self._own_def(x, sc) is not None:
                        continue  # not a library's, or the app's own method
                    # a method of an object a library made (`self.client.login(pw)`)?
                    self._left, self._hops, self._busy = _HANDOFF_BUDGET, 0, set()
                    got = self._t(x.func.value, sc, True, 0)
                    left -= _HANDOFF_BUDGET - max(self._left, 0)
                    lib = next((o.detail for o in sorted(got) if o.kind == _LIB), "")
                    if not lib:
                        continue
                carried = self.carried(args, sc, _HANDOFF_BUDGET)
                left -= _HANDOFF_BUDGET - max(self._left, 0)
                ids, _tokens = logins(carried)
                addresses: list[tuple[str, tuple[Origin, ...]]] = []
                for k in x.keywords:
                    if k.arg and ADDRESS_ARG.search(k.arg):
                        got = tuple(self.address(k.value, sc, _HANDOFF_BUDGET))
                        left -= _HANDOFF_BUDGET - max(self._left, 0)
                        if any(o.kind != UNKNOWN for o in got):
                            addresses.append((k.arg[:_KEY_MAX], got))
                connects = _call_name(x)[:1].isupper() or _CONNECTS.search(_call_name(x))
                for a in x.args[:_FAN] if connects else []:  # `Device(host, token)`
                    got = tuple(self.address(a, sc, _HANDOFF_BUDGET))
                    left -= _HANDOFF_BUDGET - max(self._left, 0)
                    if any(o.kind in (SITE, LIST, DISCOVERY, HA) or (o.kind == SETUP
                           and ADDRESS_ARG.search(o.detail)) for o in got):  # fmt: skip
                        addresses.append(("", got))
                if not ids and not addresses:
                    continue
                if py_requests._SESSION.search(_tail(x.func)) and not ids:
                    continue
                key = (lib, _call_name(x))
                h = out.get(key)
                if h is None:
                    h = out[key] = Handoff(lib, _call_name(x)[:_KEY_MAX], at=f"{s.rel}:{x.lineno}")
                    h.method = isinstance(x.func, ast.Attribute) and not self.library(x, sc)
                h.logins = tuple(dict.fromkeys(h.logins + ids))
                # (py_library) what each argument holds, for reading inside the library
                named = [*((str(i), a, sc) for i, a in enumerate(x.args[:_FAN])
                           if not isinstance(a, ast.Starred)),
                         *((k.arg, k.value, sc) for k in x.keywords[:_FAN] if k.arg)]  # fmt: skip
                for k in x.keywords[:_FAN]:  # `**kwargs`: a dict the code spells out
                    for dct, dsc in self._dicts(k.value, sc) if k.arg is None else []:
                        for kk, vv in list(zip(dct.keys, dct.values, strict=False))[:_FAN]:
                            if kk is not None and (kn := self._key(kk, dsc)) not in ("", "\x00"):
                                named.append((kn[:_KEY_MAX], vv, dsc))
                for arg, value, vsc in named[: _FAN * 2]:
                    lead = self.address(value, vsc, _HANDOFF_BUDGET)
                    left -= _HANDOFF_BUDGET - max(self._left, 0)
                    held = self.carried([value], vsc, _HANDOFF_BUDGET)
                    left -= _HANDOFF_BUDGET - max(self._left, 0)
                    was = h.passed.get(arg, (frozenset(), frozenset()))
                    h.passed[arg] = (
                        was[0] | {o for o in lead if o.kind != UNKNOWN},
                        was[1] | {o for o in held if not o.kind.startswith("_")},
                    )
                for name, got in addresses:
                    if (name, got) not in h.addresses:
                        h.addresses.append((name, got))
        return sorted(out.values(), key=lambda h: (h.library, h.call))

    def _site_passed(self, x: ast.Call, df: _Def, sc: _Scope) -> str:
        """The site a call of the app's own request helper passes as the address: the
        argument for a parameter named like an address (url, endpoint, path…), when the
        code spells its site out; "" otherwise."""
        from sniff_test.analyzers import py_requests

        params = _params(df.fn)
        if params[:1] in (["self"], ["cls"]) and isinstance(x.func, ast.Attribute):
            params = params[1:]
        hosts = set()
        for name in params:
            if not py_requests._URLISH.search(name) and name != "path":
                continue
            arg = _bound(x, params, name)
            if arg is None:
                continue
            saved = self.reader._left
            try:
                host, *_ = py_requests._site(self.reader.address(arg, sc))
            finally:
                self.reader._left = saved
            if host:
                hosts.add(host)
        return hosts.pop() if len(hosts) == 1 else ""

    def _own_def(self, x: ast.Call, sc: _Scope) -> _Def | None:
        f = x.func
        if (
            isinstance(f, ast.Attribute)
            and isinstance(f.value, ast.Name)
            and f.value.id in ("self", "cls")
            and sc.cls is not None
        ):
            for node in sc.cls.body:
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == f.attr
                ):
                    return _Def(sc.rel, node, sc.cls)
            return None
        name = _call_name(x)
        defs = self.index().funcs.get(name, [])
        if len(defs) == 1 and not name.startswith("__"):
            return defs[0]
        return None

    def _returns(self, df: _Def, lead: bool, d: int) -> set[Origin]:
        if self._hops >= _HOPS:
            self._cut("hops")
            return {_UNK}
        self._hops += 1
        out: set[Origin] = set()
        try:
            inner = self._scope(df.rel, df.fn, df.cls)
            n = 0
            for node in ast.walk(df.fn):
                if isinstance(node, ast.Return) and node.value is not None:
                    n += 1
                    if n > _FAN:
                        break
                    out |= self._t(node.value, inner, lead, d)
        finally:
            self._hops -= 1
        return out or self._unk(df.fn, "returns nothing")

    def _request_site(self, x: ast.Call, sc: _Scope, d: int = 0) -> str | None:
        """The site of a request call whose answer the code reads ("" when the address
        isn't in the code), or None when the call isn't a request."""
        from sniff_test.analyzers import py_requests

        name = _call_name(x)
        url = x.args[1] if name == "request" and len(x.args) > 1 else (
            x.args[0] if x.args and name != "request" else None)  # fmt: skip
        if url is None:
            url = next((k.value for k in x.keywords if k.arg == "url"), None)
        if url is None:
            return None
        saved = self.reader._left
        try:
            host, *_ = py_requests._site(self.reader.address(url, sc))
        finally:
            self.reader._left = saved
        if host is None and name != "urlopen" and not py_requests._looks_like_request(x, url):
            return None
        if host is None:  # `f"{API_BASE}{endpoint}"`: the site it starts with names the answer
            got = self._t(url, sc, True, d)
            sites = {o.detail for o in got if o.kind == SITE}
            if len(sites) == 1 and all(o.kind == SITE for o in got):
                return sites.pop()
        return host or ""


@dataclass
class Handoff:
    library: str  # the package (as imported)
    call: str  # the function or class called
    logins: tuple[str, ...] = ()  # setup fields that are logins (with who-you-are ones)
    addresses: list[tuple[str, tuple[Origin, ...]]] = field(default_factory=list)  # (arg, from)
    at: str = ""  # file:line of the first such call
    method: bool = False  # a method of an object the library made (`client.login(pw)`)
    # (py_library) argument ("0", "1"… or its keyword) -> (where it comes from as an
    # address, where every piece of it comes from); not in the report
    passed: dict[str, tuple[frozenset[Origin], frozenset[Origin]]] = field(default_factory=dict)
    inside: dict[str, object] | None = None  # (py_library) what Barkley read inside it

    def as_dict(self) -> dict[str, object]:
        return {"library": self.library, "call": self.call, "logins": list(self.logins),
                "addresses": [{"arg": a, "from": [o.as_dict() for o in got]}
                              for a, got in self.addresses[:6]], "at": self.at,
                **({"inside": self.inside} if self.inside is not None else {})}  # fmt: skip


@dataclass
class Entry:
    """(py_library) A function of a library the app calls: `classes` for a constructor
    (the class called and the ones it inherits from), None for a plain function or, with
    `method`, a method of any of the library's classes."""

    func: str
    classes: frozenset[str] | None
    method: bool
    passed: dict[str, tuple[frozenset[Origin], frozenset[Origin]]]
    # a class with no constructor of its own (a dataclass, a pydantic model): its fields in
    # the order the made-up constructor takes them
    fields: tuple[str, ...] = ()

    def field(self, cls: ast.ClassDef | None, attr: str, lead: bool) -> frozenset[Origin] | None:
        """What the app passed for field `attr` (`self.attr` in the class), or None (not
        this entry's field, or not passed: the class's own default answers)."""
        if cls is None or self.classes is None or cls.name not in self.classes:
            return None
        if attr not in self.fields:
            return None
        key = attr if attr in self.passed else str(self.fields.index(attr))
        got = self.passed.get(key)
        if got is None:
            return None
        return (got[0] if lead else got[1]) or frozenset({_UNK})

    def value(self, fn: ast.AST, sc: _Scope, name: str, lead: bool) -> frozenset[Origin] | None:
        """What the app passed for parameter `name` of `fn` (empty: nothing, so the
        library's default), or None when `fn` isn't this entry."""
        if getattr(fn, "name", "") != self.func or (sc.cls is not None) != (
            self.method or self.classes is not None
        ):
            return None
        if self.classes is not None and (sc.cls is None or sc.cls.name not in self.classes):
            return None
        params = _params(fn)
        pos = params[1:] if sc.cls is not None and params[:1] in (["self"], ["cls"]) else params
        key = name if name in self.passed else (str(pos.index(name)) if name in pos else "")
        got = self.passed.get(key)
        if got is None:
            return frozenset()  # not passed: the library's own default
        return (got[0] if lead else got[1]) or frozenset({_UNK})  # passed, origin unknown


# --- what the page says -----------------------------------------------------------------


def logins(origins: list[Origin]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(setup fields that are logins, sites whose answer gives a token) among `origins`.
    Who-you-are fields (user name, email) are kept only beside a login."""
    setup = {o.detail.lower() for o in origins if o.kind == SETUP and o.detail}
    secret = sorted(f for f in setup if LOGIN_FIELD.search(f))
    ids = sorted(f for f in setup if ID_FIELD.search(f))
    tokens = sorted({o.site or "?" for o in origins
                     if o.kind == ANSWER and TOKEN_KEY.search(o.detail)})  # fmt: skip
    return (tuple(ids + secret) if secret else ()), tuple(tokens)
