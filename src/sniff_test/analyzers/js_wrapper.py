"""(0.14.0) `card-token-exfil` precision: same-origin URLs Semgrep's rule can't prove.

Read only, never run: every check here is Semgrep parsing the app's JavaScript or a text
read of it. A finding is dropped only when the URL the token goes to is proven to stay on
Home Assistant's own origin; anything unclear keeps it.

1. Template literals. `fetch(`/api/x/${id}`)` starts with a fixed "/" and a character
   that isn't "/" or "\\", so it can't leave the origin (the rule's regex only sees plain
   strings). `fetch(`${BASE}/x/${id}`)` is same-origin when Semgrep's own scoped
   constant propagation gives BASE a relative value (a shadowing parameter, a `let` that
   is reassigned, or an unknown name don't count).
2. Constants imported from another module of the app: `import { BASE } from
   "./constants.js"` where that file has exactly one `export const BASE = "/api/…"`.
3. Wrappers (a real integration scored 0 on this): the token is added inside a function
   whose URL is its first parameter, `async function fetchWithAuth(url, options) { …
   fetch(url, …) }`. Every call of that function in the app must pass a same-origin URL
   (forms 1 and 2, a plain relative string, or a relative constant + anything), the
   parameter must never be reassigned, and the function must not escape (passed as a
   value, stored on `window`, re-exported, imported under another name or through a
   namespace). Calls are looked up where the name is in scope: the same file, plus the
   files importing it when it's exported. A file that isn't module-scoped (no
   import/export, and not loaded as a module by the app) shares its top-level names with
   every script on the page, so its wrappers keep the finding. One wrapper calling
   another is followed up to three levels.
"""

from __future__ import annotations

import bisect
import functools
import itertools
import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from sniff_test.models import Finding

RULE = "card-token-exfil"
_JS = (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx")
_MAX_TEXT = 60_000_000
_IDENT = re.compile(r"^[A-Za-z_][\w]*$")  # no `$`: Semgrep would read it as a metavariable
_SAFE_START = re.compile(r"""^(?:["']/[^/\\]|`/[^/\\$`])""")
_SAME_ORIGIN = r'"=~/^\/[^\/\\]/"'
_DEPTH = 3

# Semgrep runner: (rules yaml text, files) -> results. Set by semgrep.run (sandboxed).
Runner = Callable[[str, list[Path]], list[dict]]


@dataclass
class Hit:
    finding: Finding
    path: Path
    start: int
    end: int


@dataclass
class _File:
    path: Path
    text: str
    module: bool
    fns: list[tuple[int, int, str, str]] = field(default_factory=list)  # start, end, F, P


# --- offsets: Semgrep counts bytes, Python strings count characters --------------------


class _Chars:
    """Byte offset -> character offset for UTF-8 text (a file with any non-ASCII
    character, an emoji in a log message, shifts every offset after it)."""

    def __init__(self, data: bytes):
        self._starts: list[int] = []  # byte offset where each multi-byte character starts
        self._extra: list[int] = []  # extra bytes up to and including that character
        extra = 0
        if not data.isascii():
            b = 0
            for ch in data.decode("utf-8", "replace"):
                n = len(ch.encode("utf-8"))  # probe copies are valid UTF-8
                if n > 1:
                    extra += n - 1
                    self._starts.append(b)
                    self._extra.append(extra)
                b += n

    def __call__(self, byte: int) -> int:
        k = bisect.bisect_left(self._starts, byte)
        return byte - (self._extra[k - 1] if k else 0)


def char_offset(data: bytes, byte: int) -> int:
    """One byte offset in `data` as a character offset of its 'replace' decoding."""
    return len(data[:byte].decode("utf-8", "replace"))


# --- reading call arguments as text ---------------------------------------------------


def _args(text: str, open_paren: int) -> list[tuple[int, int]]:
    """Offsets of each top-level argument of the call whose "(" is at `open_paren`."""
    out: list[tuple[int, int]] = []
    depth = 0
    i = open_paren + 1
    start = i
    stack: list[str] = []
    n = len(text)
    while i < n:
        c = text[i]
        if stack and stack[-1] == "`":
            if c == "\\":
                i += 2
                continue
            if c == "`":
                stack.pop()
            elif text.startswith("${", i):
                stack.append("{")
                i += 2
                continue
            i += 1
            continue
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if c == "`":
            stack.append("`")
        elif c in "([{":
            stack.append(c)
            depth += 1
        elif c in ")]}":
            if not stack:
                out.append((start, i))
                return [(a, b) for a, b in out if text[a:b].strip()]
            stack.pop()
            depth -= 1
        elif c == "," and not stack:
            out.append((start, i))
            start = i + 1
        i += 1
    return []


def _arg_text(text: str, span: tuple[int, int]) -> str:
    return text[span[0] : span[1]].strip()


def _url_arg(text: str, start: int, end: int) -> tuple[int, int] | None:
    """The URL argument of the sink matched at text[start:end]."""
    sink = text[start:end]
    m = re.match(
        r"(?:(?:window|self|globalThis)\.)?(fetch|navigator\.sendBeacon|open)\s*+\("
        r"|new\s++(?:WebSocket|EventSource)\s*+\("
        r"|[\w$.\[\]\"']+\.open\s*+\(",
        sink,
    )
    if not m:
        # (0.15) `img.src = url`: the value after the "="
        src = re.match(r"[\w$.\[\]\"']+\.src\s*+=(?!=)\s*+", sink)
        return (start + src.end(), end) if src else None
    args = _args(text, start + m.end() - 1)
    second = m.group(1) is None and not m.group(0).startswith("new")
    want = 1 if second else 0
    return args[want] if len(args) > want else None


# --- modules, imports, constants -----------------------------------------------------

_IMPORT = re.compile(r"""import\s*+\{([^}]*)\}\s*+from\s*+["'](\.{1,2}/[^"']+)["']""")
_NS_IMPORT = re.compile(r"""import\s*+\*\s*+as\s++[\w$]+\s++from\s*+["'](\.{1,2}/[^"']+)["']""")
_DYN_IMPORT = re.compile(r"""import\s*+\(\s*+["'`](\.{1,2}/[^"'`]+)""")
_REEXPORT = re.compile(r"""export\s*+(?:\*|\{[^}]*\})\s*+from\s*+["'](\.{1,2}/[^"']+)["']""")
_ESM = re.compile(r"^[ \t]*+(?:import\s*+[\w{*\"']|export\s)", re.M)


def _resolve(root: Path, frm: Path, spec: str) -> Path | None:
    base = (frm.parent / spec.split("?")[0]).resolve()
    for cand in (base, base.with_suffix(base.suffix + ".js"), base / "index.js"):
        try:
            cand.relative_to(root)
        except ValueError:
            return None
        if cand.is_file() and not cand.is_symlink():
            return cand
    return None


def _specifiers(block: str) -> list[tuple[str, str]]:
    out = []
    for part in block.split(","):
        bits = part.strip().split()
        if not bits:
            continue
        if len(bits) == 3 and bits[1] == "as":
            out.append((bits[0], bits[2]))
        elif len(bits) == 1:
            out.append((bits[0], bits[0]))
    return out


_PARAMS = (
    re.compile(r"function\s*+\*?\s*+[\w$]*+\s*+\(([^()]*+)\)"),
    re.compile(r"\(([^()]*+)\)\s*+=>"),
    re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*+)\s*+=>"),
    re.compile(
        r"(?m)^[ \t]*+(?:static\s++|async\s++|get\s++|set\s++)*"
        r"(?!(?:if|for|while|switch|catch|with|return|function)\b)[\w$]+\s*+\(([^()]*+)\)\s*+\{"
    ),
    re.compile(r"catch\s*+\(([^()]*+)\)"),
)


def _binds(text: str, name: str) -> bool:
    """`name` declared in this file (a local of that name would shadow an import): a
    declaration, a parameter of any function, arrow or method, a catch variable, or a
    destructuring."""
    n = re.escape(name)
    text = _IMPORT.sub("", text)  # `import { NAME } from …` is the binding we expect
    if name in destructured(text):
        return True
    if re.search(rf"\b(?:const|let|var|function|class)\s++{n}\b", text):
        return True
    return any(name in _NAME.findall(m.group(1)) for rx in _PARAMS for m in rx.finditer(text))


class _Index:
    def __init__(self, root: Path):
        self.root = root
        self._texts: dict[Path, str] = {}
        self._loaded_as_module: set[str] | None = None
        self.card = False
        # (0.14.1) visible() per scope: hundreds of calls in one bundle see a handful of
        # scopes, and each view of a 1 MB file took tens of milliseconds to build.
        self._scopes: dict[Path, list[tuple[int, int, int]]] = {}
        self._views: dict[tuple[Path, tuple[int, ...]], tuple[str, frozenset[str]]] = {}

    def text(self, path: Path) -> str:
        if path not in self._texts:
            try:
                data = path.read_bytes()[:_MAX_TEXT] if path.stat().st_size < _MAX_TEXT else b""
            except OSError:
                data = b""
            self._texts[path] = data.decode("utf-8", "replace")
        return self._texts[path]

    def js_files(self) -> list[Path]:
        return sorted(
            p
            for p in self.root.rglob("*")
            if p.suffix in _JS and p.is_file() and not p.is_symlink()
        )[:5000]

    def module_names(self) -> set[str]:
        """File names the app loads as a module: `<script type="module" src=…>`, a panel's
        `module_url`, or `import(…)`."""
        if self._loaded_as_module is None:
            found: set[str] = set()
            for p in sorted(self.root.rglob("*"))[:20000]:
                if (
                    p.suffix not in (".html", ".htm", ".py", *_JS)
                    or not p.is_file()
                    or p.is_symlink()
                ):
                    continue
                t = self.text(p)
                for m in re.finditer(r"<script\b[^>]*>", t, re.I):
                    tag = m.group(0)
                    src = re.search(r"""src\s*+=\s*+["']([^"']+)["']""", tag, re.I)
                    if src and re.search(r"""type\s*+=\s*+["']module["']""", tag, re.I):
                        found.add(src.group(1).split("?")[0].rsplit("/", 1)[-1])
                for m in re.finditer(r"""module_url\s*+[=:]\s*+f?["']([^"']+)["']""", t):
                    found.add(m.group(1).split("?")[0].rsplit("/", 1)[-1])
            self._loaded_as_module = found
        return self._loaded_as_module

    def trusted(self, path: Path, arg: str, at: int) -> bool:
        """propagation_trusted, judged on the code that can see offset `at`: every
        function (parameters and body) that doesn't contain `at` is blanked out first, so
        a minified bundle's unrelated `({i}) => …` elsewhere doesn't count."""
        text, names = self._view(path, at)
        return propagation_trusted(text, arg, names, at)

    def _view(self, path: Path, at: int) -> tuple[str, frozenset[str]]:
        """visible(text, at) and its destructured names, built once per scope."""
        full = self.text(path)
        if path not in self._scopes:
            self._scopes[path] = _functions(full)
        fns = self._scopes[path]
        key = (path, tuple(i for i, (bs, be, _cs) in enumerate(fns) if bs <= at < be))
        if key not in self._views:
            if len(self._views) >= _MAX_VIEWS:
                self._views.pop(next(iter(self._views)))
            text = _blank(full, fns, at)
            self._views[key] = (text, destructured(text))
        return self._views[key]

    def is_module(self, path: Path) -> bool:
        if self.card or _ESM.search(self.text(path)):
            return True
        return path.name in self.module_names()

    def imported_const(self, path: Path, name: str) -> str | None:
        """The value of `name` when this file imports it from another module of the app
        that has exactly one `export const name = "…"`."""
        text = self.text(path)
        hits = []
        for m in _IMPORT.finditer(text):
            for orig, local in _specifiers(m.group(1)):
                if local == name:
                    hits.append((orig, m.group(2)))
        if len(hits) != 1 or _binds(text, name):
            return None
        orig, spec = hits[0]
        src = _resolve(self.root, path, spec)
        if src is None:
            return None
        st = self.text(src)
        vals = re.findall(
            rf"""export\s+const\s+{re.escape(orig)}\s*=\s*+(["'])((?:(?!\1)[^\\\n])*)\1\s*[;,\n]""",
            st,
        )
        if len(vals) == 1 and not re.search(rf"export\s++(?:let|var)\s++{re.escape(orig)}\b", st):
            return vals[0][1]
        return None


_STRING_NAMES = re.compile(
    r"""(?:\b(?:const|let|var)\s++|[,;{(]\s*+|^[ \t]*+)([A-Za-z_$][\w$]*+)\s*+=\s*+["'`]""", re.M
)
_DESTRUCTURE = (
    # const {C} = …  /  let [C] = …  (also `for (const {C} of …)`)
    re.compile(r"\b(?:const|let|var)\s*+([{\[][^;=]*?[}\]])\s*+(?:=|of\b|in\b)"),
    # ({C} = obj)  /  [C] = arr   (an assignment, not a comparison or an arrow). A bracket
    # right after a name, `)` or `]` is a property access (`n[e] = o`), not a pattern.
    re.compile(r"(?<![\w$)\]])([{\[][^{}\[\]()=;]*+[}\]])\s*+=(?![=>])"),
)
_NAME = re.compile(r"[A-Za-z_$][\w$]*+")


# What blanked code is filled with: not whitespace, a word character or punctuation, so no
# pattern here can match inside it or run along it. Spaces made `\s*` runs of 100 000+
# characters in minified bundles, and a pattern with several of them back to back took
# minutes per call while holding the interpreter (a real card froze the panel, 0.14.0).
_FILL = "\x01"


_MAX_VIEWS = 16


def visible(text: str, at: int) -> str:
    """`text` with every function that doesn't contain offset `at` blanked (same length):
    its parameter list and its `{…}` body, for `function (…) {…}`, methods and arrows
    with a block body. What's left is the scope chain around `at` (plus expression-bodied
    arrows, which only make the check stricter)."""
    return _blank(text, _functions(text), at)


def _functions(text: str) -> list[tuple[int, int, int]]:
    """Every function body in `text` as (body start, body end, cut start): the `{…}`
    after `)` or `=>`, cut from its parameter list on."""
    from sniff_test.report.fingerprint import _parsed

    toks, braces = _parsed(text)
    parens: dict[int, int] = {}
    stack: list[int] = []
    for i, (_k, v, _o) in enumerate(toks):
        if v == "(":
            stack.append(i)
        elif v == ")" and stack:
            parens[i] = stack.pop()
    out: list[tuple[int, int, int]] = []
    for open_i, close_i in braces.items():
        if open_i == 0:
            continue
        start, end = toks[open_i][2], toks[close_i][2] + 1
        prev = toks[open_i - 1][1]
        if prev == ")" and (open_i - 1) in parens:
            cut = toks[parens[open_i - 1]][2]
        elif prev == "=>" and open_i >= 2:
            q = open_i - 2
            cut = toks[parens[q]][2] if toks[q][1] == ")" and q in parens else toks[q][2]
        else:
            continue
        out.append((start, end, cut))
    return out


def _blank(text: str, fns: list[tuple[int, int, int]], at: int) -> str:
    cut = sorted((c, end) for start, end, c in fns if not start <= at < end)
    if not cut:
        return text
    out, pos = [], 0
    for a, b in cut:
        if b <= pos:
            continue
        a = max(a, pos)
        out.append(text[pos:a])
        out.append(re.sub(r"[^\n]", _FILL, text[a:b]))
        pos = b
    out.append(text[pos:])
    return "".join(out)


def destructured(text: str) -> frozenset[str]:
    """Names a destructuring may bind in this file: in a parameter list (`({C}) =>`,
    `function f(a, [C])`, a method's), a declaration (`const {C} = p`), an assignment
    pattern (`[C] = arr`) or `catch ({C})`. An object or array literal passed as an
    argument isn't one."""
    out: set[str] = set()
    for rx in _DESTRUCTURE:
        for m in rx.finditer(text):
            out.update(_NAME.findall(m.group(1)))
    for rx in _PARAMS:
        for m in rx.finditer(text):
            for d in re.finditer(r"[{\[][^{}\[\]]*[}\]]", m.group(1)):
                out.update(_NAME.findall(d.group(0)))
    return frozenset(out)


_LEAD = re.compile(r"^\s*+(?:`\$\{\s*+([A-Za-z_$][\w$]*+)\s*+\}|([A-Za-z_$][\w$]*+))")


def propagation_trusted(
    text: str, arg: str, names: frozenset[str], at: int | None = None, depth: int = 0
) -> bool:
    """Whether a Semgrep proof of `arg` (used at offset `at`) can be trusted. Semgrep
    1.185's constant propagation doesn't see a destructured binding as shadowing
    (`({C}) => fetch(C + "/x")` read C as an outer "/api/…"), so the proof is refused when
    the name the URL starts with may be bound by a destructuring in `text` (the code that
    can see the call: js_wrapper.visible), or when the value last assigned to that name
    before the call starts with such a name (followed three levels)."""
    m = _LEAD.match(arg)
    if not m:
        return True  # starts with a literal
    name = m.group(1) or m.group(2)
    if name in names:
        return False
    if depth >= 3:
        return False
    before = text if at is None else text[:at]
    last = None
    for a in re.finditer(
        rf"(?<![\w$.]){re.escape(name)}\s*+=(?![=>])\s*+([^;\n]{{0,200}})", before
    ):
        last = a
    if last is None:
        return True
    return propagation_trusted(text, last.group(1), names, last.start(1), depth + 1)


def _relative(value: str) -> bool:
    return bool(re.match(r"^/[^/\\]", value))


def _text_safe(arg: str, index: _Index, path: Path) -> bool:
    """Same-origin by its text: a relative literal, a relative template literal, or an
    imported relative constant at the start (alone, `+ …`, `.concat(…)`, `${C}…`)."""
    if _SAFE_START.match(arg):
        return True
    m = re.match(
        r"^(?:`\$\{\s*+([A-Za-z_$][\w$]*+)\s*+\}|([A-Za-z_$][\w$]*+)\s*+(?:\+|\.concat\s*+\(|$))",
        arg,
    )
    if not m:
        return False
    name = m.group(1) or m.group(2)
    value = index.imported_const(path, name)
    return value is not None and _relative(value)


# --- Home Assistant's own origin (0.15, the 600-app batch) -------------------------------
#
# Four of 600 real cards were read as stealing the login token because the URL is built
# from Home Assistant's own address in a way the rule can't follow in minified code:
# `const a = cond ? hass.connection.options.url.replace(/^ws/, "http") : hass.hassUrl();
#  const o = `${a.replace(/\/$/, "")}/api/upload`; fetch(o, {headers: {Authorization: …}})`.
# A URL is HA's own when every way it can be built starts with HA's origin (or is
# relative) and anything appended after an origin starts with "/", "?" or "#" (an origin
# followed by "@evil.example" would move the host). Names are followed back only to their
# assignments inside the block that encloses the use, never past a parameter of the same
# name, and only when every value it is given is HA's own; anything unclear keeps the
# finding. Every scan is bounded (`_HA_WINDOW`, `_HA_SEARCH`, `_HA_DEPTH`, `_HA_STEPS`).

_HA_WINDOW = 4000  # longest expression read
_HA_SEARCH = 60000  # how far back a name's assignments are looked for
_HA_SEEN = 64  # assignment-like matches of one name in the window
_HA_DEFS = 8  # more assignments to one name than this: not proven
_HA_DEPTH = 10
_HA_STEPS = 200  # name lookups and splits per URL, so a chain of names can't blow up
_LOC = r"(?:(?:window|self|globalThis|document)\.)?location"
_ORIGIN_EXPR = re.compile(
    # dotted names: a match starts only where a name starts, each part is possessive (it
    # ends at a "." anyway) and the parts are bounded, so nothing backtracks far
    rf"(?<![\w$.])(?:{_LOC}\.origin|document\.baseURI"
    r"|[\w$]++(?:\.[\w$]++){0,4}?\.connection\.options\.url"
    r"|[\w$]++(?:\.[\w$]++){0,4}?\.config\.(?:external|internal)_url"
    # (0.15) HA's own address in its login data, and the websocket address HA's
    # websocket library builds from it (`auth.wsUrl`); `hassUrl(…)` is read by `_hass_url`
    r"|[\w$]++(?:\.[\w$]++){0,4}?\.auth\.data\.hassUrl"
    r"|[\w$]++(?:\.[\w$]++){0,4}?\.auth\.wsUrl)$"
)
_ORIGIN_TEMPLATE = re.compile(rf"^`\$\{{{_LOC}\.protocol\}}//\$\{{{_LOC}\.host\}}")
# (0.15) `${scheme}//${location.host}` where `scheme` is a name holding "ws:"/"wss:"/…
_SCHEME_TEMPLATE = re.compile(rf"^`\$\{{([A-Za-z_$][\w$]*+)\}}//\$\{{{_LOC}\.host\}}")
_SCHEME = re.compile(r"""^(["'`])(?:https?|wss?):\1$""")
_ORIGIN_CONCAT = re.compile(
    rf"^{_LOC}\.protocol\s*+\+\s*+([\"'])//\1\s*+\+\s*+{_LOC}\.host(?![\w$.])"
)
# What may follow an origin and still mean that origin: trimming a trailing slash, or
# turning HA's websocket address into its http one.
_ORIGIN_TAIL = re.compile(
    r"\.replace\s*+\(\s*+/(?:\\/\+?\$|\^wss?|\^https?)/[gi]*+\s*+,\s*+([\"'`])(?:|https?|wss?)\1\s*+\)$"
)


def _scan_top(expr: str, want: str) -> list[int]:
    """Offsets of `want` (one of "?", ":", "||", "??", "+", ",", ";") at the top level of
    `expr`: outside brackets, strings, templates and regex-free text. One pass."""
    out: list[int] = []
    stack: list[str] = []
    i, n = 0, len(expr)
    while i < n:
        c = expr[i]
        if stack and stack[-1] == "`":
            if c == "\\":
                i += 2
                continue
            if c == "`":
                stack.pop()
            elif expr.startswith("${", i):
                stack.append("{")
                i += 2
                continue
            i += 1
            continue
        if c in "\"'":
            j = i + 1
            while j < n and expr[j] != c:
                j += 2 if expr[j] == "\\" else 1
            i = j + 1
            continue
        if c == "`":
            stack.append("`")
        elif c in "([{":
            stack.append(c)
        elif c in ")]}":
            if stack:
                stack.pop()
        elif not stack and expr.startswith(want, i):
            out.append(i)
            i += len(want)
            continue
        i += 1
    return out


def _unwrap(expr: str) -> str:
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")") and _closing(expr, 0) == len(expr) - 1:
        expr = expr[1:-1].strip()
    return expr


def _closing(expr: str, at: int) -> int:
    """Offset of the bracket that closes the one at `at`, or -1."""
    depth = 0
    for i in range(at, len(expr)):
        if expr[i] in "([{":
            depth += 1
        elif expr[i] in ")]}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _template_parts(expr: str) -> tuple[str, str] | None:
    """For a template literal that starts with `${X}`: (X, the text right after it)."""
    if not expr.startswith("`${"):
        return None
    end = _closing(expr, 2)
    if end < 0:
        return None
    return expr[3:end], expr[end + 1 :]


def _path_after_origin(rest: str) -> bool:
    """May `rest` follow an origin? Nothing, or text that starts with "/", "?" or "#"."""
    rest = rest.lstrip()
    return rest in ("", "`") or rest[0] in "/?#" or rest.startswith(("`/", "`?", "`#"))


class _HaContext:
    """Where a name is used: the file text, the use offset and the enclosing function."""

    def __init__(
        self,
        text: str,
        at: int,
        fn: tuple[int, int, str] | None,
        assume: frozenset[str] = frozenset(),
    ) -> None:
        self.text, self.at, self.fn = text, at, fn
        self.steps = 0
        self._base = -1
        self._depth: list[int] = []
        self._floor: list[int] = []
        # (0.15) Parameters of the enclosing helper taken as same-origin for now; the
        # ones the proof leaned on are recorded with how they were used ("url": the
        # whole address, "path": what follows an origin), and every call of the helper
        # must then pass a value that is that (`_helper_safe`).
        self.assume = assume
        self.used: dict[str, str] = {}

    def encloses(self, pos: int) -> bool:
        """Is the block that holds offset `pos` still open at the use? (Counted once per
        URL over the search window: depth at each offset, and the lowest depth after it.)"""
        if self._base < 0:
            self._base = max(0, self.at - _HA_SEARCH)
            depth, out = 0, []
            for c in self.text[self._base : self.at]:
                depth += (c == "{") - (c == "}")
                out.append(depth)
            floor, low = [0] * len(out), depth
            for i in range(len(out) - 1, -1, -1):
                low = min(low, out[i])
                floor[i] = low
            self._depth, self._floor = out, floor
        i = pos - self._base
        return 0 <= i < len(self._depth) and self._floor[i] >= self._depth[i]


def _assignments(name: str, ctx: _HaContext) -> list[str] | None:
    """Every value `name` is given before `ctx.at`, in a block that encloses the use; None
    when there is none, when it is also changed another way (`+=`, `++`), or when a
    parameter of that name shadows it."""
    if not _IDENT.match(name) or name in ("window", "location", "document", "self"):
        return None
    lo = max(0, ctx.at - _HA_SEARCH)
    esc = re.escape(name)
    if ctx.fn is not None and re.search(rf"(?<![\w$]){esc}(?![\w$])", ctx.fn[2]):
        # A parameter of the enclosing function, unless a block around the use declares
        # its own (`let e = "";` inside a `try`): read from there. (A name from around
        # the function, a closure, is fine: any parameter of that name in between is
        # refused below, and every other assignment must be HA's too.)
        inner = max(lo, ctx.fn[0])
        decl = list(re.finditer(rf"(?<![\w$.])(?:let|const|var)\s++{esc}\s*+=(?![=>])",
                                ctx.text[inner : ctx.at]))  # fmt: skip
        if not decl:
            return None
        lo = inner + decl[-1].start()
    window = ctx.text[lo : ctx.at]
    # The assignments that can set the value used: those in a block still open at the use
    # (not another function's), and, after the first of them, any plain assignment in a
    # block that has closed since (`if (c) { o = u }` still changes o); only a fresh
    # `let`/`const` in a closed block is a different variable.
    found = list(
        itertools.islice(re.finditer(rf"(?<![\w$.]){esc}\s*+=(?![=>])", window), _HA_SEEN + 1)
    )
    if len(found) > _HA_SEEN:
        return None  # a name assigned this often in reach isn't worth proving
    open_ = [d for d in found if ctx.encloses(lo + d.start())]
    # the innermost declaration still open at the use shadows every one before it
    decls = [
        d
        for d in open_
        if re.search(r"(?:let|const|var)\s++$", window[max(0, d.start() - 12) : d.start()])
    ]
    if decls:
        open_ = [d for d in open_ if d.start() >= decls[-1].start()]
    if not open_:
        return None
    first = open_[0].start()
    if re.search(
        rf"(?<![\w$.]){esc}\s*+(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)=|\+\+\s*+{esc}(?![\w$])"
        rf"|(?<![\w$.]){esc}\s*+\+\+",
        window[first:],
    ):
        return None
    defs = [
        d
        for d in found
        if d in open_
        or (
            d.start() > first
            and not re.search(r"(?:let|const)\s++$", window[max(0, d.start() - 12) : d.start()])
        )
    ]
    if len(defs) > _HA_DEFS:
        return None
    between = window[first:]
    # a parameter of a function defined between the first assignment and the use, or
    # the name taken out of an array or object (`const [C] = p`, `({ C }) => …`)
    if re.search(rf"(?:\[|(?<!\$)\{{|,)\s*+(?:\.\.\.)?{esc}\s*+[,\]}}]", between) or re.search(
        # an arrow's parameter: `(o) =>`, `(a, o, b) =>`, `(o = 1) =>`; not `f(o), v = m =>`
        rf"(?<![\w$.]){esc}\s*+=>"
        rf"|[(,]\s*+{esc}\s*+(?:\)|,[^;{{]{{0,200}}?\)|=[^;{{]{{0,200}}?)\s*+=>"
        # (0.15) a `function` keyword, not the word inside a string (`typeof f ===
        # "function" ? f(url) : …` read `url` as a parameter, a real card)
        # (0.15) a catch variable or a loop variable of that name
        rf"|(?<![\w$.])catch\s*+\(\s*+{esc}\s*+\)"
        rf"|(?<![\w$.])for\s*+\(\s*+(?:const|let|var)\s++{esc}\s++(?:of|in)(?![\w$])"
        rf"|(?<![\w$\"'`])function\s*+\*?\s*+[\w$]{{0,80}}\s*+\([^)]{{0,200}}(?<![\w$]){esc}(?![\w$])",
        between,
    ):
        return None
    values = []
    for d in defs:
        rhs = window[d.end() : d.end() + _HA_WINDOW]
        ends = sorted(_scan_top(rhs, ",") + _scan_top(rhs, ";"))
        value = (rhs[: ends[0]] if ends else rhs).strip()
        if not value:
            return None
        values.append(value)
    return values


def _ha_url(expr: str, ctx: _HaContext, depth: int = 0) -> bool:
    """Does the URL `expr` stay on Home Assistant's own origin, every way it can be built?"""
    ctx.steps += 1
    if depth > _HA_DEPTH or len(expr) > _HA_WINDOW or ctx.steps > _HA_STEPS:
        return False
    expr = _unwrap(expr)
    if expr in ('""', "''", "``") or _SAFE_START.match(expr):
        return True
    q = _scan_top(expr, "?")
    if q and not expr.startswith("?", q[0] + 1) and not expr.startswith(".", q[0] + 1):
        colon = [c for c in _scan_top(expr, ":") if c > q[0]]
        if not colon:
            return False
        return _ha_url(expr[q[0] + 1 : colon[0]], ctx, depth + 1) and _ha_url(
            expr[colon[0] + 1 :], ctx, depth + 1
        )
    for op in ("||", "??"):
        parts = _scan_top(expr, op)
        if parts:
            starts = [0, *(p + len(op) for p in parts)]
            ends = [*parts, len(expr)]
            return all(
                _ha_url(expr[a:b], ctx, depth + 1) for a, b in zip(starts, ends, strict=True)
            )
    if (m := _ORIGIN_TEMPLATE.match(expr)) is not None:
        return _after_origin(expr[m.end() :], ctx)
    if (m := _SCHEME_TEMPLATE.match(expr)) is not None and _scheme(m.group(1), ctx, depth):
        return _after_origin(expr[m.end() :], ctx)
    tpl = _template_parts(expr)
    if tpl is not None:
        head, rest = tpl
        if _rel(head, ctx, depth + 1):
            return True  # "/x…" and anything after it stays relative
        return _ha_base(head, ctx, depth + 1) and _after_origin(rest, ctx)
    if (m := _ORIGIN_CONCAT.match(expr)) is not None:
        tail = expr[m.end() :].strip()
        return tail == "" or (tail.startswith("+") and _literal_path(tail[1:]))
    plus = _scan_top(expr, "+")
    if plus:
        head, rest = expr[: plus[0]], expr[plus[0] + 1 :]
        if _SAFE_START.match(_unwrap(head)) or _rel(head, ctx, depth + 1):
            return True
        return _ha_base(head, ctx, depth + 1) and (_literal_path(rest) or _assumed_path(rest, ctx))
    return _ha_base(expr, ctx, depth + 1)


def _literal_path(rest: str) -> bool:
    """Does `rest` (what is added after an origin) start with a literal "/", "?" or "#"?"""
    rest = rest.strip()
    return len(rest) > 1 and rest[0] in "\"'`" and rest[1] in "/?#"


def _after_origin(rest: str, ctx: _HaContext) -> bool:
    """`_path_after_origin`, or (0.15) a template part `${p}…` where `p` is a parameter of
    the helper taken as a path for now (`fetch(`${base}${path}`)`)."""
    if _path_after_origin(rest):
        return True
    m = _LEAD_PARAM.match(rest)
    return m is not None and _assumed_path(m.group(1), ctx)


_LEAD_PARAM = re.compile(r"^\$\{\s*+([A-Za-z_][\w]*+)\s*+\}")


def _assumed_path(expr: str, ctx: _HaContext) -> bool:
    expr = _unwrap(expr)
    plus = _scan_top(expr, "+")
    if plus:
        expr = _unwrap(expr[: plus[0]])
    if _IDENT.match(expr) and _assumed(expr, ctx):
        ctx.used[expr] = "path"
        return True
    return False


def _assumed(name: str, ctx: _HaContext) -> bool:
    """`name` is a parameter taken as HA's for now, and at the use it still is that
    parameter: no declaration of the name (`let`, `const`, `var`, a loop or catch
    variable, a destructuring) in a block open at the use, inside the function."""
    if name not in ctx.assume:
        return False
    lo = ctx.fn[0] if ctx.fn else max(0, ctx.at - _HA_SEARCH)
    window = ctx.text[lo : ctx.at]
    n = re.escape(name)
    for m in itertools.islice(
        re.finditer(
            rf"(?<![\w$.])(?:let|const|var)\s++(?:[^;=]{{0,200}}?[,{{\[]\s*+)?{n}(?![\w$])"
            rf"|(?<![\w$.])catch\s*+\(\s*+{n}\s*+\)",
            window,
        ),
        _HA_SEEN + 1,
    ):
        if ctx.encloses(lo + m.start()):
            return False
    return True


def _rel(expr: str, ctx: _HaContext, depth: int) -> bool:
    """(0.15) Is `expr` a relative address ("/" then neither "/" nor "\\"), every way it
    can be built? Anything appended to such a start stays on the page's own origin."""
    ctx.steps += 1
    if depth > _HA_DEPTH or len(expr) > _HA_WINDOW or ctx.steps > _HA_STEPS:
        return False
    expr = _unwrap(expr)
    if _SAFE_START.match(expr):
        return True
    tpl = _template_parts(expr)
    if tpl is not None:
        return _rel(tpl[0], ctx, depth + 1)
    plus = _scan_top(expr, "+")
    if plus:
        return _rel(expr[: plus[0]], ctx, depth + 1)
    if _IDENT.match(expr):
        if _assumed(expr, ctx):
            ctx.used[expr] = "path"
            return True
        values = _assignments(expr, ctx)
        return values is not None and all(_rel(v, ctx, depth + 1) for v in values)
    value = _static_value(ctx.text, expr)
    return value is not None and _rel(value, ctx, depth + 1)


def _scheme(name: str, ctx: _HaContext, depth: int) -> bool:
    """`name` holds only a URL scheme ("ws:", "https:", …) or the page's own."""
    if re.fullmatch(rf"{_LOC}\.protocol", name):
        return True
    if not _IDENT.match(name):
        return False
    values = _assignments(name, ctx)
    if not values:
        return False
    for v in values:
        v = _unwrap(v)
        q = _scan_top(v, "?")
        if q:
            colon = [c for c in _scan_top(v, ":") if c > q[0]]
            if not colon:
                return False
            parts = [v[q[0] + 1 : colon[0]], v[colon[0] + 1 :]]
        else:
            parts = [v]
        if not all(_SCHEME.match(_unwrap(x)) or _scheme(_unwrap(x), ctx, depth + 1)
                   for x in parts if depth < _HA_DEPTH):  # fmt: skip
            return False
    return True


_HASS_URL_CALL = re.compile(r"^[\w$]++(?:\.[\w$]++){0,4}?\.hassUrl\s*+\(")


def _hass_url(expr: str, ctx: _HaContext, depth: int) -> bool | None:
    """(0.15) `hass.hassUrl(path)` is HA's address with `path` added: HA's own when the
    path is empty or starts with "/", "?" or "#" (else "@other.host/" could follow the
    address). None when `expr` isn't such a call. (Read by brackets: a nested "(" in the
    path made the old pattern miss it, two real cards.)"""
    m = _HASS_URL_CALL.match(expr)
    if m is None or _closing(expr[:_HA_WINDOW], m.end() - 1) != len(expr) - 1:
        return None
    inner = _unwrap(expr[m.end() : -1])
    if inner == "" or _literal_path(inner) or _assumed_path(inner, ctx):
        return True
    if _IDENT.match(inner):
        values = _assignments(inner, ctx)
        return values is not None and all(_literal_path(v) for v in values)
    return False


_DOTTED = re.compile(r"^([A-Za-z_][\w]*+)((?:\.[A-Za-z_$][\w$]*+){1,5})$")


def _ha_base(expr: str, ctx: _HaContext, depth: int) -> bool:
    """Is `expr` Home Assistant's origin, or a URL on it (so a path may follow)?"""
    ctx.steps += 1
    if depth > _HA_DEPTH or ctx.steps > _HA_STEPS:
        return False
    expr = _unwrap(expr)
    while (m := _ORIGIN_TAIL.search(expr)) is not None:
        expr = _unwrap(expr[: m.start()])
    if _ORIGIN_EXPR.match(expr):
        return True
    if (m := _ORIGIN_CONCAT.match(expr)) is not None and not expr[m.end() :].strip():
        return True
    if (m := _ORIGIN_TEMPLATE.match(expr)) is not None:
        return _path_after_origin(expr[m.end() :])
    if (m := _SCHEME_TEMPLATE.match(expr)) is not None and _scheme(m.group(1), ctx, depth):
        return _path_after_origin(expr[m.end() :])
    if (h := _hass_url(expr, ctx, depth)) is not None:
        return h
    if _guarded(expr, ctx):
        return True
    if _IDENT.match(expr):
        if _assumed(expr, ctx):
            ctx.used.setdefault(expr, "url")
            return True
        values = _assignments(expr, ctx)
        return values is not None and all(_ha_url(v, ctx, depth + 1) for v in values)
    value = _static_value(ctx.text, expr)
    if value is not None:
        return _ha_url(value, ctx, depth + 1)
    if (m := _DOTTED.match(expr)) is not None and m.group(1) not in ctx.assume:
        # `e.wsUrl` where `e = t.auth`: the name read as the value it was given
        values = _assignments(m.group(1), ctx)
        if values and all(_DOTTED.match(_unwrap(v)) or _IDENT.match(_unwrap(v)) for v in values):
            return all(_ha_base(_unwrap(v) + m.group(2), ctx, depth + 1) for v in values)
        return False
    return _ha_url(expr, ctx, depth + 1)


# --- (0.15) guards, static constants -----------------------------------------------------
#
# From the full Marketplace run: a token sent only after the code has checked the address
# is a relative path (`if (!bg.startsWith("/media/")) return;`, a flag `const local =
# String(u).startsWith("/api/x/")` then `if (local) {…}`) or on the page's own origin
# (`if (new URL(u).origin !== location.origin) return null;`). A check counts only in
# code (not in a comment or a string), in a block still open at the use, with the
# address never given another value after it. The prefix must be "/" and a character
# that isn't "/" or "\\" ("/" alone lets "//other.host" through: that stays a finding).

_GUARD_SUBJECT = re.compile(
    r"^(?:String\s*+\(\s*+)?([A-Za-z_$][\w$]*+(?:\??\.[A-Za-z_$][\w$]*+){0,5})(?:\s*+\))?$"
)
_IF = re.compile(r"(?<![\w$.])if\s*+\(")
_EXIT = re.compile(r"^\s*+(?:return|throw)(?![\w$])")
_GUARD_SEEN = 64  # `if (` openings looked at per address


def _test_rx(subject: str) -> str:
    """A `startsWith("/x…")` test of `subject` (plain, `String(…)`, `?.`)."""
    esc = re.escape(subject).replace(r"\.", r"\??\.")
    return (
        rf"(?:String\s*+\(\s*+{esc}\s*+\)|{esc})\s*+\??\.\s*+startsWith\s*+\(\s*+"
        rf"(?:{_PREFIX})\s*+\)"
    )


# "/" and a character that is neither "/" nor "\\", in any quotes (no backreference: the
# pattern is used inside others)
_PREFIX = "|".join(rf"{q}/[^/\\{q}$\s][^{q}\\$\n]{{0,200}}{q}" for q in ('"', "'", "`"))


def _origin_rx(subject: str, ops: str) -> str:
    """`new URL(subject[, base]).origin <op> location.origin`, either way round."""
    esc = re.escape(subject)
    url = rf"new\s++URL\s*+\(\s*+{esc}\s*+(?:,[^()]{{0,200}})?\)\s*+\.\s*+(origin|host|hostname)"
    loc = rf"{_LOC}\.(origin|host|hostname)"
    return rf"(?:{url}\s*+(?:{ops})\s*+{loc}|{loc}\s*+(?:{ops})\s*+{url})"


@functools.lru_cache(maxsize=4)
def _code_ids(text: str) -> frozenset[int]:
    """Offsets where a name starts in code (not in a comment or a string)."""
    from sniff_test.report.fingerprint import _parsed

    toks, _pairs = _parsed(text)
    return frozenset(o for k, _v, o in toks if k == "id")


def _guarded(expr: str, ctx: _HaContext) -> bool:
    m = _GUARD_SUBJECT.match(expr)
    if m is None:
        return False
    subject = m.group(1).replace("?.", ".")
    text, at = ctx.text, ctx.at
    lo = max(0, at - _HA_SEARCH)
    window = text[lo:at]
    if subject.split(".", 1)[0] not in window:
        return False
    test = re.compile(_test_rx(subject))
    negative = re.compile(rf"^!\s*+(?:{test.pattern}|\(\s*+{test.pattern}\s*+\))$")
    exit_origin = re.compile(rf"^{_origin_rx(subject, '!==|!=')}$")
    in_origin = re.compile(rf"^{_origin_rx(subject, '===|==')}$")
    flags = [
        f.group(1)
        for f in re.finditer(
            rf"(?<![\w$.])const\s++([A-Za-z_$][\w$]*+)\s*+=\s*+{test.pattern}\s*+[;,\n]", window
        )
        if lo + f.start() in _code_ids(text) and ctx.encloses(lo + f.start())
    ]
    seen = 0
    head = subject.split(".", 1)[0]
    names = (head, *flags)
    for g in _IF.finditer(window):
        if not any(n in window[g.end() : g.end() + 400] for n in names):
            continue  # an `if` about something else
        seen += 1
        if seen > _GUARD_SEEN:
            return False
        pos = lo + g.start()
        if pos not in _code_ids(text) or not ctx.encloses(pos):
            continue
        open_ = lo + g.end() - 1
        close = _closing(text[open_ : open_ + _HA_WINDOW], 0)
        if close < 0:
            continue
        cond = text[open_ + 1 : open_ + close]
        after = open_ + close + 1
        if after >= at:
            continue
        ors = _split(cond, "||")
        ands = _split(cond, "&&")
        exits = any(
            negative.match(p) or exit_origin.match(p) or any(p == f"!{f}" for f in flags)
            for p in ors
        )
        enters = any(
            re.fullmatch(test.pattern, p) or in_origin.match(p) or p in flags for p in ands
        )
        if exits and _exits(text, after, at) and not _changed(subject, text, pos, at):
            return True
        if enters:
            b = text.find("{", after, after + 40)
            if (
                b >= 0
                and not text[after:b].strip()
                and b < at
                and ctx.encloses(b + 1)
                and not _changed(subject, text, pos, at)
            ):
                return True
    return False


def _split(cond: str, op: str) -> list[str]:
    cuts = _scan_top(cond, op)
    starts = [0, *(c + len(op) for c in cuts)]
    ends = [*cuts, len(cond)]
    return [_unwrap(cond[a:b]) for a, b in zip(starts, ends, strict=True)]


def _exits(text: str, after: int, at: int) -> bool:
    """What follows the `if (…)` at `after` always leaves: `return`/`throw`, or a block
    whose last statement is one, closed before `at`."""
    rest = text[after : min(at, after + _HA_WINDOW)]
    if _EXIT.match(rest):
        return True
    body = rest.lstrip()
    if not body.startswith("{"):
        return False
    close = _closing(body, 0)
    if close < 0:
        return False
    inner = body[1:close].rstrip().rstrip(";")
    stops = _scan_top(inner, ";")
    last = inner[stops[-1] + 1 :] if stops else inner
    return bool(_EXIT.match(last)) and not _scan_top(last, "{")


def _changed(subject: str, text: str, pos: int, at: int) -> bool:
    """Is `subject` (or the object it is read from) given another value after the check,
    up to the end of the block the check is in (a closure can run later)?"""
    depth, end, limit = 0, None, min(len(text), pos + 2 * _HA_SEARCH)
    for i in range(pos, limit):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth < 0:
                end = i
                break
    if end is None or end < at:
        end = limit if end is None else end
        if end < at:
            return True
    span = text[pos:end]
    parts = subject.split(".")
    for k in range(1, len(parts) + 1):
        if parts[0] == "this" and k == 1:
            continue
        name = r"\.".join(re.escape(x) for x in parts[:k])
        if re.search(
            rf"(?<![\w$.]){name}\s*+(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)?=(?![=>])"
            rf"|(?<![\w$.]){name}\s*+(?:\+\+|--)|(?:\+\+|--)\s*+{name}(?![\w$])",
            span,
        ):
            return True
    return False


_STATIC_GET = r"static\s++get\s++{n}\s*+\(\s*+\)\s*+\{{\s*+return\s++({lit})\s*+;?\s*+\}}"
_STATIC_FIELD = r"static\s++{n}\s*+=\s*+({lit})\s*+[;\n]"
_LIT = r"\"[^\"\\\n]{0,500}\"|'[^'\\\n]{0,500}'|`[^`\\$]{0,500}`"


def _static_value(text: str, expr: str) -> str | None:
    """(0.15) `Panel.apiBase` where the class has `static get apiBase() { return "/x"; }`
    (or `static apiBase = "/x"`), defined once in the file and never assigned."""
    m = re.fullmatch(r"[A-Za-z_$][\w$]*+\.([A-Za-z_$][\w$]*+)", expr)
    if m is None:
        return None
    n = re.escape(m.group(1))
    if n not in text:
        return None
    hits = [
        h.group(1)
        for rx in (_STATIC_GET, _STATIC_FIELD)
        for h in re.finditer(rx.format(n=n, lit=_LIT), text)
    ]
    defs = re.findall(rf"(?<![\w$])(?:get\s++|set\s++){n}\s*+\(|(?<![\w$.]){n}\s*+=(?![=>])", text)
    if len(hits) != 1 or len(defs) != 1:
        return None
    if re.search(rf"\.\s*+{n}\s*+(?:[-+*/%&|^]|\?\?|\|\||&&)?=(?![=>])", text):
        return None
    return hits[0]


def _enclosing(res: list[dict], text: str, at: int) -> tuple[int, int, str] | None:
    """The innermost function (with a parameter) around offset `at`: (start, end, its
    parameter list as text)."""
    best: tuple[int, int] | None = None
    for r in res:
        if _rid(r) != "fns":
            continue
        s, e = r["start"]["offset"], r["end"]["offset"]
        if s <= at < e and (best is None or e - s < best[1] - best[0]):
            best = (s, e)
    if best is None:
        return None
    s, e = best
    head = text[s : min(e, s + 400)]
    arrow, paren = head.find("=>"), head.find("(")
    if paren < 0 or (0 <= arrow < paren):
        params = head[: arrow if arrow >= 0 else 0].rsplit("=", 1)[-1]
    else:
        close = _closing(head, paren)
        params = head[paren + 1 : close] if close > 0 else head[paren + 1 :]
    return s, e, params


def ha_origin(text: str, arg: str, at: int, fn: tuple[int, int, str] | None) -> bool:
    """The URL text `arg`, used at offset `at` (inside the function `fn`: start, end and
    its parameter list), stays on Home Assistant's own origin."""
    return _ha_url(arg, _HaContext(text, at, fn))


# --- Semgrep rules, generated -----------------------------------------------------------

_FNS = """
- id: fns
  languages: [javascript, typescript]
  severity: INFO
  message: f
  pattern-either:
    - pattern: function $F($P, ...) {...}
    - pattern: $F = function ($P, ...) {...}
    - pattern: $F = ($P, ...) => {...}
    - pattern: $F = ($P, ...) => $E
"""

_SINKS = ("fetch", "navigator.sendBeacon", "window.open", "new WebSocket", "new EventSource")


def _proof_rules(rid: str, callee: str, lead: str = "") -> str:
    """Two rules: every call of `callee` (`all-…`), and the calls whose URL Semgrep can't
    prove relative (`open-…`). Proven = in the first and not in the second. The proof
    uses the same `pattern-not` forms as the shipped rule, whose constant propagation is
    scoped correctly (a parameter, `let`, `catch` or loop variable of the same name
    shadows the constant). `metavariable-pattern` is not used: Semgrep 1.185 ignores
    shadowing there (checked on eight forms). Template literals are read as `+` chains;
    `_probe_copy` turns a leading `${C}` into `C  +` so longer ones fit the chain."""
    chain = [
        _SAME_ORIGIN,
        *(f"{_SAME_ORIGIN} + $Y" + "".join(f" + $Z{i}" for i in range(n)) for n in range(5)),
    ]
    nots = "".join(f"\n    - pattern-not: {callee}({lead}{c}, ...)" for c in chain)
    nots += f"\n    - pattern-not: {callee}({lead}{_SAME_ORIGIN}.concat(...), ...)"
    return f"""
- id: all-{rid}
  languages: [javascript, typescript]
  severity: INFO
  message: a
  pattern: {callee}({lead}$A, ...)
- id: open-{rid}
  languages: [javascript, typescript]
  severity: INFO
  message: o
  options: {{symbolic_propagation: true}}
  patterns:
    - pattern: {callee}({lead}$A, ...){nots}
"""


def _proven(res: list[dict], rid: str) -> set[tuple[int, int]]:
    def spans(prefix: str) -> set[tuple[int, int]]:
        return {
            (r["start"]["offset"], r["end"]["offset"]) for r in res if _rid(r) == f"{prefix}-{rid}"
        }

    return spans("all") - spans("open")


def _call_rules(name: str) -> str:
    return f"""
- id: refs-{name}
  languages: [javascript, typescript]
  severity: INFO
  message: r
  patterns:
    - pattern: {name}
    - pattern-not-inside: {name}(...)
""" + _proof_rules(f"c-{name}", name)


_LEAD_CONST = re.compile(r"`\$\{([A-Za-z_][\w]*)\}")


def _probe_copy(text: str) -> str:
    """The same text with each template literal that starts with `${C}` turned into
    `C  +`…: the same length, so every offset still points at the original."""
    return _LEAD_CONST.sub(lambda m: f"{m.group(1)}  +`", text)


def _rid(r: dict) -> str:
    return str(r.get("check_id", "")).rsplit(".", 1)[-1]


def _by_file(results: list[dict]) -> dict[Path, list[dict]]:
    out: dict[Path, list[dict]] = {}
    for r in results:
        out.setdefault(Path(r["path"]).resolve(), []).append(r)
    return out


_FN_HEADS = (
    re.compile(
        r"^(?:async\s++)?function\s*+\*?\s*+([A-Za-z_$][\w$]*+)\s*+\(\s*+([A-Za-z_$][\w$]*+)"
    ),
    re.compile(
        r"^([A-Za-z_$][\w$]*+)\s*+=\s*+(?:async\s++)?function\b[^(]*\(\s*+([A-Za-z_$][\w$]*+)"
    ),
    re.compile(r"^([A-Za-z_$][\w$]*+)\s*+=\s*+(?:async\s*+)?\(\s*+([A-Za-z_$][\w$]*+)"),
    re.compile(r"^([A-Za-z_$][\w$]*+)\s*+=\s*+(?:async\s++)?([A-Za-z_$][\w$]*+)\s*+=>"),
)


def _fn_head(text: str) -> tuple[str, str] | None:
    for rx in _FN_HEADS:
        if m := rx.match(text):
            return m.group(1), m.group(2)
    return None


def _reassigned(body: str, param: str) -> bool:
    p = re.escape(param)
    return bool(
        re.search(rf"(?<![\w$.]){p}\s*+(?:[-+*/%&|^]|\*\*|<<|>>>?|\?\?|&&|\|\|)?=(?![=>])", body)
        or re.search(rf"(?<![\w$.]){p}\s*+(?:\+\+|--)|(?:\+\+|--)\s*+{p}(?![\w$])", body)
    )


# --- the check ------------------------------------------------------------------------


class _Runs:
    """(0.14.1) One scan's Semgrep runs for this check. The function list (`fns`) of a
    file never changes within a scan, but it was asked again with every rule set, and on
    a 1.15 MB bundle it is 14 of a 16 s run; so it rides along only in the first run that
    reads a file, and is reused after. A run with the same rules on the same files (two
    token hits inside one minified wrapper) is answered from the first. Errors are not
    remembered: the caller gives up, as before."""

    def __init__(self, run: Runner):
        self._run = run
        self._memo: dict[tuple[str, tuple[Path, ...]], list[dict]] = {}
        self._fns: dict[Path, list[dict]] = {}

    def __call__(self, rules: str, files: list[Path]) -> list[dict]:
        """`rules` (without `fns`) on `files`, plus the function list of those files."""
        key = (rules, tuple(files))
        if key not in self._memo:
            need = [f for f in files if f not in self._fns]
            if need:
                res = self._run(rules + _FNS, files)
                found: dict[Path, list[dict]] = {f: [] for f in need}
                for r in res:
                    if _rid(r) == "fns" and (p := Path(r["path"]).resolve()) in found:
                        found[p].append(r)
                self._memo[key] = [r for r in res if _rid(r) != "fns"]
                self._fns.update(found)
            else:
                self._memo[key] = self._run(rules, files)
        return self._memo[key] + [r for f in files for r in self._fns.get(f, [])]


def precise(hits: list[Hit], root: Path, run: Runner, card: bool = False) -> set[int]:
    """ids (Python `id()`) of the findings in `hits` that are proven same-origin."""
    if not hits:
        return set()
    index = _Index(root.resolve())
    index.card = card
    files = sorted({h.path.resolve() for h in hits})
    sink_ids = [f"sink{i}" for i in range(len(_SINKS))] + ["sinkxhr"]
    rules = (
        "rules:\n"
        + "".join(_proof_rules(f"sink{i}", s) for i, s in enumerate(_SINKS))
        + _proof_rules("sinkxhr", "$X.open", "$M, ")
    )
    runs = _Runs(run)
    try:
        first = _by_file(runs(rules, files))
    except (OSError, ValueError, subprocess.SubprocessError):
        return set()
    dropped: set[int] = set()
    wrappers: dict[int, tuple[Path, int, int, str, str]] = {}
    later: list[tuple[Hit, tuple[int, int] | None]] = []
    for h in hits:
        path = h.path.resolve()
        text = index.text(path)
        span = _url_arg(text, h.start, h.end)
        later.append((h, span))
        if span is None:
            continue
        arg = _arg_text(text, span)
        res = first.get(path, [])
        safe = index.trusted(path, arg, span[0]) and any(
            cs <= span[0] and span[1] <= ce for rid in sink_ids for cs, ce in _proven(res, rid)
        )
        if (
            safe
            or _text_safe(arg, index, path)
            or ha_origin(text, arg, span[0], _enclosing(res, text, h.start))
        ):
            dropped.add(id(h.finding))
            continue
        if not _IDENT.match(arg):
            continue
        fns = []
        for r in res:
            if _rid(r) != "fns":
                continue
            s, e = r["start"]["offset"], r["end"]["offset"]
            head = _fn_head(text[s:e])
            if head and s <= h.start and h.end <= e and head[1] == arg:
                fns.append((e - s, s, e, *head))
        if not fns:
            continue
        _, s, e, name, param = min(fns)
        body = text[s:e]
        brace = body.find("{", body.find(param) + len(param))
        if brace < 0 or _reassigned(body[brace:], param) or not _IDENT.match(name):
            continue
        wrappers[id(h.finding)] = (path, s, e, name, param)
    for fid, (path, s, e, name, param) in wrappers.items():
        if _wrapper_safe(index, runs, path, s, e, name, param, 1):
            dropped.add(fid)
    # (0.15) what the steps above can't prove: helpers taking the address in any
    # parameter (methods, prototype methods, classic scripts), and HA's own websocket
    for h, span in later:
        if id(h.finding) in dropped:
            continue
        path = h.path.resolve()
        text = index.text(path)
        if span is None:
            ok = _socket_on_ha(index, path, text, h.start, h.end)
        else:
            ok = _helper_url(index, path, text, _arg_text(text, span), span[0])
        if ok:
            dropped.add(id(h.finding))
    return dropped


# --- (0.15) helpers and sockets, from the full Marketplace run -----------------------------
#
# 16 real findings sent the token through a helper the steps above couldn't follow: the
# address was not its first parameter (`authFetch(hass, url, init)`), it was a method
# (`async _apiFetch(path) {…}`, `C.prototype._apiFetch = function (path) {…}`), or it
# sat in a classic script. Here the address is proven with the helper's own parameters
# taken as HA's for now, and then every place the helper's name appears in the app must be
# a call passing such an address in those places (followed through helpers calling
# helpers, `_DEPTH` levels). Any other use of the name (passed as a value, stored,
# renamed on import or export, `obj["name"]`) keeps the finding. A classic script's
# helper is looked for in every script of the app: another app on the same page could
# call it, but that app could read the token itself; what counts is what this one does.

_KEYWORDS = frozenset(
    "if for while switch catch with return typeof new delete void in of await yield do else"
    " function".split()
)
_HELPER_BUDGET = 400  # calls looked at per finding
# Methods the browser or Home Assistant calls with values of their own (the card's
# settings from the dashboard, the hass object, events): never followed as a helper, even
# when the app calls them too.
_CALLED_BY_OTHERS = frozenset(
    """constructor setConfig connectedCallback disconnectedCallback attributeChangedCallback
    adoptedCallback handleEvent render update updated firstUpdated willUpdate shouldUpdate
    requestUpdate getCardSize getGridOptions getLayoutOptions getConfigElement getStubConfig
    getConfigForm toString valueOf then""".split()
)


@dataclass
class _Fn:
    start: int  # body "{"
    end: int
    name: str | None
    params: list[str | None]
    params_text: str
    accessor: bool = False  # `get x()` / `set x(v)`: run by reading or setting `x`


def _fn_records(index: _Index, path: Path) -> list[_Fn]:
    cache = index.__dict__.setdefault("_fnrec", {})
    if path not in cache:
        text = index.text(path)
        if path not in index._scopes:
            index._scopes[path] = _functions(text)
        out = []
        for start, end, cut in index._scopes[path]:
            rec = _header(text, start, end, cut)
            if rec is not None:
                out.append(rec)
        cache[path] = out
    return cache[path]


def _header(text: str, start: int, end: int, cut: int) -> _Fn | None:
    """A function's name (None when it has none) and parameter names, from the text
    before its body; None when the `{…}` belongs to `if (…)`, `for (…)` and the like."""
    head = text[cut:start]
    if head.startswith("("):
        close = _closing(head, 0)
        if close < 0:
            return None
        params_text = head[1:close]
    else:
        m = re.match(r"[A-Za-z_$][\w$]*+", head)
        if m is None:
            return None
        params_text = m.group(0)
    before = text[max(0, cut - 120) : cut]
    word = re.search(r"([A-Za-z_$][\w$]*+)\s*+$", before)
    if word and word.group(1) in _KEYWORDS - {"function"}:
        return None
    name = None
    for rx in (
        r"(?<![\w$])function\s*+\*?\s*+([A-Za-z_$][\w$]*+)\s*+$",
        r"([A-Za-z_$][\w$]*+)\s*+[:=]\s*+(?:async\s++)?function\s*+\*?\s*+(?:[A-Za-z_$][\w$]*+)?\s*+$",
        r"([A-Za-z_$][\w$]*+)\s*+[:=]\s*+(?:async\s*+)?$",
        r"(?:^|[{};,\s])(?:(?:static|async|get|set)\s++|\*\s*+)*+([A-Za-z_$][\w$]*+)\s*+$",
    ):
        if (m := re.search(rx, before)) is not None:
            name = m.group(1)
            break
    if name in _KEYWORDS or name in ("async", "constructor"):
        name = None
    params: list[str | None] = []
    for a, b in zip([0, *(c + 1 for c in _scan_top(params_text, ","))],
                    [*_scan_top(params_text, ","), len(params_text)], strict=True):  # fmt: skip
        part = params_text[a:b].strip()
        if part.startswith("..."):
            part = part[3:]
        m = re.match(r"([A-Za-z_$][\w$]*+)\s*+(?:[=:?]|$)", part)
        params.append(m.group(1) if m else None)
    accessor = (
        bool(name)
        and re.search(rf"(?<![\w$])(?:get|set)\s++{re.escape(name or '')}\s*+$", before) is not None
    )
    return _Fn(start, end, name, params, params_text, accessor)


def _around(index: _Index, path: Path, at: int) -> tuple[_Fn | None, frozenset[str]]:
    """The innermost named function around `at`, and the parameters of it that no
    function in between (a callback) declares again."""
    inner = sorted(
        (f for f in _fn_records(index, path) if f.start <= at < f.end),
        key=lambda f: f.end - f.start,
    )
    shadow: set[str] = set()
    for f in inner:
        if f.name is None:
            shadow.update(p for p in f.params if p)
            continue
        return f, frozenset(p for p in f.params if p and p not in shadow)
    return None, frozenset()


def _helper_url(index: _Index, path: Path, text: str, arg: str, at: int) -> bool:
    fn, params = _around(index, path, at)
    if fn is None or not params:
        return False
    ctx = _HaContext(text, at, (fn.start, fn.end, fn.params_text), params)
    if not _ha_url(arg, ctx) or not ctx.used:
        return False
    return _helper_safe(index, path, fn, ctx.used, 1, [_HELPER_BUDGET])


def _helper_safe(
    index: _Index, path: Path, fn: _Fn, used: dict[str, str], depth: int, budget: list[int]
) -> bool:
    """Every use of `fn`'s name in the app is a call passing, in each parameter `used`
    names, an address that is HA's own ("url") or relative ("path")."""
    name = fn.name
    if name is None or not _IDENT.match(name) or name in _CALLED_BY_OTHERS or fn.accessor:
        return False
    body = index.text(path)[fn.start : fn.end]
    need: dict[int, str] = {}
    for p, mode in used.items():
        if p not in fn.params or _param_reassigned(body, p):
            return False
        need[fn.params.index(p)] = mode
    if _module_escapes(index, path):
        return False
    calls = 0
    for f in _helper_scope(index, path, name):
        text = index.text(f)
        ids = _code_ids(text)
        for m in re.finditer(rf"(?<![\w$]){re.escape(name)}(?![\w$])", text):
            pos = m.start()
            if pos not in ids:
                continue  # in a comment or a string ("name" in `obj["name"]` is below)
            budget[0] -= 1
            if budget[0] < 0:
                return False
            kind = _use(text, pos, name)
            if kind in ("definition", "import"):
                continue
            if kind != "call":
                return False
            calls += 1
            paren = text.find("(", m.end())
            args = _args(text, paren)
            caller, cparams = _around(index, f, pos)
            for i, mode in need.items():
                if i >= len(args):
                    return False
                a = _arg_text(text, args[i])
                if _text_safe(a, index, f):
                    continue
                fn_t = (caller.start, caller.end, caller.params_text) if caller else None
                ctx = _HaContext(text, args[i][0], fn_t, cparams)
                ok = _rel(a, ctx, 0) if mode == "path" else _ha_url(a, ctx)
                if not ok:
                    return False
                if not ctx.used:
                    continue
                if caller is None:
                    return False
                if (caller.start, f) == (fn.start, path) and all(
                    q in fn.params
                    and fn.params.index(q) in need
                    and (need[fn.params.index(q)] == "path" or m2 == "url")
                    for q, m2 in ctx.used.items()
                ):
                    continue  # the helper calling itself with an address it was given
                if depth >= _DEPTH or not _helper_safe(
                    index, f, caller, ctx.used, depth + 1, budget
                ):
                    return False
        if re.search(rf"[\"'`]{re.escape(name)}[\"'`]", text):
            return False  # `obj["name"](…)`: called by a name built at run time
    # No call in the app: whatever calls it isn't in the app (the browser, Home Assistant
    # or another page), so what it passes isn't known.
    return calls > 0


def _param_reassigned(body: str, param: str) -> bool:
    """`_reassigned`, except a new `let`/`const` of that name in an inner block (another
    variable: it can't change the parameter; `var` would, it is the same one)."""
    p = re.escape(param)
    if re.search(rf"(?<![\w$.]){p}\s*+(?:\+\+|--)|(?:\+\+|--)\s*+{p}(?![\w$])", body):
        return True
    rx = rf"(?<![\w$.]){p}\s*+((?:[-+*/%&|^]|\*\*|<<|>>>?|\?\?|&&|\|\|)?)=(?![=>])"
    for m in itertools.islice(re.finditer(rx, body), _HA_SEEN + 1):
        if not m.group(1):  # a plain `=`: maybe a declaration
            start = max(body.rfind(c, 0, m.start()) for c in ";{}")
            seg = body[start + 1 : m.start()]
            depth = sum(seg.count(c) for c in "([") - sum(seg.count(c) for c in ")]")
            if re.match(r"\s*+(?:let|const)\s", seg) and depth == 0 and "`" not in seg:
                continue
        return True
    return False


def _use(text: str, pos: int, name: str) -> str:
    """How the name at `pos` is used: "definition", "import" (an import or export list
    that keeps the name), "call", or "other"."""
    before = text[max(0, pos - 120) : pos]
    after = text[pos + len(name) : pos + len(name) + 400]
    if _DEF_BEFORE.search(before) or _DEF_AFTER.match(after):
        return "definition"
    if _CALL_AFTER.match(after):
        if _NEW_BEFORE.search(before):
            return "other"
        dotted = _DOT_BEFORE.search(before) is not None
        close = _closing(after, after.index("("))
        if not dotted and close >= 0 and _BLOCK_AFTER.match(after[close + 1 :]):
            return "definition"  # a method: `name(a, b) {`
        return "call"
    if _LIST_AFTER.match(after) and _LIST_BEFORE.search(text[max(0, pos - 2000) : pos]):
        return "import"
    return "other"


_DEF_BEFORE = re.compile(r"(?<![\w$])function\s*+\*?\s*+$")
_DEF_AFTER = re.compile(
    r"\A\s*+=\s*+(?:async\s*+)?(?:function(?![\w$])|\([^()]{0,200}\)\s*+=>|[A-Za-z_$][\w$]*+\s*+=>)"
)
_CALL_AFTER = re.compile(r"\A\s*+\(")
_NEW_BEFORE = re.compile(r"(?<![\w$])new\s++$")
_DOT_BEFORE = re.compile(r"\.\s*+$")
_BLOCK_AFTER = re.compile(r"\A\s*+\{")
_LIST_AFTER = re.compile(r"\A\s*+[,}]")
_LIST_BEFORE = re.compile(r"(?<![\w$])(?:import|export)\s*+(?:type\s++)?\{[^{}]{0,2000}$")


def _module_escapes(index: _Index, path: Path) -> bool:
    """Another file takes the whole module as one object (`import * as api`, `import()`,
    `export … from`): its functions can then be reached without their names."""
    for other in index.js_files():
        if other == path:
            continue
        t = index.text(other)
        if path.stem not in t:
            continue
        for rx, g in ((_NS_IMPORT, 1), (_DYN_IMPORT, 1), (_REEXPORT, 1)):
            for m in rx.finditer(t):
                if _resolve(index.root, other, m.group(g)) == path:
                    return True
    return False


def _helper_scope(index: _Index, path: Path, name: str) -> list[Path]:
    """Where a helper can be called from: its own file when it is a function in a module
    that doesn't export it; otherwise every script of the app."""
    text = index.text(path)
    n = re.escape(name)
    local = (
        index.is_module(path)
        and re.search(rf"(?<![\w$])function\s*+\*?\s*+{n}\s*+\(", text) is not None
        and re.search(rf"export[^;]{{0,200}}(?<![\w$]){n}(?![\w$])", text) is None
    )
    return [path] if local else index.js_files()


_SEND = re.compile(
    r"(?<![\w$])([A-Za-z_$][\w$]*+(?:\.[A-Za-z_$][\w$]*+){0,3})\s*+\.\s*+send\s*+\(\s*+$"
)
_SEND_LEAD = re.compile(r"\A([A-Za-z_$][\w$]*+(?:\.[A-Za-z_$][\w$]*+){0,3})\s*+\.\s*+send\s*+\(")
_NEW_SOCKET = re.compile(r"^new\s++(?:(?:window|self|globalThis)\.)?WebSocket\s*+\(")
_NO_SOCKET = ("null", "undefined", "void 0", "!1", "false")


def _socket_on_ha(index: _Index, path: Path, text: str, start: int, end: int) -> bool:
    """(0.15) A token sent over a websocket opened to Home Assistant itself (HA's own
    login message, four real apps): `ws.send(…)` where every value `ws` is given is
    `new WebSocket(<HA's address>)` (or nothing yet, `null`)."""
    m = _SEND.search(text[max(0, start - 200) : start])
    if m is None:
        lead = _SEND_LEAD.match(text[start:end])
        if lead is None:
            return False
        sock, at = lead.group(1), start
    else:
        sock, at = m.group(1), start
    fn, _ = _around(index, path, at)
    fn_t = (fn.start, fn.end, fn.params_text) if fn else None
    if _IDENT.match(sock):
        ctx = _HaContext(text, at, fn_t)
        values = _assignments(sock, ctx)
        return bool(values) and all(_ha_socket(v, ctx) for v in values)
    if not sock.startswith("this."):
        return False
    prop = re.escape(sock.split(".")[-1])
    found = list(itertools.islice(
        re.finditer(rf"(?<![\w$])this\.{prop}\s*+=(?![=>])", text), _HA_SEEN + 1
    ))  # fmt: skip
    if not found or len(found) > _HA_SEEN:
        return False
    if re.search(rf"(?<!this)\.{prop}\s*+(?:[-+*/%&|^]|\?\?|\|\||&&)?=(?![=>])", text):
        return False  # set from outside the object too
    for d in found:
        rhs = text[d.end() : d.end() + _HA_WINDOW]
        ends = sorted(_scan_top(rhs, ",") + _scan_top(rhs, ";") + _scan_top(rhs, "\n"))
        value = _unwrap(rhs[: ends[0]] if ends else rhs)
        f2, _ = _around(index, path, d.start())
        ctx = _HaContext(text, d.start(), (f2.start, f2.end, f2.params_text) if f2 else None)
        if not _ha_socket(value, ctx):
            return False
    return True


def _ha_socket(value: str, ctx: _HaContext) -> bool:
    value = _unwrap(value)
    if value in _NO_SOCKET:
        return True
    m = _NEW_SOCKET.match(value)
    if m is None or _closing(value, m.end() - 1) != len(value) - 1:
        return False
    args = _args(value, m.end() - 1)
    return bool(args) and _ha_url(_arg_text(value, args[0]), ctx)


def _scope(index: _Index, path: Path, name: str) -> list[Path] | None:
    """Files where `name` (defined in `path`) can be called, or None when we can't know."""
    if not index.is_module(path):
        return None  # a classic script's top-level names are shared with the whole page
    files = [path]
    text = index.text(path)
    exported = re.search(
        rf"export\s++(?:default\s++)?(?:async\s++)?function\s*+\*?\s*+{re.escape(name)}\b"
        rf"|export\s++(?:const|let|var)\s++{re.escape(name)}\b",
        text,
    )
    if re.search(rf"export\s*+\{{[^}}]*\b{re.escape(name)}\b", text) or re.search(
        r"export\s++default\s++" + re.escape(name) + r"\b", text
    ):
        return None  # exported by a list or as default: followed by name, so keep it simple
    if not exported:
        return files
    for other in index.js_files():
        if other == path:
            continue
        t = index.text(other)
        if name not in t:
            continue
        for m in _NS_IMPORT.finditer(t):
            if _resolve(index.root, other, m.group(1)) == path:
                return None
        for m in list(_DYN_IMPORT.finditer(t)) + list(_REEXPORT.finditer(t)):
            if _resolve(index.root, other, m.group(1)) == path:
                return None
        for m in _IMPORT.finditer(t):
            if _resolve(index.root, other, m.group(2)) != path:
                continue
            for orig, local in _specifiers(m.group(1)):
                if orig == name:
                    if local != name:
                        return None  # imported under another name
                    files.append(other)
    return sorted(set(files))


def _wrapper_safe(
    index: _Index, run: _Runs, path: Path, s: int, e: int, name: str, param: str, depth: int
) -> bool:
    files = _scope(index, path, name)
    if files is None:
        return False
    try:
        results = _by_file(run("rules:\n" + _call_rules(name), files))
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    for f in files:
        res = results.get(f, [])
        text = index.text(f)
        if any(_rid(r) == f"refs-{name}" for r in res):
            return False  # passed as a value, stored, re-exported
        safe = _proven(res, f"c-{name}")
        for r in res:
            if _rid(r) != f"all-c-{name}":
                continue
            cs, ce = r["start"]["offset"], r["end"]["offset"]
            if (cs, ce) in safe and index.trusted(f, _first_arg(text, cs, name), cs):
                continue
            paren = text.find("(", cs + len(name))
            args = _args(text, paren) if paren >= 0 else []
            if not args:
                return False
            arg = _arg_text(text, args[0])
            if f == path and s <= cs and ce <= e and arg == param:
                continue  # the wrapper calling itself with its own URL
            if _text_safe(arg, index, f):
                continue
            if depth < _DEPTH and _IDENT.match(arg):
                outer = _outer(res, text, cs, ce, arg)
                if outer is not None:
                    os_, oe, oname = outer
                    body = text[os_:oe]
                    brace = body.find("{", body.find(arg) + len(arg))
                    if (
                        brace >= 0
                        and not _reassigned(body[brace:], arg)
                        and _IDENT.match(oname)
                        and _wrapper_safe(index, run, f, os_, oe, oname, arg, depth + 1)
                    ):
                        continue
            return False
    return True


def _first_arg(text: str, cs: int, name: str) -> str:
    paren = text.find("(", cs + len(name))
    args = _args(text, paren) if paren >= 0 else []
    return _arg_text(text, args[0]) if args else ""


def _outer(res: list[dict], text: str, cs: int, ce: int, arg: str) -> tuple[int, int, str] | None:
    """The innermost function around a call whose first parameter is `arg`."""
    best = None
    for r in res:
        if _rid(r) != "fns":
            continue
        s, e = r["start"]["offset"], r["end"]["offset"]
        head = _fn_head(text[s:e])
        if (
            head
            and s <= cs
            and ce <= e
            and head[1] == arg
            and (best is None or e - s < best[1] - best[0])
        ):
            best = (s, e, head[0])
    return best


def semgrep_runner(exe: str, root: Path, run_dir: Path, env: dict[str, str], proc_run) -> Runner:
    """A Runner using the same sandboxed Semgrep as the main pass. It scans probe copies
    (`_probe_copy`, in the run folder, outside the app) and reports the original paths."""
    counter = [0]
    root = root.resolve()

    def run(rules: str, files: list[Path]) -> list[dict]:
        counter[0] += 1
        rule_file = run_dir / f"js-wrapper-{counter[0]}.yaml"
        rule_file.write_text(rules, "utf-8")
        probe = run_dir / f"js-probe-{counter[0]}"
        back: dict[str, Path] = {}
        targets = []
        for f in files:
            rel = f.resolve().relative_to(root)
            copy = probe / rel
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_text(_probe_copy(f.read_text("utf-8", "replace")), "utf-8")
            back[str(copy.resolve())] = f.resolve()
            targets.append(str(copy))
        cmd = [exe, "scan", "--config", str(rule_file), "--json", "--metrics=off",
               "--disable-version-check", "--no-git-ignore", "--max-target-bytes", "50000000",
               "--timeout", "120", "--quiet", *targets]  # fmt: skip
        proc = proc_run(cmd, run_dir, 600, env, tool="semgrep", read=(rule_file, probe))
        out = []
        maps: dict[str, _Chars] = {}
        for r in json.loads(proc.stdout).get("results", []):
            copy = str(Path(r["path"]).resolve())
            orig = back.get(copy)
            if orig is None:
                continue
            if copy not in maps:
                maps[copy] = _Chars(Path(copy).read_bytes())
            c = maps[copy]
            out.append(
                {
                    **r,
                    "path": str(orig),
                    "start": {**r["start"], "offset": c(r["start"]["offset"])},
                    "end": {**r["end"], "offset": c(r["end"]["offset"])},
                }
            )
        return out

    return run
