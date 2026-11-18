"""(0.14.0) Names a card builds from pieces: `['fe','tch'].join('')`, `'hass' + 'Tokens'`.

Read only, never run. One pass per file: a tokenizer (strings, templates, comments and
regular expressions read whole, so nothing starts inside a string the way a regex over
raw text does in minified code) and a parser that evaluates only literal pieces:
strings, whole numbers, arrays of them, `+`, `.join`, `.concat`, `.split`,
`.reverse()`, `String.fromCharCode`, `atob` and escapes. Anything else is unknown and
never guessed; the parser walks through it to reach the literal expressions inside.
(A Semgrep rule finding the expressions first took 213 s on a real 1.6 MB bundle.)

Two results:
1. `card-hidden-name`: a sensitive name (`fetch`, `hassTokens`, `eval`, ...) that is in
   the joined value but in none of the pieces as written. `["fetch failed:", m].join(" ")`
   keeps "fetch" in one piece, so it isn't hiding anything; `"docu" + "mentation"` isn't
   "document" (a name must stand alone).
2. Rewrites: where a whole expression's value is exactly such a name, the scan's copy of
   the file gets the plain literal in its place (`"fetch"` padded with spaces, newlines
   kept, so byte offsets and lines don't move), and the Semgrep rules run on that file
   again. The value is the same string, so the code means the same; the rules can now
   see the name. The original bytes are put back before anything else reads the file.

Every loop here is bounded by the expression's length; there are no regular expressions.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from pathlib import Path

from sniff_test.models import Category, Finding, Severity

RULE = "card-hidden-name"
_JS = (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx")

# Names whose only reason to be built from pieces is not to be found by reading or
# searching: the token store, ways out of the browser, ways to run text as code.
SENSITIVE = (
    "hassTokens", "access_token", "refresh_token", "cookie",
    "localStorage", "sessionStorage", "getItem",
    "fetch", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon",
    "eval", "Function", "importScripts", "atob", "document",
)  # fmt: skip
_SENSITIVE = frozenset(SENSITIVE)

_MAX_FILE = 60_000_000  # characters; a bigger file is left alone (never guessed)
_OPEN = {"(": ")", "[": "]", "{": "}"}
_STARTS = frozenset(("String", "atob", "window", "globalThis", "self"))
# After these words a "/" starts a regular expression, not a division.
_BEFORE_REGEX = frozenset(
    "return typeof instanceof in of new delete void throw case do else yield await".split()
)
_MAX_DEPTH = 40
_MAX_VALUE = 1_000_000


class _Unknown(Exception):
    """Not a literal-only expression (or too deep): no value."""


# --- tokens ---------------------------------------------------------------------------

STR, NUM, TPL, NAME, PUNCT, OTHER = "str", "num", "tpl", "name", "punct", "other"


@dataclass
class Tok:
    kind: str
    text: str
    start: int
    end: int


def _is_name(c: str) -> bool:
    return c.isalnum() or c in "_$" or ord(c) > 127


def _skip_string(s: str, i: int) -> int:
    """i at an opening quote; returns the index after the closing one (or len)."""
    q, n = s[i], len(s)
    i += 1
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == q or c == "\n":
            return i + 1
        i += 1
    return n


def _skip_template(s: str, i: int) -> int:
    """i at a backtick; returns the index after the closing one. `${...}` nest."""
    n = len(s)
    i += 1
    stack = [0]  # open braces inside each `${`, innermost last; [0] = template text
    in_tpl = [True]
    while i < n:
        c = s[i]
        if in_tpl[-1]:
            if c == "\\":
                i += 2
                continue
            if c == "`":
                in_tpl.pop()
                stack.pop()
                if not in_tpl:
                    return i + 1
                i += 1
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "{":
                in_tpl.append(False)
                stack.append(0)
                i += 2
                continue
            i += 1
            continue
        # code inside ${ ... }
        if c in "'\"":
            i = _skip_string(s, i)
            continue
        if c == "`":
            in_tpl.append(True)
            stack.append(0)
            i += 1
            continue
        if c == "{":
            stack[-1] += 1
        elif c == "}":
            if stack[-1] == 0:
                in_tpl.pop()
                stack.pop()
            else:
                stack[-1] -= 1
        i += 1
    return n


def tokens(s: str) -> list[Tok]:
    """A JavaScript expression's tokens. Linear; anything odd becomes OTHER."""
    out: list[Tok] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            j = s.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "*":
            j = s.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        start = i
        if c in "'\"":
            i = _skip_string(s, i)
            out.append(Tok(STR, s[start:i], start, i))
        elif c == "`":
            i = _skip_template(s, i)
            out.append(Tok(TPL, s[start:i], start, i))
        elif c.isdigit() or (c == "." and i + 1 < n and s[i + 1].isdigit()):
            while i < n and (_is_name(s[i]) or s[i] == "."):
                i += 1
            out.append(Tok(NUM, s[start:i], start, i))
        elif _is_name(c):
            while i < n and _is_name(s[i]):
                i += 1
            out.append(Tok(NAME, s[start:i], start, i))
        elif c == "/":
            prev = out[-1] if out else None
            division = prev is not None and (
                (prev.kind == NAME and prev.text not in _BEFORE_REGEX)
                or prev.kind in (NUM, STR, TPL)
                or prev.text in (")", "]", "}")
            )
            if division:
                i += 1
                out.append(Tok(PUNCT, "/", start, i))
            else:  # a regex literal: skip it whole (classes may hold "/")
                i += 1
                in_class = False
                while i < n and s[i] != "\n":
                    ch = s[i]
                    if ch == "\\":
                        i += 2
                        continue
                    if ch == "[":
                        in_class = True
                    elif ch == "]":
                        in_class = False
                    elif ch == "/" and not in_class:
                        i += 1
                        break
                    i += 1
                while i < n and _is_name(s[i]):
                    i += 1
                out.append(Tok(OTHER, s[start:i], start, i))
        else:
            i += 1
            out.append(Tok(PUNCT, c, start, i))
    return out


# --- literal values ------------------------------------------------------------------

_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def _hex(s: str) -> int:
    if not s or any(c not in "0123456789abcdefABCDEF" for c in s):
        raise _Unknown
    return int(s, 16)


def unescape(body: str) -> str:
    """The value of a JavaScript string literal's body (between the quotes)."""
    out: list[str] = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        if i + 1 >= n:
            raise _Unknown
        e = body[i + 1]
        if e == "x":
            out.append(chr(_hex(body[i + 2 : i + 4])))
            i += 4
        elif e == "u" and body[i + 2 : i + 3] == "{":
            j = body.find("}", i + 3)
            if j < 0 or j - i > 12:
                raise _Unknown
            cp = _hex(body[i + 3 : j])
            if cp > 0x10FFFF:
                raise _Unknown
            out.append(chr(cp))
            i = j + 1
        elif e == "u":
            out.append(chr(_hex(body[i + 2 : i + 6])))
            i += 6
        elif e == "\n":
            i += 2
        elif e == "\r":
            i += 3 if body[i + 2 : i + 3] == "\n" else 2
        elif e in _SIMPLE and not (e == "0" and body[i + 2 : i + 3].isdigit()):
            out.append(_SIMPLE[e])
            i += 2
        elif e.isdigit():
            raise _Unknown  # legacy octal: not in modules, never guessed
        else:
            out.append(e)
            i += 2
    return "".join(out)


def _number(text: str) -> int:
    t = text.replace("_", "")
    try:
        if t[:2].lower() == "0x":
            return int(t[2:], 16)
        if t[:2].lower() == "0o":
            return int(t[2:], 8)
        if t[:2].lower() == "0b":
            return int(t[2:], 2)
        if t.isdigit():
            return int(t)
        f = float(t)
    except ValueError:
        raise _Unknown from None
    if f != int(f) or abs(f) > 2**53:
        raise _Unknown
    return int(f)


def _to_str(v: object) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        raise _Unknown
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return ",".join(_to_str(x) for x in v)
    raise _Unknown


@dataclass
class Fold:
    """A string an expression is known to produce, from literal pieces."""

    value: str
    pieces: list[str]  # the literal tokens as written (quotes and escapes included)
    start: int  # character offsets in the parsed text
    end: int
    built: bool  # an operator, call or escape was involved (not a plain literal)


@dataclass
class _Val:
    v: object  # str | int | list
    pieces: list[str] = field(default_factory=list)
    built: bool = False


class _Parser:
    """Recursive descent over literal-only expressions. Unknown code is walked through,
    not evaluated: every bracket inside it is parsed for literal expressions of its own,
    so one pass over a file reaches every fold (`globalThis[atob("…")](…)` included)."""

    def __init__(self, text: str, toks: list[Tok], depth: int = 0, base: int = 0):
        self.s = text
        self.t = toks
        self.i = 0
        self.depth = depth
        self.base = base  # offset of `text` in the file (template substitutions)
        self.folds: list[Fold] = []
        self.memo: dict[int, tuple[_Val | None, int]] = {}

    def peek(self, k: int = 0) -> Tok | None:
        j = self.i + k
        return self.t[j] if j < len(self.t) else None

    def at(self, text: str, k: int = 0) -> bool:
        tok = self.peek(k)
        return tok is not None and tok.kind in (PUNCT, NAME) and tok.text == text

    def take(self, text: str) -> None:
        if not self.at(text):
            raise _Unknown
        self.i += 1

    # An operand we can't read: walk to its end (the next `,` `;` `)` `]` `}` or `+` at
    # its own bracket level). Its value is unknown, so none of its strings become pieces
    # of the expression around it; the expressions inside its brackets and template
    # substitutions are parsed on their own.
    def skip_unknown(self) -> None:
        start = self.i
        while self.i < len(self.t):
            tok = self.t[self.i]
            if tok.kind == PUNCT and tok.text in ")]}":
                break
            if tok.kind == PUNCT and (tok.text in ",;" or (tok.text == "+" and self.i != start)):
                break
            if self.i == start:
                # The token this operand failed on: walk into it, never parse it again.
                self.i += 1
                if tok.kind == PUNCT and tok.text in _OPEN:
                    self.inside(_OPEN[tok.text])
                elif tok.kind == TPL:
                    self.template_folds(tok)
                continue
            prev = self.t[self.i - 1]
            # `f(…)`, `x[…]`, html`…`: a call, an index or a tagged template belongs to
            # the unknown operand; only what's inside it is read.
            follows = prev.kind in (NAME, NUM, STR, TPL) or prev.text in (")", "]")
            if follows and tok.kind == PUNCT and tok.text in _OPEN:
                self.i += 1
                self.inside(_OPEN[tok.text])
                continue
            if follows and tok.kind == TPL:
                self.template_folds(tok)
                self.i += 1
                continue
            if (
                tok.kind in (STR, NUM, TPL)
                or (tok.kind == PUNCT and tok.text in "([")
                or (tok.kind == NAME and tok.text in _STARTS)
            ):
                at = self.i
                self.statement()  # an expression of its own (`= [..].join("")`, `f(…)`)
                if self.i == at:
                    self.i += 1
                continue
            if tok.kind == PUNCT and tok.text == "{":
                self.i += 1
                self.inside("}")
                continue
            self.i += 1

    def inside(self, close: str) -> None:
        """Parse expressions up to and including the matching `close`."""
        if self.depth > _MAX_DEPTH:  # too deep to recurse: walk to the close, flat
            level = 0
            while self.i < len(self.t):
                tok = self.t[self.i]
                self.i += 1
                if tok.kind == PUNCT and tok.text in _OPEN:
                    level += 1
                elif tok.kind == PUNCT and tok.text in ")]}":
                    if level == 0:
                        return
                    level -= 1
            return
        self.depth += 1
        try:
            while self.i < len(self.t):
                tok = self.t[self.i]
                if tok.kind == PUNCT and tok.text in ")]}":
                    if tok.text == close:
                        self.i += 1
                    return  # a stray close ends this level too
                self.statement()
        finally:
            self.depth -= 1

    def statement(self) -> None:
        """One expression (recorded when it builds a string), always making progress."""
        start = self.i
        try:
            v = self.expr()
            if v is not None and self.i > start:
                self.record(v, start, self.i)
        except _Unknown:
            pass
        if self.i == start:
            self.i += 1

    def template_folds(self, tok: Tok) -> None:
        """Folds inside a template's substitutions (the template itself is unknown)."""
        body = tok.text[1:-1] if tok.text.endswith("`") and len(tok.text) >= 2 else tok.text[1:]
        i, n = 0, len(body)
        while i < n:
            c = body[i]
            if c == "\\":
                i += 2
                continue
            if c == "$" and i + 1 < n and body[i + 1] == "{":
                try:
                    end = i + 2 + _close_brace(body, i + 2)
                except _Unknown:
                    return
                self.sub_folds(body[i + 2 : end], tok.start + 1 + i + 2)
                i = end + 1
                continue
            i += 1

    def sub_folds(self, inner: str, at: int) -> _Parser:
        sub = _Parser(inner, tokens(inner), self.depth + 1, self.base + at)
        if self.depth + 1 <= _MAX_DEPTH:
            while sub.i < len(sub.t):
                sub.statement()
        self.folds += sub.folds
        return sub

    def record(self, v: _Val, a: int, b: int) -> None:
        if isinstance(v.v, str) and v.built and len(v.v) <= _MAX_VALUE:
            s, e = self.base + self.t[a].start, self.base + self.t[b - 1].end
            self.folds.append(Fold(v.v, list(v.pieces), s, e, True))

    # expr := term ('+' term)*  -- string runs are kept even when other operands are unknown
    def expr(self) -> _Val | None:
        # Every nesting (brackets, parentheses, call arguments, `${}`) passes through
        # here, so this bounds the recursion on hostile input like "[[[[…".
        if self.depth > _MAX_DEPTH:
            raise _Unknown
        self.depth += 1
        try:
            return self._expr()
        finally:
            self.depth -= 1

    def _expr(self) -> _Val | None:
        first = self.i
        ops: list[tuple[_Val | None, int, int]] = []
        while True:
            a = self.i
            val = self.term()
            ops.append((val, a, self.i))
            if self.at("+"):
                self.i += 1
                continue
            break
        if len(ops) == 1:
            return ops[0][0]
        # Known runs of string-valued operands (JavaScript adds left to right: once a
        # string is in the run, every later operand is appended as text).
        run: list[tuple[_Val, int, int]] = []
        whole: _Val | None = None
        all_known = all(v is not None for v, _, _ in ops)

        def close() -> None:
            if len(run) >= 2:
                joined = _Val("".join(_to_str(v.v) for v, _, _ in run), [], True)
                for v, _, _ in run:
                    joined.pieces += v.pieces
                self.record(joined, run[0][1], run[-1][2])

        for v, a, b in ops:
            if v is not None and (isinstance(v.v, str) or (run and isinstance(v.v, int))):
                run.append((v, a, b))
            else:
                close()
                run = []
        close()
        if all_known and run and run[0][1] == first and len(run) == len(ops):
            whole = _Val("".join(_to_str(v.v) for v, _, _ in run), [], True)
            for v, _, _ in run:
                whole.pieces += v.pieces
        return whole

    def term(self) -> _Val | None:
        # Each position is read once (a packrat cache): a failed operand is walked again
        # from outside, and without the cache "((((…" costs 2^depth.
        a = self.i
        if (hit := self.memo.get(a)) is not None:
            self.i = hit[1]
            return hit[0]
        val = self._term()
        self.memo[a] = (val, self.i)
        return val

    def _term(self) -> _Val | None:
        a = self.i
        try:
            val = self.primary()
        except _Unknown:
            self.i = a
            self.skip_unknown()
            return None
        while self.at("."):
            name = self.peek(1)
            if name is None or name.kind != NAME or not self.at("(", 2):
                break
            mark = self.i
            try:
                self.i += 3
                val = self.method(val, name.text)
            except _Unknown:
                self.i = mark
                self.skip_unknown()
                return None
            self.record(val, a, self.i)
        return val

    def args(self) -> list[_Val]:
        out: list[_Val] = []
        while not self.at(")"):
            v = self.expr()
            if v is None:
                raise _Unknown
            out.append(v)
            if self.at(","):
                self.i += 1
            elif not self.at(")"):
                raise _Unknown
        self.take(")")
        return out

    def method(self, val: _Val, name: str) -> _Val:
        args = self.args()
        pieces = val.pieces + [p for x in args for p in x.pieces]
        v = val.v
        if name == "join" and isinstance(v, list) and len(args) <= 1:
            sep = _to_str(args[0].v) if args else ","
            return _Val(sep.join(_to_str(x) for x in v), pieces, True)
        if name == "concat" and isinstance(v, str):
            return _Val(v + "".join(_to_str(x.v) for x in args), pieces, True)
        if name == "concat" and isinstance(v, list):
            more: list[object] = []
            for x in args:
                more += x.v if isinstance(x.v, list) else [x.v]
            return _Val(v + more, pieces, True)
        if name == "split" and isinstance(v, str) and len(args) == 1:
            sep = args[0].v
            if not isinstance(sep, str):
                raise _Unknown
            return _Val(list(v) if sep == "" else v.split(sep), pieces, True)
        if name == "reverse" and isinstance(v, list) and not args:
            return _Val(v[::-1], pieces, True)
        if name == "toString" and not args and isinstance(v, str | list):
            return _Val(_to_str(v), pieces, True)
        raise _Unknown

    def primary(self) -> _Val:
        tok = self.peek()
        if tok is None:
            raise _Unknown
        if tok.kind == STR:
            self.i += 1
            if len(tok.text) < 2 or tok.text[-1] != tok.text[0]:
                raise _Unknown
            body = tok.text[1:-1]
            return _Val(unescape(body), [tok.text], "\\" in body)
        if tok.kind == NUM:
            self.i += 1
            return _Val(_number(tok.text), [], False)
        if tok.kind == TPL:
            self.i += 1
            return self.template(tok)
        if tok.kind == PUNCT and tok.text == "[":
            self.i += 1
            items: list[object] = []
            pieces: list[str] = []
            while not self.at("]"):
                v = self.expr()
                if v is None:
                    raise _Unknown
                items.append(v.v)
                pieces += v.pieces
                if self.at(","):
                    self.i += 1
                elif not self.at("]"):
                    raise _Unknown
            self.take("]")
            return _Val(items, pieces, False)
        if tok.kind == PUNCT and tok.text == "(":
            self.i += 1
            v = self.expr()
            if v is None:
                raise _Unknown
            self.take(")")
            return v
        if tok.kind == NAME:
            # String.fromCharCode(...), atob("...") / window.atob("...")
            if tok.text == "String" and self.at(".", 1):
                nxt = self.peek(2)
                if nxt is not None and nxt.text == "fromCharCode" and self.at("(", 3):
                    self.i += 4
                    args = self.args()
                    codes = [x.v for x in args]
                    if not all(isinstance(c, int) and not isinstance(c, bool) for c in codes):
                        raise _Unknown
                    return _Val("".join(chr(int(c) & 0xFFFF) for c in codes), [], True)  # type: ignore[call-overload]
            k = 0
            if tok.text in ("window", "globalThis", "self") and self.at(".", 1):
                k = 2
            nxt = self.peek(k)
            if nxt is not None and nxt.text == "atob" and self.at("(", k + 1):
                self.i += k + 2
                args = self.args()
                if len(args) != 1 or not isinstance(args[0].v, str):
                    raise _Unknown
                raw = "".join(args[0].v.split())
                try:
                    data = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
                except (binascii.Error, ValueError):
                    raise _Unknown from None
                return _Val(data.decode("latin-1"), args[0].pieces, True)
        raise _Unknown

    def template(self, tok: Tok) -> _Val:
        body = tok.text[1:-1] if tok.text.endswith("`") and len(tok.text) >= 2 else None
        if body is None:
            raise _Unknown
        out: list[str] = []
        pieces: list[str] = []
        i, n = 0, len(body)
        built = False
        lit_start = 0
        while i < n:
            c = body[i]
            if c == "\\":
                i += 2
                continue
            if c == "$" and i + 1 < n and body[i + 1] == "{":
                out.append(unescape(body[lit_start:i]))
                pieces.append(body[lit_start:i])
                inner_end = i + 2 + _close_brace(body, i + 2)
                inner = body[i + 2 : inner_end]
                sub = _Parser(inner, tokens(inner), self.depth + 1, self.base + tok.start + i + 3)
                v = sub.expr()
                if v is None or sub.i != len(sub.t):
                    raise _Unknown  # skip_unknown then reads the substitutions on their own
                self.folds += sub.folds
                out.append(_to_str(v.v))
                pieces += v.pieces
                built = True
                i = inner_end + 1
                lit_start = i
                continue
            i += 1
        out.append(unescape(body[lit_start:]))
        pieces.append(body[lit_start:])
        return _Val("".join(out), pieces, built or "\\" in body)


def _close_brace(body: str, i: int) -> int:
    """Offset (from i) of the `}` closing a `${` whose code starts at body[i]."""
    depth, j, n = 0, i, len(body)
    while j < n:
        c = body[j]
        if c in "'\"":
            j = _skip_string(body, j)
            continue
        if c == "`":
            j = _skip_template(body, j)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            if depth == 0:
                return j - i
            depth -= 1
        j += 1
    raise _Unknown


def folds(text: str) -> list[Fold]:
    """Every string the text builds from literal pieces, wherever it is: one pass over
    the tokens, bounded by the text's length and the nesting limit."""
    if len(text) > _MAX_FILE:
        return []
    p = _Parser(text, tokens(text))
    while p.i < len(p.t):
        try:
            p.statement()
        except (RecursionError, ValueError, OverflowError):
            p.i += 1
    return p.folds


# --- hidden names --------------------------------------------------------------------


def _standalone(value: str, name: str) -> bool:
    """name occurs in value with no name character on either side."""
    start = 0
    while (k := value.find(name, start)) >= 0:
        before = value[k - 1] if k else ""
        after = value[k + len(name)] if k + len(name) < len(value) else ""
        if not (before and _is_name(before)) and not (after and _is_name(after)):
            return True
        start = k + 1
    return False


def hidden(f: Fold) -> list[str]:
    """Sensitive names in the value that no piece contains as written."""
    return [
        n
        for n in SENSITIVE
        if n in f.value and _standalone(f.value, n) and not any(n in p for p in f.pieces)
    ]


# --- the scan step ------------------------------------------------------------------


@dataclass
class Result:
    findings: list[Finding]
    rewrites: dict[Path, bytes]  # file -> rewritten bytes (same length as the original)


def _replacement(span: bytes, literal: bytes) -> bytes | None:
    """`literal` padded to span's length, newlines kept in place; None if it can't fit."""
    pos = 0
    for seg in span.split(b"\n"):
        seg_len = len(seg.rstrip(b"\r")) if seg.endswith(b"\r") else len(seg)
        if seg_len >= len(literal):
            out = bytearray(b" " * len(span))
            for k, ch in enumerate(span):
                if ch in (0x0A, 0x0D):
                    out[k] = ch
            out[pos : pos + len(literal)] = literal
            return bytes(out)
        pos += len(seg) + 1
    return None


def _quote(name: str) -> bytes:
    return ('"' + name + '"').encode()


def _short(text: str, limit: int = 160) -> str:
    one = " ".join(text.split())
    return one if len(one) <= limit else one[: limit - 1] + "…"


def _byte_offset(text: str, k: int) -> int:
    return k if text.isascii() else len(text[:k].encode("utf-8", "surrogateescape"))


# Every source of the second pass's token rule names one of these (tests/test_js_fold.py
# checks), so a file with none of them can't hold a source.
TOKEN_HINTS = (
    b"hassTokens",
    b"localStorage",
    b"auth",
    b"access_token",
    b"refresh_token",
    b"cookie",
)


def may_hold_token(path: Path) -> bool:
    try:
        data = path.read_bytes()
    except OSError:
        return True
    return any(h in data for h in TOKEN_HINTS)


def js_files(root: Path) -> list[Path]:
    return sorted(
        p for p in root.rglob("*") if p.suffix in _JS and p.is_file() and not p.is_symlink()
    )


def analyse(files: list[Path], root: Path) -> Result:
    """Hidden-name findings and same-length rewrites for the app's JavaScript files."""
    findings: list[Finding] = []
    rewrites: dict[Path, bytes] = {}
    root = root.resolve()
    for path in files:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        text = data.decode("utf-8", "surrogateescape")
        hits = [(f, h) for f in folds(text) if (h := hidden(f))]
        if not hits:
            continue
        # Outermost first: a fold inside one already counted is part of it.
        hits.sort(key=lambda fh: (fh[0].start, fh[0].start - fh[0].end))
        outer: list[tuple[Fold, list[str]]] = []
        for f, h in hits:
            if outer and f.end <= outer[-1][0].end:
                continue
            outer.append((f, h))
        new = bytearray(data)
        by_line: dict[int, tuple[list[str], str]] = {}
        for f, h in outer:
            line = text.count("\n", 0, f.start) + 1
            names, example = by_line.get(line, ([], text[f.start : f.end]))
            by_line[line] = (names + [n for n in h if n not in names], example)
            if f.value in _SENSITIVE:
                b0, b1 = _byte_offset(text, f.start), _byte_offset(text, f.end)
                rep = _replacement(data[b0:b1], _quote(f.value))
                if rep is not None:
                    new[b0:b1] = rep
        if bytes(new) != data and len(new) == len(data):
            rewrites[path] = bytes(new)
        try:
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = path.name
        for line, (names, example) in sorted(by_line.items()):
            shown = ", ".join(f"`{n}`" for n in names)
            findings.append(
                Finding(
                    rule_id=RULE,
                    title="Card builds a sensitive name from pieces",
                    severity=Severity.HIGH,
                    category=Category.CODE_EXEC,
                    message=(
                        f"Builds {shown} from pieces at run time ({_short(example)}). "
                        "Code only hides a name like this so it can't be found by "
                        "reading or searching it. Barkley joined the pieces and checked "
                        "what the code does with the result."
                    ),
                    file=rel,
                    line=line,
                    evidence=_short(example, 300),
                    analyzer="semgrep",
                )
            )
    return Result(findings, rewrites)
