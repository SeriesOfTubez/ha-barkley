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
        return None
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
        text = visible(self.text(path), at)
        return propagation_trusted(text, arg, destructured(text), at)

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


def visible(text: str, at: int) -> str:
    """`text` with every function that doesn't contain offset `at` blanked (same length):
    its parameter list and its `{…}` body, for `function (…) {…}`, methods and arrows
    with a block body. What's left is the scope chain around `at` (plus expression-bodied
    arrows, which only make the check stricter)."""
    from sniff_test.report.fingerprint import _parsed

    toks, braces = _parsed(text)
    parens: dict[int, int] = {}
    stack: list[int] = []
    for i, (_k, v, _o) in enumerate(toks):
        if v == "(":
            stack.append(i)
        elif v == ")" and stack:
            parens[i] = stack.pop()
    cut: list[tuple[int, int]] = []
    for open_i, close_i in braces.items():
        start, end = toks[open_i][2], toks[close_i][2] + 1
        if start <= at < end or open_i == 0:
            continue
        prev = toks[open_i - 1][1]
        if prev == ")" and (open_i - 1) in parens:
            start = toks[parens[open_i - 1]][2]
        elif prev == "=>" and open_i >= 2:
            q = open_i - 2
            start = toks[parens[q]][2] if toks[q][1] == ")" and q in parens else toks[q][2]
        else:
            continue
        cut.append((start, end))
    if not cut:
        return text
    cut.sort()
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
        + _FNS
        + "".join(_proof_rules(f"sink{i}", s) for i, s in enumerate(_SINKS))
        + _proof_rules("sinkxhr", "$X.open", "$M, ")
    )
    try:
        first = _by_file(run(rules, files))
    except (OSError, ValueError, subprocess.SubprocessError):
        return set()
    dropped: set[int] = set()
    wrappers: dict[int, tuple[Path, int, int, str, str]] = {}
    for h in hits:
        path = h.path.resolve()
        text = index.text(path)
        span = _url_arg(text, h.start, h.end)
        if span is None:
            continue
        arg = _arg_text(text, span)
        res = first.get(path, [])
        safe = index.trusted(path, arg, span[0]) and any(
            cs <= span[0] and span[1] <= ce for rid in sink_ids for cs, ce in _proven(res, rid)
        )
        if safe or _text_safe(arg, index, path):
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
        if _wrapper_safe(index, run, path, s, e, name, param, 1):
            dropped.add(fid)
    return dropped


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
    index: _Index, run: Runner, path: Path, s: int, e: int, name: str, param: str, depth: int
) -> bool:
    files = _scope(index, path, name)
    if files is None:
        return False
    try:
        results = _by_file(run("rules:\n" + _call_rules(name) + _FNS, files))
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
