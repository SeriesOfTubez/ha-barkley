"""(0.14.0) Fingerprints: the same finding on the same code gets the same hash in the next
version, wherever the code moved. Part 3 keeps a reviewed finding accepted while its
fingerprint holds, and reopens it when it changes.

Agreed with the user (2026-11-17), checked on 21 real findings across 6 version pairs
(20 held, the one that changed had a real change):
- Python: the rule plus the syntax tree (`ast.dump`, positions left out) of the smallest
  function around the line. A finding on a `class` line hashes the whole class. Otherwise
  the smallest top-level statement. Parsed with the PEP 758 retry (Python 3.14's
  `except A, B:`); a file that still can't be parsed hashes whole.
- JavaScript: the rule plus the tokens of the smallest function body around the match
  (whitespace and comments dropped, local names replaced by placeholders in order of
  appearance, because minifiers rename them between builds). Property names, keywords and
  strings stay.
- Dependencies: the package, its version and the advisory ids; a GuardDog hit hashes
  the flagged file's content (guarddog.py).
- Anything else: the rule and its evidence.
The file path is never part of the hash: moving code doesn't reopen a finding. Every
choice errs toward a new fingerprint (reopen) rather than keeping a changed one.
"""

from __future__ import annotations

import ast
import functools
import hashlib
import re
from pathlib import Path

from sniff_test.analyzers.py_resolve import parse

_LEN = 24


def _h(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", "replace"))
        h.update(b"\0")
    return h.hexdigest()[:_LEN]


# --- Python ---------------------------------------------------------------------------


def _python_node(tree: ast.Module, line: int) -> ast.AST | None:
    best = None
    for n in ast.walk(tree):
        if (
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.lineno <= line <= (n.end_lineno or n.lineno)
            and (
                best is None
                or (n.end_lineno or 0) - n.lineno < (best.end_lineno or 0) - best.lineno
            )
        ):
            best = n
    if best is not None:
        return best
    for st in tree.body:
        if st.lineno <= line <= (st.end_lineno or st.lineno):
            if isinstance(st, ast.ClassDef):
                if line == st.lineno or any(d.lineno == line for d in st.decorator_list):
                    return st  # a finding on the class line: the whole class
                for inner in st.body:
                    if inner.lineno <= line <= (inner.end_lineno or inner.lineno):
                        return ast.ClassDef(
                            name=st.name, bases=st.bases, keywords=st.keywords, body=[inner],
                            decorator_list=[], type_params=[],
                        )  # fmt: skip
            return st
    return None


def python(rule: str, text: str, line: int | None) -> str:
    tree = parse(text)
    if tree is None or not line:
        return _h("py-file", rule, text)
    node = _python_node(tree, line)
    if node is None:
        return _h("py-file", rule, text)
    return _h("py", rule, ast.dump(node, include_attributes=False))


# --- JavaScript ------------------------------------------------------------------------

_TOKEN = re.compile(
    r"""(?P<ws>\s+)
      |(?P<c1>//[^\n]*)
      |(?P<c2>/\*.*?\*/)
      |(?P<str>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)
      |(?P<id>[A-Za-z_$][\w$]*)
      |(?P<num>\d[\w.]*)
      |(?P<p>=>|\.\.\.|[{}()\[\];,.<>+\-*/%=&|^!~?:@#])
      |(?P<other>.)""",
    re.X | re.S,
)
_KEYWORDS = frozenset(
    """break case catch class const continue debugger default delete do else export extends
    false finally for function if import in instanceof let new null return super switch this
    throw true try typeof undefined var void while with yield async await of static get set
    window document fetch localStorage navigator console JSON Object Array Promise Math""".split()
)
_MAX_SPAN = 20_000


def _tokens(text: str) -> list[tuple[str, str, int]]:
    out = []
    for m in _TOKEN.finditer(text):
        kind = m.lastgroup or "other"
        if kind in ("ws", "c1", "c2"):
            continue
        out.append((kind, m.group(0), m.start()))
    return out


@functools.lru_cache(maxsize=4)
def _parsed(text: str) -> tuple[list[tuple[str, str, int]], dict[int, int]]:
    toks = _tokens(text)
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for i, (_k, v, _o) in enumerate(toks):
        if v == "{":
            stack.append(i)
        elif v == "}" and stack:
            pairs[stack.pop()] = i
    return toks, pairs


def _enclosing_body(
    toks: list[tuple[str, str, int]], pairs: dict[int, int], at: int
) -> tuple[int, int]:
    """Token range of the smallest `{…}` around offset `at` that follows `)` or `=>`
    (a function body); else the match's own statement-ish window."""
    best: tuple[int, int] | None = None
    for open_i, close_i in pairs.items():
        if (
            toks[open_i][2] <= at <= toks[close_i][2]
            and open_i > 0
            and toks[open_i - 1][1] in (")", "=>")
        ) and (best is None or close_i - open_i < best[1] - best[0]):
            best = (open_i, close_i)
    if best is not None and best[1] - best[0] <= _MAX_SPAN:
        return best
    idx = next((i for i, t in enumerate(toks) if t[2] >= at), len(toks) - 1)
    return max(0, idx - 40), min(len(toks) - 1, idx + 40)


def javascript(rule: str, text: str, start: int, end: int) -> str:
    toks, pairs = _parsed(text)
    if not toks:
        return _h("js-file", rule, text)
    a, b = _enclosing_body(toks, pairs, start)
    names: dict[str, str] = {}
    out: list[str] = []
    for i in range(a, b + 1):
        kind, v, _o = toks[i]
        if kind == "id" and v not in _KEYWORDS and not (i > 0 and toks[i - 1][1] == "."):
            v = names.setdefault(v, f"${len(names)}")
        out.append(v)
    match = "".join(t[1] for t in _tokens(text[start:end]) if t[0] != "id" or t[1] in _KEYWORDS)
    return _h("js", rule, match, " ".join(out))


# --- dependencies and the rest -------------------------------------------------------------


def dependency(rule: str, evidence: str) -> str:
    """dep-vuln / dep-malicious evidence is "name@version (ecosystem): ids"."""
    return _h("dep", rule, evidence)


def other(rule: str, evidence: str | None, message: str) -> str:
    return _h("other", rule, evidence or message)


def file_content(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""
