"""A replaced Home Assistant function, compared with its replacement (0.12.0).

An app can assign a function of its own to a method of one of Home Assistant's built-in
integrations. What the replacement does differently is the question a reader has, and
neither the page nor the AI could answer it: the original is Home Assistant's code, not
the app's. So during the scan, for a `ha-monkeypatch` finding whose
object resolves to `homeassistant.*` and whose replacement is a function defined in the
app, Barkley reads that one file of Home Assistant at the scan's HA version and compares
the two functions line by line (`difflib`). No AI takes part. The result is stored with
the finding's patch fact (`context.items[id].patch.compare`), shown under "What it
replaces", and given to the AI as lines it can cite.

Home Assistant's file is HA's code, fetched from `home-assistant/core` through the GitHub
client (deps.ha_env.source_file, cached per release). It is parsed, never run. The app's
side comes from the syntax tree the scan already has.

Never a result: no HA version (an offline scan), GitHub not answering, or a file Barkley
can't read each leave a stated reason (`state: "none"`, `why`) and nothing else changes.
A rate limit is not caught here: the job waits and scans again.

`inside()` is Barkley's own sentence about the replacement: which other findings,
addresses and ports of this scan sit on its lines. It says what was looked at, not that
the code is safe.
"""

from __future__ import annotations

import ast
import difflib
import re
from collections.abc import Callable
from typing import Any

from sniff_test.fetch.github import RateLimitError

MAX_FETCH = 2  # files asked of GitHub per scan (server._GITHUB_NEED counts them)
CONTEXT = 3  # unchanged lines kept around a change
MAX_ROWS = 160  # diff rows stored per comparison
MAX_FUNC_LINES = 800  # a longer function on either side isn't compared
LONG_LINE = 300
_IDENT = re.compile(r"[A-Za-z_]\w*")
_MODULE = re.compile(r"[a-z0-9_]+")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# Python 3.14 lets `except A, B:` go without parentheses (PEP 758; the same meaning as
# `except (A, B):` when there is no `as`), and Home Assistant's formatter writes it that
# way: 394 of 10,913 files of 2026.11.1 don't parse on the image's Python 3.13, core.py and
# auth/__init__.py among them. The copy that is parsed (only to find where a function
# starts and ends; the lines shown and compared are the original ones) gets the
# parentheses back. Checked on all of 2026.11.1: every one of the 394 then parses.
_EXCEPT = re.compile(r"^(\s*except\*?\s+)([^:()#]+,[^:()#]+?)(\s*:\s*(?:#.*)?)$", re.M)

# why there is no comparison, in the page's words (ui.compare_html)
WHY = {
    "offline": "this scan ran without a Home Assistant version to compare with",
    "not-a-function": "the replacement isn't a function defined in this app",
    "limit": f"Barkley compares at most {MAX_FETCH} Home Assistant files per scan",
    "unreachable": "GitHub didn't hand out Home Assistant's file when this was sniffed",
    "not-found": "Barkley didn't find the original where the app's import says it is",
    "unreadable": "Barkley's parser couldn't read Home Assistant's file",
    "too-long": f"one of the two functions is longer than {MAX_FUNC_LINES} lines",
}


def locate(obj: str, attr: str) -> tuple[list[str], list[str]] | None:
    """(candidate file paths in home-assistant/core, the name's path inside the module)
    for a patched `obj.attr`, from the import path alone. Module names are lower case;
    the first part that isn't starts the names inside the module (a class)."""
    parts = obj.split(".")
    if parts[0] != "homeassistant" or not all(_IDENT.fullmatch(p) for p in [*parts, attr]):
        return None
    k = next((i for i, p in enumerate(parts) if not _MODULE.fullmatch(p)), len(parts))
    if k < 2:
        return None  # `homeassistant.X`: nothing names a module
    base = "/".join(parts[:k])
    return [f"{base}.py", f"{base}/__init__.py"], [*parts[k:], attr]


def parse(text: str) -> ast.Module | None:
    """Home Assistant's file as a syntax tree, line numbers as in the file."""
    for candidate in (text, _EXCEPT.sub(lambda m: f"{m[1]}({m[2]}){m[3]}", text)):
        try:
            return ast.parse(candidate)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
    return None


def find_function(tree: ast.Module, qual: list[str]) -> ast.AST | None:
    """The function `Class.method` / `function` names at module level, else None."""
    body: list[ast.stmt] = tree.body
    for name in qual[:-1]:
        cls = next((n for n in body if isinstance(n, ast.ClassDef) and n.name == name), None)
        if cls is None:
            return None
        body = cls.body
    return next(
        (
            n
            for n in body
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == qual[-1]
        ),
        None,
    )


def span(node: ast.AST) -> tuple[int, int]:
    start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
    return start, node.end_lineno or node.lineno


def _dedent(lines: list[str]) -> list[str]:
    """Without the indentation every line shares: a method and a module-level function
    would otherwise differ on every line."""
    width = min((len(x) - len(x.lstrip()) for x in lines if x.strip()), default=0)
    return [x[width:].rstrip() for x in lines]


def _clean(line: str) -> str:
    line = _CONTROL.sub("", line)
    return line[:LONG_LINE] + " …" if len(line) > LONG_LINE else line


def diff(
    old: list[str], old_start: int, new: list[str], new_start: int
) -> tuple[list[list[list[Any]]], int, int, bool]:
    """(hunks, lines added, lines removed, cut?). A hunk is rows of [tag, old line number
    or 0, new line number or 0, text]: "-" only in the original, "+" only in the
    replacement, " " in both. Line numbers are the files' own."""
    a, b = _dedent(old), _dedent(new)
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    added = removed = 0
    hunks: list[list[list[Any]]] = []
    rows = 0
    cut = False
    for group in matcher.get_grouped_opcodes(CONTEXT):
        hunk: list[list[Any]] = []
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                hunk += [[" ", old_start + i, new_start + j1 + (i - i1), _clean(a[i])]
                         for i in range(i1, i2)]  # fmt: skip
                continue
            removed += i2 - i1
            added += j2 - j1
            hunk += [["-", old_start + i, 0, _clean(a[i])] for i in range(i1, i2)]
            hunk += [["+", 0, new_start + j, _clean(b[j])] for j in range(j1, j2)]
        if rows + len(hunk) > MAX_ROWS:
            cut = True  # the counts stay whole; the rows shown stop here
            continue
        rows += len(hunk)
        hunks.append(hunk)
    return hunks, added, removed, cut


def compare(
    fact: dict[str, Any],
    replacement: tuple[str, list[str], ast.AST] | None,
    ha_version: str | None,
    fetch: Callable[[str], str | None] | None,
    budget: list[int],
) -> dict[str, Any] | None:
    """The `compare` entry for one patch fact, or None when the patched object isn't Home
    Assistant's source (a network library, the running `hass`). `replacement`: (file,
    its lines, the function's node) when the app defines it as a function. `fetch(path)`
    returns Home Assistant's file or None if that release has none; it raises OSError-like
    errors when GitHub can't be asked (caught: "unreachable") and lets a rate limit
    through. `budget`: one-element list, the fetches this scan may still make."""
    where = locate(str(fact.get("object") or ""), str(fact.get("attr") or ""))
    if where is None:
        return None
    if replacement is None:
        return {"state": "none", "why": "not-a-function"}
    if not ha_version or fetch is None:
        return {"state": "none", "why": "offline"}
    paths, qual = where
    text = path = None
    for cand in paths:
        if budget[0] <= 0:
            return {"state": "none", "why": "limit"}
        budget[0] -= 1
        try:
            text = fetch(cand)
        except RateLimitError:
            raise  # never a result: the job waits for GitHub and scans again
        except Exception:  # GitHub down, DNS, a proxy: no comparison, and the page says so
            return {"state": "none", "why": "unreachable", "ha_version": ha_version}
        if text is not None:
            path = cand
            break
    if text is None or path is None:
        return {"state": "none", "why": "not-found", "ha_version": ha_version}
    tree = parse(text)
    if tree is None:
        return {"state": "none", "why": "unreadable", "ha_version": ha_version, "file": path}
    node = find_function(tree, qual)
    if node is None:
        return {"state": "none", "why": "not-found", "ha_version": ha_version, "file": path}
    a1, a2 = span(node)
    rel, lines, rnode = replacement
    b1, b2 = span(rnode)
    if a2 - a1 >= MAX_FUNC_LINES or b2 - b1 >= MAX_FUNC_LINES:
        return {"state": "none", "why": "too-long", "ha_version": ha_version, "file": path}
    old_lines = text.splitlines()
    hunks, added, removed, cut = diff(old_lines[a1 - 1 : a2], a1, lines[b1 - 1 : b2], b1)
    return {
        "state": "ok",
        "ha_version": ha_version,
        "file": path,
        "name": ".".join(qual)[:200],
        "original": [a1, a2],
        "replacement": [rel, b1, b2],
        "added": added,
        "removed": removed,
        "hunks": hunks,
        "cut": cut,
        # for the AI's citations: which original lines are comments or docstrings
        "noncode": _noncode(text, tree, a1, a2),
    }


def _noncode(text: str, tree: ast.Module, a: int, b: int) -> list[int]:
    from sniff_test.report.context import _python_noncode

    try:
        rows, _cols = _python_noncode(text, tree)
    except Exception:
        return []
    return sorted(n for n in rows if a <= n <= b)


def inside(
    rel: str,
    a: int,
    b: int,
    own_id: str,
    findings: list[dict[str, Any]],
    places: list[tuple[str, str, int]],
) -> dict[str, Any]:
    """What else of this scan sits on the replacement's lines `rel:a-b`: other findings
    (rule ids, at most 5) and the inventory's addresses and ports. `places`: (kind, file,
    line) of every address and port the scan listed."""
    rules: list[str] = []
    for f in findings:
        if f.get("id") == own_id or f.get("file") != rel:
            continue
        if isinstance(f.get("line"), int) and a <= f["line"] <= b and f["rule_id"] not in rules:
            rules.append(str(f["rule_id"]))
    here = [k for k, f, n in places if f == rel and a <= n <= b]
    return {
        "lines": [a, b],
        "findings": rules[:5],
        "more_findings": max(0, len(rules) - 5),
        "addresses": sum(1 for k in here if k in ("host", "ip")),
        "ports": sum(1 for k in here if k == "port"),
    }


def original_segments(cmp: dict[str, Any]) -> list[dict[str, Any]]:
    """Home Assistant's lines that the comparison shows, as snippet segments: what the AI
    is sent of the original and may cite."""
    out: list[dict[str, Any]] = []
    for hunk in cmp.get("hunks") or []:
        run: list[tuple[int, str]] = []
        for _tag, old, _new, text in [r for r in hunk if r[0] in (" ", "-")]:
            if run and old != run[-1][0] + 1:
                out.append({"file": cmp["file"], "start": run[0][0], "code": [t for _n, t in run]})
                run = []
            run.append((old, text))
        if run:
            out.append({"file": cmp["file"], "start": run[0][0], "code": [t for _n, t in run]})
    return out
