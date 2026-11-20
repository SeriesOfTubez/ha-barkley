"""(0.15, his decision 2026-11-20) The environment variables the app's Python reads and
sets, by name when the code spells the name out.

Home Assistant's environment holds settings of the machine it runs on and, on Home
Assistant OS, the Supervisor's token (reading that one by name is its own finding,
`ha-supervisor-token`). The inventory only said "reads environment variables"; this says
which ones:

- reads: `os.environ["X"]`, `os.environ.get("X")`, `os.getenv("X")`, `"X" in os.environ`;
- sets: `os.environ["X"] = …`, `.setdefault`, `.update({...})`, `os.putenv`, and removals
  (`del`, `.pop`, `os.unsetenv`);
- a read of a name the app sets itself is marked `own` (it reads back its own setting);
- a name built while the app runs is counted without a name;
- any other use of `os.environ` (copied, looped over, handed to another program) is
  "the whole environment".

Names are followed through string constants like addresses are (py_requests.Reader). They
are text from the scanned code: only plain names are kept, capped, and escaped where
shown. Never scored. Parse only: `ast.parse`; nothing is imported or run.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from sniff_test.analyzers.py_requests import Reader, ScopeVisitor

VERSION = 1
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,79}$")
_MAX_FILES = 3000
_MAX_NAMES = 60
_MAX_AT = 3
_READ_CALLS = frozenset({"get"})
_WRITE_CALLS = frozenset({"setdefault", "pop", "update"})
_WHOLE_CALLS = frozenset({"copy", "items", "keys", "values"})


class _Visitor(ScopeVisitor):
    def __init__(self, reader: Reader, rel: str, tree: ast.Module):
        super().__init__(reader, rel)
        self.os_names: set[str] = set()  # names the `os` module goes by here
        self.environ: set[str] = set()  # names `os.environ` goes by
        self.funcs: dict[str, str] = {}  # local name -> getenv | putenv | unsetenv
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name == "os":
                        self.os_names.add(a.asname or "os")
            elif isinstance(node, ast.ImportFrom) and node.module == "os" and node.level == 0:
                for a in node.names:
                    if a.name == "environ":
                        self.environ.add(a.asname or a.name)
                    elif a.name in ("getenv", "putenv", "unsetenv"):
                        self.funcs[a.asname or a.name] = a.name
        self.done: set[int] = set()  # environ nodes a handled form already covers
        self.uses: list[tuple[str, str | None, int]] = []  # (read|write|whole, name, line)

    def _is_environ(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.environ
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "environ"
            and isinstance(node.value, ast.Name)
            and node.value.id in self.os_names
        )

    def _os_func(self, func: ast.expr) -> str:
        if isinstance(func, ast.Name):
            return self.funcs.get(func.id, "")
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in self.os_names
            and func.attr in ("getenv", "putenv", "unsetenv")
        ):
            return func.attr
        return ""

    def _name(self, expr: ast.expr | None) -> str | None:
        text = self.text(expr)
        return text if text is not None and _NAME.match(text) else None

    def _add(self, what: str, key: ast.expr | None, node: ast.AST) -> None:
        self.uses.append((what, self._name(key) if key is not None else None, node.lineno))

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self._is_environ(node.value):
            self.done.add(id(node.value))
            self._add("read" if isinstance(node.ctx, ast.Load) else "write", node.slice, node)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        if (
            len(node.ops) == 1
            and isinstance(node.ops[0], (ast.In, ast.NotIn))
            and self._is_environ(node.comparators[0])
        ):
            self.done.add(id(node.comparators[0]))
            self._add("read", node.left, node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        f = node.func
        first = node.args[0] if node.args else None
        if isinstance(f, ast.Attribute) and self._is_environ(f.value):
            self.done.add(id(f.value))
            if f.attr in _READ_CALLS:
                self._add("read", first, node)
            elif f.attr == "update":
                keys: list[ast.expr | None] = []
                if isinstance(first, ast.Dict):
                    keys += list(first.keys)
                keys += [ast.Constant(value=k.arg) for k in node.keywords if k.arg]
                for k in keys or [None]:
                    self.uses.append(("write", self._name(k) if k else None, node.lineno))
            elif f.attr in _WRITE_CALLS:
                self._add("write", first, node)
            else:  # .copy(), .items() and anything else: all of it
                self.uses.append(("whole", None, node.lineno))
        elif fn := self._os_func(f):
            self._add("read" if fn == "getenv" else "write", first, node)
        self.generic_visit(node)

    def _bare(self, node: ast.AST) -> None:
        if self._is_environ(node) and id(node) not in self.done:
            self.done.add(id(node))
            self.uses.append(("whole", None, node.lineno))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._bare(node)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self._bare(node)


def uses_in(root: Path) -> list[tuple[str, str | None, str, int]]:
    """(read | write | whole, name or None, file, line) for every use, in file order."""
    reader = Reader(root)
    out: list[tuple[str, str | None, str, int]] = []
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
        v = _Visitor(reader, rel, tree)
        if not (v.os_names or v.environ or v.funcs):
            continue
        try:
            v.visit(tree)
        except RecursionError:
            continue
        out += [(what, name, rel, line) for what, name, line in sorted(v.uses, key=lambda u: u[2])]
    return out


def _group(rows: list[tuple[str | None, str, int]]) -> tuple[list[dict[str, Any]], int]:
    by: dict[str, dict[str, Any]] = {}
    unnamed = 0
    for name, rel, line in rows:
        if name is None:
            unnamed += 1
            continue
        d = by.get(name)
        if d is None:
            if len(by) >= _MAX_NAMES:
                continue
            d = by[name] = {"name": name, "count": 0, "at": []}
        d["count"] += 1
        if len(d["at"]) < _MAX_AT:
            d["at"].append(f"{rel}:{line}")
    return sorted(by.values(), key=lambda d: d["name"]), unnamed


def summary(uses: list[tuple[str, str | None, str, int]]) -> dict[str, Any] | None:
    """The report's `environment` section, or None when the code doesn't touch the
    environment. Names are untrusted text (plain names only)."""
    if not uses:
        return None
    reads, unnamed_reads = _group([(n, f, ln) for w, n, f, ln in uses if w == "read"])
    writes, unnamed_writes = _group([(n, f, ln) for w, n, f, ln in uses if w == "write"])
    own = {d["name"] for d in writes}
    for d in reads:
        d["own"] = d["name"] in own
    whole = [f"{f}:{ln}" for w, _n, f, ln in uses if w == "whole"]
    return {
        "version": VERSION,
        "reads": reads,
        "writes": writes,
        "unnamed_reads": unnamed_reads,
        "unnamed_writes": unnamed_writes,
        "whole": {"count": len(whole), "at": whole[:_MAX_AT]},
    }
