"""`ha-monkeypatch` for the assignment forms Semgrep doesn't match (parsed, never run).

Checked 2026-11-09 on Semgrep 1.181 with isolated cases, and again on 1.185 (2026-11-13:
the same 7 of 22 forms seen): Semgrep matches `homeassistant.x = v`, tuple and
annotated targets, and `setattr(homeassistant, ...)`, but not
- chained assignments: `x = homeassistant.y = v`, `homeassistant.y = x = v`
- augmented ones (`+=`), `for`/`with ... as` targets, `[homeassistant.y] = [v]`
- anything on a name bound by `from ... import`, because the rule's regex sees the local
  text: `from homeassistant.helpers import aiohttp_client` followed by
  `aiohttp_client.async_get_clientsession = evil`, or `setattr(core, "x", v)`.

This walks every store-context attribute and every `setattr(obj, ...)` call, resolves the
object's first name through the file's imports, and matches the rule's own object regex.
A name the enclosing function rebinds (a parameter or a local assignment) is that local
object, not the import, the same scoping Python uses (a false positive on a real
integration was Semgrep ignoring that). Lines Semgrep already flagged are skipped.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from sniff_test.models import Category, Finding, Severity

# Must stay identical to rules/python/tamper.yaml (tests/test_py_tamper.py checks it).
RULE_ID = "ha-monkeypatch"
TITLE = "Monkeypatches core or network stack"
MESSAGE = (
    "Replaces attributes on Home Assistant core, the auth system, or the network/TLS "
    "stack at runtime. That changes behaviour for every integration, and is how code "
    "hides traffic, steals credentials in flight, or disables TLS checks globally."
)
OBJ_REGEX = (
    r"^(homeassistant(\.\w+)*|HomeAssistant|socket|socket\.socket|ssl|ssl\.SSLContext|"
    r"aiohttp(\.\w+)*|ClientSession|TCPConnector|requests(\.\w+)*|urllib3(\.\w+)*|"
    r"http\.client(\.\w+)*|builtins|(self\.)?_?hass\.(auth|http|bus|states|services|"
    r"config_entries|loop)(\.\w+)*)$"
)
_OBJ = re.compile(OBJ_REGEX)
_EVIDENCE_MAX = 300
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _dotted(node: ast.expr) -> list[str] | None:
    """`a.b.c` -> ["a", "b", "c"]; None for anything that isn't a plain name chain."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return parts[::-1]


def _imports(tree: ast.AST) -> dict[str, str]:
    """Local name -> the module path it was imported as (absolute imports only)."""
    out: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.asname:
                    out[a.asname] = a.name
                else:
                    top = a.name.split(".", 1)[0]
                    out[top] = top
        elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
            for a in n.names:
                if a.name != "*":
                    out[a.asname or a.name] = f"{n.module}.{a.name}"
    return out


def _locals(func: ast.AST) -> set[str]:
    """Names a function binds itself, as Python decides it, minus `global`/`nonlocal`.

    Getting this wrong in the "too many" direction would hide a real patch, so only real
    bindings count: parameters, assignment/`for`/`with`/walrus/`del` targets,
    `def`/`class` names, `except ... as`, and match captures. Imports inside the function
    don't count: they bind the module itself, which `_imports` already resolves. A
    comprehension's own loop variable lives in the comprehension's scope, so it doesn't
    shadow anything here.
    """
    args = func.args
    names = {
        a.arg
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg)
        if a is not None
    }
    declared: set[str] = set()
    todo = list(func.body) if isinstance(func.body, list) else [func.body]
    while todo:
        n = todo.pop()
        if isinstance(n, (ast.Global, ast.Nonlocal)):
            declared.update(n.names)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            names.add(n.id)
        elif isinstance(n, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and n.name:
            names.add(n.name)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            names.add(n.rest)
        elif isinstance(n, ast.comprehension):
            todo.extend([n.iter, *n.ifs])  # not n.target: that's the comprehension's
            continue
        if isinstance(n, (*_FUNCS, ast.ClassDef)):
            if not isinstance(n, ast.Lambda):
                names.add(n.name)
            continue  # its body is another scope
        todo.extend(ast.iter_child_nodes(n))
    return names - declared


def _patched_objects(tree: ast.AST) -> list[tuple[ast.AST, ast.expr]]:
    """(node, object) for each `obj.attr` store and each `setattr(obj, ...)` call."""
    out: list[tuple[ast.AST, ast.expr]] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Store):
            out.append((n, n.value))
        elif (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "setattr"
            and n.args
        ):
            out.append((n, n.args[0]))
    return out


def _evidence(lines: list[str], line: int) -> str:
    text = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    return text[:_EVIDENCE_MAX] + ("…" if len(text) > _EVIDENCE_MAX else "")


def check_tree(tree: ast.AST) -> list[tuple[int, str]]:
    """(line, resolved object) for every patch of a watched object in one module."""
    imports = _imports(tree)
    parent: dict[ast.AST, ast.AST] = {}
    for n in ast.walk(tree):
        for c in ast.iter_child_nodes(n):
            parent[c] = n
    scope_locals: dict[ast.AST, set[str]] = {}

    def enclosing_locals(node: ast.AST) -> set[str]:
        p = parent.get(node)
        while p is not None and not isinstance(p, _FUNCS):
            p = parent.get(p)
        if p is None:
            return set()  # module scope: imports are what the names mean
        if p not in scope_locals:
            scope_locals[p] = _locals(p)
        return scope_locals[p]

    hits: list[tuple[int, str]] = []
    for node, obj in _patched_objects(tree):
        parts = _dotted(obj)
        if not parts:
            continue
        head, rest = parts[0], parts[1:]
        if head in imports:
            if head in enclosing_locals(node):
                continue  # a local that shadows the import
            resolved = ".".join([imports[head], *rest])
        else:
            resolved = ".".join(parts)
        if _OBJ.match(resolved):
            hits.append((node.lineno, resolved))
    return hits


def find(root: Path, skip: set[tuple[str, int]], trees: dict[str, Any]) -> list[Finding]:
    """ha-monkeypatch findings for every .py under root, except (file, line) in skip."""
    out: list[Finding] = []
    seen: set[tuple[str, int]] = set(skip)
    for p in sorted(root.rglob("*.py")):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(root).as_posix()
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if rel not in trees:
            try:
                trees[rel] = ast.parse(data)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                trees[rel] = None  # Semgrep reports unparseable files (scan-parse-error)
        tree = trees[rel]
        if tree is None:
            continue
        lines = data.decode("utf-8", errors="replace").splitlines()
        for line, resolved in check_tree(tree):
            if (rel, line) in seen:
                continue
            seen.add((rel, line))
            out.append(
                Finding(
                    rule_id=RULE_ID,
                    title=TITLE,
                    severity=Severity.HIGH,
                    category=Category.TAMPER,
                    message=f"{MESSAGE} Patched object: {resolved}.",
                    file=rel,
                    line=line,
                    evidence=_evidence(lines, line),
                    analyzer="semgrep+ast",
                )
            )
    return out
