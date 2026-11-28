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

(0.15, #32) A line that puts back the original a function saved isn't reported, and the
patch it undoes says so (`temporary`).
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
    "stack at runtime. That changes behavior for every integration, and is how code "
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


# (0.15, #32) Added to a patch the same function undoes.
PUT_BACK = (
    "The same function puts the original back afterwards. Until it does, the change "
    "applies to all of Home Assistant, not just this app."
)


def _scope_nodes(func: ast.AST) -> list[ast.AST]:
    """Every node of `func`'s own scope (nested functions and classes left out)."""
    out: list[ast.AST] = []
    todo = list(func.body) if isinstance(func.body, list) else [func.body]
    while todo:
        n = todo.pop()
        out.append(n)
        if isinstance(n, (*_FUNCS, ast.ClassDef)):
            continue
        todo.extend(ast.iter_child_nodes(n))
    return out


def _key(obj: ast.expr, attr: ast.expr | str) -> tuple[str, ...] | None:
    """(object parts..., attribute) for `obj.attr`, or `obj` and a literal name."""
    parts = _dotted(obj)
    if isinstance(attr, ast.Constant):
        attr = attr.value
    if not parts or not isinstance(attr, str):
        return None
    return (*parts, attr)


def temporary(tree: ast.AST) -> tuple[set[int], set[int]]:
    """(0.15, #32) (restore lines, patch lines a restore undoes) in one module.

    A real integration forces IPv4 for one request: `original = getattr(conn,
    "allowed_gai_family", None)`, then `conn.allowed_gai_family = <its own>` in a `try`,
    and `conn.allowed_gai_family = original` in the `finally`. Putting the saved original
    back isn't a second patch. All three must be in one function, the saved name bound
    exactly once there (not a parameter, `global` or `nonlocal`), the restore after the
    save, and the object's first name not rebound in that function; anything else keeps
    every line.
    """
    restores: set[int] = set()
    undone: set[int] = set()
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        nodes = _scope_nodes(func)
        own = _locals(func)
        args = func.args
        params = {
            a.arg
            for a in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg)
            if a is not None
        }
        stores: dict[str, int] = {}
        for n in nodes:
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                stores[n.id] = stores.get(n.id, 0) + 1
        saved: dict[str, tuple[tuple[str, ...], int]] = {}
        writes: list[tuple[tuple[str, ...], int, ast.expr]] = []  # (key, line, value)
        for n in nodes:
            if isinstance(n, ast.Assign) and len(n.targets) == 1:
                t, v = n.targets[0], n.value
                if isinstance(t, ast.Name):
                    key = None
                    if isinstance(v, ast.Attribute):
                        key = _key(v.value, v.attr)
                    elif (
                        isinstance(v, ast.Call)
                        and isinstance(v.func, ast.Name)
                        and v.func.id == "getattr"
                        and len(v.args) in (2, 3)
                        and not v.keywords
                    ):
                        key = _key(v.args[0], v.args[1])
                    if key:
                        saved[t.id] = (key, n.lineno)
                elif isinstance(t, ast.Attribute) and (key := _key(t.value, t.attr)):
                    writes.append((key, n.lineno, v))
            elif (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "setattr"
                and len(n.args) == 3
                and (key := _key(n.args[0], n.args[1]))
            ):
                writes.append((key, n.lineno, n.args[2]))
        for key, line, value in writes:
            if not isinstance(value, ast.Name) or value.id not in saved:
                continue
            skey, sline = saved[value.id]
            if (
                skey == key
                and sline < line
                and stores.get(value.id) == 1
                and value.id in own
                and value.id not in params
                and key[0] not in own
            ):
                restores.add(line)
                undone.update(w for k, w, _ in writes if k == key and w != line)
    return restores, undone - restores


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
        restores, undone = temporary(tree)
        for line, resolved in check_tree(tree):
            if (rel, line) in seen or line in restores:
                continue
            seen.add((rel, line))
            note = f" {PUT_BACK}" if line in undone else ""
            out.append(
                Finding(
                    rule_id=RULE_ID,
                    title=TITLE,
                    severity=Severity.HIGH,
                    category=Category.TAMPER,
                    message=f"{MESSAGE} Patched object: {resolved}.{note}",
                    file=rel,
                    line=line,
                    evidence=_evidence(lines, line),
                    analyzer="semgrep+ast",
                )
            )
    return out
