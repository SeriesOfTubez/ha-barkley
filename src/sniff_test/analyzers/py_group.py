"""(0.14.1, #19) One "What it can do" finding per Python function.

A single feature often makes several calls of the same kind: a real integration's
admin-only websocket command that gives a PC its own user and token made four auth calls
(read the old tokens, remove them, create a refresh token, create an access token), and
each was a finding of its own, so one feature cost almost 44 points. Hits of the same
capability rule inside one function are now one finding that lists every line. Threats
are never folded: each place stays a finding of its own.

A capability inside a function behind `@websocket_api.require_admin` says that only an
administrator can run it. The score doesn't change: the decorator limits who can trigger
the command, not what the app's own code can do.

Parse only: `ast.parse` of the app's files, nothing is imported or run.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

from sniff_test import kinds
from sniff_test.models import Finding

_ADMIN = "require_admin"


@dataclasses.dataclass(frozen=True)
class _Scope:
    name: str  # qualified, e.g. "Cls.method" or "ws_provision"
    start: int
    end: int
    admin: bool


def _scopes(tree: ast.AST) -> list[_Scope]:
    out: list[_Scope] = []

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}{child.name}"
                if not isinstance(child, ast.ClassDef):
                    admin = any(_decorator_name(d) == _ADMIN for d in child.decorator_list)
                    out.append(_Scope(name, child.lineno, child.end_lineno or child.lineno, admin))
                walk(child, name + ".")
            else:
                walk(child, prefix)

    walk(tree, "")
    return out


def _decorator_name(d: ast.expr) -> str:
    if isinstance(d, ast.Call):
        d = d.func
    if isinstance(d, ast.Attribute):
        return d.attr
    if isinstance(d, ast.Name):
        return d.id
    return ""


def _innermost(scopes: list[_Scope], line: int) -> _Scope | None:
    best = None
    for s in scopes:
        if s.start <= line <= s.end and (best is None or s.end - s.start < best.end - best.start):
            best = s
    return best


def _parse(path: Path) -> ast.AST | None:
    try:
        text = path.read_text("utf-8", "replace")
    except OSError:
        return None
    try:
        return ast.parse(text)
    except SyntaxError:
        try:  # Python 3.14's `except A, B:` (HA's formatter writes it; PEP 758)
            import re

            return ast.parse(re.sub(r"^(\s*except\s+)([^():\n]+,[^():\n]+):", r"\1(\2):", text,
                                    flags=re.M))  # fmt: skip
        except SyntaxError:
            return None


def group(findings: list[Finding], root: Path) -> list[Finding]:
    root = root.resolve()
    trees: dict[str, list[_Scope] | None] = {}

    def scopes(rel: str) -> list[_Scope] | None:
        if rel not in trees:
            p = (root / rel).resolve()
            try:
                p.relative_to(root)
            except ValueError:
                trees[rel] = None
                return None
            tree = _parse(p) if p.is_file() else None
            trees[rel] = _scopes(tree) if tree is not None else None
        return trees[rel]

    groups: dict[tuple[str, str, str], list[Finding]] = {}
    where: dict[int, _Scope] = {}
    order: list[Finding | tuple[str, str, str]] = []
    for f in findings:
        if (
            not f.file
            or not f.line
            or not f.file.endswith(".py")
            or kinds.kind(f.rule_id) != kinds.CAPABILITY
        ):
            order.append(f)
            continue
        sc = scopes(f.file)
        scope = _innermost(sc, f.line) if sc else None
        if scope is None:
            order.append(f)
            continue
        key = (f.rule_id, f.file, scope.name)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
        where[id(f)] = scope
    out: list[Finding] = []
    for item in order:
        if isinstance(item, Finding):
            out.append(item)
            continue
        hits = sorted(groups[item], key=lambda f: (f.line or 0, f.id))
        # the one kept: the most severe, the earliest line among those
        first = min(hits, key=lambda f: (-int(f.severity), f.line or 0, f.id))
        scope = where[id(first)]
        extra = ""
        if len(hits) > 1:
            lines = ", ".join(str(h.line) for h in hits)
            extra += (
                f" The same function, `{scope.name}`, does this {len(hits)} times (lines "
                f"{lines}); it counts once."
            )
        if scope.admin:
            extra += (
                " Only an administrator can run this command (`@websocket_api.require_admin`); "
                "that limits who can trigger it, not what the app's own code can do."
            )
        out.append(dataclasses.replace(first, message=first.message + extra) if extra else first)
    return out
