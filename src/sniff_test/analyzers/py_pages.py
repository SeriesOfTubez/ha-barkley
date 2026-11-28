"""(0.15, his question) The address each login-free page answers on.

`ha-unauth-view` flags a `HomeAssistantView` class with `requires_auth = False` and keeps
the class line. This reads the class body for `url = "/api/…"` (and how many
`extra_urls` it lists), so the panel can say which page it is. The address may be a plain
string, or built from module-level string constants (a name, an f-string or `+` over
them) in the same file or imported from a sibling module (`from .const import X`). One
that depends on anything else (a setting, a call) is recorded as "" and shown as "built
while the app runs". The value is text from the scanned code: capped here, escaped where
shown.

Parse only: `ast.parse` of the app's files, nothing is imported or run.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

from sniff_test.models import Finding

RULE = "ha-unauth-view"
_MAX = 200
_MAX_FILE = 5 * 1024 * 1024


_DEPTH = 6


class _Consts:
    """Module-level string constants, followed across `from .x import Y` (parse only)."""

    def __init__(self, root: Path):
        self.root = root
        self._mods: dict[str, tuple[dict[str, ast.expr], dict[str, tuple[str, str]]]] = {}

    def _module(self, rel: str) -> tuple[dict[str, ast.expr], dict[str, tuple[str, str]]]:
        if rel in self._mods:
            return self._mods[rel]
        self._mods[rel] = ({}, {})  # a cycle sees an empty module
        p = self.root / rel
        try:
            if p.is_symlink() or not p.is_file() or p.stat().st_size > _MAX_FILE:
                return self._mods[rel]
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError, ValueError, RecursionError, MemoryError):
            return self._mods[rel]
        assigns: dict[str, ast.expr] = {}
        imports: dict[str, tuple[str, str]] = {}
        here = Path(rel).parent
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        assigns[t.id] = node.value
            elif isinstance(node, ast.ImportFrom) and node.level >= 1 and node.module:
                base = here
                for _ in range(node.level - 1):
                    base = base.parent
                mod = (base / (node.module.replace(".", "/") + ".py")).as_posix()
                for a in node.names:
                    imports[a.asname or a.name] = (mod, a.name)
        self._mods[rel] = (assigns, imports)
        return self._mods[rel]

    def value(self, rel: str, expr: ast.expr | None, depth: int = 0) -> str | None:
        if expr is None or depth > _DEPTH:
            return None
        if isinstance(expr, ast.Constant):
            return expr.value if isinstance(expr.value, str) else None
        if isinstance(expr, ast.Name):
            assigns, imports = self._module(rel)
            if expr.id in assigns:
                return self.value(rel, assigns[expr.id], depth + 1)
            if expr.id in imports:
                mod, name = imports[expr.id]
                return self.value(mod, ast.Name(id=name, ctx=ast.Load()), depth + 1)
            return None
        if isinstance(expr, ast.JoinedStr):
            parts = []
            for v in expr.values:
                if isinstance(v, ast.FormattedValue):
                    if v.conversion != -1 or v.format_spec is not None:
                        return None
                    v = v.value
                got = self.value(rel, v, depth + 1)
                if got is None:
                    return None
                parts.append(got)
            return "".join(parts)[:_MAX]
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            a, b = self.value(rel, expr.left, depth + 1), self.value(rel, expr.right, depth + 1)
            return (a + b)[:_MAX] if a is not None and b is not None else None
        return None


def _page(cls: ast.ClassDef, rel: str, consts: _Consts) -> str:
    url, extra = "", 0
    for node in cls.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = {t.id for t in targets if isinstance(t, ast.Name)}
        v = node.value
        if "url" in names:
            url = (consts.value(rel, v) or "").strip()[:_MAX]
        if "extra_urls" in names and isinstance(v, (ast.List, ast.Tuple, ast.Set)):
            extra = len(v.elts)
    if url and extra:
        url += f" (+{extra} more)"
    return url


def annotate(findings: list[Finding], root: Path) -> list[Finding]:
    """Each `ha-unauth-view` finding with `page` set: the address, or "" when the class
    has no plain-text `url`. Other findings are returned unchanged."""
    files = {f.file for f in findings if f.rule_id == RULE and f.file and f.file.endswith(".py")}
    classes: dict[str, dict[int, ast.ClassDef]] = {}
    for rel in files:
        p = root / rel
        try:
            if p.is_symlink() or not p.is_file() or p.stat().st_size > _MAX_FILE:
                continue
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        classes[rel] = {n.lineno: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
    consts = _Consts(root)
    out = []
    for f in findings:
        cls = classes.get(f.file or "", {}).get(f.line or -1) if f.rule_id == RULE else None
        page = _page(cls, f.file or "", consts) if cls is not None else None
        doc = " ".join((ast.get_docstring(cls) or "").split())[:_MAX] if cls is not None else ""
        out.append(dataclasses.replace(f, page=page, page_note=doc or None)
                   if page is not None else f)  # fmt: skip
    return out
