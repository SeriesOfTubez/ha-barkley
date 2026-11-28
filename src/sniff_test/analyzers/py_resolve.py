"""Parse-only helpers to read what a name in an integration's Python stands for.

Several precision checks need the string behind a name: `DOMAIN` in
`hass.config_entries.async_entries(DOMAIN, ...)`, `_RENDER_DIR = f"{DOMAIN}_renders"` in
`hass.config.path(".storage", _RENDER_DIR)`, `CONF_HOST` in `entry.data.get(CONF_HOST)`.
Everything here parses the scanned code with `ast` and never runs or imports it.

A name resolves only when the answer is certain: a module-level constant assigned
exactly once in its file (two assignments, `global` rebinding or anything computed give
None), followed through relative imports inside the integration's own folder. Callers
decide what None means; every caller here keeps the finding when it can't tell.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

# Python 3.14 (PEP 758) allows `except A, B:` without brackets; Home Assistant's own
# formatter writes it, so apps copying that style don't parse on the scanner's 3.13.
# Same retry as report.compare.parse: brackets put back in the copy we parse.
_EXCEPT = re.compile(r"^(\s*except\*?\s+)([^():\n]+,[^():\n]+?)(\s+as\s+\w+)?(\s*:)", re.M)

# Home Assistant's own constants that name non-secret fields (homeassistant.const).
HA_CONST = {
    "CONF_HOST": "host",
    "CONF_MAC": "mac",
    "CONF_NAME": "name",
    "CONF_UNIQUE_ID": "unique_id",
    "CONF_ID": "id",
}
_MAX_DEPTH = 4
_MAX_BYTES = 2_000_000


def parse(text: str) -> ast.Module | None:
    """`text` as a syntax tree (line numbers as in the file), or None."""
    fixed = _EXCEPT.sub(lambda m: f"{m[1]}({m[2].strip()}){m[3] or ''}{m[4]}", text)
    for candidate in (text, fixed) if fixed != text else (text,):
        try:
            return ast.parse(candidate)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
    return None


class Resolver:
    """Constants of the Python files under `root` (an integration's install folder)."""

    def __init__(self, root: Path, package: str | None = None) -> None:
        self.root = root.resolve()
        # (0.15, py_library) a library read from inside: `from <package>.x import y` is
        # its own file, as `custom_components.<folder>.x` is an app's
        self.own = [package] if package else ["custom_components", self.root.name]
        self._trees: dict[str, ast.Module | None] = {}
        self._imports: dict[str, dict[str, tuple[str, str]]] = {}
        self.domains: frozenset[str] | None = None  # py_precision.own_domains' cache

    # --- files -------------------------------------------------------------------------

    def tree(self, rel: str) -> ast.Module | None:
        if rel not in self._trees:
            path = (self.root / rel).resolve()
            tree = None
            try:
                path.relative_to(self.root)  # never outside the integration
                if path.is_file() and not path.is_symlink() and path.stat().st_size < _MAX_BYTES:
                    tree = parse(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                tree = None
            self._trees[rel] = tree
        return self._trees[rel]

    def _module_file(self, rel: str, level: int, module: str | None) -> str | None:
        """`from <level dots><module> import x` in file `rel` -> that module's file."""
        if level == 0:
            # (0.15) `from custom_components.<this folder>.const import DOMAIN` is the app's
            # own module, written absolutely (4 wrong findings on the 600-app batch);
            # any other absolute import is another package, never resolved.
            parts = module.split(".") if module else []
            n = len(self.own)
            if parts[:n] != self.own:
                return None
            stem = Path(*parts[n:]) if parts[n:] else Path()
            for cand in (stem.with_suffix(".py") if parts[n:] else None, stem / "__init__.py"):
                if cand is not None and self.tree(cand.as_posix()) is not None:
                    return cand.as_posix()
            return None
        base = Path(rel).parent
        for _ in range(level - 1):
            if base == Path():
                return None  # above the integration's folder
            base = base.parent
        parts = module.split(".") if module else []
        stem = base.joinpath(*parts) if parts else base
        for cand in (stem.with_suffix(".py") if parts else None, stem / "__init__.py"):
            if cand is not None and self.tree(cand.as_posix()) is not None:
                return cand.as_posix()
        return None

    def imports(self, rel: str) -> dict[str, tuple[str, str]]:
        """Local name -> (module, imported name) for every `from … import …` at any depth.
        Relative modules are written with their dots ("..const")."""
        if rel not in self._imports:
            out: dict[str, tuple[str, str]] = {}
            tree = self.tree(rel)
            for n in ast.walk(tree) if tree else ():
                if isinstance(n, ast.ImportFrom):
                    mod = "." * n.level + (n.module or "")
                    for a in n.names:
                        out[a.asname or a.name] = (mod, a.name)
            self._imports[rel] = out
        return self._imports[rel]

    def _own_module(self, rel: str, name: str) -> str | None:
        """The file of the app's own module that `name` stands for in `rel`
        (`from . import const as name`, `from .helpers import const`), else None. A name
        the file also assigns is not certain."""
        hit = self.imports(rel).get(name)
        tree = self.tree(rel)
        if hit is None or tree is None or not hit[0].startswith("."):
            return None
        for n in ast.walk(tree):
            if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store):
                return None
        mod, orig = hit
        level = len(mod) - len(mod.lstrip("."))
        inner = ".".join(p for p in (mod.lstrip("."), orig) if p)
        return self._module_file(rel, level, inner)

    # --- values ------------------------------------------------------------------------

    def constant(self, rel: str, name: str, depth: int = 0) -> str | None:
        """The string a module-level name in `rel` certainly holds, else None."""
        tree = self.tree(rel)
        if tree is None or depth > _MAX_DEPTH:
            return None
        values: list[ast.expr | None] = []
        for st in tree.body:
            if isinstance(st, ast.Assign):
                for t in st.targets:
                    if isinstance(t, ast.Name) and t.id == name:
                        values.append(st.value if len(st.targets) == 1 else None)
                    elif any(isinstance(e, ast.Name) and e.id == name for e in ast.walk(t)):
                        values.append(None)  # tuple unpacking etc.: not certain
            elif (
                isinstance(st, ast.AnnAssign | ast.AugAssign)
                and isinstance(st.target, ast.Name)
                and st.target.id == name
            ):
                values.append(st.value if isinstance(st, ast.AnnAssign) and st.value else None)
        if any(isinstance(n, ast.Global) and name in n.names for n in ast.walk(tree)):
            return None
        if len(values) == 1 and values[0] is not None:
            return self.value(rel, values[0], depth + 1)
        if values:
            return None
        if name in self.imports(rel):
            mod, orig = self.imports(rel)[name]
            level = len(mod) - len(mod.lstrip("."))
            if (target := self._module_file(rel, level, mod.lstrip(".") or None)) is not None:
                return self.constant(target, orig, depth + 1)
        return None

    def value(self, rel: str, node: ast.expr, depth: int = 0) -> str | None:
        """The string an expression certainly evaluates to (literals, names of
        constants, f-strings and `+` of those), else None."""
        if depth > _MAX_DEPTH:
            return None
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.Name):
            return self.constant(rel, node.id, depth)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            # `from . import const as c` … `c.DOMAIN`: a constant of the app's own module
            if (target := self._own_module(rel, node.value.id)) is not None:
                return self.constant(target, node.attr, depth + 1)
            return None
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                elif (
                    isinstance(v, ast.FormattedValue)
                    and v.conversion == -1
                    and v.format_spec is None
                    and (s := self.value(rel, v.value, depth + 1)) is not None
                ):
                    parts.append(s)
                else:
                    return None
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.value(rel, node.left, depth + 1)
            right = self.value(rel, node.right, depth + 1)
            return left + right if left is not None and right is not None else None
        return None

    def ha_const(self, rel: str, node: ast.expr) -> str | None:
        """`CONF_HOST` imported from homeassistant.const -> "host" (only the names in
        HA_CONST); `const.CONF_HOST` after `from homeassistant import const` too."""
        if isinstance(node, ast.Name) and node.id in self.imports(rel):
            mod, orig = self.imports(rel)[node.id]
            if mod == "homeassistant.const" and orig in HA_CONST:
                return HA_CONST[orig]
        if (
            isinstance(node, ast.Attribute)
            and node.attr in HA_CONST
            and isinstance(node.value, ast.Name)
            and self.imports(rel).get(node.value.id) == ("homeassistant", "const")
        ):
            return HA_CONST[node.attr]
        return None


def parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
