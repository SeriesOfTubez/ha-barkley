"""The app's own Python, kept beside its scans so "Explain in context" can show the AI
more code when it asks (0.11.0).

Captured by the scanner while the workspace exists: the files are read as text and parsed
with `ast`/`tokenize` (report.context), never run or imported. What is kept per file: the
text, which lines aren't code and where trailing comments start (the citation check needs
both), plus an index of what a reader can ask for by name: module-level functions,
classes, their methods and module-level constants. With the index, a later click slices
lines out of the stored text and parses nothing.

Integrations only: a card's bundle is minified, its names mean nothing. Capped at
MAX_PACKED compressed; above that nothing is kept and the page says the AI can't ask for
more. The store keeps one copy per content hash (Store.save), for the installed version
and a waiting update (watch.Watcher.sweep drops the rest).

Everything in here is text from the scanned repository: untrusted. Names reach the AI
only as a menu it picks from (report.ai_context), and only plain ASCII names and paths
are offered at all.
"""

from __future__ import annotations

import ast
import json
import re
import zlib
from pathlib import Path
from typing import Any

from sniff_test.models import Target, TargetKind
from sniff_test.report import context

KEY = "_app_source"  # how a scan function hands the source to Store.save; never stored in a report
VERSION = 1
MAX_PACKED = 1_000_000  # bytes, zlib level 6
MAX_FILES = 3_000  # Python files read; more than that and nothing is kept
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}(\.[A-Za-z_][A-Za-z0-9_]{0,79})?")
_PATH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./\-]{0,199}")


def pack(source: dict[str, Any]) -> bytes:
    return zlib.compress(json.dumps(source, separators=(",", ":"), sort_keys=True).encode(), 6)


def _index(rel: str, py: Any) -> list[list[Any]]:
    """[[name, file, first line, last line, kind], …] for one parsed file."""
    out: list[list[Any]] = []

    def add(name: str, a: int, b: int, kind: str) -> None:
        if _NAME.fullmatch(name) and _PATH.fullmatch(rel) and ".." not in rel:
            out.append([name, rel, a, b, kind])

    for stmt in py.tree.body:
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            add(stmt.name, *context._span(stmt), "function")
        elif isinstance(stmt, ast.ClassDef):
            add(stmt.name, *context._span(stmt), "class")
            for sub in stmt.body:
                if isinstance(sub, ast.FunctionDef | ast.AsyncFunctionDef):
                    add(f"{stmt.name}.{sub.name}", *context._span(sub), "method")
    for names, a, b in py.consts:
        for name in sorted(names):
            add(name, a, min(b, a + context.CONST_LINES - 1), "constant")
    return out


def capture(target: Target) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """(the source to keep or None, a note for the report's `context.source`)."""
    if target.kind is not TargetKind.INTEGRATION:
        return None, {"kept": False, "why": "cards"}
    return capture_root(Path(target.root))


def capture_root(root: Path) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    tree = context._Tree(root)
    files: dict[str, dict[str, Any]] = {}
    index: list[list[Any]] = []
    rels = tree.py_files(MAX_FILES + 1)
    if len(rels) > MAX_FILES:
        return None, {"kept": False, "why": "too big", "files": len(rels)}
    for rel in rels:
        text = tree.text(rel)
        if text is None:
            continue
        py = tree.py(rel)
        entry: dict[str, Any] = {"text": "\n".join(context._clean(x) for x in text.splitlines())}
        if py is not None:
            entry["noncode"] = sorted(py.noncode)
            entry["comment_col"] = {str(n): c for n, c in sorted(py.comment_col.items())}
            index += _index(rel, py)
        files[rel] = entry
    if not files:
        return None, {"kept": False, "why": "no Python"}
    source = {"v": VERSION, "files": files, "index": index}
    packed = len(pack(source))
    if packed > MAX_PACKED:
        return None, {"kept": False, "why": "too big", "packed": packed}
    return source, {"kept": True, "files": len(files), "packed": packed}
