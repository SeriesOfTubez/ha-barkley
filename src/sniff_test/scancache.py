"""(0.14.1) A cache of what Barkley found in code it has already read.

Keyed by content, never by name: an entry is the Semgrep results of one file for one
rule set, found under SHA-256(rule set, the file's path in the app, its bytes as
scanned), inside a folder named after the scan-logic key (logic.py), so new rules or
tools never read old answers. js_wrapper's answer is kept the same way for the whole
app (every JavaScript file and every token hit). Only Barkley writes here, and only
answers from complete runs: a file whose run timed out or failed is never kept.

The folder is held under a size limit (the Settings page): the least recently used
entries go first, and folders of other scan-logic keys go at once.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sniff_test import paths

MB = 1024 * 1024


@dataclass
class Stats:
    hits: int = 0  # files answered from the cache
    files: int = 0  # files a cached step looked at
    saved: float = 0.0  # seconds the cached answers took when they were made


@dataclass
class Cache:
    """`limit_mb` 0: off (nothing read or written)."""

    logic: str
    limit_mb: int = 1024
    root: Path = field(default_factory=lambda: paths.cache_root() / "scan-cache")
    stats: Stats = field(default_factory=Stats)

    @property
    def on(self) -> bool:
        return self.limit_mb > 0

    @property
    def folder(self) -> Path:
        return self.root / self.logic.replace("/", "_")

    def _path(self, kind: str, key: str) -> Path:
        k = hashlib.sha256(f"{kind}\0{key}".encode()).hexdigest()
        return self.folder / k[:2] / f"{k}.json"

    def get(self, kind: str, key: str) -> dict[str, Any] | None:
        if not self.on:
            return None
        p = self._path(kind, key)
        try:
            data = json.loads(p.read_text("utf-8"))
        except (OSError, ValueError):
            return None
        with contextlib.suppress(OSError):
            os.utime(p)  # least recently used goes first
        return data if isinstance(data, dict) else None

    def put(self, kind: str, key: str, value: dict[str, Any]) -> None:
        if not self.on:
            return
        with contextlib.suppress(OSError):
            paths.atomic_write(self._path(kind, key), json.dumps(value, separators=(",", ":")))

    def prune(self) -> None:
        """Drop other scan-logic keys' folders, then the least recently used entries
        until the folder fits the limit."""
        if not self.root.is_dir():
            return
        for other in self.root.iterdir():
            if other.is_dir() and other != self.folder and not other.is_symlink():
                shutil.rmtree(other, ignore_errors=True)
        if not self.on or not self.folder.is_dir():
            if not self.on:
                shutil.rmtree(self.folder, ignore_errors=True)
            return
        entries = []
        total = 0
        for p in self.folder.rglob("*.json"):
            with contextlib.suppress(OSError):
                st = p.stat()
                entries.append((st.st_mtime, st.st_size, p))
                total += st.st_size
        limit = self.limit_mb * MB
        for _mtime, size, p in sorted(entries):
            if total <= limit:
                break
            with contextlib.suppress(OSError):
                p.unlink()
                total -= size


def file_key(rules: str, rel: str, data: bytes) -> str:
    return f"{rules}\0{rel}\0{hashlib.sha256(data).hexdigest()}"


def size_mb(root: Path | None = None) -> float:
    root = root or paths.cache_root() / "scan-cache"
    total = 0
    for p in root.rglob("*.json") if root.is_dir() else ():
        with contextlib.suppress(OSError):
            total += p.stat().st_size
    return total / MB


def saved_text(seconds: float) -> str:
    if seconds < 90:
        return f"about {max(1, round(seconds))} s"
    return f"about {round(seconds / 60)} min"


def now() -> float:
    return time.monotonic()
