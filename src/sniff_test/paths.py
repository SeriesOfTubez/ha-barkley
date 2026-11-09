"""Where Sniff Test keeps downloaded data (the add-on sets SNIFF_TEST_CACHE=/data/cache)."""

from __future__ import annotations

import os
from pathlib import Path


def cache_root() -> Path:
    if override := os.environ.get("SNIFF_TEST_CACHE"):
        return Path(override)
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "sniff-test"
