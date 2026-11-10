"""Where Sniff Test keeps downloaded data (the add-on sets SNIFF_TEST_CACHE=/data/cache)."""

from __future__ import annotations

import os
from pathlib import Path


def cache_root() -> Path:
    if override := os.environ.get("SNIFF_TEST_CACHE"):
        return Path(override)
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "sniff-test"


def atomic_write(path: Path, text: str) -> None:
    """Write via a uniquely named temp file in the same folder, then rename, so parallel
    scans filling the same cache entry never publish a half-written or mixed file."""
    import os
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        Path(tmp).replace(path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
