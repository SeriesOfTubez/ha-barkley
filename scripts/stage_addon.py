"""Stage a self-contained add-on folder: the add-on files plus the scanner's source.

The Supervisor builds a local add-on from its folder alone, so the folder has to carry
everything the Dockerfile copies. Usage:

    uv run python scripts/stage_addon.py            # -> dist/addon/sniff_test/
    uv run python scripts/stage_addon.py OUT_DIR

Then copy the staged `sniff_test/` folder into the HA `/addons` share. Tests and
fixtures (deliberately malicious samples) are never staged.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADDON = ROOT / "addon" / "sniff_test"
SCANNER_FILES = ("pyproject.toml", "uv.lock", "README.md")
SCANNER_DIRS = ("src", "rules")
_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")


def stage(out: Path) -> Path:
    dest = out / "sniff_test"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(ADDON, dest, ignore=_IGNORE)
    scanner = dest / "scanner"
    scanner.mkdir()
    for name in SCANNER_FILES:
        shutil.copy2(ROOT / name, scanner / name)
    for name in SCANNER_DIRS:
        shutil.copytree(ROOT / name, scanner / name, ignore=_IGNORE)
    return dest


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist" / "addon"
    print(stage(target))
