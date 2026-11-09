"""Stage a self-contained add-on folder: the add-on files plus the scanner's source.

The Supervisor builds a local add-on from its folder alone, so the folder has to carry
everything the Dockerfile copies. Usage:

    uv run python scripts/stage_addon.py            # -> dist/addon/sniff_test/
    uv run python scripts/stage_addon.py OUT_DIR

It also writes `sniff_test.tar` next to the folder: a plain archive (no extended
attributes, no pax headers) to stream into HA's local add-on folder over SSH:

    ssh root@homeassistant.local 'rm -rf /local_apps/sniff_test && tar -C /local_apps -xf -' \
        < dist/addon/sniff_test.tar

macOS `tar` (from a user's Terminal) adds AppleDouble `._*` files for extended
attributes; HA's busybox `tar` extracted them as real files
(`rules/python/._code-exec.yaml`) and Semgrep crashed loading them as rules
(UnicodeDecodeError on byte 0xa3). Tests and fixtures (deliberately malicious
samples) are never staged.
"""

from __future__ import annotations

import shutil
import sys
import tarfile
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


def archive(dest: Path) -> Path:
    """A plain GNU-format tar of the staged folder: regular files and dirs only."""
    out = dest.parent / f"{dest.name}.tar"

    def clean(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        if not (info.isfile() or info.isdir()):
            return None
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.pax_headers = {}
        return info

    with tarfile.open(out, "w", format=tarfile.GNU_FORMAT) as tar:
        tar.add(dest, arcname=dest.name, filter=clean)
    return out


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist" / "addon"
    staged = stage(target)
    print(staged)
    print(archive(staged))
