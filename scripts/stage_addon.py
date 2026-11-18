"""Stage a self-contained add-on folder: the add-on files plus the scanner's source.

The Supervisor builds a local add-on from its folder alone, so the folder has to carry
everything the Dockerfile copies. Usage:

    uv run python scripts/stage_addon.py            # -> dist/addon/sniff_test/
    uv run python scripts/stage_addon.py OUT_DIR
    uv run python scripts/stage_addon.py --box-build 2   # version X.Y.Z.2, for a test box

`--box-build N` stamps the staged copy (config.yaml, pyproject.toml, the package's
__version__) with `<version>.N`. Only for deploying unreleased work to a test box: the
Supervisor offers Update (which loads the AppArmor profile; Rebuild doesn't) only when
the version changed, and Barkley reuses a stored scan only when it was made by the same
version, so scans from an earlier build of the same release are sniffed again. The repo
never carries the stamp.

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


def _build_locally(config: Path) -> None:
    """Drop the `image:` key from the staged manifest.

    The repository's config.yaml names the published image, so the app store pulls it.
    With that key the Supervisor never builds: a staged folder on a box would pull the
    last published image and ignore the source it carries.
    """
    lines = config.read_text().splitlines(keepends=True)
    kept = [line for line in lines if not line.startswith("image:")]
    if len(kept) != len(lines) - 1:
        raise SystemExit(f"{config}: expected exactly one top-level `image:` line")
    config.write_text("".join(kept))


def stage(out: Path) -> Path:
    dest = out / "sniff_test"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(ADDON, dest, ignore=_IGNORE)
    _build_locally(dest / "config.yaml")
    scanner = dest / "scanner"
    scanner.mkdir()
    for name in SCANNER_FILES:
        shutil.copy2(ROOT / name, scanner / name)
    for name in SCANNER_DIRS:
        shutil.copytree(ROOT / name, scanner / name, ignore=_IGNORE)
    return dest


def stamp(dest: Path, build: int) -> str:
    """Write `<version>.<build>` into the staged copy only (see the module docstring)."""
    init = dest / "scanner" / "src" / "sniff_test" / "__init__.py"
    text = init.read_text()
    old = text.split('__version__ = "', 1)[1].split('"', 1)[0]
    new = f"{old}.{build}"
    init.write_text(text.replace(f'__version__ = "{old}"', f'__version__ = "{new}"', 1))
    for path, before, after in (
        (dest / "config.yaml", f'version: "{old}"', f'version: "{new}"'),
        (dest / "scanner" / "pyproject.toml", f'version = "{old}"', f'version = "{new}"'),
    ):
        t = path.read_text()
        if before not in t:
            raise SystemExit(f"{path}: expected {before!r}")
        path.write_text(t.replace(before, after, 1))
    return new


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
    args = sys.argv[1:]
    build = None
    if "--box-build" in args:
        i = args.index("--box-build")
        build = int(args[i + 1])
        if build < 1:
            raise SystemExit("--box-build wants a number from 1")
        del args[i : i + 2]
    target = Path(args[0]) if args else ROOT / "dist" / "addon"
    staged = stage(target)
    if build is not None:
        print("version", stamp(staged, build))
    print(staged)
    print(archive(staged))
