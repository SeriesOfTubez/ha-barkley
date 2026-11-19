"""Temp workspaces and hostile-archive extraction.

Everything we download is attacker-controlled. Rules enforced here:
- each target gets its own fresh temp dir, never inside this repository;
- archives are extracted without ever following or creating links;
- no member may escape the destination (zip-slip, absolute paths, drive letters);
- total size and member count are capped (zip bombs), measured on bytes actually
  written, not on the sizes the archive header claims.
"""

from __future__ import annotations

import shutil
import stat
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 50_000
_CHUNK = 1024 * 1024

_REPO_ROOT = Path(__file__).resolve().parents[2]


class UnsafeArchiveError(Exception):
    pass


@contextmanager
def workspace(keep: bool = False) -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="sniff-test-")).resolve()
    if path.is_relative_to(_REPO_ROOT):  # pragma: no cover - defensive
        raise RuntimeError(f"refusing to use workspace inside the repo: {path}")
    try:
        yield path
    finally:
        if not keep:
            shutil.rmtree(path, ignore_errors=True)


STALE_AFTER = 24 * 3600
# (0.14.1, #22) Python reports a full temp folder as "No usable temporary directory
# found", which points at the wrong thing; these words mean the disk was full.
_FULL_WORDS = ("No usable temporary directory", "No space left on device", "Errno 28")
LOW_SPACE_MB = 100


def free_mb(path: Path | str | None = None) -> int | None:
    """Free space in MB where `path` lives (the temp folder by default)."""
    try:
        return shutil.disk_usage(path or tempfile.gettempdir()).free // (1024 * 1024)
    except OSError:
        return None


def space_hint(error: str, path: Path | str | None = None) -> str:
    """ "; out of temporary space: 12 MB free in /tmp; set TMPDIR to a folder with more
    room" when `error` looks like a full disk (or the folder has almost nothing left),
    else ""."""
    where = Path(path or tempfile.gettempdir())
    free = free_mb(where)
    if not any(w in error for w in _FULL_WORDS) and (free is None or free >= LOW_SPACE_MB):
        return ""
    have = f"{free} MB free" if free is not None else "almost no space"
    return f"; out of temporary space: {have} in {where}; set TMPDIR to a folder with more room"


def sweep_stale(root: Path | None = None, now: float | None = None) -> int:
    """Remove workspaces a killed run left behind (older than a day: no scan runs that
    long). Matters where the temp folder outlives the process, as with TMPDIR on a
    standalone container's data volume. Returns how many were removed."""
    import time

    root = Path(root or tempfile.gettempdir())
    cutoff = (now if now is not None else time.time()) - STALE_AFTER
    n = 0
    try:
        found = list(root.glob("sniff-test-*"))
    except OSError:
        return 0
    for d in found:
        try:
            st = d.lstat()
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode) and st.st_mtime < cutoff:
            shutil.rmtree(d, ignore_errors=True)
            n += 1
    return n


def new_subdir(ws: Path, name: str) -> Path:
    d = ws / name
    d.mkdir(parents=True, exist_ok=False)
    return d


def _safe_relpath(name: str) -> PurePosixPath | None:
    """Normalize an archive member name; None means 'skip silently' (e.g. pure dirs)."""
    name = name.replace("\\", "/")
    p = PurePosixPath(name)
    if p.is_absolute() or (p.parts and ":" in p.parts[0]):
        raise UnsafeArchiveError(f"absolute path in archive: {name!r}")
    parts = [part for part in p.parts if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise UnsafeArchiveError(f"path traversal in archive: {name!r}")
    if not parts:
        return None
    return PurePosixPath(*parts)


class _Budget:
    def __init__(self) -> None:
        self.bytes = 0
        self.members = 0

    def member(self) -> None:
        self.members += 1
        if self.members > MAX_MEMBERS:
            raise UnsafeArchiveError("archive has too many members")

    def add(self, n: int) -> None:
        self.bytes += n
        if self.bytes > MAX_TOTAL_BYTES:
            raise UnsafeArchiveError("archive expands beyond size limit")


def _write_stream(src, dest: Path, budget: _Budget) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("xb") as out:
        while chunk := src.read(_CHUNK):
            budget.add(len(chunk))
            out.write(chunk)
    dest.chmod(0o644)  # never keep executable bits from the archive


def _resolve_inside(dest_root: Path, rel: PurePosixPath) -> Path:
    target = (dest_root / rel).resolve()
    if not target.is_relative_to(dest_root):
        raise UnsafeArchiveError(f"member escapes destination: {rel}")
    return target


def extract_zip(archive: Path, dest: Path) -> list[str]:
    """Extract a zip. Returns names of skipped (link/special) members."""
    dest = dest.resolve()
    budget = _Budget()
    skipped: list[str] = []
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            budget.member()
            rel = _safe_relpath(info.filename)
            if rel is None:
                continue
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                skipped.append(info.filename)
                continue
            target = _resolve_inside(dest, rel)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if target.exists():
                raise UnsafeArchiveError(f"duplicate member: {info.filename!r}")
            with zf.open(info) as src:
                _write_stream(src, target, budget)
    return skipped


def extract_tar(archive: Path, dest: Path) -> list[str]:
    """Extract a tar(.gz). Only regular files and dirs; links/devices are skipped."""
    dest = dest.resolve()
    budget = _Budget()
    skipped: list[str] = []
    with tarfile.open(archive, mode="r:*") as tf:
        for member in tf:
            budget.member()
            if member.name == "pax_global_header":
                continue
            rel = _safe_relpath(member.name)
            if rel is None:
                continue
            if member.isdir():
                _resolve_inside(dest, rel).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                skipped.append(member.name)
                continue
            target = _resolve_inside(dest, rel)
            if target.exists():
                raise UnsafeArchiveError(f"duplicate member: {member.name!r}")
            src = tf.extractfile(member)
            if src is None:
                skipped.append(member.name)
                continue
            with src:
                _write_stream(src, target, budget)
    return skipped


def extract(archive: Path, dest: Path) -> list[str]:
    if zipfile.is_zipfile(archive):
        return extract_zip(archive, dest)
    if tarfile.is_tarfile(archive):
        return extract_tar(archive, dest)
    raise UnsafeArchiveError(f"unrecognized archive format: {archive.name}")


def copy_tree_safely(src: Path, dest: Path) -> list[str]:
    """Copy a local directory into the workspace without following symlinks."""
    src = src.resolve()
    budget = _Budget()
    skipped: list[str] = []
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        if ".git" in rel.parts:
            continue
        budget.member()
        if path.is_symlink():
            skipped.append(str(rel))
            continue
        out = dest / rel
        if path.is_dir():
            out.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            with path.open("rb") as fh:
                _write_stream(fh, out, budget)
        else:
            skipped.append(str(rel))
    return skipped


def single_top_dir(root: Path) -> Path:
    """GitHub tarballs wrap content in one '<owner>-<repo>-<sha>/' dir; unwrap it."""
    entries = [p for p in root.iterdir() if not p.name.startswith(".")] if root.exists() else []
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return root
