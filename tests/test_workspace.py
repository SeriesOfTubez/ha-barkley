import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from sniff_test import workspace as ws_mod
from sniff_test.workspace import UnsafeArchiveError, copy_tree_safely, extract, workspace


def _zip(path: Path, members: dict[str, bytes], symlinks: dict[str, str] | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    return path


def _tar(path: Path, members: dict[str, bytes], links: dict[str, str] | None = None) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    return path


def test_workspace_is_outside_repo_and_cleaned():
    repo = Path(__file__).resolve().parents[1]
    with workspace() as ws:
        assert not ws.is_relative_to(repo)
        kept = ws
    assert not kept.exists()


@pytest.mark.parametrize("name", ["../evil.py", "a/../../evil.py", "/etc/passwd", "C:/x.py"])
def test_zip_rejects_escaping_paths(tmp_path, name):
    archive = _zip(tmp_path / "a.zip", {name: b"x"})
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(UnsafeArchiveError):
        extract(archive, dest)


def test_tar_rejects_traversal(tmp_path):
    archive = _tar(tmp_path / "a.tgz", {"../evil.py": b"x"})
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(UnsafeArchiveError):
        extract(archive, dest)


def test_links_are_skipped_not_followed(tmp_path):
    z = _zip(tmp_path / "a.zip", {"ok.py": b"1"}, symlinks={"link": "/etc/passwd"})
    t = _tar(tmp_path / "a.tgz", {"ok.py": b"1"}, links={"link": "/etc/passwd"})
    for archive, out in ((z, "oz"), (t, "ot")):
        dest = tmp_path / out
        dest.mkdir()
        skipped = extract(archive, dest)
        assert skipped == ["link"]
        assert (dest / "ok.py").read_bytes() == b"1"
        assert not (dest / "link").exists()


def test_size_cap_counts_real_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(ws_mod, "MAX_TOTAL_BYTES", 1000)
    archive = _zip(tmp_path / "bomb.zip", {"a": b"0" * 600, "b": b"0" * 600})
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(UnsafeArchiveError, match="size"):
        extract(archive, dest)


def test_extracted_files_lose_exec_bit(tmp_path):
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("run.sh")
        info.external_attr = (stat.S_IFREG | 0o755) << 16
        zf.writestr(info, b"#!/bin/sh")
    dest = tmp_path / "out"
    dest.mkdir()
    extract(archive, dest)
    assert not (dest / "run.sh").stat().st_mode & 0o111


def test_copy_tree_skips_symlinks(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x")
    (src / "secret").symlink_to("/etc/hosts")
    dest = tmp_path / "dest"
    dest.mkdir()
    assert copy_tree_safely(src, dest) == ["secret"]
    assert (dest / "a.py").exists()
    assert not (dest / "secret").exists()
