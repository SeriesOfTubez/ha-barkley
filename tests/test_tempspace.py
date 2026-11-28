"""(0.14.1, #22) A full temporary folder, said in plain words, and an archive removed with
its unpacked copy. Nothing is downloaded or run here."""

from __future__ import annotations

from pathlib import Path

from sniff_test.analyzers import python_deps
from sniff_test.deps.uv import Artifact
from sniff_test.workspace import space_hint

FULL = "[Errno 2] No usable temporary directory found in ['/tmp', '/var/tmp']"


def test_a_full_temp_folder_is_named_plainly(tmp_path, monkeypatch):
    import sniff_test.workspace as ws

    monkeypatch.setattr(ws, "free_mb", lambda path=None: 0)
    hint = space_hint(FULL, tmp_path)
    assert hint == (
        f"; out of temporary space: 0 MB free in {tmp_path}; set TMPDIR to a folder with more room"
    )
    monkeypatch.setattr(ws, "free_mb", lambda path=None: 5000)
    assert space_hint("exit 1: some other failure", tmp_path) == ""
    assert "5000 MB free" in space_hint("No space left on device", tmp_path)
    monkeypatch.setattr(ws, "free_mb", lambda path=None: 40)  # nearly full: said anyway
    assert "40 MB free" in space_hint("exit 1: something", tmp_path)


def test_discard_removes_the_archive_and_its_copy(tmp_path):
    art = Artifact(
        "https://files.example.invalid/a.whl", "acme-1.0-py3-none-any.whl", "ab" * 32, "wheel"
    )
    d = tmp_path / "dists"
    d.mkdir()
    (d / f"{'ab' * 16}-acme-1.0-py3-none-any.whl").write_bytes(b"x")
    (d / f"{'ab' * 16}.d").mkdir()
    art.local = d / f"{'ab' * 16}.d"
    python_deps.discard_artifact(art, tmp_path)
    assert list(d.iterdir()) == [] and art.local is None
    assert isinstance(tmp_path, Path)
