"""(0.14.1, #22) A full temporary folder: said in plain words, and GuardDog's archives freed
one by one. Nothing is downloaded or run here: fetching and GuardDog are faked, and the
package names are made up."""

from __future__ import annotations

from pathlib import Path

from sniff_test.analyzers import guarddog, python_deps
from sniff_test.analyzers.python_deps import Resolution, ResolvedPackage
from sniff_test.deps.uv import Artifact
from sniff_test.models import AnalyzerState
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


def _resolution(n: int) -> Resolution:
    pkgs = {}
    for i in range(n):
        name = f"acme_pkg{i}-1.0-py3-none-any.whl"
        art = Artifact(f"https://files.example.invalid/p{i}.whl", name, f"{i:064x}", "wheel")
        pkgs[(f"acme-pkg{i}", "1.0")] = ResolvedPackage(
            f"acme-pkg{i}", "1.0", {"x86_64"}, {art.filename: art}
        )
    return Resolution(packages=pkgs)


def test_each_archive_is_freed_after_guarddog_read_it(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    live: list[int] = []
    peak = [0]

    def fetch(art, w):
        d = w / "dists"
        d.mkdir(exist_ok=True)
        key = art.sha256[:32]
        (d / f"{key}-{art.filename}").write_bytes(b"x" * 10)
        (d / f"{key}.d").mkdir()
        (d / f"{key}.d" / "setup.py").write_text("print(1)\n")
        art.local = d / f"{key}.d"
        live.append(1)
        peak[0] = max(peak[0], len(list(d.iterdir())))
        return art.local

    read_while_there: list[bool] = []

    def findings(data, pkg, art):
        read_while_there.append(art.local is not None and (art.local / "setup.py").is_file())
        return []

    monkeypatch.setattr(guarddog, "fetch_artifact", fetch)
    monkeypatch.setattr(guarddog, "to_findings", findings)
    monkeypatch.setattr(
        guarddog, "_scan", lambda exe, local, run_dir, env: ({"results": {}}, "", True)
    )
    monkeypatch.setattr(guarddog.shutil, "which", lambda name: "/fake/guarddog")
    monkeypatch.setattr(guarddog, "tool_env", lambda exe: {})
    monkeypatch.setattr(guarddog, "guarddog_version", lambda: "3.2.0")
    res = guarddog.run(_resolution(12), work, jobs=1)
    assert res.state is AnalyzerState.OK
    assert read_while_there == [True] * 12  # findings came from the files, then they went
    assert list((work / "dists").iterdir()) == []
    assert peak[0] <= 2  # one archive and its unpacked copy at a time (jobs=1)


def test_the_scan_detail_says_the_temp_folder_is_full(tmp_path, monkeypatch):
    import sniff_test.workspace as ws

    work = tmp_path / "work"
    work.mkdir()

    def fetch(art, w):
        art.local = w
        return w

    monkeypatch.setattr(guarddog, "fetch_artifact", fetch)
    monkeypatch.setattr(guarddog, "discard_artifact", lambda art, w: None)
    monkeypatch.setattr(
        guarddog, "_scan", lambda exe, local, run_dir, env: (None, f"exit 1: ERROR: {FULL}", True)
    )
    monkeypatch.setattr(guarddog.shutil, "which", lambda name: "/fake/guarddog")
    monkeypatch.setattr(guarddog, "tool_env", lambda exe: {})
    monkeypatch.setattr(guarddog, "guarddog_version", lambda: "3.2.0")
    monkeypatch.setattr(ws, "free_mb", lambda path=None: 0)
    res = guarddog.run(_resolution(1), work, jobs=1)
    assert res.state is AnalyzerState.ERROR
    assert "out of temporary space: 0 MB free in" in res.detail
    assert res.detail.index("out of temporary space") < res.detail.index("No usable")


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
