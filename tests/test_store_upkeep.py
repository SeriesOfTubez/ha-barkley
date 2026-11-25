"""(his decisions 2026-11-25) Keeping the scan store in shape: VACUUM once a quarter of
the file is free pages, a checkpoint before each Home Assistant backup (config.yaml's
backup_pre, which must never fail the backup), and "Versions kept per app" (default:
all of them; the installed version and a waiting update are always kept). Made-up
reports; hosts use .invalid."""

from __future__ import annotations

import re
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_store import report
from test_watch import ctx  # noqa: F401  (the fixture)

from sniff_test import cli, server, settings
from sniff_test import store as store_mod
from sniff_test.store import Store
from sniff_test.supervisor import Installed

ADDON = Path(__file__).resolve().parents[1] / "addon" / "sniff_test"


def _free(s: Store) -> float:
    with sqlite3.connect(s.path) as db:
        return (
            db.execute("PRAGMA freelist_count").fetchone()[0]
            / db.execute("PRAGMA page_count").fetchone()[0]
        )


def _fill(s: Store, n: int) -> list[int]:
    big = [{"rule_id": "x", "file": f"f{i}.py", "line": i, "severity": "low",
            "message": "y" * 2000, "id": f"{i:016x}"} for i in range(40)]  # fmt: skip
    return [s.save(report(repo=f"acme/a{i}", ref="v1", findings=big)) for i in range(n)]


def test_compact_runs_only_once_a_quarter_is_free(tmp_path):
    s = Store(tmp_path / "s.db")
    ids = _fill(s, 12)
    s.delete(ids[0])  # a little free space: left for later saves to reuse
    assert 0 < _free(s) < store_mod.COMPACT_AT
    assert s.compact() is False
    before = s.size_bytes()
    for sid in ids[1:8]:
        s.delete(sid)
    assert _free(s) >= store_mod.COMPACT_AT
    assert s.compact() is True
    assert _free(s) == 0 and s.size_bytes() < before
    assert not (tmp_path / "s.db-wal").exists() or (tmp_path / "s.db-wal").stat().st_size == 0
    assert len(s.history(limit=100)) == 4  # nothing kept was lost


def test_the_checkpoint_empties_the_wal_and_never_creates_a_store(tmp_path):
    s = Store(tmp_path / "s.db")
    _fill(s, 2)
    wal = tmp_path / "s.db-wal"
    db = sqlite3.connect(s.path)  # stays open, as the running panel's can
    try:
        db.execute("SELECT count(*) FROM scans").fetchone()
        s.save(report(repo="acme/b", ref="v1"))
        assert wal.stat().st_size > 0  # the save waits in the WAL
        assert store_mod.checkpoint(s.path) == "the scan store is ready for the backup"
        assert wal.stat().st_size == 0
    finally:
        db.close()
    missing = tmp_path / "none.db"
    assert "nothing to do" in store_mod.checkpoint(missing)
    assert not missing.exists()


def test_a_busy_store_still_gets_backed_up(tmp_path):
    s = Store(tmp_path / "s.db")
    _fill(s, 1)
    reader = sqlite3.connect(s.path, isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT count(*) FROM scans").fetchone()  # a read that pins the WAL
    s.save(report(repo="acme/b", ref="v1"))
    try:
        out = store_mod.checkpoint(s.path, tries=2, wait=0, timeout=0.1)
    finally:
        reader.close()
    assert out == "the scan store was busy; backing it up as it is"


@pytest.mark.parametrize("given", [True, False])
def test_the_checkpoint_command_always_exits_0(tmp_path, capsys, given):
    path = tmp_path / ("s.db" if given else "missing.db")
    if given:
        Store(path)
    assert cli.main(["checkpoint", "--store", str(path)]) == 0
    assert path.exists() is given
    assert "🐕" in capsys.readouterr().out


def test_the_app_settles_the_store_before_a_backup():
    cfg = (ADDON / "config.yaml").read_text()
    assert "\nbackup_pre: sniff-test checkpoint --store /data/sniff-test.db\n" in cfg
    # Supervisor ignores backup_pre in a cold backup (and refuses the pair)
    assert not re.search(r"(?m)^backup:\s*cold", cfg)
    run = (ADDON / "rootfs/etc/s6-overlay/s6-rc.d/sniff-test/run").read_text()
    assert "\nexport SQLITE_TMPDIR=/tmp\n" in run  # VACUUM's copy, where AppArmor allows it
    assert "/tmp/{,**} rwk," in (ADDON / "apparmor.txt").read_text()


def _ids(store: Store) -> dict[tuple[str, str], int]:
    return {(r.repo, r.ref): r.id for r in store.history(limit=1000)}


def test_versions_kept_trims_older_versions_of_installed_apps(ctx):  # noqa: F811
    store, _worker, fakes, w = ctx
    fakes.items[:] = [Installed("acme/a", "integration", "A", "v1", "v7", False),
                      Installed("acme/card", "card", "B", "v9", "v9", False)]  # fmt: skip
    for v in ("v1", "v2", "v3", "v4", "v5", "v6", "v7"):
        store.save(report(repo="acme/a", ref=v))
    store.save(report(repo="acme/a", ref="v3"))  # a re-sniff of v3, newer than v6 and v7
    for v in ("v7", "v8", "v9"):
        store.save(report(repo="acme/card", ref=v, kind="plugin"))
    recent = datetime.fromtimestamp(fakes.now, UTC)
    store.save(report(repo="acme/gone", ref="v1"), scanned_at=recent)  # the age-out's business
    w.keep_versions_fn = lambda: 3
    w.sweep()
    # the newest three by scan (v3, v7, v6), the installed v1 and the waiting v7
    assert {r for (repo, r) in _ids(store) if repo == "acme/a"} == {"v1", "v3", "v6", "v7"}
    assert sum(1 for r in store.history(limit=100) if r.repo == "acme/a") == 5  # both v3s
    assert ("acme/gone", "v1") in _ids(store)
    assert {r for (repo, r) in _ids(store) if repo == "acme/card"} == {"v7", "v8", "v9"}


def test_versions_kept_leaves_an_app_with_a_job_alone(ctx):  # noqa: F811
    store, worker, fakes, w = ctx
    fakes.items[:] = [Installed("acme/busy", "card", "B", "v9", "v9", False)]
    for v in ("v6", "v7", "v8", "v9"):
        store.save(report(repo="acme/busy", ref=v, kind="plugin"))
    started, release = threading.Event(), threading.Event()

    def slow(repo, ref):
        started.set()
        release.wait(5)
        return report(repo=repo, ref=ref)

    worker.scan_fn = slow
    worker.submit("scan", "acme/busy", "v9")
    assert started.wait(5)
    w.keep_versions_fn = lambda: 3
    w.sweep()
    assert len(store.history(limit=100)) == 4
    release.set()
    worker.wait()


def test_keeping_them_all_is_the_default_and_deletes_nothing(ctx):  # noqa: F811
    store, _worker, _fakes, w = ctx
    assert settings.DEFAULTS.keep_versions == 0
    assert w.keep_versions_fn() == 0
    for v in ("v0", "v1", "v2", "v3", "v4"):
        store.save(report(repo="acme/a", ref=v))
    assert w.sweep() == 0 and len(store.history(limit=100)) == 5


def test_the_settings_page_offers_versions_kept_and_shows_the_store_size():
    out = server.render_settings("", settings.DEFAULTS, "t", store_mb=3.25).decode()
    i = out.index("<b>Versions kept per app</b>")
    row = out[i : out.index("</select>", i)]
    assert "The scan store uses 3.2 MB now." in row
    assert "always kept" in row
    assert re.findall(r"<option[^>]*>([^<]+)</option>", row) == [
        "All of them (default)", "The last 20", "The last 10", "The last 5", "The last 3"
    ]  # fmt: skip
    assert "keep_versions" in settings.PARTS["checking"]
    assert settings.from_dict({"keep_versions": "7"}).keep_versions == 0  # not a choice
    assert settings.from_dict({"keep_versions": "5"}).keep_versions == 5


def test_the_auto_sniff_box_says_what_is_kept(ctx):  # noqa: F811
    _store, _worker, _fakes, w = ctx
    assert "scans of installed apps are kept." in server.render_auto_activity("", w)
    w.keep_versions_fn = lambda: 5
    assert "installed apps keep the scans of their last 5 versions." in (
        server.render_auto_activity("", w)
    )
