"""SQLite scan store: round trip, reuse rules, CLI `--store`, diff of stored scans."""

import json
import sqlite3

import pytest
from conftest import requires_semgrep
from real_cases import case

from sniff_test import __version__, cli
from sniff_test.diff import diff
from sniff_test.store import STORE_VERSION, Store, StoreError


def report(
    repo="acme/acme",
    ref="v1",
    kind="integration",
    ha="2026.11.0",
    exposure="local",
    tool=__version__,
    findings=(),
    edges=(),
    score=100,
):
    subject = {"id": "integration:acme", "kind": "integration", "label": "acme", "attrs": {}}
    host = {"id": "host:x.invalid", "kind": "host", "ring": "network", "label": "x.invalid"}
    return {
        "schema_version": 1,
        "tool": {"name": "sniff-test", "version": tool},
        "target": {
            "input": repo,
            "kind": kind,
            "repo": repo,
            "ref": ref,
            "commit_sha": "a" * 40,
            "install_source": "tag_source",
            "artifact_sha256": None,
            "domain": "acme",
        },
        "exposure": exposure,
        "ha_version": ha if kind == "integration" else None,
        "complete": True,
        "score": score,
        "verdict": {"key": "good_boy" if score >= 90 else "very_sus", "label": "x"},
        "findings": list(findings),
        "graph": {"subject": subject["id"], "nodes": [subject, host], "edges": list(edges)},
        "provenance": None,
    }


FINDING = {
    "id": "f" * 16,
    "rule_id": "ha-read-secrets",
    "title": "Reads secrets.yaml",
    "severity": "high",
    "category": "exfil",
    "file": "diag.py",
    "line": 3,
    "evidence": "open('secrets.yaml'); -- '); DROP TABLE scans; --",
}
EDGE = {
    "id": "e" * 16,
    "source": "integration:acme",
    "target": "host:x.invalid",
    "relation": "talks_to",
    "evidence": "possible",
    "count": 2,
    "samples": [],
    "finding_ids": ["f" * 16],
    "attrs": {"class": "undeclared"},
}


def test_report_round_trips_exactly_and_indexes_are_derived(tmp_path):
    store = Store(tmp_path / "s.db")
    rep = report(findings=[FINDING], edges=[EDGE], score=75)
    sid = store.save(rep)
    assert store.report(sid) == rep  # what diff.py reads is what the scan produced
    row = store.get(sid)
    assert (row.repo, row.ref, row.score, row.verdict, row.ha_version) == (
        "acme/acme",
        "v1",
        75,
        "very_sus",
        "2026.11.0",
    )
    db = sqlite3.connect(tmp_path / "s.db")
    assert db.execute("SELECT rule_id, severity FROM findings").fetchall() == [
        ("ha-read-secrets", "high")
    ]
    assert db.execute("SELECT count(*) FROM nodes").fetchone() == (2,)
    assert db.execute("SELECT edge_id, finding_id FROM edge_findings").fetchall() == [
        ("e" * 16, "f" * 16)
    ]
    assert db.execute("SELECT count(*) FROM scans").fetchone() == (1,)  # injection is data
    assert store.scans_reaching("host:x.invalid") == [(sid, "talks_to", "possible")]


def test_delete_cascades(tmp_path):
    store = Store(tmp_path / "s.db")
    sid = store.save(report(findings=[FINDING], edges=[EDGE]))
    assert store.delete(sid)
    db = sqlite3.connect(tmp_path / "s.db")
    for table in ("scans", "findings", "nodes", "edges", "edge_findings"):
        assert db.execute(f"SELECT count(*) FROM {table}").fetchone() == (0,)  # noqa: S608
    with pytest.raises(StoreError):
        store.report(sid)


def test_find_reuses_only_scans_a_fresh_scan_would_reproduce(tmp_path):
    store = Store(tmp_path / "s.db")
    old = store.save(report(ha="2026.10.0"))
    cur = store.save(report(ha="2026.11.0"))
    store.save(report(exposure="public"))
    store.save(report(tool="0.0.1"))
    kw = {"exposure": "local", "tool_version": __version__}
    assert store.find("ACME/acme", "v1", ha_version="2026.11.0", **kw).id == cur
    assert store.find("acme/acme", "v1", ha_version="2026.10.0", **kw).id == old
    assert store.find("acme/acme", "v1", ha_version="2026.12.0", **kw) is None
    assert store.find("acme/acme", "v2", ha_version="2026.11.0", **kw) is None
    # Cards don't depend on the HA release.
    card = store.save(report(repo="acme/card", kind="plugin"))
    assert store.find("acme/card", "v1", ha_version="2026.12.0", **kw).id == card


def test_history_is_newest_first_and_filters_by_repo(tmp_path):
    store = Store(tmp_path / "s.db")
    a = store.save(report(ref="v1"))
    b = store.save(report(repo="other/x", ref="v9"))
    c = store.save(report(ref="v2"))
    assert [r.id for r in store.history()] == [c, b, a]
    assert [r.id for r in store.history("Acme/Acme")] == [c, a]


def test_rejects_newer_store_and_non_reports(tmp_path):
    path = tmp_path / "s.db"
    db = sqlite3.connect(path)
    db.execute(f"PRAGMA user_version = {STORE_VERSION + 1}")
    db.close()
    with pytest.raises(StoreError, match="newer"):
        Store(path)
    with pytest.raises(StoreError, match="not a sniff-test report"):
        Store(tmp_path / "t.db").save({"findings": []})


def test_cli_diff_of_stored_ids_needs_store(tmp_path, monkeypatch):
    monkeypatch.delenv(cli.STORE_ENV, raising=False)
    assert cli.main(["diff", "@1", "@2"]) == 1
    db = tmp_path / "s.db"
    assert cli.main(["diff", "@1", "@2", "--store", str(db)]) == 1  # no such scans


def test_cli_reuses_stored_scans_for_from_to(tmp_path, monkeypatch):
    db = tmp_path / "s.db"
    store = Store(db)
    store.save(report(ref="v1"))
    store.save(report(ref="v2", findings=[FINDING], edges=[EDGE], score=75))

    def no_scan(*a, **k):
        raise AssertionError("should have used the stored scans")

    monkeypatch.setattr(cli, "scan", no_scan)
    # (0.14.1) stored scans are found by the scan-logic key; these reports carry only the
    # tool version, which stands in for it here
    monkeypatch.setattr(cli.logic, "key", lambda: report()["tool"]["version"])
    out = tmp_path / "d.json"
    args = ["diff", "acme/acme", "--from", "v1", "--to", "v2", "--ha-version", "2026.11.0"]
    assert cli.main([*args, "--store", str(db), "--json", "-o", str(out)]) == 0
    d = json.loads(out.read_text())
    assert d["score"] == {"from": 100, "to": 75, "delta": -25}
    assert d["changes"]  # the edge into x.invalid is new


def test_diff_warns_when_ha_releases_differ():
    d = diff(report(ha="2026.10.0"), report(ha="2026.11.0"))
    assert any("different HA releases" in w for w in d["warnings"])


@requires_semgrep
def test_cli_scan_store_then_diff_stored_fixture_pair(tmp_path, fixtures, monkeypatch):
    monkeypatch.delenv(cli.STORE_ENV, raising=False)
    db = tmp_path / "s.db"
    for name in ("clean_integration", "clean_integration_v2"):
        assert cli.main(["scan", str(fixtures / name), "--offline", "--store", str(db)]) == 0
    rows = Store(db).history()
    assert [r.score for r in rows] == [50, 89]  # --offline is incomplete: capped at 89
    clean = Store(db).report(rows[1].id)
    assert clean["complete"] is False  # --offline: incomplete, but zero findings
    assert clean["findings"] == []
    out = tmp_path / "d.json"
    old, new = rows[1].id, rows[0].id
    args = ["diff", f"@{old}", f"@{new}", "--store", str(db), "--json", "-o", str(out)]
    assert cli.main(args) == 0
    kinds = sorted(c["kind"] for c in json.loads(out.read_text())["changes"])
    assert kinds == ["new_flow", "new_host", "new_read"]
    assert cli.main(["history", "--store", str(db)]) == 0


@pytest.mark.network
@requires_semgrep
def test_a_publisher_handover_from_stored_scans(tmp_path, monkeypatch):
    """The M5 done criterion: two stored scans of a real card, diffed from the store."""
    repo, old_tag, new_tag, publisher, _before = case("BARKLEY_TEST_HANDOVER", 5)
    db = tmp_path / "s.db"
    for tag in (old_tag, new_tag):
        rc = cli.main(["scan", repo, "--ref", tag, "--store", str(db)])
        assert rc == 0
    new, old = (r.id for r in Store(db).history())
    monkeypatch.setattr(cli, "scan", lambda *a, **k: pytest.fail("scanned again"))
    out = tmp_path / "d.json"
    args = ["diff", repo, "--from", old_tag, "--to", new_tag]
    assert cli.main([*args, "--store", str(db), "--json", "-o", str(out)]) == 0
    by_id = tmp_path / "e.json"
    args = ["diff", f"@{old}", f"@{new}", "--store", str(db), "--json", "-o", str(by_id)]
    assert cli.main(args) == 0
    for path in (out, by_id):
        top = json.loads(path.read_text())["changes"][0]
        assert top["kind"] == "new_publisher"
        assert publisher in top["text"]
