"""Advisory re-checks (0.10.0): a scan's lockfiles saved beside the report, OSV asked again
from them, a change stored as a new scan entry (the old one never edited), the daily pass
and its notification."""

import copy
import hashlib
import json
import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_server import get, post
from test_store import FINDING, report
from test_watch import Fakes

from sniff_test import recheck, server, trust, watch
from sniff_test.analyzers import osv
from sniff_test.analyzers.python_deps import Resolution, ResolvedPackage
from sniff_test.deps.reqs import ReqKind, Requirement
from sniff_test.models import AnalyzerResult, AnalyzerState, Target, TargetKind
from sniff_test.store import Store
from sniff_test.supervisor import Installed

HOSTILE_PKG = "evil-pkg<script>"


def osv_finding(
    pkg="yaml-lib", version="4.1.1", ids="GHSA-aaaa", severity="medium", rule="dep-vuln"
):
    evidence = f"{pkg}@{version} (npm): {ids}"
    return {
        "id": hashlib.sha256(f"{rule}{evidence}".encode()).hexdigest()[:16],
        "rule_id": rule,
        "title": "Dependency with known vulnerabilities",
        "severity": severity,
        "base_severity": None,
        "category": "dependency",
        "tags": [],
        "message": f"{pkg} {version} has 1 known vulnerability: {ids}.",
        "file": "package-lock.json",
        "line": None,
        "evidence": evidence,
        "analyzer": "osv",
        "platforms": [],
        "dependency": {"package": pkg, "ecosystem": "npm", "version": version, "advisories": []},
    }


CODE = {**FINDING, "analyzer": "semgrep", "severity": "low", "title": "t", "message": "m"}
PKG_EDGE = {
    "id": "p" * 16,
    "source": "plugin:acme",
    "target": "package:npm/yaml-lib",
    "relation": "bundles",
    "evidence": "declared",
    "count": 1,
    "finding_ids": [],
    "attrs": {},
}
INPUTS = {
    "version": 1,
    "ecosystem": "npm",
    "lockfiles": {"package-lock.json": {"name": "package-lock.json", "text": "{}"}},
    "package_json": '{"dependencies": {"yaml-lib": "^4"}}',
}


def card_report(findings, ref="v1", **kw):
    """A stored card report with every section a re-check has to keep in line."""
    r = report(repo="acme/card", ref=ref, kind="plugin", findings=findings, **kw)
    scored = trust.rescore([(f["id"], f["rule_id"], f["severity"]) for f in findings], True)
    r.update(
        score=scored.score,
        raw_score=scored.raw_score,
        verdict={"key": scored.verdict_key, "label": scored.verdict_label},
        caps_applied=scored.caps,
        score_breakdown=scored.breakdown,
        counts={},
        analyzers=[
            {"name": "semgrep", "state": "ok", "detail": "", "tool_version": "1", "findings": 1},
            {"name": "osv-npm", "state": "ok", "detail": "old", "tool_version": "2.7.0",
             "findings": sum(f.get("analyzer") == "osv" for f in findings)},
        ],
        hygiene={"dependabot": ["npm"], "dependabot_but_known_vulns": any(
            f["rule_id"] == "dep-vuln" for f in findings)},
        ai_brief={"contract": "c", "score": scored.score, "verdict": scored.verdict_label,
                  "incomplete_analyzers": [],
                  "findings": [{"id": f["id"], "rule_id": f["rule_id"], "marker": "kept"}
                               for f in findings]},
        context={"version": 3, "snippets": {"s1": {"segments": []}}, "items": {
            f["id"]: {"kind": "dependency", "package": f["dependency"]["package"], "file": "a.js",
                      "line": 3, "snippet": "s1"}
            for f in findings if f.get("dependency")}},
    )  # fmt: skip
    r["graph"]["edges"] = [
        {**PKG_EDGE, "finding_ids": sorted(f["id"] for f in findings if f.get("dependency"))}
    ]
    return r


def result(findings=0, state=AnalyzerState.OK, detail="package-lock.json"):
    r = AnalyzerResult("osv-npm", state, [], detail, tool_version="2.7.0")
    r.findings = [object()] * findings  # only counted
    return r


# --- what a scan saves ---------------------------------------------------------------------


def test_an_integration_scan_saves_its_lockfiles_and_what_osv_needs_besides(tmp_path):
    lock = tmp_path / "pylock.linux_x86_64.toml"
    lock.write_text('lock-version = "1.0"\n')
    res = Resolution(
        requirements=[Requirement("Foo_Bar==1", ReqKind.PLAIN, "foo-bar")],
        packages={
            ("foo-bar", "1"): ResolvedPackage(name="foo-bar", version="1"),
            ("aiohttp", "3"): ResolvedPackage(name="aiohttp", version="3", ha_provided=True),
        },
        lockfiles={"linux_x86_64": lock},
    )
    target = Target(source="x", kind=TargetKind.INTEGRATION, root=tmp_path)
    got = recheck.capture(target, res)
    assert got == {
        "version": 1,
        "ecosystem": "PyPI",
        "lockfiles": {"linux_x86_64": {"name": lock.name, "text": 'lock-version = "1.0"\n'}},
        "ha_provided": ["aiohttp"],
        "direct": ["foo-bar"],
    }
    assert recheck.capture(target, None) is None  # nothing resolved: nothing to ask about


def test_a_card_scan_saves_its_lockfile_and_package_json_and_skips_oversized_ones(
    tmp_path, monkeypatch
):
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}')
    (tmp_path / "package.json").write_text('{"dependencies": {"a": "1"}}')
    (tmp_path / "evil.lock").write_text("not a lockfile we know")
    target = Target(source="x", kind=TargetKind.PLUGIN, root=tmp_path, source_root=tmp_path)
    got = recheck.capture(target, None)
    assert list(got["lockfiles"]) == ["package-lock.json"] and got["ecosystem"] == "npm"
    assert got["package_json"] == '{"dependencies": {"a": "1"}}'
    monkeypatch.setattr(recheck, "MAX_FILE", 5)
    assert recheck.capture(target, None) is None  # too large to keep: this scan isn't re-checked


def test_the_store_keeps_inputs_beside_the_report_never_in_it(tmp_path):
    store = Store(tmp_path / "s.db")
    rep = card_report([CODE])
    sid = store.save({**rep, recheck.KEY: INPUTS})  # how the panel's scan function hands them over
    assert store.report(sid) == rep and recheck.KEY not in store.report(sid)
    assert store.inputs(sid) == INPUTS and store.has_inputs() == {sid}
    plain = store.save(rep)
    assert store.inputs(plain) is None
    with sqlite3.connect(store.path) as db:  # stored compressed, not as text
        (blob,) = db.execute("SELECT data FROM scan_inputs").fetchone()
    assert isinstance(blob, bytes) and b"package_json" not in blob
    store.note_recheck(sid, "same")
    assert store.rechecks()[sid][1] == "same"
    store.delete(sid)  # the lockfiles and the re-check note go with the scan
    assert store.inputs(sid) is None and store.rechecks() == {} and store.has_inputs() == set()


# --- asking again --------------------------------------------------------------------------


def test_run_writes_only_known_file_names_and_uses_the_scans_own_osv_code(tmp_path, monkeypatch):
    seen = {}

    def npm(root, work):
        seen["npm"] = sorted(p.name for p in root.iterdir())
        return result()

    def python(lockfiles, ha_provided, direct, work):
        seen["py"] = ({k: (p.name, p.read_text()) for k, p in lockfiles.items()}, ha_provided,
                      direct)  # fmt: skip
        return result()

    monkeypatch.setattr(osv, "check_npm", npm)
    monkeypatch.setattr(osv, "check_python", python)
    a = tmp_path / "a"
    a.mkdir()
    recheck.run(INPUTS, a)
    assert seen["npm"] == ["package-lock.json", "package.json"]
    b = tmp_path / "b"
    b.mkdir()
    lock = {"name": "pylock.linux_x86_64.toml", "text": "t"}
    py = {"version": 1, "ecosystem": "PyPI", "ha_provided": ["aiohttp"], "direct": ["foo"],
          "lockfiles": {"linux_x86_64": lock}}  # fmt: skip
    recheck.run(py, b)
    assert seen["py"] == ({"linux_x86_64": ("pylock.linux_x86_64.toml", "t")}, {"aiohttp"}, {"foo"})
    for i, bad in enumerate([
        {**INPUTS, "lockfiles": {"../../etc/x": {"name": "../../etc/x", "text": ""}}},
        {**py, "lockfiles": {"p": {"name": "../pylock.toml", "text": ""}}},
        {**py, "lockfiles": {"../p": {"name": "pylock.toml", "text": ""}}},
        {**INPUTS, "version": 99},
        {**INPUTS, "ecosystem": "cargo"},
    ]):  # fmt: skip
        d = tmp_path / f"bad{i}"
        d.mkdir()
        with pytest.raises(recheck.RecheckError):
            recheck.run(bad, d)
        assert not list(tmp_path.glob("**/x")) and not (tmp_path / "pylock.toml").exists()


def test_the_same_advisories_change_nothing():
    a = osv_finding()
    rep = card_report([a, CODE])
    assert recheck.apply(rep, [copy.deepcopy(a)], result(1), 7, "2026-11-12T00:00:00+00:00") is None


def test_a_new_advisory_makes_a_new_report_with_every_section_in_line():
    a = osv_finding()
    rep = card_report([a, CODE])
    before = copy.deepcopy(rep)
    worse = osv_finding(ids="GHSA-aaaa, GHSA-bbbb", severity="high")  # same package, one more
    other = osv_finding(pkg="left-pad", version="1.0.0", ids="MAL-2026-1", severity="critical",
                        rule="dep-malicious")  # fmt: skip
    del other["dependency"]
    now = datetime(2026, 11, 13, 2, 0, tzinfo=UTC)
    new = recheck.apply(rep, [worse, other], result(2, detail="new"), 7,
                        "2026-11-12T00:00:00+00:00", now)  # fmt: skip
    assert rep == before  # the stored report is never touched
    ids = [f["id"] for f in new["findings"]]
    assert ids == [other["id"], worse["id"], CODE["id"]]  # most severe first, the scanner's order
    want = trust.rescore([(f["id"], f["rule_id"], f["severity"]) for f in new["findings"]], True)
    assert (new["score"], new["raw_score"], new["verdict"]["key"]) == (
        want.score, want.raw_score, want.verdict_key)  # fmt: skip
    assert new["score"] <= 39 and new["caps_applied"] == want.caps  # a malicious package: bork
    assert new["score_breakdown"] == want.breakdown
    assert new["counts"] == {"critical": 1, "high": 1, "low": 1}
    assert new["analyzers"][0] == rep["analyzers"][0]
    assert new["analyzers"][1] == {"name": "osv-npm", "state": "ok", "detail": "new",
                                   "tool_version": "2.7.0", "findings": 2}  # fmt: skip
    assert new["graph"]["edges"][0]["finding_ids"] == [worse["id"]]  # the old id is gone
    assert new["hygiene"]["dependabot_but_known_vulns"] is True
    brief = new["ai_brief"]
    assert (brief["score"], brief["verdict"]) == (want.score, want.verdict_label)
    assert [b["id"] for b in brief["findings"]] == ids
    assert brief["findings"][2] == {"id": CODE["id"], "rule_id": CODE["rule_id"], "marker": "kept"}
    assert brief["findings"][1]["evidence_untrusted"] == worse["evidence"]
    # where the app uses the package didn't change: the new finding takes the item over
    assert new["context"]["items"] == {worse["id"]: rep["context"]["items"][a["id"]]}
    assert new["recheck"] == {"of": 7, "code_scanned_at": "2026-11-12T00:00:00+00:00",
                              "at": "2026-11-13T02:00:00+00:00"}  # fmt: skip
    assert new["target"] == rep["target"] and new["tool"] == rep["tool"]
    # a withdrawn advisory goes the other way, and keeps the date the code was sniffed
    back = recheck.apply(new, [], result(0), 9, "ignored", now + timedelta(days=1))
    assert [f["id"] for f in back["findings"]] == [CODE["id"]]
    assert back["score"] == trust.rescore([(CODE["id"], CODE["rule_id"], "low")], True).score
    assert back["graph"]["edges"][0]["finding_ids"] == []
    assert back["hygiene"]["dependabot_but_known_vulns"] is False
    assert back["context"]["items"] == {}
    assert back["recheck"]["of"] == 9
    assert back["recheck"]["code_scanned_at"] == "2026-11-12T00:00:00+00:00"


def test_a_package_that_had_no_finding_gets_the_no_usage_item():
    rep = card_report([CODE])
    a = osv_finding()
    new = recheck.apply(rep, [a], result(1), 1, "2026-11-12T00:00:00+00:00")
    assert new["context"]["items"] == {
        a["id"]: {"kind": "dependency", "package": "yaml-lib", "snippet": None, "unread": True}
    }
    assert new["graph"]["edges"][0]["finding_ids"] == [a["id"]]


def test_osv_not_answering_is_an_error_never_a_result(monkeypatch):
    monkeypatch.setattr(
        recheck, "run", lambda inputs, work: result(state=AnalyzerState.ERROR, detail="timed out")
    )
    with pytest.raises(recheck.RecheckError, match="timed out"):
        recheck.recheck(card_report([osv_finding()]), INPUTS, 1, "2026-11-12T00:00:00+00:00")


# --- the worker job ------------------------------------------------------------------------


def _worker(store, fn):
    return server.Worker(store, lambda repo, ref: {}, ha_fn=lambda: "2026.11.0", recheck_fn=fn)


def test_a_recheck_job_saves_a_change_as_a_new_scan_and_leaves_the_old_one(tmp_path):
    store = Store(tmp_path / "s.db")
    a = osv_finding()
    rep = card_report([a, CODE])
    sid = store.save(rep, inputs=INPUTS)
    row = store.get(sid)
    calls = []

    def fn(report_, inputs, of, when):
        calls.append((inputs, of, when))
        worse = osv_finding(ids="GHSA-aaaa, GHSA-bbbb", severity="high")
        return recheck.apply(report_, [worse], result(1), of, when)

    worker = _worker(store, fn)
    job = worker.submit("recheck", "acme/card", "v1", scan=sid)
    worker.wait()
    assert (job.state, job.message) == ("done", "advisories changed")
    new_id = job.scan_ids[1]
    assert job.scan_ids == [sid, new_id] and calls == [(INPUTS, sid, row.scanned_at)]
    assert store.report(sid) == rep  # the old entry is exactly as it was
    assert store.get(new_id).score < row.score and store.inputs(new_id) == INPUTS
    assert store.rechecks()[sid][1] == f"changed:{new_id}"
    found = store.find("acme/card", "v1", exposure="local", tool_version=worker.tool_version)
    assert found.id == new_id  # the app's page and update checks now use the new entry
    # the old entry is no longer the newest of its version: it isn't re-checked again
    job2 = worker.submit("recheck", "acme/card", "v1", scan=sid)
    worker.wait()
    assert "newer scan" in job2.message and len(calls) == 1 and job2.scan_ids == [sid]


def test_a_recheck_job_that_finds_nothing_or_fails_stores_no_scan(tmp_path):
    store = Store(tmp_path / "s.db")
    sid = store.save(card_report([CODE]), inputs=INPUTS)
    bare = store.save(card_report([CODE], ref="v2"))  # no package list saved
    outcome = [None]

    def fn(report_, inputs, of, when):
        if isinstance(outcome[0], Exception):
            raise outcome[0]
        return None

    worker = _worker(store, fn)
    job = worker.submit("recheck", "acme/card", "v1", scan=sid)
    worker.wait()
    assert (job.state, job.message, job.scan_ids) == ("done", "advisories unchanged", [sid])
    assert store.rechecks()[sid][1] == "same"
    outcome[0] = recheck.RecheckError("osv-npm error: timed out")
    job = worker.submit("recheck", "acme/card", "v1", scan=sid)
    worker.wait()
    assert job.state == "failed" and "timed out" in job.message
    assert store.rechecks()[sid][1] == "failed: osv-npm error: timed out"
    job = worker.submit("recheck", "acme/card", "v2", scan=bare)
    worker.wait()
    assert job.state == "done" and "no package list" in job.message
    stale = store.save(card_report([CODE], ref="v3", tool="0.9.0"), inputs=INPUTS)
    job = worker.submit("recheck", "acme/card", "v3", scan=stale)
    worker.wait()
    assert job.state == "done" and "by this Barkley version" in job.message
    assert len(store.history(limit=10)) == 3  # nothing was added by any of them
    assert server._need(job) == 0  # a re-check never spends GitHub's budget


# --- the daily pass and its notification ---------------------------------------------------


@pytest.fixture
def daily(tmp_path):
    store = Store(tmp_path / "s.db")
    fakes = Fakes([Installed("acme/card", "card", "Card", "v1", "v2", False)])
    fakes.now = time.time()  # the worker stamps re-checks with the real clock
    state = {"new": None, "calls": []}

    def fn(report_, inputs, of, when):
        state["calls"].append(of)
        if isinstance(state["new"], Exception):
            raise state["new"]
        return recheck.apply(report_, state["new"], result(1), of, when) if state["new"] else None

    worker = _worker(store, fn)
    w = watch.Watcher(
        store, worker, fakes.installed, notify_fn=fakes.notify, notify_service_fn=fakes.push,
        slug_fn=lambda: "local_sniff_test", sleep_fn=fakes.slept.append, now_fn=lambda: fakes.now,
    )  # fmt: skip
    worker.on_done.append(w.on_job_done)
    w.check()  # the snapshot the pass reads
    at = datetime.fromtimestamp(fakes.now, UTC)
    return store, worker, fakes, w, state, at


def test_the_daily_pass_rechecks_installed_and_offered_versions_once_a_day(daily):
    store, worker, fakes, w, state, at = daily
    a = osv_finding()
    v1 = store.save(card_report([a]), at - timedelta(hours=25), inputs=INPUTS)
    v2 = store.save(card_report([a], ref="v2"), at - timedelta(hours=30), inputs=INPUTS)
    fresh = store.save(card_report([a], ref="v3"), at - timedelta(hours=30), inputs=INPUTS)
    other = Store.save(store, report(repo="acme/gone", ref="v1"), at - timedelta(days=3),
                       inputs=INPUTS)  # fmt: skip
    assert w.recheck_due() == 2  # v1 installed, v2 waiting; v3 and acme/gone aren't either
    worker.wait()
    assert sorted(state["calls"]) == [v1, v2] and fresh and other
    assert fakes.bell == [] and w.log() == []  # nothing changed: nobody is told
    assert w.rechecked == 2 and w.recheck_changes == 0
    assert w.recheck_due() == 0  # asked a moment ago
    fakes.now += 23 * 3600
    assert w.recheck_due() == 0
    fakes.now += 2 * 3600
    assert w.recheck_due() == 2
    worker.wait()


def test_a_scan_sniffed_today_or_without_a_package_list_is_left_alone(daily):
    store, worker, fakes, w, _state, at = daily
    store.save(card_report([CODE]), at - timedelta(hours=2), inputs=INPUTS)
    store.save(card_report([CODE], ref="v2"), at - timedelta(days=2))  # no inputs
    assert w.recheck_due() == 0 and worker.jobs == []
    w.enabled = False  # with auto-sniff off the pass doesn't run at all
    fakes.now += 48 * 3600
    w.last_check = fakes.now
    w.tick()
    assert worker.jobs == []


def test_a_failed_recheck_is_retried_after_an_hour_and_tells_nobody(daily):
    store, worker, fakes, w, state, at = daily
    sid = store.save(card_report([CODE]), at - timedelta(hours=25), inputs=INPUTS)
    state["new"] = recheck.RecheckError("osv-npm error: no route")
    assert w.recheck_due() == 1
    worker.wait()
    assert worker.jobs[0].state == "failed" and fakes.bell == [] and w.log() == []
    assert store.rechecks()[sid][1].startswith("failed")
    assert len(store.history(limit=10)) == 1
    store.note_recheck(sid, "failed: x", at)  # the note carries the fake clock's time
    fakes.now += 1800
    assert w.recheck_due() == 0
    fakes.now += 1900
    assert w.recheck_due() == 1
    worker.wait()


def test_changed_advisories_notify_with_counts_and_scores_never_package_names(daily):
    store, worker, fakes, w, state, at = daily
    w.set_target("mobile_app_phone")
    w.notify_target = "mobile_app_phone"
    a = osv_finding()
    sid = store.save(card_report([a, CODE]), at - timedelta(hours=25), inputs=INPUTS)
    was = store.get(sid).score
    state["new"] = [
        osv_finding(ids="GHSA-aaaa, GHSA-bbbb", severity="high"),
        osv_finding(pkg=HOSTILE_PKG, version="1", ids="MAL-2026-1", severity="critical",
                    rule="dep-malicious"),
        osv_finding(pkg="third", version="2", ids="GHSA-cccc"),
    ]  # fmt: skip
    assert w.recheck_due() == 1
    worker.wait()
    job = worker.jobs[0]
    new_id = job.scan_ids[1]
    now = store.get(new_id).score
    ((title, message, nid),) = fakes.bell
    assert title == "Barkley: acme/card v1 (advisories changed)" and nid == "barkley_acme_card"
    assert message.startswith("A package this app uses is now listed as malicious.")
    assert f"{now}/100 (it was {was}/100)" in message and "BORK" in message
    want = ("What changed: 1 package now listed as malicious, 1 package newly with known "
            "vulnerabilities, 1 package with different advisories than before.")  # fmt: skip
    assert want in message
    assert "The app's code was not scanned again" in message
    assert f"scan @{new_id}, what changed @{sid} → @{new_id}" in message
    for leak in (HOSTILE_PKG, "yaml-lib", "third", "GHSA", "MAL-"):
        assert leak not in message and leak not in title
    ((target, ptitle, plain, _url),) = fakes.pushed
    assert target == "mobile_app_phone" and ptitle == title and HOSTILE_PKG not in plain
    entry = w.log()[0]
    assert (entry["action"], entry["score"], entry["was"]) == ("advisories", now, was)
    assert entry["scan_ids"] == [sid, new_id] and w.recheck_changes == 1


def test_a_withdrawn_advisory_is_reported_too(daily):
    store, worker, fakes, w, _state, at = daily
    rep = card_report([osv_finding(), CODE])
    sid = store.save(rep, at - timedelta(hours=25), inputs=INPUTS)
    worker.recheck_fn = lambda r, i, of, when: recheck.apply(r, [], result(0), of, when)
    assert w.recheck_due() == 1
    worker.wait()
    ((_title, message, _nid),) = fakes.bell
    assert "What changed: 1 package no longer with any." in message
    assert "malicious" not in message and f"(it was {store.get(sid).score}/100)" in message


# --- the panel -----------------------------------------------------------------------------


@pytest.fixture
def panel(tmp_path):
    store = Store(tmp_path / "s.db")
    state = {"new": None}

    def fn(report_, inputs, of, when):
        return recheck.apply(report_, state["new"], result(1), of, when) if state["new"] else None

    httpd = server.serve(store, lambda repo, ref: {}, "127.0.0.1", 0, {"127.0.0.1"})
    httpd.panel.worker.recheck_fn = fn
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield store, f"http://127.0.0.1:{httpd.server_address[1]}", httpd, state
    httpd.shutdown()


def test_the_app_page_says_when_advisories_were_asked_and_offers_to_ask_again(panel):
    store, base, httpd, state = panel
    a = osv_finding(pkg=HOSTILE_PKG)
    sid = store.save(card_report([a, CODE]), inputs=INPUTS)
    bare = store.save(card_report([CODE], ref="v0"))
    _, _, page = get(f"{base}/scan/{sid}")
    assert "Check advisories again</button>" in page and f'name=scan value="{sid}"' in page
    assert "Check advisories again" not in get(f"{base}/scan/{bare}")[2]  # no package list
    stale = store.save(card_report([CODE], ref="v9", tool="0.9.0"), inputs=INPUTS)
    assert "Check advisories again" not in get(f"{base}/scan/{stale}")[2]  # other rules
    assert post(base + "/recheck", {"token": "bad", "scan": sid})[0] == 403
    assert post(base + "/recheck", {"token": httpd.panel.token, "scan": "x"})[0] == 400
    assert post(base + "/recheck", {"token": httpd.panel.token, "scan": 999})[0] == 404
    status, headers = post(base + "/recheck", {"token": httpd.panel.token, "scan": sid})
    assert status == 303 and headers["Location"].endswith(f"/scan/{sid}")
    httpd.panel.worker.wait()
    _, _, page = get(f"{base}/scan/{sid}")
    when = store.rechecks()[sid][0]
    assert f"Advisories asked again {when[:10]} {when[11:16]} UTC: nothing changed." in page
    assert len(store.history(limit=10)) == 3
    # now OSV lists one more advisory: a new entry, linked both ways, the old page unchanged
    state["new"] = [osv_finding(pkg=HOSTILE_PKG, ids="GHSA-aaaa, GHSA-bbbb", severity="high")]
    post(base + "/recheck", {"token": httpd.panel.token, "scan": sid})
    httpd.panel.worker.wait()
    new_id = httpd.panel.worker.jobs[0].scan_ids[1]
    _, _, old_page = get(f"{base}/scan/{sid}")
    assert f'found changes: see <a href="/scan/{new_id}">scan @{new_id}</a>' in old_page
    assert "Check advisories again" not in old_page  # only the newest entry is re-checked
    _, _, new_page = get(f"{base}/scan/{new_id}")
    assert f'this entry replaced <a href="/scan/{sid}">scan @{sid}</a>' in new_page
    assert f'href="/diff?old={sid}&amp;new={new_id}">what changed</a>' in new_page
    assert "only the advisories were asked again" in new_page
    assert "Check advisories again</button>" in new_page
    assert "<script>" not in new_page.replace("&lt;script&gt;", "")  # the package name is escaped
    _, _, index = get(base + "/")
    assert "advisory re-check" in index and f"diff?old={sid}&amp;new={new_id}" in index
    status, _, diff_page = get(f"{base}/diff?old={sid}&new={new_id}")
    assert status == 200 and "What the advisory re-check changed" in diff_page
    assert "Same version and the same code" in diff_page
    assert "What the update changes" not in diff_page
    assert json.loads(get(f"{base}/scan/{new_id}.json")[2])["recheck"]["of"] == sid


def test_the_page_reloads_itself_while_its_recheck_runs(panel):
    store, base, httpd, _state = panel
    sid = store.save(card_report([CODE]), inputs=INPUTS)
    go = threading.Event()
    httpd.panel.worker.recheck_fn = lambda r, i, of, when: go.wait(10) and None
    post(base + "/recheck", {"token": httpd.panel.token, "scan": sid})
    _, _, page = get(f"{base}/scan/{sid}")
    assert 'http-equiv="refresh"' in page and "Asking OSV again about its packages" in page
    assert "Check advisories again" not in page
    go.set()
    httpd.panel.worker.wait()
    assert 'http-equiv="refresh"' not in get(f"{base}/scan/{sid}")[2]


def test_capture_reads_nothing_outside_the_scan(tmp_path):
    """A lockfile that is a symlink (to anything) is never read into the store."""
    secret = tmp_path / "secret"
    secret.write_text("TOKEN")
    root = tmp_path / "src"
    root.mkdir()
    (root / "package-lock.json").symlink_to(secret)
    (root / "yarn.lock").write_text("# yarn")
    (root / "package.json").symlink_to(secret)
    target = Target(source="x", kind=TargetKind.PLUGIN, root=root, source_root=root)
    got = recheck.capture(target, None)
    assert list(got["lockfiles"]) == ["yarn.lock"] and got["package_json"] is None
    assert "TOKEN" not in json.dumps(got) and Path(secret).read_text() == "TOKEN"
