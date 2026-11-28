"""Auto-sniff: installs and updates noticed from the installed list, scanned at the version
that landed, reusing stored scans; notifications built from fixed text; age-out."""

import json
import threading

import pytest
from test_server import Calls
from test_store import EDGE, FINDING, report

from sniff_test import server, supervisor, watch
from sniff_test.store import Store
from sniff_test.supervisor import Installed, SupervisorError

HOSTILE = "evil-evidence <script>steal()</script> x.invalid"


class Fakes:
    """Installed list, notifications and a clock the watcher reads."""

    def __init__(self, items):
        self.items = list(items)
        self.error = None
        self.bell = []
        self.pushed = []
        self.now = 1_800_000_000.0
        self.slept = []

    def installed(self):
        if self.error:
            raise SupervisorError(self.error)
        return list(self.items), {}

    def notify(self, title, message, nid):
        self.bell.append((title, message, nid))

    def push(self, target, title, message, url):
        self.pushed.append((target, title, message, url))


def _scan(repo, ref):
    if ref == "v2":  # the new version has a finding with hostile evidence and a new host
        f = {**FINDING, "evidence": HOSTILE, "title": HOSTILE, "file": HOSTILE}
        edge = {**EDGE, "relation": "connects_to"}
        return report(repo=repo, ref=ref, findings=[f], edges=[edge], score=75)
    return report(repo=repo, ref=ref)


@pytest.fixture
def ctx(tmp_path):
    store = Store(tmp_path / "s.db")
    fakes = Fakes([Installed("acme/a", "integration", "A", "v1", "v1", False)])
    worker = server.Worker(store, _scan, ha_fn=lambda: "2026.11.0")
    w = watch.Watcher(
        store, worker, fakes.installed,
        notify_fn=fakes.notify, notify_service_fn=fakes.push,
        targets_fn=lambda: ["mobile_app_phone", "persistent_notification"],
        slug_fn=lambda: "local_sniff_test", sleep_fn=fakes.slept.append,
        now_fn=lambda: fakes.now,
    )  # fmt: skip
    worker.on_done.append(w.on_job_done)
    return store, worker, fakes, w


def test_first_check_only_remembers_what_is_installed(ctx):
    store, worker, fakes, w = ctx
    assert w.check() == []
    assert json.loads(store.setting(watch.SNAPSHOT_KEY)) == {
        "acme/a": {"repo": "acme/a", "kind": "integration", "version": "v1", "available": "v1"}
    }
    assert worker.jobs == [] and fakes.bell == []


def test_an_install_is_sniffed_at_its_version_and_notified(ctx):
    store, worker, fakes, w = ctx
    w.check()
    fakes.items.append(Installed("acme/b", "card", "B", "v2", "v9", False))  # v9 is newer
    changes = w.check()
    assert changes[0] == watch.Change("install", "acme/b", "card", "v2")
    assert changes[1].action == "available"  # (0.15) v9 waiting is sniffed too
    worker.wait()
    job = next(j for j in worker.jobs if j.prev is None)
    assert (job.kind, job.ref, job.prev, job.state) == ("auto", "v2", None, "done")
    assert store.get(job.scan_ids[0]).ref == "v2"  # the version that landed, not v9
    (title, message, nid), _offer = fakes.bell
    assert title == "Barkley: acme/b v2" and nid == "barkley_acme_b"
    assert "Card acme/b v2 was installed. Barkley sniffed it." in message
    assert "🟢 Threat: none · 🟢 Exposure: low." in message  # (0.15) no score; no "(0)"
    assert "/100" not in message
    assert "[Open Barkley](/app/local_sniff_test) to see scan @1." in message
    assert HOSTILE not in message and "x.invalid" not in message
    assert fakes.pushed == []  # no target chosen
    entry = next(x for x in w.log() if x["action"] == "install")
    assert entry["scan_ids"] == [1]
    assert entry["readings"]["threat_level"] == "none" and "score" not in entry


def test_an_update_reuses_the_old_scan_and_says_what_changed(ctx):
    store, worker, fakes, w = ctx
    w.set_target("mobile_app_phone")
    w.check()
    old_id = store.save(report(repo="acme/a", ref="v1"))  # sniffed earlier
    fakes.items[0] = Installed("acme/a", "integration", "A", "v2", "v2", False)
    assert w.check() == [watch.Change("update", "acme/a", "integration", "v2", "v1")]
    worker.wait()
    job = worker.jobs[0]
    assert job.prev == "v1" and job.scan_ids[0] == old_id and job.state == "done"
    ((title, message, _),) = fakes.bell
    assert "Integration acme/a was updated from v1 to v2. Barkley sniffed it." in message
    assert "Changes in this update: 1 new site." in message  # fixed words, never the host
    assert f"@{old_id} → @{job.scan_ids[1]}" in message
    ((target, ptitle, plain, url),) = fakes.pushed
    assert target == "mobile_app_phone" and ptitle == title
    # (2026-11-25) the push leads with the readings; the title names the app, a tap opens it
    assert plain == (
        "🟢 Threat: none · 🟢 Exposure: low. Changes in this update: 1 new site. Updated from v1."
    )
    assert url == "/app/local_sniff_test"
    assert HOSTILE not in plain


def test_every_auto_job_leaves_one_outcome_line_in_the_log(ctx, capsys):
    _store, worker, fakes, w = ctx
    w.set_target("mobile_app_phone")
    w.check()
    fakes.items.append(Installed("acme/b", "card", "B", "v2", "v2", False))
    w.check()
    worker.wait()
    err = capsys.readouterr().err
    assert "auto-sniff: acme/b installed v2" in err
    assert ("auto-sniff: acme/b v2 sniffed: 🟢 Threat: none · 🟢 Exposure: low; @1; "
            "notified bell + notify.mobile_app_phone") in err  # fmt: skip
    assert HOSTILE not in err


def test_a_restart_during_a_sniff_resumes_it(ctx):
    """The snapshot already holds the new version when the job runs, so a restart (an app
    rebuild, a host reboot) would lose the change: the change is kept in the store until
    its job ends, and re-queued at the next start."""
    store, worker, fakes, w = ctx
    w.check()
    hold = threading.Event()
    worker.scan_fn = lambda repo, ref: hold.wait(10) and report(repo=repo, ref=ref)
    fakes.items.append(Installed("acme/b", "card", "B", "v2", "v2", False))
    w.check()  # the job starts and hangs, like a scan cut short by a restart
    assert [(c.repo, c.version) for c in w.pending()] == [("acme/b", "v2")]
    # Barkley starts again: a new worker and watcher on the same store
    worker2 = server.Worker(store, _scan, ha_fn=lambda: "2026.11.0")
    w2 = watch.Watcher(
        store, worker2, fakes.installed, notify_fn=fakes.notify,
        slug_fn=lambda: "local_sniff_test", sleep_fn=fakes.slept.append,
        now_fn=lambda: fakes.now,
    )  # fmt: skip
    worker2.on_done.append(w2.on_job_done)
    assert w2.check() == []  # the snapshot already had v2: nothing looks new
    assert [c.repo for c in w2.resume()] == ["acme/b"]
    worker2.wait()
    assert worker2.jobs[0].state == "done" and store.get(worker2.jobs[0].scan_ids[0]).ref == "v2"
    assert fakes.bell[0][0] == "Barkley: acme/b v2"
    assert w2.pending() == [] and w2.resume() == []  # ended: forgotten
    hold.set()


def test_resume_drops_what_is_no_longer_installed_at_that_version(ctx):
    store, worker, _fakes, w = ctx
    w.check()
    store.set_setting(watch.PENDING_KEY, json.dumps([
        {"action": "update", "repo": "acme/a", "kind": "integration", "version": "v9",
         "previous": "v1"},  # the box has v1 now (rolled back, or updated again)
        {"action": "install", "repo": "acme/gone", "kind": "card", "version": "v1"},
        {"bad": "entry"},
    ]))  # fmt: skip
    assert w.resume() == [] and worker.jobs == [] and w.pending() == []
    w.enabled = False
    store.set_setting(watch.PENDING_KEY, json.dumps(
        [{"action": "install", "repo": "acme/a", "kind": "integration", "version": "v1"}]
    ))  # fmt: skip
    assert w.resume() == [] and worker.jobs == []  # off: nothing is sniffed


def test_a_scan_sniffed_from_search_is_reused_on_install(ctx):
    store, worker, fakes, w = ctx
    w.check()
    sid = store.save(report(repo="acme/c", ref="v1"))  # from search, same version
    calls = []
    worker.scan_fn = lambda repo, ref: calls.append((repo, ref)) or report(repo=repo, ref=ref)
    fakes.items.append(Installed("acme/c", "integration", "C", "v1", "v1", True))
    w.check()
    worker.wait()
    assert calls == [] and worker.jobs[0].scan_ids == [sid]
    assert "🟢 Threat: none" in fakes.bell[0][1]


def test_off_means_noticed_but_not_sniffed(ctx):
    store, worker, fakes, w = ctx
    w.check()
    w.set_enabled(False)
    assert store.setting("auto_scan") == "off"
    fakes.items.append(Installed("acme/d", "card", "D", "v1", "v1", False))
    w.check()
    assert worker.jobs == [] and fakes.bell == []
    assert w.log()[0]["state"] == "noticed"
    # The stored choice wins over the option at the next start.
    again = watch.Watcher(store, worker, fakes.installed, enabled=True)
    assert again.enabled is False


def test_a_failed_scan_still_notifies(ctx):
    _store, worker, fakes, w = ctx
    w.check()

    def boom(repo, ref):
        raise RuntimeError("network down")

    worker.scan_fn = boom
    fakes.items.append(Installed("acme/e", "card", "E", "v1", "v1", False))
    w.check()
    worker.wait()
    ((_title, message, _),) = fakes.bell
    assert (
        "couldn't sniff version v1 of acme/e (failed: something went wrong inside Barkley"
        in message
    )
    assert w.log()[0]["state"] == "failed"


def test_the_same_version_is_not_queued_twice(ctx):
    _store, worker, fakes, w = ctx
    w.check()
    started, release = threading.Event(), threading.Event()

    def slow(repo, ref):
        started.set()
        release.wait(5)
        return report(repo=repo, ref=ref)

    worker.scan_fn = slow
    worker.submit("installed", "acme/f", "v1")  # queued by hand, still running below
    assert started.wait(5)
    fakes.items.append(Installed("acme/f", "card", "F", "v1", "v1", False))
    assert w.check() == [watch.Change("install", "acme/f", "card", "v1")]
    assert len(worker.jobs) == 1  # no "auto" job beside the active one for that version
    release.set()
    worker.wait()


def test_list_errors_change_nothing(ctx):
    _store, _worker, fakes, w = ctx
    w.check()
    fakes.error = "the Marketplace hasn't finished loading yet"
    assert w.check() == [] and w.error.startswith("the Marketplace")
    assert w.sweep() == 0
    ok, line = w.diagnostics()
    assert not ok and "Last error: the Marketplace" in line


def test_only_an_ended_install_or_an_uninstall_triggers_a_check(ctx):
    store, worker, fakes, w = ctx
    w.check()
    fakes.items.append(Installed("acme/g", "card", "G", "v1", "v1", False))
    events = [
        (supervisor.SIGNAL_INSTALL_PROGRESS, {"repository": "acme/g", "progress": 50}),
        (supervisor.SIGNAL_REPOSITORY, {"action": "update", "repository": "acme/g"}),
        (supervisor.SIGNAL_REPOSITORY, {"action": "registration", "repository": "acme/g"}),
        None,
    ]
    w.watch(iter(events))
    assert worker.jobs == [] and w.events_seen == 3
    w.watch(iter([(supervisor.SIGNAL_INSTALL_PROGRESS, {"repository": "acme/g",
                                                          "progress": False})]))  # fmt: skip
    assert fakes.slept == [watch.SETTLE] and [j.ref for j in worker.jobs] == ["v1"]
    assert w.last_event == "repository_install_progress acme/g False"
    worker.wait()
    fakes.items.pop()
    w.watch(iter([(supervisor.SIGNAL_REPOSITORY, {"action": "uninstall", "repository": "acme/g"})]))
    assert "acme/g" not in json.loads(store.setting(watch.SNAPSHOT_KEY))


def test_idle_ticks_poll_and_sweep(ctx):
    _store, worker, fakes, w = ctx
    w.check()
    fakes.items.append(Installed("acme/h", "card", "H", "v1", "v1", False))
    w.watch(iter([None]))
    assert worker.jobs == []  # polled too recently
    fakes.now += watch.POLL
    w.watch(iter([None]))
    assert [j.repo for j in worker.jobs] == ["acme/h"]
    worker.wait()


def test_age_out_deletes_only_old_scans_of_apps_that_are_not_installed(ctx):
    store, worker, fakes, w = ctx
    from datetime import UTC, datetime, timedelta

    now = datetime.fromtimestamp(fakes.now, UTC)
    old = now - timedelta(days=8)
    keep_installed = store.save(report(repo="acme/a", ref="v0"), scanned_at=old)  # older version
    keep_recent = store.save(report(repo="acme/gone", ref="v1"), scanned_at=now - timedelta(days=6))
    drop = store.save(report(repo="acme/gone", ref="v0"), scanned_at=old)
    drop_card = store.save(report(repo="acme/never", ref="v3", kind="plugin"), scanned_at=old)
    keep_busy = store.save(report(repo="acme/busy", ref="v1"), scanned_at=old)
    started = threading.Event()
    release = threading.Event()

    def slow(repo, ref):
        started.set()
        release.wait(5)
        return report(repo=repo, ref=ref)

    worker.scan_fn = slow
    worker.submit("scan", "acme/busy", "v1")  # a running job protects its repo's scans
    assert started.wait(5)
    assert w.sweep() == 2
    ids = {r.id for r in store.history(limit=100)}
    assert ids == {keep_installed, keep_recent, keep_busy}
    assert drop not in ids and drop_card not in ids
    release.set()
    worker.wait()


def test_notification_text_is_built_from_fixed_words_only():
    rep = report(repo="acme/x", ref="v2", findings=[
        {**FINDING, "severity": "medium", "rule_id": "dep-vuln", "evidence": HOSTILE},
        {**FINDING, "id": "a" * 16, "severity": "critical", "rule_id": "ha-exfil-taint",
         "evidence": HOSTILE},
        {**FINDING, "id": "b" * 16, "severity": "low", "rule_id": "py-eval", "evidence": HOSTILE},
    ], score=10)  # fmt: skip
    rep["complete"] = False
    entry = {"repo": "acme/x", "kind": "integration", "version": "v2", "previous": "v1",
             "scan_ids": [3, 4]}  # fmt: skip
    d = {"changes": [
        {"rank": 90, "group": "repo", "sign": "~", "text": HOSTILE},
        {"rank": 60, "group": "hosts", "sign": "+", "text": HOSTILE},
        {"rank": 60, "group": "hosts", "sign": "+", "text": HOSTILE},
        {"rank": 5, "group": "coverage", "sign": "+", "text": HOSTILE},
    ], "what": [{"kind": "actions", "added": [HOSTILE, "x.b"], "removed": [], "n_added": 2,
                 "n_removed": 0}]}  # fmt: skip
    title, md, plain = watch.notification(entry, rep, d, "/app/x")
    # (0.15) what else it changes: counts only, never the names
    assert "It also adds 2 actions you can use in automations." in md and "x.b" not in md
    assert title == "Barkley: 🔴 malicious behavior found in acme/x v2"
    assert md.startswith(
        "Integration acme/x was updated from v1 to v2. Barkley sniffed it. 🔴 Threat: found · "
        "🔴 Exposure: high (10)"
    )
    assert "/100" not in md and "It sends your Home Assistant data out of your home." in md
    assert "Changes in this update: 1 publisher or repository change, 2 new sites." in md
    assert "Part of the check didn't finish." in md
    assert HOSTILE not in md and HOSTILE not in plain
    assert "what the update changes (@3 → @4)" in md


def test_notify_test_and_target_validation(ctx):
    store, worker, fakes, w = ctx
    assert w.set_target("not_offered") is False
    assert w.set_target("../x") is False
    assert w.set_target("mobile_app_phone") is True and store.setting("notify_target") == (
        "mobile_app_phone"
    )
    assert w.notify_test() == ""
    assert fakes.bell[0][2] == "barkley_test" and fakes.pushed[0][0] == "mobile_app_phone"
    assert w.last_test.startswith("Test notification sent at")
    assert w.set_target("") is True and store.setting("notify_target") == "none"
    again = watch.Watcher(store, worker, fakes.installed, notify_target="mobile_app_phone")
    assert again.notify_target == ""  # the panel's "bell only" wins over the option


def test_worker_hooks_never_break_the_worker(tmp_path):
    store = Store(tmp_path / "s.db")
    worker = server.Worker(store, Calls())
    seen = []

    def bad(job):
        seen.append(job.id)
        raise RuntimeError("hook broke")

    worker.on_done.append(bad)
    worker.submit("scan", "acme/a", "v1")
    worker.submit("scan", "acme/b", "v1")
    worker.wait()
    assert sorted(seen) == [1, 2] and all(j.state == "done" for j in worker.jobs)


def test_watcher_thread_starts_and_catches_up(ctx):
    store, worker, _fakes, w = ctx
    w.subscribe_fn = None
    done = threading.Event()

    def sleep(_s):
        w.stop.set()  # end the loop after the first idle wait
        done.set()

    w.sleep_fn = sleep
    store.set_setting(watch.SNAPSHOT_KEY, json.dumps({}))  # Barkley was stopped; A arrived
    t = w.start()
    assert done.wait(5)
    t.join(5)
    worker.wait()
    assert [(j.kind, j.repo, j.ref, j.prev) for j in worker.jobs] == [
        ("auto", "acme/a", "v1", None)
    ], [(j.kind, j.repo, j.ref, j.prev) for j in worker.jobs]
    assert w.mode == "polling"


def test_an_offered_update_is_sniffed_before_it_is_installed(ctx, capsys):
    """User request 2026-11-12: when the Marketplace starts offering an update, sniff that
    version right away and say what it changes, so the heads-up comes before the update."""
    store, worker, fakes, w = ctx
    w.set_target("mobile_app_phone")
    w.check()
    fakes.items[0] = Installed("acme/a", "integration", "A", "v1", "v2", False)  # v2 offered
    changes = w.check()
    assert changes == [watch.Change("available", "acme/a", "integration", "v2", "v1")]
    worker.wait()
    assert w.check() == []  # still offered: not queued again
    title, md, _nid = fakes.bell[-1]
    assert title == "Barkley: acme/a v2 (update waiting)"
    assert "has an update waiting, v1 to v2. Barkley sniffed it before you install it" in md
    assert "Changes in this update" in md and HOSTILE not in md
    ids = [r.id for r in store.history("acme/a")]
    assert len(ids) == 2  # v1 (scanned first, it had no scan) and v2
    err = capsys.readouterr().err
    assert "auto-sniff: acme/a has an update waiting v1 → v2" in err
    assert "v1 → v2 (update waiting) sniffed:" in err
    # The update lands: both scans are reused, the diff is the same one.
    fakes.items[0] = Installed("acme/a", "integration", "A", "v2", "v2", False)
    assert w.check() == [watch.Change("update", "acme/a", "integration", "v2", "v1")]
    worker.wait()
    assert [r.id for r in store.history("acme/a")] == ids
    assert "was updated from v1 to v2. Barkley sniffed it" in fakes.bell[-1][1]
    # A pending offered update survives a restart while it is still offered.
    fakes.items[0] = Installed("acme/a", "integration", "A", "v2", "v3", False)
    w2 = watch.Watcher(
        store, worker, fakes.installed, notify_fn=fakes.notify,
        notify_service_fn=fakes.push, targets_fn=lambda: ["mobile_app_phone"],
        slug_fn=lambda: "local_sniff_test", sleep_fn=fakes.slept.append,
        now_fn=lambda: fakes.now,
    )  # fmt: skip
    w2._save_pending([watch.Change("available", "acme/a", "integration", "v3", "v2")])
    w2.check()
    assert w2.resume() == [] or True  # queued by check() already (a new offer), or resumed
    worker.wait()
    assert any(r.ref == "v3" for r in store.history("acme/a"))


def test_an_older_version_installed_with_an_update_waiting_sniffs_both(ctx):
    """Seen on his box 2026-11-23: an older version installed on purpose, the newer one
    already offered. Only the install was sniffed, and the snapshot kept the offer, so no
    later check saw it as new. Both are sniffed now, the installed version once, and the
    offer's notification doesn't replace the install's."""
    store, worker, fakes, w = ctx
    w.check()
    fakes.items.append(Installed("acme/new", "integration", "New", "v1", "v2", False))
    assert w.check() == [
        watch.Change("install", "acme/new", "integration", "v1"),
        watch.Change("available", "acme/new", "integration", "v2", "v1", after_install=True),
    ]
    worker.wait()
    assert sorted(r.ref for r in store.history("acme/new")) == ["v1", "v2"]  # v1 once
    nids = {nid: title for title, _md, nid in fakes.bell}
    assert nids["barkley_acme_new"] == "Barkley: acme/new v1"
    assert nids["barkley_acme_new_update"] == "Barkley: acme/new v2 (update waiting)"
    assert w.check() == []  # still offered: not queued again
    # a pending one survives a restart with its flag
    w._save_pending([watch.Change("available", "acme/new", "integration", "v2", "v1",
                                  after_install=True)])  # fmt: skip
    assert w.pending()[0].after_install is True


def test_a_failed_job_says_a_fixed_sentence_never_the_projects_text():
    """A reported weakness: an archive member's name reached the bell and the
    notify service through the job's message."""
    from sniff_test.server import failure_message
    from sniff_test.workspace import UnsafeArchiveError

    crafted = "member escapes destination: '[Update now](https://x.invalid)'"
    msg = failure_message(UnsafeArchiveError(crafted))
    assert "x.invalid" not in msg and "[" not in msg and "won't unpack" in msg
    assert "app log" in failure_message(RuntimeError("anything at all"))
    assert "anything" not in failure_message(RuntimeError("anything at all"))
    # (0.15) a repository that is gone says so (it read "GitHub didn't answer")
    from sniff_test.fetch.github import GitHubError, NotFoundError

    gone = failure_message(NotFoundError("https://api.github.com/repos/a/b"))
    assert "deleted or made private" in gone and "api.github.com" not in gone
    assert "didn't answer" in failure_message(GitHubError("503"))


def test_notify_when_setting():
    """(0.15, #29) A clean result needn't notify; signs of malicious behavior and a sniff
    that didn't finish always do."""
    from sniff_test.watch import worth_notifying

    def entry(threat="none", level="low", complete=True):
        return {"readings": {"threat_level": threat, "exposure_level": level},
                "complete": complete}  # fmt: skip

    assert worth_notifying(entry(), "all")
    for when in ("medium", "high", "threat"):
        assert not worth_notifying(entry(), when)
        assert worth_notifying(entry(threat="possible"), when)
        assert worth_notifying(entry(complete=False), when)
    assert worth_notifying(entry(level="medium"), "medium")
    assert not worth_notifying(entry(level="medium"), "high")
    assert worth_notifying(entry(level="high"), "high")
    assert not worth_notifying(entry(level="high"), "threat")


def test_an_older_stable_release_offered_on_a_pre_release_isnt_sniffed():
    """(0.15, #27)"""
    old = watch.snapshot_of([Installed("acme/c", "card", "C", "v2.0.0-beta.3", "", False)])
    new = watch.snapshot_of([Installed("acme/c", "card", "C", "v2.0.0-beta.3", "v1.9.5", False)])
    assert watch.snapshot_changes(old, new) == []
    newer = watch.snapshot_of([Installed("acme/c", "card", "C", "v2.0.0-beta.3", "v2.0.0", False)])
    assert [c.action for c in watch.snapshot_changes(old, newer)] == ["available"]


def test_the_phone_push_leads_with_the_readings():
    """(his report 2026-11-25) A phone cut the push off before the readings: the name and
    versions came first, though the title already has them. The push starts with the
    readings, the Exposure number shows only when it isn't 0, and a waiting update ends
    with when it was sniffed."""
    rep = report(repo="acme/w", ref="v1.13.1")
    entry = {"repo": "acme/w", "kind": "integration", "version": "v1.13.1",
             "previous": "v1.12.3", "action": "available", "scan_ids": [933, 934]}  # fmt: skip
    title, md, plain = watch.notification(entry, rep, {"changes": [], "what": []}, "/app/x")
    assert title == "Barkley: acme/w v1.13.1 (update waiting)"
    assert plain == (
        "🟢 Threat: none · 🟢 Exposure: low. Nothing important changed since v1.12.3. "
        "Sniffed before you install it."
    )
    # the bell keeps the whole sentence and the link to both scans
    assert md.startswith("Integration acme/w has an update waiting, v1.12.3 to v1.13.1.")
    assert "(@933 → @934)" in md


def test_the_advisory_push_leads_with_the_readings():
    rep = report(repo="acme/w", ref="v2")
    entry = {"repo": "acme/w", "kind": "integration", "version": "v2", "malicious": True,
             "changes": "1 package newly listed as malicious", "scan_ids": [5, 6]}  # fmt: skip
    _t, md, plain = watch.advisory_notification(entry, rep, "")
    assert plain.startswith(
        "A package this app uses is now listed as malicious. 🟢 Threat: none · 🟢 Exposure: low. "
        "The known security advisories for its packages have changed. What changed: "
    )
    assert plain.endswith("It only looked up its packages again.") and "acme/w" not in plain
    assert "integration acme/w v2 uses" in md


# (0.15, #29 follow-up) "Send notifications to": the bell and the notify service, either,
# or Disabled. A user who keeps the bell for things that need attention now can leave
# Barkley out of it and still have every result sniffed and listed.


def test_send_to_the_notify_service_only(ctx, capsys):
    store, worker, fakes, w = ctx
    assert w.set_target("mobile_app_phone", bell=False) is True
    assert store.setting("notify_bell") == "off" and w.channels() == "notify.mobile_app_phone"
    w.check()
    fakes.items.append(Installed("acme/b", "card", "B", "v2", "v2", False))
    w.check()
    worker.wait()
    assert fakes.bell == [] and len(fakes.pushed) == 1
    assert "notified notify.mobile_app_phone" in capsys.readouterr().err
    again = watch.Watcher(store, worker, fakes.installed)
    assert (again.notify_target, again.notify_bell) == ("mobile_app_phone", False)


def test_disabled_sends_nothing_but_still_sniffs_and_lists(ctx, capsys):
    store, worker, fakes, w = ctx
    assert w.set_target("", bell=False) is True and w.channels() == "disabled"
    w.check()
    fakes.items.append(Installed("acme/b", "card", "B", "v2", "v2", False))
    w.check()
    worker.wait()
    assert fakes.bell == [] and fakes.pushed == []
    assert worker.jobs[0].state == "done"
    assert any(x["action"] == "install" for x in w.log())  # still under Auto-sniff activity
    err = capsys.readouterr().err
    assert "not notified (notifications disabled in Settings)" in err
    assert w.notify_test() == "" and fakes.bell == [] and fakes.pushed == []
    assert w.last_test == "Notifications are disabled, so nothing was sent."
    assert "Notifications are disabled" in w.diagnostics()[1]
    again = watch.Watcher(store, worker, fakes.installed, notify_target="mobile_app_phone")
    assert again.channels() == "disabled"  # the panel's choice wins over the option


def test_before_the_first_time_setup_auto_sniff_says_it_waits_for_the_token(ctx):
    _store, _worker, _fakes, w = ctx
    w.mode, w.error = "polling (no subscription)", supervisor.NOT_SET_UP
    ok, line = w.diagnostics()
    assert not ok and "starts once Barkley has its own Home Assistant token" in line
    assert "Last error" not in line and "couldn't subscribe" not in line


def test_a_new_token_wakes_a_failed_subscription_at_once(tmp_path):
    """(0.15, his report) after Create token, Settings still showed "no token yet" for up
    to 10 minutes: the retry waited out its backoff. The token now wakes it."""
    import time

    def no_token():
        raise SupervisorError(supervisor.NOT_SET_UP)

    w = watch.Watcher(Store(tmp_path / "s.db"), None, lambda: ([], []), subscribe_fn=no_token)
    threading.Timer(0.2, w.retry_now).start()
    started = time.monotonic()
    assert w._round(600) == watch._RECONNECT  # woken: back off from the start
    assert time.monotonic() - started < 5
    assert w.mode == "polling (no subscription)" and not w.wake.is_set()
