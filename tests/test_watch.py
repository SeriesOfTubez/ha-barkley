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
        "acme/a": {"repo": "acme/a", "kind": "integration", "version": "v1"}
    }
    assert worker.jobs == [] and fakes.bell == []


def test_an_install_is_sniffed_at_its_version_and_notified(ctx):
    store, worker, fakes, w = ctx
    w.check()
    fakes.items.append(Installed("acme/b", "card", "B", "v2", "v9", False))  # v9 is newer
    changes = w.check()
    assert changes == [watch.Change("install", "acme/b", "card", "v2")]
    worker.wait()
    job = worker.jobs[0]
    assert (job.kind, job.ref, job.prev, job.state) == ("auto", "v2", None, "done")
    assert store.get(job.scan_ids[0]).ref == "v2"  # the version that landed, not v9
    ((title, message, nid),) = fakes.bell
    assert title == "Barkley: acme/b v2" and nid == "barkley_acme_b"
    assert "Card acme/b v2 was installed and sniffed" in message
    assert "75/100" in message and "Worth a look: Reads your secrets file" in message
    assert "[Open Barkley](/hassio/ingress/local_sniff_test): scan @1." in message
    assert HOSTILE not in message and "x.invalid" not in message
    assert fakes.pushed == []  # no target chosen
    entry = w.log()[0]
    assert entry["action"] == "install" and entry["score"] == 75 and entry["scan_ids"] == [1]


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
    assert "Integration acme/a was updated from v1 to v2 and sniffed" in message
    assert "What the update changes: 1 new site." in message  # fixed words, never the host
    assert f"@{old_id} → @{job.scan_ids[1]}" in message
    ((target, ptitle, plain, url),) = fakes.pushed
    assert target == "mobile_app_phone" and ptitle == title
    assert "Open Barkley from the sidebar" in plain and "[" not in plain
    assert url == "/hassio/ingress/local_sniff_test"
    assert HOSTILE not in plain


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
    assert "No security concerns were found" in fakes.bell[0][1]


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
    assert "couldn't sniff version v1 of acme/e (failed: RuntimeError: network down)" in message
    assert w.log()[0]["state"] == "failed"


def test_the_same_version_is_not_queued_twice(ctx):
    _store, worker, fakes, w = ctx
    w.check()
    worker.submit("installed", "acme/f", "v1")  # already queued by hand
    fakes.items.append(Installed("acme/f", "card", "F", "v1", "v1", False))
    # a second snapshot change for the same (repo, version) while a job is active
    w._pending.clear()
    assert w.check() == [watch.Change("install", "acme/f", "card", "v1")]
    assert len(worker.jobs) == 1  # no "auto" job beside the active one


def test_list_errors_change_nothing(ctx):
    _store, _worker, fakes, w = ctx
    w.check()
    fakes.error = "the Marketplace hasn't finished loading yet"
    assert w.check() == [] and w.error.startswith("the Marketplace")
    assert w.sweep() == 0
    ok, line = w.diagnostics()
    assert not ok and "last error: the Marketplace" in line


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
    ]}  # fmt: skip
    title, md, plain = watch.notification(entry, rep, d, "/hassio/ingress/x")
    assert title == "Barkley: acme/x v2"
    assert md.startswith(
        "Integration acme/x was updated from v1 to v2 and sniffed: 🐕\u200d🦺 Very Sus"
    )
    assert "10/100" in md
    assert "Worth a look: Sends private Home Assistant data out of your home; " in md
    assert "What the update changes: 1 publisher or repository change, 2 new sites." in md
    assert "score is capped at 89" in md
    assert HOSTILE not in md and HOSTILE not in plain
    assert "what the update changes @3 → @4" in md


def test_notify_test_and_target_validation(ctx):
    store, worker, fakes, w = ctx
    assert w.set_target("not_offered") is False
    assert w.set_target("../x") is False
    assert w.set_target("mobile_app_phone") is True and store.setting("notify_target") == (
        "mobile_app_phone"
    )
    assert w.notify_test() == ""
    assert fakes.bell[0][2] == "barkley_test" and fakes.pushed[0][0] == "mobile_app_phone"
    assert w.last_test.startswith("sent at")
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
    assert seen == [1, 2] and all(j.state == "done" for j in worker.jobs)


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
    assert [j.repo for j in worker.jobs] == ["acme/a"] and w.mode == "polling"
