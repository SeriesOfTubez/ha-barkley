"""The add-on's ingress panel: who may connect, form tokens, escaping, update jobs."""

import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest
from test_store import EDGE, FINDING, report

from sniff_test import server
from sniff_test.store import Store

HOSTILE = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'


class Calls:
    def __init__(self):
        self.calls = []

    def __call__(self, repo, ref):
        self.calls.append((repo, ref))
        if ref is None:  # "what HACS installs now"
            return report(repo=repo, ref="v2", findings=[FINDING], edges=[EDGE], score=75)
        return report(repo=repo, ref=ref)


@pytest.fixture
def panel(tmp_path):
    store = Store(tmp_path / "s.db")
    scan_fn = Calls()
    httpd = server.serve(store, scan_fn, "127.0.0.1", 0, {"127.0.0.1"})
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield store, scan_fn, base, httpd
    httpd.shutdown()


def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})  # noqa: S310 - local server
    try:
        with urllib.request.urlopen(req) as r:  # noqa: S310
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def post(url, data):
    body = urllib.parse.urlencode(data).encode()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(urllib.request.Request(url, data=body)) as r:  # noqa: S310
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


def token(base):
    _, _, page = get(base + "/")
    return re.search(r'name=token value="([^"]+)"', page)[1]


def test_refuses_clients_other_than_the_allowed(tmp_path):
    store = Store(tmp_path / "s.db")
    httpd = server.serve(store, Calls(), "127.0.0.1", 0, {server.SUPERVISOR_IP})
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        status, _, body = get(f"http://127.0.0.1:{httpd.server_address[1]}/")
        assert status == 403
        assert "only reachable through Home Assistant" in body
    finally:
        httpd.shutdown()


def test_post_needs_the_form_token(panel):
    _store, scan_fn, base, _ = panel
    assert post(base + "/scan", {"repo": "acme/acme"})[0] == 403
    assert post(base + "/scan", {"repo": "acme/acme", "token": "nope"})[0] == 403
    assert scan_fn.calls == []


def test_rejects_bad_repo_and_ref(panel):
    _, _scan_fn, base, _ = panel
    tok = token(base)
    for data in (
        {"repo": "../../etc", "token": tok},
        {"repo": "acme/acme", "ref": "v1; rm -rf /", "token": tok},
        {"repo": "https://evil.invalid/a/b", "token": tok},
        {"repo": "acme/acme", "token": tok, "ref": ""},  # fine for /scan
    ):
        status, _ = post(base + "/scan", data)
        assert status == (303 if data.get("ref") == "" else 400)
    assert post(base + "/update", {"repo": "acme/acme", "token": tok})[0] == 400  # needs ref


def test_scan_job_stores_and_page_escapes_untrusted_text(panel):
    store, scan_fn, base, httpd = panel
    hostile = report(
        repo="acme/acme",
        ref="v1",
        findings=[{**FINDING, "evidence": HOSTILE, "file": HOSTILE}],
        score=75,
    )
    sid = store.save(hostile)
    status, headers, page = get(f"{base}/scan/{sid}")
    assert status == 200
    assert "<script>" not in page and "<img" not in page
    assert "&lt;script&gt;" in page
    assert "script-src" not in headers["Content-Security-Policy"]  # default-src 'none'
    assert headers["X-Content-Type-Options"] == "nosniff"
    status, headers, _body = get(f"{base}/scan/{sid}.json")
    assert headers["Content-Type"].startswith("application/json")

    status, headers = post(base + "/scan", {"repo": "acme/acme", "ref": "v1", "token": token(base)})
    assert status == 303
    worker = _worker(httpd)
    worker.wait()
    assert scan_fn.calls == [("acme/acme", "v1")]
    assert len(store.history()) == 2


def _worker(httpd):
    return httpd.panel.worker


def test_update_job_reuses_the_stored_installed_scan_and_links_a_diff(panel):
    store, scan_fn, base, httpd = panel
    installed = store.save(report(ref="v1"))
    tok = token(base)
    assert post(base + "/update", {"repo": "acme/acme", "ref": "v1", "token": tok})[0] == 303
    _worker(httpd).wait()
    assert scan_fn.calls == [("acme/acme", None)]  # only the new release was scanned
    job = _worker(httpd).jobs[0]
    assert job.state == "done", job.message
    assert job.scan_ids[0] == installed
    _, _, page = get(base + "/")
    assert f"diff?old={installed}&amp;new={job.scan_ids[1]}" in page
    status, _, page = get(f"{base}/diff?old={installed}&new={job.scan_ids[1]}")
    assert status == 200
    assert "x.invalid" in page
    assert "100 → 75" in page


def test_ingress_path_header_is_used_only_when_well_formed(panel):
    store, _, base, _ = panel
    sid = store.save(report())
    good = {"X-Ingress-Path": "/api/hassio_ingress/AbC_123-x"}
    _, _, page = get(f"{base}/scan/{sid}", good)
    assert 'href="/api/hassio_ingress/AbC_123-x/"' in page
    _, _, page = get(f"{base}/scan/{sid}", {"X-Ingress-Path": '/x"><script>'})
    assert "<script>" not in page
    assert 'href="/"' in page


def test_failed_scan_marks_the_job_and_the_worker_survives(tmp_path):
    store = Store(tmp_path / "s.db")
    calls = []

    def flaky(repo, ref):
        calls.append(ref)
        if ref == "bad":
            raise RuntimeError("boom")
        return report(repo=repo, ref=ref)

    w = server.Worker(store, flaky)
    w.submit("scan", "acme/acme", "bad")
    w.submit("scan", "acme/acme", "v1")
    w.wait()
    assert [j.state for j in w.jobs] == ["done", "failed"]
    assert "boom" in w.jobs[1].message
    assert len(store.history()) == 1


def test_missing_scan_is_404(panel):
    _, _, base, _ = panel
    assert get(f"{base}/scan/999")[0] == 404
    assert get(f"{base}/diff?old=x&new=1")[0] == 400
    assert get(f"{base}/nope")[0] == 404


def test_scan_page_names_analyzers_that_did_not_finish(panel):
    store, _, base, _ = panel
    rep = report()
    rep["complete"] = False
    rep["analyzers"] = [
        {"name": "semgrep", "state": "ok", "detail": "2 files"},
        {"name": "osv-npm", "state": "error", "detail": "<b>network</b> unreachable"},
        {"name": "python-deps", "state": "not_applicable", "detail": ""},
    ]
    _, _, page = get(f"{base}/scan/{store.save(rep)}")
    assert "Part of the check didn't finish" in page
    assert "osv-npm" in page and "&lt;b&gt;network&lt;/b&gt; unreachable" in page
    assert "python-deps" not in page


def doctor_done(base, tries=200):
    """The Diagnostics page once its background run has ended."""
    for _ in range(tries):
        status, _, page = get(base + "/doctor")
        if 'http-equiv="refresh"' not in page:
            return status, page
        time.sleep(0.02)
    raise AssertionError("the diagnostics run never ended")


def test_doctor_page_opens_at_once_and_fills_in_as_checks_end(panel, monkeypatch):
    """The user's report: the link did nothing for 15 s. The page must answer while the
    tools still run, name what it waits for, reload itself, and end without a refresh."""
    _, _, base, _ = panel
    go, calls = threading.Event(), []

    def slow(addon=False, on_step=None):
        calls.append(1)
        first = server.doctor.Check("environment", True, "uid=0")
        on_step("environment", [first])
        assert go.wait(10)
        return [first, server.doctor.Check("uv --version", True, "exit 0", "uv --version", 0, 0.1)]

    monkeypatch.setattr(server.doctor, "run_checks", slow)
    t0 = time.monotonic()
    _, _, page = get(base + "/doctor")
    assert time.monotonic() - t0 < 2
    total = len(server.doctor.steps(addon=True))
    assert '<meta http-equiv="refresh" content="2">' in page
    assert f"Running the checks: 1 of {total} done" in page
    assert "<b>environment</b> uid=0" in page
    assert "<b>memory guard</b> running…" in page and "<b>uv --version</b> waiting" in page
    get(base + "/doctor")  # a reload while it runs starts nothing new
    go.set()
    _, page = doctor_done(base)
    assert "<b>uv --version</b> exit 0" in page and "running…" not in page
    assert "All checks ran just now" in page and 'href="/doctor?again=1"' in page
    get(base + "/doctor")  # fresh results are shown again, not rerun
    assert len(calls) == 1
    get(base + "/doctor?again=1")  # urllib follows the redirect back to /doctor
    doctor_done(base)
    assert len(calls) == 2


def test_a_diagnostics_run_that_raises_still_ends(panel, monkeypatch):
    _, _, base, _ = panel

    def broken(**kw):
        raise OSError("no <tmp>")

    monkeypatch.setattr(server.doctor, "run_checks", broken)
    _, page = doctor_done(base)
    assert "FAIL" in page and "OSError: no &lt;tmp&gt;" in page


def test_doctor_page_shows_failures_escaped(panel, monkeypatch):
    _, _, base, _ = panel
    checks = [
        server.doctor.Check("environment", True, "uid=0; apparmor=hassio-addons (enforce)"),
        server.doctor.Check(
            "semgrep scan", False, "exit 2", "semgrep scan ...", 2, 0.4, "", "<boom>"
        ),
    ]
    monkeypatch.setattr(server.doctor, "run_checks", lambda **kw: checks)
    status, page = doctor_done(base)
    assert status == 200
    assert "FAIL" in page and "&lt;boom&gt;" in page
    assert "hassio-addons (enforce)" in page
    _, _, index = get(base + "/")
    assert 'href="/doctor"' in index


# --- installed HACS items (M6) -------------------------------------------------------------

from sniff_test import memory  # noqa: E402
from sniff_test.supervisor import Installed, SupervisorError  # noqa: E402

INSTALLED = [
    Installed("acme/moved", "card", "Moved", "v1", "v2", False),  # update, checked: new publisher
    Installed("acme/quiet", "integration", "Quiet", "v1", "v2", False),  # update, checked: quiet
    Installed("acme/new", "integration", "Unchecked", "v1", "v2", False),  # update, unchecked
    Installed("acme/fine", "integration", "Fine", "v1", "v1", False),  # current, sniffed, 100
    Installed("acme/never", "card", "Never", "v3", "v3", True),  # current, never sniffed
]


def _mem(gb):
    return lambda: memory.parse(f"MemTotal: 16777216 kB\nMemAvailable: {int(gb * 1048576)} kB\n")


@pytest.fixture
def addon(tmp_path):
    store = Store(tmp_path / "s.db")
    scan_fn = Calls()
    state = {"fn": lambda: (list(INSTALLED), {"theme": 2}), "mem": _mem(8)}
    httpd = server.serve(
        store, scan_fn, "127.0.0.1", 0, {"127.0.0.1"},
        ha_fn=lambda: "2026.11.0",
        installed_fn=lambda: state["fn"](),
        memory_fn=lambda: state["mem"](),
    )  # fmt: skip
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield store, scan_fn, f"http://127.0.0.1:{httpd.server_address[1]}", httpd, state
    httpd.shutdown()


def _seed(store):
    moved_old = report(repo="acme/moved", ref="v1", kind="plugin")
    moved_old["provenance"] = {"publishers": {"v1": ["alice"]}}
    store.save(moved_old)
    store.save(report(repo="acme/moved", ref="v2", kind="plugin", findings=[FINDING], score=75))
    store.save(report(repo="acme/quiet", ref="v1"))
    store.save(report(repo="acme/quiet", ref="v2"))
    store.save(report(repo="acme/fine", ref="v1"))


def _card(page, name):
    """The HTML of one card in the grid, by app name."""
    i = page.index(f">{name}<")
    start = page.rindex('<div class="app ', 0, i)
    nxt = page.find('<div class="app ', i)
    return page[start : nxt if nxt != -1 else page.index('<div class="legend"', i)]


def _card_order(page):
    return re.findall(r'class="app-name"[^>]*>([^<]+)<', page)


def test_installed_grid_leads_with_what_needs_attention(addon):
    store, _, base, _, _ = addon
    _seed(store)
    _, _, page = get(base + "/")
    # not checked (grey) first, then lowest score first
    order = _card_order(page)
    assert order[:2] == ["Never", "Unchecked"] or order[:2] == ["Unchecked", "Never"]
    assert order.index("Moved") < order.index("Fine")
    moved = _card(page, "Moved")
    assert 'class="app grey"' not in moved and "Update v2 needs a look" in moved
    assert "Update v2 needs a look" in moved and "diff?old=" in moved
    unchecked = _card(page, "Unchecked")
    assert "app grey" in unchecked or 'class="app "' not in unchecked
    assert "Check update" in unchecked and 'name=to value="v2"' in unchecked
    assert "Sniff it" in _card(page, "Never")
    assert "<b>5</b> apps installed" in page
    assert "Sniff the 2 not yet sniffed" in page
    assert "Not scanned (not an integration or card): 2 theme" in page
    _, _, look = get(base + "/?f=look")
    assert _card_order(look) == ["Moved"]
    _, _, ups = get(base + "/?f=updates")
    assert sorted(_card_order(ups)) == ["Moved", "Quiet", "Unchecked"]


def test_detail_page_of_an_installed_app_shows_its_update(addon):
    store, _, base, _, _ = addon
    _seed(store)
    sid = store.history("acme/moved")[-1].id  # v1, the installed version
    _, _, page = get(f"{base}/scan/{sid}")
    assert "<h1>Moved</h1>" in page and "All apps</a>" in page
    assert "Update available: v1 → v2" in page
    assert "Everything the update" in page
    assert "What we found" in page and "Where it connects" in page


def test_check_runs_the_update_diff_reusing_stored_scans(addon):
    store, scan_fn, base, httpd, _ = addon
    installed = store.save(report(repo="acme/new", ref="v1"))
    tok = token(base)
    data = {"repo": "acme/new", "ref": "v1", "to": "v2", "token": tok}
    assert post(base + "/update", data)[0] == 303
    _worker(httpd).wait()
    assert scan_fn.calls == [("acme/new", "v2")]  # exactly what HACS offers, not re-derived
    job = _worker(httpd).jobs[0]
    assert job.state == "done" and job.scan_ids[0] == installed
    # A second click reuses both stored scans: nothing is scanned again.
    assert post(base + "/update", data)[0] == 303
    _worker(httpd).wait()
    assert len(scan_fn.calls) == 1
    _, _, page = get(base + "/")
    assert f"diff?old={installed}&amp;new={job.scan_ids[1]}" in page


def test_sniff_all_never_sniffed_queues_installed_versions(addon):
    store, scan_fn, base, httpd, _ = addon
    _seed(store)
    assert post(base + "/installed-all", {"token": token(base)})[0] == 303
    _worker(httpd).wait()
    assert sorted(scan_fn.calls) == [("acme/never", "v3"), ("acme/new", "v1")]


def test_installed_list_error_is_shown_and_typed_checks_remain(addon):
    _, _, base, _, state = addon

    def broken():
        raise SupervisorError("HACS isn't <b>installed</b>")

    state["fn"] = broken
    _, _, page = get(base + "/?refresh=1")
    assert "Can't list installed items: HACS isn&#x27;t &lt;b&gt;installed&lt;/b&gt;" in page
    assert "What would updating change?" in page


def test_installed_list_is_cached(addon):
    _, _, base, _, state = addon
    calls = []
    state["fn"] = lambda: calls.append(1) or (list(INSTALLED), {})
    get(base + "/")
    get(base + "/")
    assert len(calls) == 1
    get(base + "/?refresh=1")
    assert len(calls) == 2


def test_memory_guard_warns_and_refuses(addon):
    _, scan_fn, base, httpd, state = addon
    state["mem"] = _mem(1.5)
    _, _, page = get(base + "/")
    assert "Memory: 1.5 GB available" in page and "may be slow" in page
    state["mem"] = _mem(0.5)
    _, _, page = get(base + "/")
    assert "scans are refused" in page
    post(base + "/scan", {"repo": "acme/acme", "ref": "v1", "token": token(base)})
    _worker(httpd).wait()
    job = _worker(httpd).jobs[0]
    assert job.state == "refused" and "0.5 GB available" in job.message
    assert scan_fn.calls == []


def test_no_installed_section_outside_an_addon(panel):
    _, _, base, _ = panel
    _, _, page = get(base + "/")
    assert "apps installed from the Marketplace" not in page


def test_a_row_shows_its_running_check_instead_of_a_second_button(addon):
    _, _, base, httpd, _ = addon
    panel = httpd.panel
    job = server.Job(99, "update", "acme/new", "v1", "v2", state="running")
    panel.worker.jobs.insert(0, job)
    _, _, page = get(base + "/")
    card = _card(page, "Unchecked")
    assert "checking…" in card and "Check update" not in card
    job.state = "done"
    _, _, page = get(base + "/")
    assert "Check update" in _card(page, "Unchecked")


def test_scans_from_older_rules_dont_count(addon):
    """After a rule change (tool version bump) the list offers to sniff again."""
    store, scan_fn, base, httpd, _ = addon
    store.save(report(repo="acme/fine", ref="v1", tool="0.0.1", score=75))
    _, _, page = get(base + "/")
    fine = _card(page, "Fine")  # the old 75 isn't shown as today's verdict
    assert "app grey" in fine and ">75<" not in fine and "Sniff it" in fine
    assert "Sniff the 5 not yet sniffed" in page
    assert post(base + "/installed-all", {"token": token(base)})[0] == 303
    _worker(httpd).wait()
    assert ("acme/fine", "v1") in scan_fn.calls


def test_an_incomplete_scan_offers_to_scan_again(addon):
    store, _, base, _, _ = addon
    _seed(store)
    bad = report(repo="acme/fine", ref="v1")
    bad["complete"] = False
    store.save(bad)  # newer, but a complete one exists: that one is shown
    _, _, page = get(base + "/?refresh=1")
    assert "Sniff again" not in page
    never = report(repo="acme/never", ref="v3", kind="plugin")
    never["complete"] = False
    store.save(never)
    _, _, page = get(base + "/?refresh=1")
    assert "Sniff again" in page


# --- auto-sniff: the panel's box and settings -------------------------------------------


@pytest.fixture
def auto(tmp_path):
    from sniff_test import watch

    store = Store(tmp_path / "s.db")
    scan_fn = Calls()
    sent = []
    w = watch.Watcher(
        store, None, lambda: (list(INSTALLED), {}),
        notify_fn=lambda t, m, n: sent.append(("bell", t, m, n)),
        notify_service_fn=lambda tg, t, m, u: sent.append(("push", tg, t, m, u)),
        targets_fn=lambda: ["mobile_app_phone"], slug_fn=lambda: "local_sniff_test",
    )  # fmt: skip
    httpd = server.serve(
        store, scan_fn, "127.0.0.1", 0, {"127.0.0.1"},
        ha_fn=lambda: "2026.11.0", installed_fn=lambda: (list(INSTALLED), {}),
        memory_fn=_mem(8), watcher=w,
    )  # fmt: skip
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield store, f"http://127.0.0.1:{httpd.server_address[1]}", httpd, w, sent
    httpd.shutdown()


def test_auto_box_says_what_it_does_and_that_a_new_integration_runs_at_once(auto):
    _store, base, httpd, w, _sent = auto
    _, _, page = get(base + "/")
    assert "Auto-sniff: on · bell notification" in page
    assert "A new integration runs as soon as it's installed" in page
    assert "sniffing it from search <i>before</i> you install" in page
    assert "deleted after 7 days; scans of installed apps are kept" in page
    assert "name=target" in page and 'value="mobile_app_phone"' in page
    assert "Turn auto-sniff off" in page
    assert httpd.panel.worker.on_done == [w.on_job_done]  # the hook is wired


def test_auto_settings_are_stored_and_the_test_button_notifies(auto):
    store, base, _httpd, w, sent = auto
    tok = token(base)
    assert post(base + "/auto-scan", {"token": tok, "on": "0"})[0] == 303
    assert store.setting("auto_scan") == "off" and not w.enabled
    _, _, page = get(base + "/")
    assert "Auto-sniff: off" in page and "Turn auto-sniff on" in page
    assert post(base + "/notify-target", {"token": tok, "target": "mobile_app_phone"})[0] == 303
    assert store.setting("notify_target") == "mobile_app_phone"
    code, _ = post(base + "/notify-target", {"token": tok, "target": "not_offered"})
    assert code == 400 and w.notify_target == "mobile_app_phone"
    assert post(base + "/notify-test", {"token": tok})[0] == 303
    assert [s[0] for s in sent] == ["bell", "push"]
    assert sent[0][3] == "barkley_test" and sent[1][1] == "mobile_app_phone"
    _, _, page = get(base + "/")
    assert "bell + notify.mobile_app_phone" in page and "sent at" in page
    assert post(base + "/notify-test", {"token": "bad"})[0] == 403


def test_auto_jobs_show_in_the_jobs_table_and_doctor_names_the_watcher(auto, monkeypatch):
    _store, base, httpd, _w, _sent = auto
    job = httpd.panel.worker.submit("auto", "acme/quiet", "v2", prev="v1")
    httpd.panel.worker.wait()
    assert job.state == "done" and len(job.scan_ids) == 2
    _, _, page = get(base + "/")
    assert '<td class="nowrap">auto-sniff</td><td class="wrap">acme/quiet@v1 → @v2</td>' in page
    assert f"diff?old={job.scan_ids[0]}&amp;new={job.scan_ids[1]}" in page
    monkeypatch.setattr(server.doctor, "run_checks", lambda **kw: [])
    _, page = doctor_done(base)
    assert "Auto-sniff (Marketplace events)" in page and "auto-sniff on" in page


def test_the_watcher_refreshes_the_panels_installed_list(auto):
    _store, base, _httpd, w, _sent = auto
    _, _, page = get(base + "/")
    assert "<b>5</b> apps installed" in page
    w.installed_fn = lambda: ([*INSTALLED, Installed("acme/just", "card", "Just", "v1", "v1",
                                                     False)], {})  # fmt: skip
    w.check()  # the watcher read a fresh list: the panel shows it without waiting 5 minutes
    _, _, page = get(base + "/")
    assert "<b>6</b> apps installed" in page and ">Just<" in page


def test_no_auto_box_outside_an_addon(panel):
    _, _, base, _ = panel
    _, _, page = get(base + "/")
    assert "Auto-sniff" not in page
    assert post(base + "/auto-scan", {"token": token(base), "on": "0"})[0] == 400


def test_a_redirect_target_is_one_local_path():
    """The backstop under every `_redirect` (CodeQL py/http-response-splitting on the
    first public run, 2026-11-14: no caller was exploitable, each builds its target from
    checked pieces; this keeps a future one from turning a form field into a header)."""
    from sniff_test.server import local_path

    base = "/api/hassio_ingress/AbC_d-9"
    for ok in (
        "/",
        "/scan/12",
        f"{base}/scan/12?open=0123456789abcdef#ai-0123456789abcdef",
        f"{base}/?f=updates&view=table&page=2",
        "/search?q=printer+%0D%0Ax&kind=",  # quoted: the characters themselves never appear
    ):
        assert local_path(ok) == ok
    for bad in (
        "",
        "scan/1",
        "//evil.invalid/x",
        "/\\evil.invalid/x",
        "https://evil.invalid/",
        "/scan/1\r\nSet-Cookie: a=b",
        "/scan/1\nX: y",
        "/scan/1 x",
        "/scan/\u00e9",
    ):
        assert local_path(bad) == "/", bad
