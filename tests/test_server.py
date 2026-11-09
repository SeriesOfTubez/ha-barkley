"""The add-on's ingress panel: who may connect, form tokens, escaping, update jobs."""

import re
import threading
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
    assert "Didn't finish" in page
    assert "osv-npm" in page and "&lt;b&gt;network&lt;/b&gt; unreachable" in page
    assert "python-deps" not in page


def test_doctor_page_shows_failures_escaped(panel, monkeypatch):
    _, _, base, _ = panel
    checks = [
        server.doctor.Check("environment", True, "uid=0; apparmor=hassio-addons (enforce)"),
        server.doctor.Check(
            "semgrep scan", False, "exit 2", "semgrep scan ...", 2, 0.4, "", "<boom>"
        ),
    ]
    monkeypatch.setattr(server.doctor, "run_checks", lambda: checks)
    status, _, page = get(base + "/doctor")
    assert status == 200
    assert "FAIL" in page and "&lt;boom&gt;" in page
    assert "hassio-addons (enforce)" in page
    _, _, index = get(base + "/")
    assert 'href="/doctor"' in index
