"""Sniff again, and sniffing an older or beta version before installing it."""

import threading

from test_server import HOSTILE, Calls, get, post, token
from test_store import report

from sniff_test import releases, server
from sniff_test.analyzers.repo_signals import to_release
from sniff_test.fetch.github import RateLimitError
from sniff_test.store import Store

RAW = [
    {"tag_name": "v3.0.0b1", "prerelease": True, "published_at": "2026-11-01T00:00:00Z",
     "author": {"login": "greg"}},
    {"tag_name": "v2.9.0-draft", "draft": True},
    {"tag_name": "v2.3.0", "published_at": "2026-10-01T00:00:00Z",
     "author": {"login": "github-actions[bot]", "type": "Bot"}},
    {"tag_name": "v2.2.0", "published_at": "2026-09-01T00:00:00Z", "author": {"login": "greg"}},
    {"tag_name": f"bad {HOSTILE}", "published_at": "2026-08-01T00:00:00Z"},
]  # fmt: skip


class FakeGH:
    def __init__(self):
        self.calls = 0

    def hacs_releases(self, owner, name):
        self.calls += 1
        return RAW


def test_recent_skips_drafts_and_marks_the_default():
    gh = FakeGH()
    rel, default = releases.recent("acme/printer-hub", gh)
    assert [r.tag for r in rel][:3] == ["v3.0.0b1", "v2.3.0", "v2.2.0"]
    assert default == "v2.3.0" and gh.calls == 1  # one request


def _serve(tmp_path, releases_fn):
    store = Store(tmp_path / "s.db")
    scan_fn = Calls()
    httpd = server.serve(store, scan_fn, "127.0.0.1", 0, {"127.0.0.1"}, releases_fn=releases_fn)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return store, scan_fn, f"http://127.0.0.1:{httpd.server_address[1]}", httpd


def test_versions_page_lists_and_sniffs_a_chosen_version(tmp_path):
    gh = FakeGH()
    store, scan_fn, base, httpd = _serve(tmp_path, lambda repo: releases.recent(repo, gh))
    store.save(report(repo="acme/printer-hub", ref="v2.2.0", score=82))
    _, _, page = get(base + "/versions?repo=acme/printer-hub")
    assert "v3.0.0b1" in page and "beta" in page and "Marketplace default" in page
    assert "v2.9.0-draft" not in page
    assert "<script>" not in page and "can't sniff this tag name" in page  # tags are untrusted
    row = page[page.index("v2.2.0") :]
    assert ">82<" in row[: row.index("</tr>")]  # already sniffed: its score
    form = {"repo": "acme/printer-hub", "ref": "v3.0.0b1", "back_to": "versions"}
    status, headers = post(base + "/scan", {**form, "token": token(base)})
    assert status == 303 and headers["Location"] == "/versions?repo=acme%2Fprinter-hub"
    httpd.panel.worker.wait()
    assert scan_fn.calls == [("acme/printer-hub", "v3.0.0b1")]
    get(base + "/versions?repo=acme/printer-hub")
    assert gh.calls == 1  # cached
    assert get(base + "/versions?repo=../../x")[0] == 400
    httpd.shutdown()


def test_a_rate_limit_is_try_later_not_a_result(tmp_path):
    def limited(repo):
        raise RateLimitError("https://api.github.com/x", 1_900_000_000, False)

    _, _, base, httpd = _serve(tmp_path, limited)
    _, _, page = get(base + "/versions?repo=a/b")
    assert "hourly limit is used up" in page and "No releases" not in page
    httpd.shutdown()


def test_sniff_again_runs_a_fresh_scan(tmp_path):
    store, scan_fn, base, httpd = _serve(tmp_path, None)
    sid = store.save(report(repo="acme/acme", ref="v1"))
    _, _, page = get(base + f"/scan/{sid}")
    assert "Sniff this version again" in page and "/versions?repo=acme%2Facme" in page
    post(base + "/scan", {"repo": "acme/acme", "ref": "v1", "token": token(base)})
    httpd.panel.worker.wait()
    assert scan_fn.calls == [("acme/acme", "v1")]  # not reused: a fresh scan
    assert len(store.history("acme/acme")) == 2
    httpd.shutdown()


def test_to_release_is_reused():
    assert to_release(RAW[0]).prerelease
