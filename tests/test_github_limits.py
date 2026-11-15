"""GitHub's rate limit: recognised, waited out by the add-on, never a scan result."""

import email.message
import io
import threading
import time
import urllib.error

import pytest
from conftest import requires_semgrep
from test_repo_signals import LONG_HISTORY, FakeGitHub, _target
from test_store import report

from sniff_test import server
from sniff_test.analyzers import repo_signals
from sniff_test.deps import ha_env
from sniff_test.fetch import github
from sniff_test.fetch.github import GitHub, RateLimit, RateLimitError
from sniff_test.scanner import scan
from sniff_test.store import Store


def _http_error(code, **headers):
    h = email.message.Message()
    for k, v in headers.items():
        h[k.replace("_", "-")] = v
    return urllib.error.HTTPError("https://api.github.com/x", code, "Forbidden", h, io.BytesIO())


def test_rate_limit_responses_are_recognised():
    reset = github._rate_limit_reset(
        _http_error(403, X_RateLimit_Remaining="0", X_RateLimit_Reset="1900000000")
    )
    assert reset == 1900000000.0
    secondary = github._rate_limit_reset(_http_error(429, Retry_After="30"))
    assert 25 < secondary - time.time() <= 30
    assert github._rate_limit_reset(_http_error(403, X_RateLimit_Remaining="12")) is None
    assert github._rate_limit_reset(_http_error(403)) is None  # a real 403 stays an error


def test_rate_limit_error_message_says_when_and_what_helps():
    msg = str(RateLimitError("https://api.github.com/repos/a/b", 0.0, authenticated=False))
    assert "60 requests/hour without a token" in msg and "resets at 00:00 UTC" in msg
    assert "token raises it to 5,000" in msg
    assert "raises" not in str(RateLimitError("u", 0.0, authenticated=True))


def _worker(tmp_path, scan_fn, budgets):
    slept = []
    banners = []

    def sleep(seconds):
        slept.append(seconds)
        banners.append(w.github_wait)

    budget = iter(budgets)
    w = server.Worker(
        Store(tmp_path / "s.db"), scan_fn,
        budget_fn=lambda: next(budget, None), sleep_fn=sleep,
    )  # fmt: skip
    return w, slept, banners


def test_worker_waits_for_a_low_budget_before_starting(tmp_path):
    low = RateLimit(3, 60, time.time() + 600, authenticated=False)
    w, slept, banners = _worker(tmp_path, lambda r, ref: report(repo=r, ref=ref), [low])
    w.submit("installed", "acme/acme", "v1")
    w.wait()
    assert [j.state for j in w.jobs] == ["done"]
    assert len(slept) == 1 and 590 < slept[0] <= 605
    assert "3 of 60 requests left" in banners[0] and "5,000" in banners[0]
    assert w.github_wait == ""  # cleared once it resumes


def test_worker_retries_a_job_that_hit_the_limit_mid_scan(tmp_path):
    calls = []

    def scan_fn(repo, ref):
        calls.append(ref)
        if len(calls) == 1:
            raise RateLimitError("https://api.github.com/x", time.time() + 60, False)
        return report(repo=repo, ref=ref)

    w, slept, _ = _worker(tmp_path, scan_fn, [])
    w.submit("scan", "acme/acme", "v1")
    w.submit("scan", "acme/acme", "v2")
    w.wait()
    assert [j.state for j in w.jobs] == ["done", "done"]
    assert calls == ["v1", "v1", "v2"]  # retried in place, order kept
    assert len(slept) == 1


def test_waiting_rows_and_banner_on_the_panel(tmp_path):
    started = threading.Event()
    release = threading.Event()

    def sleep(_s):
        started.set()
        release.wait(5)

    low = RateLimit(0, 60, time.time() + 60, authenticated=False)
    w = server.Worker(Store(tmp_path / "s.db"), lambda r, ref: report(repo=r, ref=ref),
                      budget_fn=iter([low]).__next__, sleep_fn=sleep)  # fmt: skip
    w.submit("installed", "acme/acme", "v1")
    assert started.wait(5)
    assert w.jobs[0].state == "waiting" and "resumes at" in w.jobs[0].message
    page = server.render_index("", w.store, list(w.jobs), "tok", github_wait=w.github_wait)
    assert b"0 of 60 requests left" in page
    release.set()
    w.wait()


def test_budget_is_sized_per_job_kind(tmp_path):
    ten = RateLimit(12, 60, time.time() + 60, authenticated=False)
    w, slept, _ = _worker(tmp_path, lambda r, ref: report(repo=r, ref=ref), [ten, ten])
    w.submit("installed", "acme/acme", "v1")  # a sniff fits in 12
    w.submit("update", "acme/acme", "v1", to="v2")  # two scans don't: waits first
    w.wait()
    assert [j.state for j in w.jobs] == ["done", "done"]
    assert len(slept) == 1


def test_queued_sniffs_and_an_update_check_all_finish_across_a_reset(tmp_path):
    """The user's case: Sniff installed queued, then Check update clicked, no token."""
    budget = {"left": 20}

    def scan_fn(repo, ref):
        if budget["left"] < 7:
            raise RateLimitError("https://api.github.com/x", time.time() + 60, False)
        budget["left"] -= 7
        return report(repo=repo, ref=ref)

    def sleep(_s):
        budget["left"] = 60  # the hour rolls over

    def budget_fn():
        return RateLimit(budget["left"], 60, time.time() + 60, False)

    w = server.Worker(Store(tmp_path / "s.db"), scan_fn, sleep_fn=sleep, budget_fn=budget_fn)
    for repo in ("a/one", "a/two", "a/three"):
        w.submit("installed", repo, "v1")
    w.submit("update", "a/four", "v1", to="v2")
    w.wait()
    assert [j.state for j in reversed(w.jobs)] == ["done"] * 4
    assert [j.kind for j in reversed(w.jobs)] == ["installed"] * 3 + ["update"]  # order kept


# --- a rate limit is never a scan result ------------------------------------------------

LIMIT = RateLimitError("https://api.github.com/x", 0.0, authenticated=False)


class LimitedGitHub(FakeGitHub):
    def __init__(self, fail_on):
        super().__init__(LONG_HISTORY, {})
        self.fail_on = fail_on

    def releases(self, owner, name, max_pages=5):
        if "releases" in self.fail_on:
            raise LIMIT
        return super().releases(owner, name)

    def get_json(self, path):
        if any(k in path for k in self.fail_on):
            raise LIMIT
        return super().get_json(path)


@pytest.mark.parametrize("fail_on", [("releases",), ("/compare/",), ("/repos/oldowner",)])
def test_repo_signals_never_turn_a_rate_limit_into_a_partial_result(tmp_path, fail_on):
    meta = {"id": 42, "full_name": "newowner/widget", "default_branch": "main"}
    files = {"README.md": "https://github.com/oldowner/widget"}  # a former-name candidate
    t = _target(tmp_path, repo_meta=meta, commit_sha="abc", files=files)
    with pytest.raises(RateLimitError):
        repo_signals.run(t, LimitedGitHub(fail_on))


def test_ha_env_lets_a_rate_limit_through(tmp_path, monkeypatch):
    monkeypatch.setenv("SNIFF_TEST_CACHE", str(tmp_path))

    class G:
        def file_at(self, *a):
            raise LIMIT

        def releases(self, *a, **k):
            raise LIMIT

    with pytest.raises(RateLimitError):
        ha_env.load("2026.11.0", G())
    with pytest.raises(RateLimitError):
        ha_env.version_at("2026-11-01T00:00:00Z", G())


def test_incomplete_scans_are_never_reused(tmp_path):
    store = Store(tmp_path / "s.db")
    bad = report(ref="v1")
    bad["complete"] = False
    store.save(bad)
    assert (
        store.find("acme/acme", "v1", exposure="local", tool_version=bad["tool"]["version"]) is None
    )
    good = store.save(report(ref="v1"))
    hit = store.find("acme/acme", "v1", exposure="local", tool_version=bad["tool"]["version"])
    assert hit.id == good


@pytest.mark.network
@requires_semgrep
def test_a_rate_limit_on_any_github_request_of_a_real_scan_aborts_it(monkeypatch):
    """Sweep: fail the Nth GitHub request of a real scan, for every N. A scan must never
    come back (stored, reused, scored) with part of it missing for a rate limit."""
    real = GitHub._request
    calls = {"n": 0, "fail_at": None}

    def counting(self, url, accept="application/vnd.github+json"):
        calls["n"] += 1
        if calls["n"] == calls["fail_at"]:
            raise RateLimitError(url, 0.0, authenticated=bool(self.token))
        return real(self, url, accept)

    monkeypatch.setattr(GitHub, "_request", counting)
    scan("ReikanYsora/Helios", ref="2026.9.6", ha_version="2026.11.0")
    total = calls["n"]
    assert total >= 5
    for n in range(1, total + 1):
        calls.update(n=0, fail_at=n)
        with pytest.raises(RateLimitError):
            scan("ReikanYsora/Helios", ref="2026.9.6", ha_version="2026.11.0")
