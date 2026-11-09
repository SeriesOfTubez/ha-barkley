"""GitHub's rate limit: recognised, waited out by the add-on, and spared by ETags."""

import email.message
import io
import threading
import time
import urllib.error

from test_store import report

from sniff_test import server
from sniff_test.fetch import github
from sniff_test.fetch.github import RateLimit, RateLimitError
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
    ten = RateLimit(10, 60, time.time() + 60, authenticated=False)
    w, slept, _ = _worker(tmp_path, lambda r, ref: report(repo=r, ref=ref), [ten, ten])
    w.submit("installed", "acme/acme", "v1")  # a sniff fits in 10
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
