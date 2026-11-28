"""Parallel scans: bounded by memory, never the same repo twice, one GitHub gate."""

import threading
import time

from test_store import report

from sniff_test import memory, server
from sniff_test.fetch.github import RateLimit
from sniff_test.store import Store


def _mem(gb):
    if gb is None:
        return lambda: memory.Memory("unknown", None, None)
    return lambda: memory.parse(f"MemTotal: 16777216 kB\nMemAvailable: {int(gb * 1048576)} kB\n")


class Slow:
    """A scan that takes a moment and records how many ran at once."""

    def __init__(self, seconds=0.3):
        self.seconds = seconds
        self.now = 0
        self.peak = 0
        self.lock = threading.Lock()
        self.by_repo: dict[str, int] = {}
        self.repo_peak = 0

    def __call__(self, repo, ref):
        with self.lock:
            self.now += 1
            self.peak = max(self.peak, self.now)
            self.by_repo[repo] = self.by_repo.get(repo, 0) + 1
            self.repo_peak = max(self.repo_peak, self.by_repo[repo])
        time.sleep(self.seconds)
        with self.lock:
            self.now -= 1
            self.by_repo[repo] -= 1
        return report(repo=repo, ref=ref or "v1")


def _worker(tmp_path, scan, gb, parallel=2, **kw):
    return server.Worker(
        Store(tmp_path / "s.db"), scan, memory_fn=_mem(gb), parallel=parallel, **kw
    )


def test_two_scans_run_together_when_memory_allows(tmp_path):
    scan = Slow()
    w = _worker(tmp_path, scan, gb=8)
    for r in ("a/one", "a/two"):
        w.submit("scan", r, "v1")
    w.wait()
    assert scan.peak == 2
    assert all(j.state == "done" for j in w.jobs)


def test_one_at_a_time_when_memory_is_tight_or_unknown(tmp_path):
    # 3 GiB: enough for one scan above the warn line, not for a second (2 + 1.5 GiB)
    for gb in (3, None):
        scan = Slow(0.15)
        w = _worker(tmp_path / str(gb), scan, gb=gb)
        for r in ("a/one", "a/two"):
            w.submit("scan", r, "v1")
        w.wait()
        assert scan.peak == 1, gb
        assert all(j.state == "done" for j in w.jobs)


def test_never_the_same_repo_twice_at_once(tmp_path):
    scan = Slow(0.15)
    w = _worker(tmp_path, scan, gb=12, parallel=3)
    for ref in ("v1", "v2", "v3"):
        w.submit("scan", "a/same", ref)
    w.wait()
    assert scan.repo_peak == 1


def test_parallel_is_capped(tmp_path):
    w = _worker(tmp_path, Slow(0), gb=8, parallel=99)
    assert w.parallel == server.PARALLEL_MAX


def test_github_budget_reserves_what_running_jobs_need(tmp_path):
    """10 requests left: one 8-request scan may run, the second waits for the reset."""
    slept = []
    budget = {"left": 10}

    def budget_fn():
        return RateLimit(limit=60, remaining=budget["left"], reset_at=time.time() + 60,
                         authenticated=False)  # fmt: skip

    def sleep_fn(s):
        slept.append(s)
        budget["left"] = 60  # the reset came

    scan = Slow(0.3)
    w = _worker(tmp_path, scan, gb=8, budget_fn=budget_fn, sleep_fn=sleep_fn)
    for r in ("a/one", "a/two"):
        w.submit("scan", r, "v1")
    w.wait()
    assert slept  # one of them waited for GitHub instead of running
    assert all(j.state == "done" for j in w.jobs)


# --- (0.14.0) Memory for scans: Auto with a container's own limit, or a fixed amount ----------


def _limited(avail_gb, limit_gb):
    gib = memory.GIB
    return lambda: memory.Memory("ok", int(avail_gb * gib), int(limit_gb * gib), limited=True)


def _room(tmp_path, mem_fn, running, gb=0):
    w = server.Worker(Store(tmp_path / "s.db"), Slow(), memory_fn=mem_fn, parallel=4)
    w.memory_gb_fn = lambda: gb
    w._running = [object()] * running
    return w._room_for_another()


def test_auto_keeps_a_small_reserve_inside_a_containers_own_limit(tmp_path):
    # a 3 GB container with 2.6 GB free: 0.5 + 1.5 for the running scan fits a second
    assert _room(tmp_path, _limited(2.6, 3), 1) == ""
    # the same free memory on a machine Home Assistant shares: 2 + 1.5 doesn't
    why = _room(tmp_path, _mem(2.6), 1)
    assert why.startswith(
        "waiting for memory. 2.6 GB is free and 3.5 GB is needed while 1 other scan runs"
    )


def test_a_fixed_amount_runs_as_many_as_fit_and_never_past_the_container(tmp_path):
    assert _room(tmp_path, _mem(20), 1, gb=4) == ""  # 4 GB: two scans
    why = _room(tmp_path, _mem(20), 2, gb=4)
    assert why.startswith("waiting for a running scan to finish. 4 GB") and "fits 2 scans" in why
    assert _room(tmp_path, _mem(20), 7, gb=12) == ""  # a big machine: eight at 1.5 GB
    # 8 GB chosen, but the container allows 3: two at most
    assert "fits 2" in _room(tmp_path, _limited(2.9, 3), 2, gb=8)
    # and never under 1 GB really free after the running scans' growth
    assert _room(tmp_path, _mem(2.0), 1, gb=8).startswith("waiting for memory")
