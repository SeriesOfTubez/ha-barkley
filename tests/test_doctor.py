"""Diagnostics and the semgrep failure detail (what a real box reports when it breaks)."""

import subprocess

from conftest import requires_semgrep

from sniff_test import doctor
from sniff_test.analyzers.semgrep import failure_detail


def _proc(rc, out="", err=""):
    return subprocess.CompletedProcess(["semgrep"], rc, out, err)


def test_failure_detail_says_what_happened():
    assert failure_detail(_proc(-9)).startswith("semgrep killed by signal 9 (out of memory?)")
    assert failure_detail(_proc(2, err="Traceback ... PermissionError")).endswith("PermissionError")
    assert "stdout: Fatal error" in failure_detail(_proc(2, out="Fatal error: x"))
    assert "no output" in failure_detail(_proc(2))
    assert "doctor" in failure_detail(_proc(2))


def test_environment_facts_are_reported():
    facts = doctor.run_checks.__globals__["_facts"]()
    assert facts.ok
    assert "HOME=" in facts.summary and "uid=" in facts.summary


@requires_semgrep
def test_checks_run_semgrep_on_our_own_sample(monkeypatch):
    offline = doctor.github_check
    monkeypatch.setattr(doctor, "github_check", lambda: offline(fetch=False))
    checks = {c.name: c for c in doctor.run_checks()}
    sg = checks["semgrep scan (our rules, one-line sample)"]
    assert sg.ok, sg.stderr
    assert "1 file(s) scanned" in sg.summary
    assert all("full_stdout" not in d for d in doctor.to_dicts(list(checks.values())))


def test_github_check_says_how_much_is_left_and_whether_a_token_is_set():
    from sniff_test.fetch.github import RateLimit

    c = doctor.github_check(RateLimit(12, 60, 0.0, False))
    assert c.ok and c.summary.startswith("12 of 60 requests left (no token: 60/hour")
    assert not doctor.github_check(RateLimit(0, 5000, 0.0, True)).ok
    assert "unknown" in doctor.github_check(fetch=False).summary
