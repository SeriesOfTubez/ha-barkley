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
def test_checks_run_semgrep_on_our_own_sample():
    checks = {c.name: c for c in doctor.run_checks()}
    sg = checks["semgrep scan (our rules, one-line sample)"]
    assert sg.ok, sg.stderr
    assert "1 file(s) scanned" in sg.summary
    assert all("full_stdout" not in d for d in doctor.to_dicts(list(checks.values())))
