"""End-to-end on the planted fixtures. These are the must-catch cases."""

import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import requires_semgrep

from sniff_test.analyzers.semgrep import rules_dir
from sniff_test.models import Severity
from sniff_test.scanner import scan

pytestmark = requires_semgrep


def _rules(result):
    return {f.rule_id for f in result.findings}


def test_semgrep_rule_unit_tests_pass():
    tests_dir = Path(__file__).parent / "rules"
    proc = subprocess.run(
        [
            "semgrep",
            "scan",
            "--test",
            "--metrics=off",
            "--disable-version-check",
            "--config",
            str(rules_dir()),
            str(tests_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_evil_integration_is_bork(fixtures):
    r = scan(str(fixtures / "evil_integration"), offline=True)
    rules = _rules(r)
    assert {"ha-exfil-taint", "py-b64-exec"} <= rules  # direct exfil + loader
    assert "dep-typosquat" in rules  # reqeusts: caught offline, from the name alone
    # split exfil across helpers: backstops must catch both halves of the source side
    assert {"ha-read-secrets", "ha-foreign-entry-data", "ha-auth-internals"} <= rules
    assert "py-eval-exec" not in rules  # collapsed into py-b64-exec on the same line
    assert r.score.verdict.key == "bork"


def test_evil_card_is_bork(fixtures):
    r = scan(str(fixtures / "evil_card"), offline=True)
    assert {"card-token-exfil", "card-read-tokens"} <= _rules(r)
    assert r.score.verdict.key == "bork"


def test_clean_integration_is_quiet_offline(fixtures):
    r = scan(str(fixtures / "clean_integration"), offline=True)
    assert [f for f in r.findings if f.severity >= Severity.LOW] == []
    assert not r.score.complete  # dependency checks were skipped, and the score says so
    assert r.score.score == 89


def test_hidden_payload_behind_semgrepignore_is_still_found(tmp_path, fixtures):
    import shutil

    repo = tmp_path / "repo"
    shutil.copytree(fixtures / "evil_integration", repo)
    (repo / ".semgrepignore").write_text("custom_components/\n")
    (repo / "custom_components" / ".semgrepignore").write_text("*\n")
    r = scan(str(repo), offline=True)
    assert "ha-exfil-taint" in _rules(r)


def test_own_storage_access_is_not_flagged(tmp_path, fixtures):
    import shutil

    repo = tmp_path / "repo"
    shutil.copytree(fixtures / "clean_integration", repo)
    init = repo / "custom_components" / "acme_weather" / "__init__.py"
    init.write_text(
        init.read_text()
        + "\n\ndef cache(hass, email):\n"
        + '    a = hass.config.path(f".storage/{DOMAIN}.{email}.pickle")\n'
        + '    b = hass.config.path(".storage/acme_weather.data")\n'
        + '    c = hass.config.path(".storage/someone_else.data")\n'
        + "    return a, b, c\n"
    )
    r = scan(str(repo), offline=True)
    hits = [f for f in r.findings if f.rule_id == "ha-raw-storage-access"]
    assert [f.line for f in hits] == [f.line for f in hits if "someone_else" in f.evidence]
    assert len(hits) == 1


# --- full scans: need network (GitHub for HA constraints, PyPI, OSV) and all tools -----

needs_tools = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("uv", "osv-scanner", "guarddog")),
    reason="uv / osv-scanner / guarddog not installed",
)


@pytest.mark.network
@needs_tools
def test_evil_integration_full(fixtures):
    r = scan(str(fixtures / "evil_integration"))
    assert {"dep-typosquat", "dep-unresolvable"} <= _rules(r)
    assert r.score.complete
    assert r.score.verdict.key == "bork"


@pytest.mark.network
@needs_tools
def test_evil_card_lockfile_is_malicious(fixtures):
    r = scan(str(fixtures / "evil_card"))
    mal = [f for f in r.findings if f.rule_id == "dep-malicious"]
    assert any("MAL-" in (f.evidence or "") and "flatmap-stream" in f.evidence for f in mal)
    assert r.score.verdict.key == "bork"


@pytest.mark.network
@needs_tools
def test_planted_osv_config_cannot_hide_malware(tmp_path, fixtures):
    repo = tmp_path / "repo"
    shutil.copytree(fixtures / "evil_card", repo)
    (repo / "osv-scanner.toml").write_text(
        '[[IgnoredVulns]]\nid = "MAL-2025-20690"\n'
        '[[PackageOverrides]]\nname = "flatmap-stream"\nignore = true\n'
    )
    r = scan(str(repo))
    assert any("flatmap-stream" in (f.evidence or "") for f in r.findings)


@pytest.mark.network
@needs_tools
def test_clean_integration_full_is_good_boy(fixtures):
    r = scan(str(fixtures / "clean_integration"))
    assert [f for f in r.findings if f.severity >= Severity.LOW] == []
    assert r.score.complete
    assert r.score.verdict.key == "good_boy"
