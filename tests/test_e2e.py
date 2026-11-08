"""End-to-end on the planted fixtures. These are the must-catch cases."""

import subprocess
from pathlib import Path

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
    r = scan(str(fixtures / "evil_integration"))
    rules = _rules(r)
    assert {"ha-exfil-taint", "py-b64-exec"} <= rules  # direct exfil + loader
    # split exfil across helpers: backstops must catch both halves of the source side
    assert {"ha-read-secrets", "ha-foreign-entry-data", "ha-auth-internals"} <= rules
    assert "py-eval-exec" not in rules  # collapsed into py-b64-exec on the same line
    assert r.score.verdict.key == "bork"


def test_evil_card_is_bork(fixtures):
    r = scan(str(fixtures / "evil_card"))
    assert {"card-token-exfil", "card-read-tokens"} <= _rules(r)
    assert r.score.verdict.key == "bork"


def test_clean_integration_is_quiet(fixtures):
    r = scan(str(fixtures / "clean_integration"))
    assert [f for f in r.findings if f.severity >= Severity.LOW] == []
    assert r.score.verdict.key == "good_boy"


def test_hidden_payload_behind_semgrepignore_is_still_found(tmp_path, fixtures):
    import shutil

    repo = tmp_path / "repo"
    shutil.copytree(fixtures / "evil_integration", repo)
    (repo / ".semgrepignore").write_text("custom_components/\n")
    (repo / "custom_components" / ".semgrepignore").write_text("*\n")
    r = scan(str(repo))
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
    r = scan(str(repo))
    hits = [f for f in r.findings if f.rule_id == "ha-raw-storage-access"]
    assert [f.line for f in hits] == [f.line for f in hits if "someone_else" in f.evidence]
    assert len(hits) == 1
