"""(0.14.1) Stored scans are reused while the scan logic is the same (logic.py): a release
that only changes the panel doesn't sniff every app again, and a change to what a scan
finds can't ship without a new key."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sniff_test import logic

PACKAGE = Path(logic.__file__).resolve().parent


def test_no_panel_only_file_is_used_by_a_scan():
    code = (
        "import sys; import sniff_test.scanner, sniff_test.report.json_report, "
        "sniff_test.recheck; "
        "print('\\n'.join(m for m in sys.modules if m.startswith('sniff_test')))"
    )
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                         check=True).stdout.split()  # fmt: skip
    used = {m.removeprefix("sniff_test.").replace(".", "/") + ".py" for m in out}
    used |= {m.removeprefix("sniff_test.").replace(".", "/") + "/__init__.py" for m in out}
    panel = logic.PANEL_ONLY - {"__init__.py", "logic.py"}
    assert not (panel & used), sorted(panel & used)


def test_every_panel_only_name_is_a_real_file():
    assert all((PACKAGE / rel).is_file() for rel in logic.PANEL_ONLY)


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    pkg, rules = tmp_path / "pkg", tmp_path / "rules"
    (pkg / "analyzers").mkdir(parents=True)
    rules.mkdir()
    (pkg / "scanner.py").write_text("x = 1\n")
    (pkg / "analyzers" / "semgrep.py").write_text("y = 1\n")
    (pkg / "ui.py").write_text("panel = 1\n")
    (pkg / "__init__.py").write_text('__version__ = "1.0.0"\n')
    (rules / "a.yaml").write_text("rules: []\n")
    return pkg, rules


TOOLS = {"semgrep": "1.185.0", "osv-scanner": "2.7.1", "guarddog": "3.2.0", "uv": "0.13.7"}


def test_the_key_follows_what_a_scan_finds(tmp_path):
    pkg, rules = _tree(tmp_path)
    first = logic.fingerprint(pkg, rules, TOOLS)
    assert first.startswith("logic-") and len(first) == len("logic-") + 12
    # panel-only changes and a new version number keep the key
    (pkg / "ui.py").write_text("panel = 2\n")
    (pkg / "__init__.py").write_text('__version__ = "1.0.1"\n')
    (pkg / "analyzers" / "__pycache__").mkdir()
    (pkg / "analyzers" / "__pycache__" / "x.pyc").write_bytes(b"\0")
    assert logic.fingerprint(pkg, rules, TOOLS) == first
    # a rule, an analyzer, a data file or a scanner tool changes it
    for change in (
        lambda: (rules / "a.yaml").write_text("rules: [1]\n"),
        lambda: (pkg / "analyzers" / "semgrep.py").write_text("y = 2\n"),
        lambda: (pkg / "data.txt").write_text("host\n"),
    ):
        before = logic.fingerprint(pkg, rules, TOOLS)
        change()
        assert logic.fingerprint(pkg, rules, TOOLS) != before
    now = logic.fingerprint(pkg, rules, TOOLS)
    assert logic.fingerprint(pkg, rules, {**TOOLS, "semgrep": "1.186.0"}) != now
    assert logic.fingerprint(pkg, rules, {**TOOLS, "uv": None}) != now


def test_a_stored_scan_is_reused_by_its_key(tmp_path):
    from sniff_test.store import Store

    store = Store(tmp_path / "s.db")

    def report(tool: dict) -> dict:
        return {
            "schema_version": 1, "tool": tool, "exposure": "local", "complete": True,
            "score": 90, "verdict": {"key": "good"}, "findings": [],
            "target": {"input": "o/r", "repo": "o/r", "ref": "v1", "kind": "plugin"},
        }  # fmt: skip

    old = store.save(report({"name": "sniff-test", "version": "0.14.0"}))
    new = store.save(report({"name": "sniff-test", "version": "0.14.1", "logic": "logic-abc"}))
    assert store.find("o/r", "v1", exposure="local", tool_version="logic-abc").id == new
    # a later release with the same scan logic still finds it; an older scan never matches
    assert store.find("o/r", "v1", exposure="local", tool_version="logic-def") is None
    assert old != new


def test_the_panel_shows_a_short_rules_label():
    from sniff_test import ui

    assert ui.rules_label("logic-acf3bd53c784") == "acf3bd5"
    assert ui.rules_label("0.14.0.5") == "0.14.0.5"
