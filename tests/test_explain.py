"""Plain-English text: every rule the scanner can produce has hand-written text."""

import re
from pathlib import Path

import yaml

from sniff_test.analyzers import guarddog
from sniff_test.report import explain

ROOT = Path(__file__).resolve().parents[1]


def _semgrep_rule_ids() -> set[str]:
    out = set()
    for f in (ROOT / "rules").rglob("*.yaml"):
        for r in yaml.safe_load(f.read_text())["rules"]:
            if not r["id"].startswith("inv-"):
                out.add(r["id"])
    return out


def _analyzer_rule_ids() -> set[str]:
    """Rule ids written as literals in the analyzers and fetch code."""
    rx = re.compile(r'"((?:dep|repo|py|endpoint|scan|card|ha)-[a-z0-9-]+|possible-exfil)"')
    out = set()
    for f in (ROOT / "src" / "sniff_test").rglob("*.py"):
        if f.parent.name in ("analyzers", "fetch"):
            out.update(rx.findall(f.read_text()))
    out.discard("repo-signals")  # the analyzer's name, not a rule
    return out


def test_every_rule_has_plain_text():
    ids = _semgrep_rule_ids() | _analyzer_rule_ids()
    assert len(ids) > 50
    missing = sorted(i for i in ids if i not in explain.RULES)
    assert missing == []


def test_every_kept_guarddog_rule_has_plain_text():
    kept = [r.removeprefix("threat-") for r, sev in guarddog.SEVERITY.items() if sev]
    assert sorted(r for r in kept if r not in explain.GUARDDOG_WHAT) == []
    e = explain.explain("dep-guarddog-filesystem-autostart")
    assert e.title == "A code library it uses sets something up to start automatically"
    assert explain.explain("dep-guarddog-something-new").title.startswith("A code library")


def test_text_is_plain_and_complete():
    for rule, e in explain.RULES.items():
        assert e.title and e.means and e.worry and e.chip, rule
        assert len(e.chip) <= 28, rule
        assert not e.title.endswith("."), rule
        assert e.means.endswith(".") and e.worry.endswith("."), rule


def test_unknown_rule_falls_back():
    assert explain.explain("brand-new-rule").title == "Something worth knowing"


def test_can_do_counts_from_the_graph():
    report = {
        "graph": {
            "subject": "integration:x",
            "nodes": [
                {"id": "http_view:A", "kind": "http_view", "label": "A"},
                {"id": "http_view:B", "kind": "http_view", "label": "B"},
                {"id": "service:x.go", "kind": "service", "label": "x.go"},
                {"id": "data:recorder history", "kind": "data", "label": "recorder history"},
                {"id": "capability:HTTP client", "kind": "capability", "label": "HTTP client"},
                {"id": "package:pypi/a", "kind": "package", "label": "pypi/a"},
                {"id": "package:pypi/b", "kind": "package", "label": "pypi/b"},
            ],
            "edges": [
                {"source": "integration:x", "relation": "registers", "target": "http_view:A"},
                {"source": "integration:x", "relation": "registers", "target": "http_view:B"},
                {"source": "integration:x", "relation": "registers", "target": "service:x.go"},
                {"source": "integration:x", "relation": "reads", "target": "data:recorder history"},
                {"source": "integration:x", "relation": "uses", "target": "capability:HTTP client"},
                {
                    "source": "integration:x",
                    "relation": "depends_on",
                    "target": "package:pypi/a",
                    "attrs": {"ha_provided": True},
                },
                {
                    "source": "integration:x",
                    "relation": "depends_on",
                    "target": "package:pypi/b",
                    "attrs": {"ha_provided": False},
                },
            ],
        }
    }
    assert explain.can_do(report) == [
        "Adds 2 pages to your Home Assistant",
        "Adds an action you can use in automations",
        "Reads your history",
        "Makes web requests",
        "Uses 2 code packages (1 already part of Home Assistant)",
    ]
