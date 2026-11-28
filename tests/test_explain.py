"""Plain-English text: every rule the scanner can produce has hand-written text."""

import re
from pathlib import Path

import yaml

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
    rx = re.compile(
        r'"((?:dep|repo|py|endpoint|scan|card|ha|packed)-[a-z0-9-]+'
        r'|possible-exfil|changes-other-app)"'
    )
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


def test_text_is_plain_and_complete():
    for rule, e in explain.RULES.items():
        assert e.title and e.means and e.worry and e.chip, rule
        assert len(e.chip) <= 28, rule
        assert not e.title.endswith("."), rule
        assert e.means.endswith(".") and e.worry.endswith("."), rule


def test_unknown_rule_falls_back():
    assert explain.explain("brand-new-rule").title == "Barkley found something"


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


def test_the_unread_file_rule_has_plain_text():
    # its id is a constant in models, so the literal sweep above doesn't see it
    from sniff_test.models import RULE_FILE_NOT_CHECKED

    assert "89" in explain.RULES[RULE_FILE_NOT_CHECKED].worry


def test_own_storage_is_described_not_judged():
    """(0.14.0) HA has no docs page for the Store helper: the text says what the code
    does and links the helper's source and the 2022 post, and claims no HA guidance."""
    from sniff_test import ui

    ex = explain.explain("ha-own-storage-path")
    assert [u for _, u in ex.links] == [
        "https://github.com/home-assistant/core/blob/dev/homeassistant/helpers/storage.py",
        "https://contributors.home-assistant.io/blog/2022/07/08/generic-store/",
    ]
    text = f"{ex.title} {ex.means} {ex.worry}".lower()
    assert "poor practice" not in text and "recommend" not in text
    html = ui._links_html(ex.links)
    assert html.count('rel="noopener noreferrer"') == 2 and "Read more" in html
    assert ui._links_html((("x", "http://example.invalid/"),)) == ""


def test_no_rule_text_claims_home_assistant_guidance():
    """Never claim HA recommends something unless its docs or code say so (a link)."""
    for rid, ex in explain.RULES.items():
        text = f"{ex.means} {ex.worry}".lower()
        if "home assistant recommends" in text or "poor practice" in text:
            assert ex.links, rid


def test_library_titles_read_naturally():
    import itertools

    """(0.14.0, the user's report) "A code library it uses uses code that's hard to read"."""
    for key in explain.GUARDDOG_WHAT:
        title = explain.explain(f"dep-guarddog-{key}").title
        words = title.lower().split()  # no "uses uses"
        assert all(a != b for a, b in itertools.pairwise(words)), title
