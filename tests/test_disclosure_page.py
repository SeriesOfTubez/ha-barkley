"""(0.15) The developer's disclosure.yaml beside the scan, and the made-up Petal Garden.

tests/fixtures/petal_garden is a made-up integration whose disclosure.yaml is the spec's
published sample, with one planted difference: the code sends its usage statistics on a
timer without checking the "Share anonymous usage" option the file says it's behind. Its
hosts use the reserved .example domain; it's only ever scanned offline, never run.
"""

import re
from html import unescape
from pathlib import Path

import pytest

from sniff_test import readings, ui
from sniff_test.report import disclosed
from sniff_test.report.json_report import to_dict
from sniff_test.scanner import scan

FIXTURE = Path(__file__).parent / "fixtures" / "petal_garden"


@pytest.fixture(scope="module")
def petal():
    return to_dict(scan(str(FIXTURE), offline=True))


def _text(page: str, start: str) -> str:
    i = page.index(start)
    j = page.index("</section>", i)
    return re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", page[i:j])))


def test_the_fixture_only_names_reserved_hosts():
    hosts = set()
    for p in FIXTURE.rglob("*"):
        if p.is_file():
            hosts |= set(re.findall(r"[a-z0-9.-]+\.(?:[a-z]{2,})\b", p.read_text()))
    web = {h for h in hosts if h.rsplit(".", 1)[-1] in ("com", "net", "org", "io", "dev")}
    # the manifest's links to a made-up repo, and the spec's address in the sample's comment
    assert web <= {"github.com", "ha-barkley.github.io"}, web


def test_petal_garden_matches_its_file_but_for_the_planted_send(petal):
    assert petal["disclosure"]["state"] == "read"
    c = ui.disclosure_compare(petal)
    assert c.state == "read"
    assert {h: n.listed for h, n in c.hosts.items()} == {
        "api.petalgarden.example": True,
        "stats.petalgarden.example": True,
        "weather.petalgarden.example": True,
        "weather-eu.petalgarden.example": True,
    }
    assert not any(n.mismatch for n in c.hosts.values())
    assert c.unseen == []  # the map tiles' wildcard covers the card's tile host
    assert [x.said.split(".")[0] for x in c.set_by] == [
        "An address you enter at setup",
        "An address from the setting “custom_tile_url”",
    ]
    odd = [x for x in [*c.telemetry, *c.pages] if x.mismatch]
    assert [x.subject for x in odd] == ["stats.petalgarden.example"]
    assert "off until you turn on “Share anonymous usage”" in odd[0].said
    assert "sent automatically with no option around it" in odd[0].scan
    assert [(x.subject, x.mismatch) for x in c.pages] == [
        ("/api/petal_garden/zones", False),
        ("/api/webhook/", False),  # the scan's webhook
    ]


def test_the_file_never_changes_a_reading(petal):
    without = {k: v for k, v in petal.items() if k != "disclosure"}
    assert readings.compute(petal) == readings.compute(without)
    assert petal["score"] == to_dict(scan(str(FIXTURE), offline=True))["score"]


def test_the_page_shows_both_and_says_where_they_differ(petal):
    page = ui.render_app("", 1, petal, []).decode()
    text = _text(page, "What the developer")
    assert "It never changes the readings." in text
    assert "All 4 sites Barkley read a request to are in the file." in text
    assert "In 1 place the file and the scan don't match." in text
    assert "doesn't match" in text and "false" not in text.lower()
    assert "Barkley doesn't compare these with the scan yet." in text
    # the developer's words carry their tag; Barkley's carry the scan's
    assert page.count('<span class="src dev">The developer&#x27;s words · disclosure.yaml') >= 5
    assert "Run by Petal Garden." in unescape(page)  # beside the site in Where it connects


def _report(data=None, findings=(), hosts=(), state="read", problems=()):
    nodes = [{"id": f"host:{h}", "kind": "host", "label": h} for h, _ in hosts]
    edges = [
        {"id": h, "source": "integration:x", "relation": "connects_to", "target": f"host:{h}",
         "samples": [], "attrs": {"class": "undeclared", "schemes": list(s)}}
        for h, s in hosts
    ]  # fmt: skip
    disc = {"state": state, "data": data or {}} if state == "read" else {
        "state": state, "problems": list(problems)}  # fmt: skip
    return {
        "target": {"repo": "someone/x", "kind": "integration"},
        "score": 100,
        "complete": True,
        "findings": list(findings),
        "graph": {"subject": "integration:x", "nodes": nodes, "edges": edges},
        "disclosure": disc,
    }


def test_each_kind_of_difference():
    tel = {"rule_id": "telemetry-shadow", "evidence": "t.example from ping",
           "message": "Sends what looks like usage reporting to t.example."}  # fmt: skip
    page = {"rule_id": "ha-unauth-view", "page": "/api/x/open"}
    data = {
        "connections": [
            {"destination": "plain.example", "source": "home_assistant", "purpose": "p",
             "when": "always", "encrypted": "always"},
            {"destination": "*.cdn.example", "source": "browser", "purpose": "q", "when": "always"},
            {"destination": "gone.example", "source": "home_assistant", "purpose": "r",
             "when": "always"},
        ],
        "links": [{"url": "https://help.example/start"}],
        "telemetry": [],
        "pages": [],
    }  # fmt: skip
    hosts = (("plain.example", ["http"]), ("a.cdn.example", ["https"]),
             ("help.example", ["https"]), ("cdn.example", ["https"]),
             ("new.example", ["https"]))  # fmt: skip
    r = _report(data, [tel, page], hosts)
    c = disclosed.compare(r, {h: set(s) for h, s in hosts}, {h for h, _ in hosts})
    assert "always encrypted" in c.hosts["plain.example"].mismatch
    assert c.hosts["a.cdn.example"].listed and not c.hosts["a.cdn.example"].mismatch
    assert not c.hosts["cdn.example"].listed  # *.cdn.example covers subdomains only
    assert "only as a link" in c.hosts["help.example"].mismatch
    assert not c.hosts["new.example"].listed
    assert [x.subject for x in c.unseen] == ["gone.example"]
    assert c.telemetry[0].mismatch and "sends no usage statistics" in c.telemetry[0].said
    assert c.pages[0].mismatch and "adds no page that opens without a login" in c.pages[0].said


def test_a_missing_section_is_not_stated_and_never_compared():
    tel = {"id": "t1", "rule_id": "telemetry-shadow", "severity": "medium", "title": "T",
           "message": "Sends usage reporting.", "evidence": "t.example from ping",
           "file": "a.py", "line": 1, "category": "endpoint"}  # fmt: skip
    r = _report({"credentials": []}, [tel], (("t.example", ["https"]),))
    c = ui.disclosure_compare(r)
    assert c.hosts == {} and c.telemetry == [] and c.pages == []
    text = _text(ui.render_app("", 1, r, []).decode(), "What the developer")
    assert "says nothing about connections, telemetry, pages" in text


def test_an_ignored_file_says_why_and_a_threat_page_hides_the_words():
    r = _report(state="ignored", problems=["telemetry[0].on_by_default: missing"])
    text = _text(ui.render_app("", 1, r, []).decode(), "What the developer")
    assert "doesn't follow version 1 of the spec" in text and "on_by_default: missing" in text
    r = _report({"connections": [{"destination": "a.example", "source": "browser",
                                  "purpose": "SECRET-PURPOSE", "when": "always"}]})  # fmt: skip
    html = ui.disclosure_html(r, dev_ok=False)
    assert "SECRET-PURPOSE" not in html and "doesn't show the developer's words" in html


def test_the_developers_words_are_escaped():
    r = _report({"connections": [{"destination": "a.example", "source": "browser",
                                  "purpose": "<script>alert(1)</script>", "when": "always"}]},
                hosts=(("a.example", ["https"]),))  # fmt: skip
    page = ui.render_app("", 1, r, []).decode()
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page


def test_no_file_no_section():
    r = _report()
    r.pop("disclosure")
    assert ui.disclosure_html(r) == ""
