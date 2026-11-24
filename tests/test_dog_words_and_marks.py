"""(his decisions 2026-11-23) The dog words follow both readings; an item that adds to
Exposure is marked; a site code comes from is listed with the sites it connects to; the
"leaves your home" label follows the grey lines only. Made-up reports; every site is
.invalid."""

from __future__ import annotations

from sniff_test import does, readings, ui


def test_good_boy_needs_low_exposure_and_a_threat_decides_first() -> None:
    def line(t: str, x: str) -> str:
        return ui.verdict_line({"threat_level": t, "exposure_level": x})

    assert line("none", "low").startswith("🦴 Good Boy · ")
    assert line("none", "medium").startswith("🐾 Needs training · ")
    assert line("none", "high").startswith("🦮 Needs a leash · ")
    assert all(line("possible", x).startswith("🐕 Grrrrr · ") for x in ("low", "high"))
    assert line("found", "low").startswith("🚨 BORK BORK BORK · ")
    assert "Sus" not in "".join(line(t, x) for t in ("none", "possible", "found")
                                for x in ("low", "medium", "high"))  # fmt: skip
    assert ui.readings_band({"threat_level": "none", "exposure_level": "medium"}) == "yellow"


def test_what_counts_in_exposure() -> None:
    def f(rule: str, sev: str = "medium") -> dict:
        return {"rule_id": rule, "severity": sev, "file": "a.js", "line": 1}

    assert readings.counts_in_exposure(f("card-remote-script"))
    assert readings.counts_in_exposure(f("card-remote-pinned"))
    assert readings.counts_in_exposure(f("py-lua-download"))
    assert readings.counts_in_exposure(f("ha-unauth-view"))
    assert readings.counts_in_exposure(f("dep-vuln", "high"))
    assert not readings.counts_in_exposure(f("dep-vuln", "low"))  # adds nothing
    assert not readings.counts_in_exposure(f("ha-service-register"))


def _sites(*hosts: str) -> dict:
    edges = [{"id": f"h{i:015x}", "source": "s", "relation": "connects_to",
              "target": f"host:{h}", "samples": [{"file": "c.js", "line": i + 1}],
              "attrs": {"class": "undeclared", "schemes": ["https"],
                        "urls": [f"https://{h}/x"]}} for i, h in enumerate(hosts)]  # fmt: skip
    nodes = [{"id": f"host:{h}", "kind": "host", "label": h} for h in hosts]
    return {"graph": {"subject": "s", "nodes": nodes, "edges": edges},
            "requests": {"sites": {}}}  # fmt: skip


def test_a_site_code_comes_from_is_listed_where_it_connects() -> None:
    rep = _sites("cdn.example.invalid", "pinned.example.invalid", "docs.example.invalid")
    rep["findings"] = [
        {"rule_id": "card-remote-script", "severity": "medium", "file": "c.js", "line": 1,
         "evidence": "https://cdn.example.invalid/npm/thing@latest/x.js"},
        {"rule_id": "card-remote-pinned", "severity": "low", "file": "c.js", "line": 2,
         "evidence": "import('https://pinned.example.invalid/x@1.2.3/x.js')"},
    ]  # fmt: skip
    connects = ui.zones_html(rep, part="connects")
    other = ui.zones_html(rep, part="mentioned")
    assert "<code>cdn.example.invalid</code>" in connects
    assert "<code>pinned.example.invalid</code>" in connects
    assert "cdn.example.invalid" not in other and "docs.example.invalid" in other
    assert ('<span class="u codeload">Loads code from here that runs in your dashboard, '
            "with your login.") in connects  # fmt: skip
    assert "Loads a fixed version of code from here" in connects


def test_lua_sites_say_what_they_send() -> None:
    rep = _sites("lua.example.invalid", "api.example.invalid")
    run = {"file": "rt.py", "line": 5, "source": "downloaded",
           "from": [{"kind": "site", "detail": "lua.example.invalid"}]}  # fmt: skip
    rep["lua"] = {"runtimes": [], "runs": [run]}
    assert "Sends Lua code that the app runs" in ui.zones_html(rep, part="connects")
    run["from"] = [{"kind": "answer", "detail": "url", "site": "api.example.invalid"}]
    html = ui.zones_html(rep, part="connects")
    assert "Its answer gives the address of Lua code" in html


def test_the_leaves_your_home_label_follows_the_grey_lines_only() -> None:
    m = does.build({"target": {"kind": "plugin"}, "findings": [
        {"rule_id": "card-remote-script", "severity": "medium", "file": "c.js", "line": 3,
         "evidence": "https://cdn.example.invalid/npm/thing@latest/x.js"}]}, "Card")  # fmt: skip
    assert m.code_only == {0}
    assert "leaves your home" not in does.wide(m)  # only code comes in: nothing leaves
    assert "svg.does .cross { fill:var(--muted); font-size:12px; paint-order:stroke;" in ui.CSS


def test_an_item_that_adds_to_exposure_says_so_and_links_up() -> None:
    f = {"id": "f1", "rule_id": "card-remote-script", "severity": "medium", "file": "c.js",
         "line": 3, "title": "Card loads code", "message": "m"}  # fmt: skip
    html = ui.finding_html(f, [f], 0, context=True, counts=True)
    assert '<a class="chip expo" href="#exposure">Counts in Exposure</a></h3>' in html
    assert "Counts in Exposure" not in ui.finding_html(f, [f], 0, context=True)
