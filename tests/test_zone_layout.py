"""The address list on an app's page (ui.zones_html)."""

from __future__ import annotations


def test_a_host_name_is_never_squeezed_beside_a_long_port_list():
    """(0.14.1) "localhost" rendered one letter per line next to "http · port 1234, 8000,
    11434 unencrypted". (0.15) The name is alone on its line now; the ports are inside."""
    from sniff_test import ui

    rep = _graph_report([("localhost", "undeclared", ["http"], [1234, 8000, 11434], [])])
    html = ui.zones_html(rep)
    line = html.split("<summary>", 1)[1].split("</summary>", 1)[0]
    assert line == "<code>localhost</code>" and "port 1234, 8000, 11434" in html


def _graph_report(hosts, ports=()):
    """hosts: (name, class, schemes, ports, urls); ports: (port, direction)."""
    nodes, edges = [], []
    for i, (name, cls, schemes, nums, urls) in enumerate(hosts):
        nodes.append({"id": f"host:{name}", "kind": "host", "label": name})
        edges.append({"id": f"h{i:015x}", "source": "s", "relation": "connects_to",
                      "target": f"host:{name}", "samples": [{"file": "a.py", "line": i + 1}],
                      "attrs": {"class": cls, "schemes": schemes, "ports": nums,
                                "urls": urls}})  # fmt: skip
    for i, (port, direction) in enumerate(ports):
        edges.append({"id": f"p{i:015x}", "source": "s", "relation": "uses_port",
                      "target": f"port:{port}", "samples": [{"file": "b.py", "line": 1}],
                      "attrs": {"names": ["PORT"], "directions": [direction]}})  # fmt: skip
    return {"graph": {"subject": "s", "nodes": nodes, "edges": edges}}


def test_each_site_is_one_line_that_folds_open_with_its_details_inside():
    """(0.15, his decision 2026-11-20) one line per site; addresses, where and Explain fold
    open (script-free <details>); 5 per zone, then "N more"."""
    from sniff_test import ui

    hosts = [(f"s{i}.example.invalid", "undeclared", ["https"], [],
              [f"https://s{i}.example.invalid/api"]) for i in range(8)]  # fmt: skip
    html = ui.zones_html(_graph_report(hosts))
    assert html.count('<details class="site"') == 8 and "<script" not in html
    assert '<details class="more"><summary>3 more</summary>' in html
    first, rest = html.split('<details class="more">', 1)
    assert first.count('<details class="site"') == 5 and rest.count('<details class="site"') == 3
    assert "https://s0.example.invalid/api" in html and "In the code at a.py:1" in html
    assert 'id="item-h000000000000000"' in html  # where the AI sheet's Close goes back to


def test_explain_sits_inside_the_fold_and_its_sheet_outside():
    from sniff_test import ui

    calls = []

    def deep(item_id, part="both"):
        calls.append((item_id, part))
        return f"<{part}:{item_id}>"

    rep = _graph_report([("a.example.invalid", "undeclared", ["https"], [], [])],
                        [(1883, "out")])  # fmt: skip
    html = ui.zones_html(rep, deep, open_id="p000000000000000")
    for eid in ("h000000000000000", "p000000000000000"):
        inside = html.split(f'id="item-{eid}"', 1)[1].split("</details>", 1)[0]
        assert f"<inline:{eid}>" in inside
        assert f"<sheet:{eid}>" not in inside and html.count(f"<sheet:{eid}>") == 1
    assert 'id="item-p000000000000000" open>' in html  # the open reading's fold is open
    assert 'id="item-h000000000000000">' in html


def _row(i, ref, tv="logic-aaaaaaa1111"):
    from sniff_test.store import ScanRow

    return ScanRow(
        id=i,
        scanned_at="2026-11-18T22:00:00",
        repo="acme/view",
        source="acme/view",
        ref=ref,
        commit_sha=None,
        kind="integration",
        exposure="local",
        ha_version=None,
        tool_version=tv,
        complete=True,
        score=100,
        verdict="good",
    )


def test_history_says_older_release_when_an_older_version_is_sniffed_later():
    from sniff_test import ui

    html = ui.history_html("", 2, {}, [_row(1, "v2.4.1"), _row(2, "v2.4.0")])
    assert "an older release than v2.4.1" in html and "update v2.4.1 → v2.4.0" not in html
    html = ui.history_html("", 2, {}, [_row(1, "v2.4.0"), _row(2, "v2.4.1")])
    assert "update v2.4.0 → v2.4.1" in html


def test_the_cache_line_has_its_own_line():
    from sniff_test import ui

    line = ui.cache_text({"cache": {"files": 124, "hits": 124, "saved_secs": 159.6}})
    assert line.startswith('<p class="muted small">')
    assert "Barkley reused 124 of 124 files it had already read, which saved about 3 min." in line
    assert ui.cache_text({"cache": {"files": 124, "hits": 0, "saved_secs": 0}}) == ""
    assert ui.cache_text({}) == ""


def test_history_is_newest_first():
    from sniff_test import ui

    html = ui.history_html("", 3, {}, [_row(1, "v1.0.0"), _row(2, "v1.1.0"), _row(3, "v1.2.0")])
    assert html.index("v1.2.0</a>") < html.index("v1.1.0</a>") < html.index("v1.0.0</a>")
    assert "first check" in html.rsplit("<li>", 1)[1]


def test_the_exposure_box_lists_the_login_free_pages():
    from sniff_test import ui

    def view(i, file):
        return {"rule_id": "ha-unauth-view", "file": file, "line": i,
                "evidence": f"class Page{i}View(HomeAssistantView):"}  # fmt: skip

    rep = {"findings": [view(i, "a.py" if i < 3 else "b.py") for i in range(7)]
           + [{"rule_id": "ha-auth-token-check", "file": "a.py", "line": 1}]}  # fmt: skip
    html = ui.login_free_pages(rep)
    assert "The 7 pages:" in html
    assert "<code>Page0View</code>" in html and "<summary>2 more</summary>" in html
    assert html.count("the same file checks a signed link or token") == 3
    assert (
        ui.login_free_pages({"findings": [{**view(1, "x.py"), "evidence": "<b>"}]}).count("<code>")
        == 0
    )
    assert ui.login_free_pages({"findings": []}) == ""


def test_a_page_shows_its_address_when_the_scan_recorded_one():
    from sniff_test import ui

    base = {"rule_id": "ha-unauth-view", "file": "views.py", "line": 4,
            "evidence": "class TokenView(HomeAssistantView):"}  # fmt: skip
    html = ui.login_free_pages({"findings": [{**base, "page": "/api/acme/token"}]})
    assert "<code>/api/acme/token</code>" in html and "TokenView in views.py:4" in html
    html = ui.login_free_pages({"findings": [{**base, "page": ""}]})
    assert "<code>TokenView</code>" in html and "its address is built while the app runs" in html
    html = ui.login_free_pages({"findings": [{**base, "page": "<b>x</b>"}]})
    assert "<b>x</b>" not in html and "&lt;b&gt;x&lt;/b&gt;" in html
