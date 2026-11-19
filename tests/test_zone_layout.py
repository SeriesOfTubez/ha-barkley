"""The address list on an app's page (ui.zones_html)."""

from __future__ import annotations


def test_a_host_name_is_never_squeezed_beside_a_long_port_list():
    """(0.14.1) "localhost" rendered one letter per line next to "http · port 1234, 8000,
    11434 unencrypted": the row now wraps, the name keeps its width, the ports wrap."""
    from sniff_test import ui

    assert ".zone li > div { display:flex; flex-wrap:wrap;" in ui.CSS
    assert (
        ".zone li > div > code { flex:0 0 auto; max-width:100%; overflow-wrap:anywhere; }" in ui.CSS
    )
    assert "white-space:nowrap" not in ui.CSS.split(".zone .p {", 1)[1].split("}", 1)[0]


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
    assert line.startswith('<p class="facts">')
    assert "124 of 124 files from the cache of code already read, about 3 min saved" in line
    assert ui.cache_text({"cache": {"files": 124, "hits": 0, "saved_secs": 0}}) == ""
    assert ui.cache_text({}) == ""


def test_history_is_newest_first():
    from sniff_test import ui

    html = ui.history_html("", 3, {}, [_row(1, "v1.0.0"), _row(2, "v1.1.0"), _row(3, "v1.2.0")])
    assert html.index("v1.2.0</a>") < html.index("v1.1.0</a>") < html.index("v1.0.0</a>")
    assert "first check" in html.rsplit("<li>", 1)[1]
