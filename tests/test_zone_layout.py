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
