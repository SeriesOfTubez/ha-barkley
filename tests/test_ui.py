"""The panel's pages: escaping, honest wording, flow lines only for real flows."""

from test_store import FINDING, report

from sniff_test import ui

HOSTILE = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
SUBJECT = "integration:acme"


def _with(rep, nodes=(), edges=()):
    rep["graph"]["nodes"] += list(nodes)
    rep["graph"]["edges"] += list(edges)
    return rep


def _edge(rel, target, attrs=None, evidence="possible", source=SUBJECT, line=3):
    return {
        "id": target,
        "source": source,
        "relation": rel,
        "target": target,
        "evidence": evidence,
        "count": 1,
        "samples": [{"file": "a.py", "line": line}],
        "finding_ids": [],
        "attrs": attrs or {},
    }


def test_hostile_text_is_escaped_in_every_section():
    host = f"host:{HOSTILE}"
    rep = _with(
        report(findings=[{**FINDING, "file": HOSTILE, "evidence": HOSTILE}]),
        nodes=[{"id": host, "kind": "host", "label": HOSTILE}],
        edges=[
            _edge("connects_to", host, {"class": "developer_hosted", "urls": [HOSTILE]}),
            _edge("uses_port", "port:1883", {"names": [HOSTILE]}),
        ],
    )
    page = ui.render_app("", 1, rep, []).decode()
    assert "<script>" not in page and "<img" not in page
    assert "&lt;script&gt;" in page


def test_no_flow_lines_without_flows():
    svg = ui.flow_svg(report(), "acme")
    assert "<path d=" not in svg.replace('<path d="M0,0', "")
    assert "No path found" in svg or "names no network addresses" in svg


def test_flow_lines_follow_the_graph():
    src, off = "data:secrets.yaml", "network:off-box (destination not visible statically)"
    rep = _with(
        report(),
        nodes=[
            {"id": src, "kind": "data", "label": "secrets.yaml"},
            {"id": off, "kind": "network", "label": "off-box (destination not visible statically)"},
        ],
        edges=[_edge("reads", src), _edge("flows_to", off, evidence="proven", source=src)],
    )
    svg = ui.flow_svg(rep, "acme")
    assert svg.count('marker-end="url(#arr)"') == 1  # the wide layout
    assert svg.count('marker-end="url(#arrv)"') == 1  # the stacked one for phones
    assert "Somewhere off your box" in svg and "Your secrets file" in svg
    assert 'stroke-dasharray="6 4"' not in svg  # proven: solid


def test_ports_alone_never_claim_a_home_network():
    rep = _with(
        report(),
        nodes=[{"id": "port:502", "kind": "port", "label": "502"}],
        edges=[_edge("uses_port", "port:502", {"names": ["DEFAULT_MODBUS_PORT"]})],
    )
    rep["graph"]["edges"] = [e for e in rep["graph"]["edges"] if e["relation"] != "connects_to"]
    text = ui.connection_sentence(rep) + ui.in_short(rep)
    assert "home network" not in text
    assert "port 502 (Modbus)" in text


def test_bands():
    assert [ui.band(s) for s in (100, 90, 89, 70, 69, 40, 39, 0)] == [
        "green", "green", "yellow", "yellow", "orange", "orange", "red", "red"
    ]  # fmt: skip
    assert ui.band(95, complete=False) == "grey" and ui.band(None) == "grey"
