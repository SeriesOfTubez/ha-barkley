"""The report's `graph` section: shape, stable ids, evidence levels, never scored."""

from sniff_test.report.graph import edge_id
from sniff_test.report.json_report import to_dict
from sniff_test.scanner import scan

LEVELS = {"declared", "possible", "proven", "observed"}


def _graph(fixtures, name):
    return to_dict(scan(str(fixtures / name), offline=True))["graph"]


def _edges(g):
    return {(e["source"], e["relation"], e["target"]): e for e in g["edges"]}


def test_every_fixture_has_a_sensible_graph(fixtures):
    for name in ("evil_integration", "evil_card", "clean_integration"):
        g = _graph(fixtures, name)
        ids = {n["id"] for n in g["nodes"]}
        assert g["subject"] in ids
        for e in g["edges"]:
            assert e["evidence"] in LEVELS
            assert e["source"] in ids and e["target"] in ids
            assert e["id"] == edge_id(e["source"], e["relation"], e["target"])
            assert e["count"] >= 1 and len(e["samples"]) <= 3
            assert not e["target"].endswith(":*") or e["relation"] == "calls"


def test_clean_integration_graph(fixtures):
    g = _graph(fixtures, "clean_integration")
    s = "integration:acme_weather"
    edges = _edges(g)
    assert edges[(s, "connects_to", "host:api.acme-weather.example")]["evidence"] == "declared"
    assert (s, "registers", "service:acme_weather.refresh") in edges
    assert (s, "registers", "http_view:AcmeStatusView") in edges
    assert edges[(s, "depends_on", "package:pypi/aiohttp")]["evidence"] == "declared"
    assert not any(r == "flows_to" for _, r, _ in edges)


def test_evil_integration_flows(fixtures):
    edges = _edges(_graph(fixtures, "evil_integration"))
    off_box = "network:off-box (destination not visible statically)"
    # proven: the hass.auth read shares a function with the taint sink
    assert edges[("auth:users and tokens", "flows_to", off_box)]["evidence"] == "proven"
    # possible: the split read (helpers.py) to the undeclared host, via the correlation
    e = edges[("data:secrets.yaml", "flows_to", "host:weather-cdn.invalid")]
    assert e["evidence"] == "possible" and e["finding_ids"]
    # the proven source is not also drawn as a merely possible flow
    assert ("auth:users and tokens", "flows_to", "host:weather-cdn.invalid") not in edges


def test_evil_card_graph(fixtures):
    edges = _edges(_graph(fixtures, "evil_card"))
    off_box = "network:off-box (destination not visible statically)"
    assert edges[("auth:stored HA tokens", "flows_to", off_box)]["evidence"] == "proven"
    assert (
        edges[("card:evil_card", "bundles", "package:npm/event-stream")]["evidence"] == "declared"
    )
    assert edges[("card:evil_card", "registers", "custom_element:custom elements")]["attrs"] == {
        "values": ["totally-legit-card"]
    }


def test_graph_never_changes_the_score(fixtures, monkeypatch):
    from sniff_test.report import graph

    base = scan(str(fixtures / "clean_integration"), offline=True)
    monkeypatch.setattr(graph, "build", lambda scan: {})
    again = scan(str(fixtures / "clean_integration"), offline=True)
    assert base.score.score == again.score.score and base.score.deductions == again.score.deductions
