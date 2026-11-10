"""Privacy notes are worked out from a stored report and never touch the score."""

from sniff_test.report import privacy

SUBJECT = "integration:x"


def _report(*edges, ports=()):
    nodes, out = [], []
    for host, attrs, line in edges:
        nodes.append({"id": f"host:{host}", "kind": "host", "label": host})
        out.append(
            {
                "source": SUBJECT,
                "relation": "connects_to",
                "target": f"host:{host}",
                "attrs": attrs,
                "samples": [{"file": "a.py", "line": line}],
            }
        )
    for port, line in ports:
        nodes.append({"id": f"port:{port}", "kind": "port", "label": str(port)})
        out.append(
            {
                "source": SUBJECT,
                "relation": "uses_port",
                "target": f"port:{port}",
                "attrs": {"names": ["mqtt_port"]},
                "samples": [{"file": "mqtt.py", "line": line}],
            }
        )
    return {"score": 100, "graph": {"subject": SUBJECT, "nodes": nodes, "edges": out}}


def _kinds(report):
    return [n.kind for n in privacy.notes(report)]


def test_telemetry_vs_other_developer_servers():
    r = _report(
        ("app-telemetry-worker.someone.workers.dev", {"class": "developer_hosted"}, 36),
        ("login-relay.someone.workers.dev", {"class": "developer_hosted"}, 9),
    )
    notes = privacy.notes(r)
    assert [n.kind for n in notes] == ["telemetry", "developer"]
    assert notes[0].hosts == ["app-telemetry-worker.someone.workers.dev"]
    assert notes[0].where == ["a.py:36"]


def test_telemetry_from_the_url_path():
    r = _report(
        (
            "x.someone.workers.dev",
            {"class": "developer_hosted", "urls": ["https://x.someone.workers.dev/ping"]},
            1,
        )
    )
    assert _kinds(r) == ["telemetry"]


def test_analytics_and_unencrypted():
    r = _report(
        ("o1.ingest.sentry.io", {"class": "analytics", "schemes": ["https"]}, 3),
        ("api.vendor.example", {"class": "declared", "schemes": ["http"]}, 4),
        ("docs.lib.example", {"class": "undeclared", "schemes": ["http", "https"]}, 7),
        ("192.168.1.2", {"class": "local", "schemes": ["http"]}, 5),  # home network
        ("github.com", {"class": "infrastructure", "schemes": ["http"]}, 6),  # docs link
    )
    notes = privacy.notes(r)
    assert [n.kind for n in notes] == ["analytics", "unencrypted"]
    assert notes[1].hosts == ["api.vendor.example"]


def test_mqtt_1883_only():
    assert _kinds(_report(ports=[(1883, 115)])) == ["mqtt"]
    assert _kinds(_report(ports=[(8883, 409)])) == []


def test_old_reports_without_graph_details():
    assert privacy.notes({"score": 90}) == []
