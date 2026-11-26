"""Privacy notes are worked out from a stored report and never touch the score."""

from sniff_test.report import privacy

SUBJECT = "integration:x"


def _report(*edges, ports=(), repo="someone/x"):
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
    return {
        "score": 100,
        "target": {"repo": repo},
        "graph": {"subject": SUBJECT, "nodes": nodes, "edges": out},
    }


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


def test_a_free_hosting_server_is_the_developers_only_with_evidence():
    """(0.15, his decision 2026-11-26) Real cases: a council's waste API and a parcel
    company's app backend on azurewebsites.net were called "the developer's server"."""
    dev = {"class": "developer_hosted"}
    council = privacy.notes(_report(("council-app-api-prod.azurewebsites.net", dev, 3),
                                    repo="someone/waste-days"))  # fmt: skip
    assert council == []  # no card, no claim: it's one of the other sites
    # the app's short name in a company's backend isn't evidence
    vendor = privacy.notes(_report(("acmedk-app-acme-prod.azurewebsites.net", dev, 3),
                                   repo="someone/ha-acme"))  # fmt: skip
    assert vendor == []
    # the whole repo name in the address is
    named = privacy.notes(_report(("homeassistant-acme-cars-worker.onrender.com", dev, 3),
                                  repo="someone/homeassistant-acme-cars"))  # fmt: skip
    assert [n.kind for n in named] == ["developer"]
    assert "developer's GitHub name or the repo's name" in named[0].means
    # a statistics-looking address without evidence keeps a note that names nobody
    tel = privacy.notes(_report(("acme-telemetry-worker.otherone.workers.dev", dev, 3)))
    assert [(n.kind, n.title) for n in tel] == [("telemetry", "Can send usage statistics")]
    assert "the developer" not in tel[0].means
    assert tel[0].unknown.startswith("Barkley can't tell who runs the server")


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
    # (his report 2026-11-21) one of its three internet sites: not "Unencrypted" outright
    assert notes[1].label == "Partly unencrypted"
    assert notes[1].title == "Reaches 1 of its 3 sites without encryption"
    assert notes[1].means.endswith("Its other sites are reached with encryption.")
    only = privacy.notes(_report(
        ("api.vendor.example", {"class": "declared", "schemes": ["http"]}, 4),
        ("ws.vendor.example", {"class": "undeclared", "schemes": ["ws"]}, 5),
        ("192.168.1.2", {"class": "local", "schemes": ["https"]}, 6),
    ))  # fmt: skip
    assert (only[0].label, only[0].title) == (
        "Unencrypted", "Uses unencrypted web addresses on the internet")  # fmt: skip


def test_mqtt_1883_only():
    assert _kinds(_report(ports=[(1883, 115)])) == ["mqtt"]
    assert _kinds(_report(ports=[(8883, 409)])) == []


def test_old_reports_without_graph_details():
    assert privacy.notes({"score": 90}) == []


# --- (0.14.0) one entry per usage-reporting address --------------------------------------------

HOST = "app-telemetry-worker.someone.workers.dev"


def _traced(
    rule, how="It can run on its own, but a condition in the code decides whether it does."
):
    r = _report((HOST, {"class": "developer_hosted"}, 36))
    sev = {"telemetry-usage": "info", "telemetry-opt-out": "low", "telemetry-shadow": "medium"}
    r["findings"] = [
        {
            "rule_id": rule,
            "severity": sev[rule],
            "message": f"Sends what looks like usage reporting to {HOST}. {how}",
            "evidence": f"{HOST} from async_maybe_ping",
            "file": "telemetry.py",
            "line": 246,
        }
    ]
    return r


def test_unscored_trace_is_folded_into_the_note():
    (n,) = privacy.notes(_traced("telemetry-usage"))
    assert n.kind == "telemetry" and n.hosts == [HOST]
    assert n.unknown.startswith("It can run on its own, but a condition")
    assert "Barkley can't tell what it sends." in n.unknown
    assert n.where[0] == "telemetry.py:246" and "a.py:36" in n.where


def test_scored_trace_replaces_the_note():
    for rule in ("telemetry-opt-out", "telemetry-shadow"):
        assert privacy.notes(_traced(rule)) == []


def test_trace_on_an_address_with_no_note_gets_one():
    r = _traced("telemetry-usage")
    r["graph"]["edges"][0]["attrs"] = {"class": "declared"}
    (n,) = privacy.notes(r)
    assert n.kind == "telemetry" and n.hosts == [HOST] and n.where == ["telemetry.py:246"]


def test_the_ai_is_told_who_runs_a_free_hosting_site_only_with_evidence():
    from sniff_test.report import ai_context

    mine = {"target": {"repo": "someone/quizgame"}}
    assert "most likely run by the developer" in ai_context._host_words(
        "developer_hosted", "quizgame-api.someone.workers.dev", mine
    )
    other = ai_context._host_words("developer_hosted", "council-api.azurewebsites.net", mine)
    assert "can't tell who runs it" in other and "run by the developer" not in other
