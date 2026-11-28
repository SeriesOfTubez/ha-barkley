"""The panel's pages: escaping, honest wording, flow lines only for real flows."""

from html import unescape

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


def test_diff_changes_read_as_plain_english():
    """The diff page used to print raw edges and rule ids; each change kind now reads as a
    sentence, rule ids become their titles, and the raw text stays under the details."""
    cases = [
        ({"kind": "new_finding", "sign": "+", "severity": "high", "rank": 90,
          "text": "Reads secrets.yaml (diagnostics.py)", "detail": {"rule_id": "ha-read-secrets"}},
         "Serious", "Reads your secrets"),
        ({"kind": "new_flow", "sign": "+", "severity": "high", "rank": 85,
          "text": "possible: secrets.yaml → status.weather-mirror.invalid · possible-exfil",
          "detail": {"source": "data:secrets.yaml",
                     "targets": ["host:status.weather-mirror.invalid"], "evidence": "possible"}},
         "Serious", "reads your secrets file and can reach status.weather-mirror.invalid"),
        ({"kind": "new_flow", "sign": "+", "severity": "critical", "rank": 100,
          "text": "proven: user's access token → evil.invalid · card-token-exfil",
          "detail": {"source": "auth:user's access token", "targets": ["host:evil.invalid"],
                     "evidence": "proven"}},
         "Danger", "Barkley traced your HA login being sent to evil.invalid"),
        ({"kind": "new_host", "sign": "+", "rank": 70,
          "text": "undeclared: status.weather-mirror.invalid (const.py:4)",
          "detail": {"target": "host:status.weather-mirror.invalid", "class": "undeclared"}},
         "New", "not linked from the app's own files"),
        ({"kind": "new_package", "sign": "+", "rank": 45, "text": "depends on requests 2.32.0",
          "detail": {"target": "package:pypi/requests", "attrs": {}}},
         "New", "A new dependency"),
        ({"kind": "removed_host", "sign": "-", "rank": 3, "text": "declared: api.old.invalid",
          "detail": {"target": "host:api.old.invalid", "relation": "connects_to"}},
         "Gone", "No longer names the site"),
        ({"kind": "package_version", "sign": "~", "rank": 8, "text": "pyyaml 6.0 → 6.0.2",
          "detail": {"target": "package:pypi/pyyaml", "from": "6.0", "to": "6.0.2"}},
         "Changed", "goes from 6.0 to 6.0.2"),
        ({"kind": "new_publisher", "sign": "+", "rank": 60, "severity": "medium",
          "text": "mallory published v2, and published none of the 12 release(s) up to v1 "
                  "(alice 12)",
          "detail": {}},
         "Check this", "A new publisher"),
        ({"kind": "install_source", "sign": "~", "rank": 30,
          "text": "installed from release_asset → tag_source", "detail": {}},
         "Changed", "now installs the tagged source"),
    ]  # fmt: skip
    for change, lead, phrase in cases:
        got_lead, html, raw = ui.change_line(change)
        assert got_lead == lead, (change["kind"], got_lead)
        assert phrase in unescape(html), (change["kind"], html)
        assert raw == change["text"]
        for rid in ("ha-read-secrets", "possible-exfil", "card-token-exfil"):
            assert rid not in html, (change["kind"], html)
    hostile = {"kind": "new_host", "sign": "+", "rank": 70, "text": f"undeclared: {HOSTILE}",
               "detail": {"target": f"host:{HOSTILE}", "class": "undeclared"}}  # fmt: skip
    assert "<script>" not in ui.change_line(hostile)[1]


def test_usage_trace_shows_once_as_a_privacy_note():
    """(0.14.0, the user's report) The same send showed as a privacy note and as an FYI."""
    h = "app-telemetry-worker.someone.workers.dev"
    tel = {
        **FINDING,
        "id": "t1",
        "rule_id": "telemetry-usage",
        "severity": "info",
        "title": "Can send usage data to the developer",
        "message": f"Sends what looks like usage reporting to {h}. It runs when you use the app.",
        "evidence": f"{h} from async_ping",
        "file": "telemetry.py",
        "line": 246,
    }
    rep = _with(
        report(findings=[tel]),
        nodes=[{"id": f"host:{h}", "kind": "host", "label": h}],
        edges=[_edge("connects_to", f"host:{h}", {"class": "developer_hosted", "urls": []})],
    )
    page = ui.render_app("", 1, rep, []).decode()
    # (0.15) no owner or repo name in the address: the note doesn't say who runs it
    assert page.count("<h3>Can send usage statistics</h3>") == 1
    assert "to the developer" not in page
    assert "Can send usage data to the developer" not in page
    assert "It runs when you use the app." in page


def test_where_it_connects_claims_only_what_the_scan_shows():
    """(0.15, his decision 2026-11-26) A site whose name only matches the app's has a
    group of its own that names nobody, and a free-hosting site is "the developer's"
    only with the owner's or the repo's name in it; the readings never move."""
    sites = {
        "api.acme.example": {"class": "declared", "declared_by": "name"},
        "docs.acme-docs.example": {"class": "declared", "declared_by": "files"},
        "quizgame-api.acme.workers.dev": {"class": "developer_hosted"},  # owner "acme"
        "council-api-prod.azurewebsites.net": {"class": "developer_hosted"},
    }
    rep = _with(
        report(repo="acme/acme"),
        nodes=[{"id": f"host:{h}", "kind": "host", "label": h} for h in sites],
        edges=[_edge("connects_to", f"host:{h}", a) for h, a in sites.items()],
    )
    zones = {h.name: h.zone for h in ui.hosts(rep)}
    assert zones == {
        "api.acme.example": "named",
        "docs.acme-docs.example": "own",
        "quizgame-api.acme.workers.dev": "dev",
        "council-api-prod.azurewebsites.net": "other",
    }
    page = unescape(ui.render_app("", 1, rep, []).decode())
    for title in ("Sites its files link to", "Sites named like the app",
                  "Servers the developer runs", "Other sites"):  # fmt: skip
        assert f"{title}</h3>" in page
    assert "The app's own sites" not in page
    assert "Barkley can't tell who runs them" in page
    # In short counts only the sites its own files link to
    assert "1 of them is linked from the app's own files or GitHub." in page
    # an older scan (no declared_by) keeps its sites in the first group
    assert ui.Host("api.acme.example", "declared").zone == "own"
