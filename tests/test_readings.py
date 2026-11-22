"""(preview) The proposed Threat and Exposure readings (readings.py): the agreed points,
shown only when Settings → Proposed readings is on, never stored and never instead of
Barkley's own score."""

from __future__ import annotations

import json

from sniff_test import readings, server, settings, ui
from sniff_test.store import Store


def f(rule: str, sev: str = "high", file: str = "a.py", **kw) -> dict:
    n = kw.pop("n", 0)
    return {"id": f"{rule}-{file}-{n}", "rule_id": rule, "severity": sev, "file": file,
            "line": 1, "title": rule, "message": "", **kw}  # fmt: skip


def rep(*findings: dict, exposure: str = "local", complete: bool = True) -> dict:
    return {"findings": list(findings), "exposure": exposure, "complete": complete}


def test_no_findings_is_nothing_on_either_reading():
    r = readings.compute(rep())
    assert (r.threat, r.threat_level, r.exposure, r.exposure_level) == (0, "none", 0, "low")
    assert r.exposure_reasons == []


def test_powerful_uses_alone_are_no_threat():
    """The #19 case: changing users and handling tokens is what an app does, not malice."""
    r = readings.compute(rep(f("ha-auth-change-users"), f("ha-auth-internals")))
    assert r.threat == 0 and r.threat_level == "none"
    # a token it may hand out: one non-administrator token, lifetime unknown (x 1.25)
    assert r.exposure == 1.25 and r.exposure_level == "low"
    assert "only as safe as that machine" in r.exposure_reasons[0]


def test_pages_without_a_login_count_by_the_check_barkley_can_see():
    # the strongest page in full, each further one a quarter (his decision 2026-11-20)
    own = [f("ha-unauth-view", "low", "views.py", n=i) for i in range(6)]
    assert readings.compute(rep(*own)).exposure == 1.69  # 0.75 + 5 x 0.1875
    signed = [f("ha-unauth-view", "low", "whep.py", n=i) for i in range(4)]
    r = readings.compute(rep(*signed, f("ha-auth-token-check", "low", "whep.py")))
    assert r.exposure == 0.44  # 0.25 + 3 x 0.0625
    assert r.exposure_reasons[0] == (
        "4 pages open without logging in to Home Assistant. They check a signed link or token "
        "instead."
    )
    one = readings.compute(rep(signed[0], f("ha-auth-token-check", "low", "whep.py")))
    assert "Assistant. It checks a signed link" in one.exposure_reasons[0]


def test_many_pages_of_one_app_stay_below_high_at_home():
    """Issue #26's shape: an OAuth integration with 12 login-free pages (callbacks and
    webhooks) used to sum to 9 by pages alone."""
    own = [f("ha-unauth-view", "low", f"oauth{i}.py") for i in range(12)]
    r = readings.compute(rep(*own))
    assert r.exposure == 2.81 and r.exposure_level == "medium"  # 0.75 + 11 x 0.1875


def test_a_page_barkley_can_confirm_counts_less_than_one_it_cannot():
    mixed = [
        f("ha-unauth-view", "low", "whep.py"),
        f("ha-auth-token-check", "low", "whep.py"),
        f("ha-unauth-view", "low", "panel.py"),
    ]
    assert readings.compute(rep(*mixed)).exposure == 0.81  # 0.75 in full + 0.25 x 0.25


def test_the_network_raises_exposure_and_public_raises_it_most():
    own = [f("ha-unauth-view", "low", "v.py", n=i) for i in range(12)]
    assert readings.compute(rep(*own), "shared").exposure == 3.52  # 2.8125 x 1.25, rounded
    assert readings.compute(rep(*own), "shared").exposure_level == "medium"
    pub = readings.compute(rep(*own, exposure="public"), "home")
    assert pub.exposure == 4.22 and pub.network == "internet"
    assert readings.compute(rep(*own), "nonsense").network == "home"


def test_library_bugs_by_severity():
    r = readings.compute(rep(f("dep-vuln", "medium", n=1), f("dep-vuln", "high", n=2)))
    assert r.exposure == 4.0 and r.exposure_level == "medium"


def test_a_critical_sign_is_found_and_exposure_is_the_maximum():
    r = readings.compute(rep(f("card-token-exfil", "critical", "c.js")))
    assert r.threat == 7.0 and r.threat_level == "found"  # 6, raised to the floor of 7
    assert r.exposure == 10 and r.exposure_level == "high"
    assert r.threat_reason == "may send your login token to another site"


def test_threat_points_repeat_at_a_quarter_and_cap_at_ten():
    two = readings.compute(rep(f("card-hidden-name", n=1), f("card-hidden-name", n=2)))
    assert two.threat == 3.12 and two.threat_level == "possible"  # 2.5 + 0.625
    many = [f("ha-exfil-taint", "critical", n=1), f("py-b64-exec", "critical", n=2),
            f("possible-exfil", n=3), f("dep-typosquat", n=4)]  # fmt: skip
    assert readings.compute(rep(*many)).threat == 10


def test_a_possible_sign_says_so_first_and_keeps_its_exposure():
    r = readings.compute(rep(f("dep-typosquat"), f("ha-unauth-view", "low", "v.py")))
    assert r.threat_level == "possible" and r.exposure == 0.75
    assert r.exposure_reasons[0].startswith("This may be a sign of malicious behavior")


def test_lifetime_buckets_are_multipliers():
    got = [readings.lifetime_factor(d) for d in (0.5, 7, 90, 300, 3650, None)]
    assert got == [0.0, 0.5, 0.75, 1.0, 1.25, 1.25]


def test_where_home_assistant_runs_is_one_choice_stored_as_two_values():
    """(0.15) Home, shared or work network, or reachable from the internet (exposure
    "public", which new scans also use)."""
    d = settings.DEFAULTS
    assert (d.where, d.exposure, d.network, d.show_minor) == ("home", "local", "home", False)
    s = settings.from_dict({"where": "shared"})
    assert (s.where, s.exposure, s.network) == ("shared", "local", "shared")
    s = settings.from_dict({"where": "internet"}, s)
    assert (s.where, s.exposure) == ("internet", "public")
    assert settings.from_dict({"where": "the moon"}, s) == s
    assert settings.from_dict({"network": "internet"}).network == "home"  # not a choice
    assert settings.PARTS["readings"] == (
        "exposure",
        "network",
        "show_minor",
        "quiet_months",
        "exposure_bar",
    )
    assert settings.from_dict({"quiet_months": "24"}).quiet_months == 24
    assert settings.from_dict({"quiet_months": "7"}).quiet_months == 12  # not a choice
    assert not hasattr(d, "preview") and not hasattr(d, "paranoid")


def _panel(tmp_path, report: dict) -> tuple[server.Panel, int]:
    store = Store(tmp_path / "s.db")
    sid = store.save(report)
    return server.Panel(store, lambda r, f: {}, None), sid


def _report() -> dict:
    return {
        "target": {"repo": "someone/an-app", "kind": "integration", "ref": "v1"},
        "exposure": "local", "complete": True, "score": 50,
        "verdict": {"key": "very_sus", "label": "Very Sus"},
        "findings": [f("ha-auth-change-users"), f("ha-auth-internals")],
        "score_breakdown": [], "caps_applied": [], "tool": {"version": "x"}, "schema_version": 1,
    }  # fmt: skip


def test_the_panel_always_adds_the_readings_and_never_stores_them(tmp_path):
    panel, sid = _panel(tmp_path, _report())
    shown = panel.shown_report(sid)
    assert shown["readings"]["exposure"] == 1.25
    assert shown["score"] == 50  # Barkley's own score is unchanged
    assert "readings" not in panel.report(sid)  # the stored report never has them
    assert "readings" not in json.dumps(panel.store.report(sid))


def test_the_page_shows_the_readings_and_no_score(tmp_path):
    """(0.15) the sniff report is the only view; the 0-100 score leaves the panel."""
    panel, sid = _panel(tmp_path, _report())
    on = ui.render_app("", sid, panel.shown_report(sid), []).decode()
    assert 'aria-label="Exposure 1.25 of 10"' in on and "<h2>Exposure <span" in on
    assert "Barkley found nothing that sends your data off your Home Assistant machine" in on
    assert "What Barkley found" not in on
    assert "of 100" not in on and "Very Sus" not in on and "Powerful" not in on
    assert "Good Boy · no signs of malicious behavior" in on
    assert "banner threat" not in on


def test_the_list_shows_the_readings_in_the_score_s_place(tmp_path):
    panel, sid = _panel(tmp_path, _report())
    row, shown = panel.store.get(sid), panel.shown_report(sid)
    assert row.readings == shown["readings"]  # the index row's, from the findings index
    c = ui.Card(repo="someone/an-app", name="An app", kind="integration", installed="v1",
                available=None, scan=row, report=shown)  # fmt: skip
    for html in (ui.card_html("", c), ui.card_row("", c)):
        assert 'class="badge' not in html and "Exposure 1.3 of 10" not in html
        assert 'aria-label="Exposure 1.25 of 10"' in html and ">1.3<" in html
    assert c.band == "green"


def test_a_found_threat_gets_the_banner():
    r = readings.compute(rep(f("card-token-exfil", "critical", "c.js"))).to_dict()
    out = ui.threat_banner(r)
    assert (
        "This app may send your login token to another site. Don&#x27;t install it." in out
        or "This app may send your login token to another site. Don't install it." in out
    )
    assert ui.threat_banner(None, 2).count("2 apps show malicious behavior") == 1
    assert ui.threat_banner(None, 0) == ""


def test_the_settings_page_has_the_readings_section():
    page = server.render_settings("", settings.DEFAULTS, "t").decode()
    assert "<h2>Readings</h2>" in page and "name=where" in page and "name=show_minor" in page
    for gone in (
        "Proposed readings",
        "Paranoid mode",
        "Powerful, no threat",
        "Pages without a login",
        "Hidden usage reporting",
        "Scoring",
    ):
        assert gone not in page, gone
