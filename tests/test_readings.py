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
    own = [f("ha-unauth-view", "low", "views.py", n=i) for i in range(6)]
    assert readings.compute(rep(*own)).exposure == 4.5  # 6 x 0.75, a check it can't confirm
    signed = [f("ha-unauth-view", "low", "whep.py", n=i) for i in range(4)]
    r = readings.compute(rep(*signed, f("ha-auth-token-check", "low", "whep.py")))
    assert r.exposure == 1.0 and "signed link" in r.exposure_reasons[0]  # 4 x 0.25


def test_the_network_raises_exposure_and_public_raises_it_most():
    own = [f("ha-unauth-view", "low", "v.py", n=i) for i in range(6)]
    assert readings.compute(rep(*own), "shared").exposure == 5.62  # 4.5 x 1.25, rounded
    assert readings.compute(rep(*own), "shared").exposure_level == "high"
    pub = readings.compute(rep(*own, exposure="public"), "home")
    assert pub.exposure == 6.75 and pub.network == "internet"
    assert readings.compute(rep(*own), "nonsense").network == "home"


def test_library_bugs_by_severity():
    r = readings.compute(rep(f("dep-vuln", "medium", n=1), f("dep-vuln", "high", n=2)))
    assert r.exposure == 4.0 and r.exposure_level == "medium"


def test_a_critical_sign_is_found_and_exposure_is_the_maximum():
    r = readings.compute(rep(f("card-token-exfil", "critical", "c.js")))
    assert r.threat == 7.0 and r.threat_level == "found"  # 6, raised to the floor of 7
    assert r.exposure == 10 and r.exposure_level == "high"
    assert r.threat_reason == "sends your login token off the box"


def test_threat_points_repeat_at_a_quarter_and_cap_at_ten():
    two = readings.compute(rep(f("card-hidden-name", n=1), f("card-hidden-name", n=2)))
    assert two.threat == 3.12 and two.threat_level == "possible"  # 2.5 + 0.625
    many = [f("ha-exfil-taint", "critical", n=1), f("py-b64-exec", "critical", n=2),
            f("possible-exfil", n=3), f("dep-typosquat", n=4)]  # fmt: skip
    assert readings.compute(rep(*many)).threat == 10


def test_a_possible_sign_says_so_first_and_keeps_its_exposure():
    r = readings.compute(rep(f("dep-typosquat"), f("ha-unauth-view", "low", "v.py")))
    assert r.threat_level == "possible" and r.exposure == 0.75
    assert r.exposure_reasons[0].startswith("A possible sign of malicious behavior")


def test_lifetime_buckets_are_multipliers():
    got = [readings.lifetime_factor(d) for d in (0.5, 7, 90, 300, 3650, None)]
    assert got == [0.0, 0.5, 0.75, 1.0, 1.25, 1.25]


def test_settings_default_off_and_check_their_values():
    assert settings.DEFAULTS.preview is False and settings.DEFAULTS.network == "home"
    s = settings.from_dict({"preview": "1", "network": "shared"})
    assert s.preview and s.network == "shared"
    assert settings.from_dict({"network": "internet"}).network == "home"  # not a choice
    assert settings.PARTS["preview"] == ("preview", "network")


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


def test_the_panel_adds_readings_only_when_the_preview_is_on(tmp_path):
    panel, sid = _panel(tmp_path, _report())
    assert "readings" not in panel.shown_report(sid)
    panel.save_settings({"preview": "1"})
    shown = panel.shown_report(sid)
    assert shown["readings"]["exposure"] == 1.25
    assert shown["score"] == 50  # Barkley's own score is unchanged
    assert "readings" not in panel.report(sid)  # the stored report never has them
    assert "readings" not in json.dumps(panel.store.report(sid))


def test_the_app_page_shows_the_dials_beside_the_score(tmp_path):
    panel, sid = _panel(tmp_path, _report())
    panel.save_settings({"preview": "1"})
    page = ui.render_app("", sid, panel.shown_report(sid), []).decode()
    assert "Proposed readings" in page and 'aria-label="Exposure 1.25 of 10"' in page
    assert 'aria-label="Score 50 of 100"' in page  # today's ring is still there
    assert "banner threat" not in page


def test_a_found_threat_gets_the_banner():
    r = readings.compute(rep(f("card-token-exfil", "critical", "c.js"))).to_dict()
    out = ui.threat_banner(r)
    assert (
        "This app sends your login token off the box. Don&#x27;t install it." in out
        or "This app sends your login token off the box. Don't install it." in out
    )
    assert ui.threat_banner(None, 2).count("2 apps show malicious behavior") == 1
    assert ui.threat_banner(None, 0) == ""


def test_the_settings_page_has_the_preview_section():
    page = server.render_settings("", settings.DEFAULTS, "t").decode()
    assert "Proposed readings (preview)" in page and "name=network" in page
