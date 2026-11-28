"""(preview) The sniff report: the app page when Settings → Proposed readings is on (round 6,
his decisions 2026-11-20). Threat and Exposure first; everything else is context with no
severity; each block says where its sentences come from; the developer's words (a
docstring from a stored snippet) are never next to a found or possible threat.

App names, files and code here are made up; hosts use .invalid."""

from __future__ import annotations

import time

from sniff_test import devnote, readings, ui


def f(rule: str, sev: str = "high", file: str = "cmds.py", line: int = 20, n: int = 0) -> dict:
    return {"id": f"{rule}-{n}", "rule_id": rule, "severity": sev, "file": file, "line": line,
            "title": rule, "message": "m", "evidence": "x = 1"}  # fmt: skip


CODE = [
    "import thing",  # 10
    "",
    "@admin_only",
    "async def make_device_user(hass, msg):",
    '    """Give a device a user of its own, not an administrator.',  # 14
    "",
    "    The user has no password. <script>alert(1)</script>",
    '    """',  # 17
    "    serial = msg['serial']",
    "    user = await hass.auth.async_create_user(serial)",
    "    token = await hass.auth.async_create_refresh_token(user)",  # 20
    "    return token",
]


def report(*findings: dict) -> dict:
    items = {x["id"]: {"kind": "finding", "file": x["file"], "line": x["line"], "snippet": "s1"}
             for x in findings}  # fmt: skip
    r = {
        "target": {"repo": "someone/device-bridge", "kind": "integration", "ref": "v2"},
        "exposure": "local", "complete": True, "score": 50,
        "verdict": {"key": "very_sus", "label": "Very Sus"},
        "findings": list(findings), "score_breakdown": [], "caps_applied": [],
        "tool": {"version": "x"}, "schema_version": 1,
        "context": {"version": 5, "items": items, "snippets": {
            "s1": {"file": "cmds.py", "lang": "python",
                   "segments": [{"file": "cmds.py", "start": 10, "code": CODE}]}}},
    }  # fmt: skip
    r["readings"] = readings.compute(r).to_dict()
    return r


def page(r: dict) -> str:
    return ui.render_app("", 1, r, []).decode()


def test_the_report_puts_threat_and_exposure_first_and_the_rest_as_context():
    out = page(report(f("ha-auth-change-users", line=19), f("ha-auth-internals")))
    t, x = out.index("<h2>Threat <span"), out.index("<h2>Exposure <span")
    c = out.index("What Barkley found")
    assert t < x < c
    assert "What Barkley found (" not in out and "Should you worry?" not in out
    assert 'class="lvl high"' not in out and "points" not in out.split("What Barkley found", 1)[1]
    assert out.count('class="src scan"') >= 5  # Threat, Exposure, In short, can do, …
    assert "capability score" in out


def test_the_developer_s_note_is_quoted_with_its_lines_and_escaped():
    out = page(report(f("ha-auth-change-users", line=19)))
    dash = "\u2013"  # the en dash the panel puts between line numbers
    assert f"note · description in the code, cmds.py:14{dash}17" in out
    assert "Give a device a user of its own, not an administrator." in out
    assert "<script>alert(1)</script>" not in out and "&lt;script&gt;" in out
    assert "change the readings." in out


def test_no_developer_s_words_on_a_page_with_a_found_threat():
    out = page(report(f("ha-auth-change-users", line=19), f("ha-exfil-taint", "critical")))
    assert "banner threat" in out and "no hidden code and no known-bad packages" not in out
    assert "Give a device a user" not in out and 'class="src dev"' not in out


def test_a_possible_threat_drops_the_note_on_the_credential_reads_it_pairs():
    """A secrets read paired with outside hosts is a possible threat; the developer's
    explanation of that read is left out, the other items keep theirs."""
    r = report(f("possible-exfil", "high", line=30), f("ha-auth-internals", line=20, n=1))
    assert r["readings"]["threat_level"] == "possible"
    out = page(r)
    assert "a possible sign of malicious behavior" in out and "Give a device a user" not in out
    assert "This may be a sign" not in out  # Threat's sentence isn't an Exposure reason
    r = report(f("possible-exfil", "high", line=30), f("ha-auth-change-users", line=19, n=2))
    assert "Give a device a user" in page(r)  # not a credential read: its note stays


def test_devnote_finds_the_docstring_of_the_enclosing_function():
    n = devnote.note(report(f("x", line=20)), "x-0")
    assert n is not None and (n.file, n.start, n.end) == ("cmds.py", 14, 17)
    assert n.text.startswith("Give a device a user of its own")


def test_devnote_gives_nothing_when_the_docstring_runs_past_the_snippet():
    r = report(f("x", line=20))
    seg = r["context"]["snippets"]["s1"]["segments"][0]
    seg["code"] = [*CODE[:6], "    user = 1"]  # docstring never closes inside the snippet
    seg["start"] = 10
    r["context"]["items"]["x-0"]["line"] = 16
    assert devnote.note(r, "x-0") is None


def test_devnote_prefers_the_docstring_the_scan_stored_with_the_item():
    """(0.15) A scan keeps the docstring itself, so a snippet that cuts it no longer hides
    it; long ones end in an ellipsis and markup stays text."""
    r = report(f("x", line=20))
    r["context"]["snippets"]["s1"]["segments"][0]["code"] = CODE[8:]  # no docstring in it
    r["context"]["snippets"]["s1"]["segments"][0]["start"] = 18
    r["context"]["items"]["x-0"]["doc"] = {
        "file": "cmds.py", "start": 14, "code": CODE[4:8], "cut": False, "of": "make_device_user",
    }  # fmt: skip
    n = devnote.note(r, "x-0")
    assert n is not None and (n.file, n.start, n.end) == ("cmds.py", 14, 17)
    assert n.text == (
        "Give a device a user of its own, not an administrator. "
        "The user has no password. <script>alert(1)</script>"
    )
    r["context"]["items"]["x-0"]["doc"] = {"file": "cmds.py", "start": 3, "code": ['"One."'],
                                           "cut": False}  # fmt: skip
    assert devnote.note(r, "x-0").text == "One."
    r["context"]["items"]["x-0"]["doc"] = {"file": "cmds.py", "start": 3, "cut": True,
                                           "code": ['"""Long'] + ["more"] * 40}  # fmt: skip
    assert devnote.note(r, "x-0").text.endswith("…")
    for junk in ({}, {"file": 1}, {"file": "a.py", "start": 1, "code": ["no quote"]},
                 {"file": "a.py", "start": 1, "code": []}):  # fmt: skip
        r["context"]["items"]["x-0"]["doc"] = junk
        assert devnote.note(r, "x-0") is None


def test_devnote_ignores_files_that_are_not_python():
    r = report(f("x", file="card.js", line=20))
    r["context"]["snippets"]["s1"]["segments"][0]["file"] = "card.js"
    assert devnote.note(r, "x-0") is None


def test_devnote_stays_linear_on_hostile_snippets():
    """Scanned code is hostile: huge lines and many headers must not blow up."""
    code = ["def f():", '    """' + "'''\"\"" * 50_000] + ["    def g():"] * 20_000 + ["x"]
    r = report(f("x", line=10 + len(code) - 1))
    r["context"]["snippets"]["s1"]["segments"][0]["code"] = code
    t = time.perf_counter()
    devnote.note(r, "x-0")
    assert time.perf_counter() - t < 1.0


def _entry(**kw) -> dict:
    return {"repo": "someone/device-bridge", "version": "v2", "previous": "v1",
            "kind": "integration", "scan_ids": [3, 4], **kw}  # fmt: skip


def test_the_update_notification_carries_stoplight_readings():
    from sniff_test import watch

    r = report(f("ha-auth-change-users", line=19), f("ha-auth-internals"))
    was = readings.compute(report()).to_dict()
    title, md, plain = watch.notification(_entry(was_readings=was), r, None, "")
    assert "🟢 Threat: none · 🟢 Exposure: low (1.25, was 0)" in plain
    assert "/100" not in plain and "Give a device" not in md and title.endswith("v2")


def test_a_found_threat_is_red_in_the_title_and_the_line():
    from sniff_test import watch

    r = report(f("card-token-exfil", "critical", "c.js"))
    title, _md, plain = watch.notification(_entry(), r, None, "")
    assert title.startswith("Barkley: 🔴 malicious behavior found")
    assert "🔴 Threat: found · 🔴 Exposure: high (10)" in plain
    assert "It may send your login token to another site." in plain


def test_a_threat_item_keeps_its_severity_but_shows_no_points():
    r = report(f("card-token-exfil", "critical", "c.js"))
    r["score_breakdown"] = [{"finding_id": "card-token-exfil-0", "rule_id": "card-token-exfil",
                             "severity": "critical", "points": 60.0}]  # fmt: skip
    out = page(r)
    assert 'class="lvl critical"' in out and "points" not in out


def test_nothing_to_accept_and_no_malware_only_link_either_way(tmp_path):
    """His call 2026-11-20: nothing is scored by a review, so no Accept all, no Mark
    reviewed and no per-app "Malware check only"; Report a false positive stays. (0.15:
    removed for good, with the preview on or off.)"""
    from sniff_test import server
    from sniff_test.store import Store

    r = report(f("ha-auth-change-users", line=19))
    r["findings"][0]["fingerprint"] = "a1b2c3d4e5f6a7b8c9d0e1f2"  # acceptable when off
    del r["readings"]
    store = Store(tmp_path / "s.db")
    sid = store.save(r)
    panel = server.Panel(store, lambda r, f: {}, None)
    off = server.render_scan("", sid, panel.shown_report(sid), store, token="t").decode()
    assert "Accept all" not in off and "Mark reviewed" not in off
    assert "Malware check only" not in off and "Report a false positive" in off
    panel.save_settings({"preview": "1"})
    on = server.render_scan("", sid, panel.shown_report(sid), store, token="t").decode()
    assert "Accept all" not in on and "Mark reviewed" not in on
    assert "Malware check only" not in on and "Report a false positive" in on


def test_the_exposure_box_reads_plainly():
    out = page(report())
    assert "<h2>Exposure <span" in out and "what it opens up" not in out
    assert "Barkley found nothing that would let someone who isn" in out
    assert "an administrator can already do everything" not in out


def test_in_short_says_it_plainly():
    out = ui.in_short(report(f("ha-auth-change-users", line=19)))
    assert "It can change who can log in to Home Assistant." in out
    assert "to check" not in out and "<b>" not in out
    assert out.endswith(
        "Barkley found nothing that sends your data off your Home Assistant machine."
    )


def test_a_card_title_is_its_own_sentence_not_it_can_it():
    assert ui._it_can("Its dashboard card reads your saved login") == (
        "Its dashboard card reads your saved login."
    )
    assert ui._it_can("Changes who can log in to Home Assistant").startswith("It can change")


def _card(r: dict) -> ui.Card:
    class Scan:  # the card reads only these of a stored scan's row
        id, score, complete = 1, 50, True

    return ui.Card(repo="someone/device-bridge", name="Device bridge", kind="integration",
                   installed="v2", available=None, scan=Scan(), report=r)  # fmt: skip


def test_card_chips_are_neutral_except_a_threat():
    """His note 2026-11-20: colour means severity, and only Threat is scored."""
    r = report(f("ha-auth-change-users", line=19), f("ha-auth-internals", n=1))
    chips = ui.card_chips(_card(r))
    assert chips and all(cls == "" for cls, _t in chips)
    r = report(f("card-token-exfil", "critical", "c.js"), f("ha-auth-change-users", line=19))
    cls = dict((t, c) for c, t in ui.card_chips(_card(r)))
    assert "bad" in cls.values() and "" in cls.values()


def test_the_card_sentence_says_plus_n_more():
    r = report(f("ha-auth-change-users", line=19), f("ha-auth-internals", n=1))
    s = ui.card_sentence(_card(r))
    assert "There is 1 more." in s and "to check" not in s


def test_the_card_sentence_leads_with_a_threat():
    """(0.15) items were ordered by their old score points, so a possible threat could sit
    behind "Handles Home Assistant login tokens"."""
    r = report(f("ha-auth-internals", n=1), f("possible-exfil", "high", line=30))
    r["score_breakdown"] = [
        {"finding_id": "ha-auth-internals-1", "rule_id": "ha-auth-internals",
         "severity": "high", "points": 40.0},
        {"finding_id": "possible-exfil-0", "rule_id": "possible-exfil",
         "severity": "high", "points": 10.0},
    ]  # fmt: skip
    assert ui.card_sentence(_card(r)).startswith(
        "Reads private data and talks to a site the app doesn't account for."
    )
