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
    t, x = out.index("Threat: none found"), out.index("Exposure: what it opens up")
    c = out.index("What it can do")
    assert t < x < c
    assert "What we found" not in out and "Should you worry?" not in out
    assert 'class="lvl high"' not in out and "points" not in out.split("What it can do", 1)[1]
    assert out.count('class="src scan"') >= 5  # Threat, Exposure, In short, can do, …
    assert "capability score" in out


def test_the_developer_s_note_is_quoted_with_its_lines_and_escaped():
    out = page(report(f("ha-auth-change-users", line=19)))
    dash = "\u2013"  # the en dash the panel puts between line numbers
    assert f"note · docstring, cmds.py:14{dash}17" in out
    assert "Give a device a user of its own, not an administrator." in out
    assert "<script>alert(1)</script>" not in out and "&lt;script&gt;" in out
    assert "It doesn&#x27;t change the reading." in out or "It doesn't change the reading." in out


def test_no_developer_s_words_on_a_page_with_a_found_threat():
    out = page(report(f("ha-auth-change-users", line=19), f("ha-exfil-taint", "critical")))
    assert "Threat: found" in out and "banner threat" in out
    assert "Give a device a user" not in out and 'class="src dev"' not in out


def test_a_possible_threat_drops_the_note_on_the_credential_reads_it_pairs():
    """A secrets read paired with outside hosts is a possible threat; the developer's
    explanation of that read is left out, the other items keep theirs."""
    r = report(f("possible-exfil", "high", line=30), f("ha-auth-internals", line=20, n=1))
    assert r["readings"]["threat_level"] == "possible"
    out = page(r)
    assert "Threat: possible" in out and "Give a device a user" not in out
    r = report(f("possible-exfil", "high", line=30), f("ha-auth-change-users", line=19, n=2))
    assert "Give a device a user" in page(r)  # not a credential read: its note stays


def test_the_old_page_is_unchanged_without_the_preview():
    r = report(f("ha-auth-change-users", line=19))
    del r["readings"]
    out = page(r)
    assert "What we found" in out and "Should you worry?" in out
    assert 'class="src' not in out and "Give a device a user" not in out


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
    assert "It sends your login token off the box." in plain


def test_without_the_preview_the_notification_keeps_the_score():
    from sniff_test import watch

    r = report(f("ha-auth-change-users", line=19))
    del r["readings"]
    _t, _md, plain = watch.notification(_entry(), r, None, "")
    assert "50/100" in plain and "Threat:" not in plain


def test_a_threat_item_keeps_its_severity_but_shows_no_points():
    r = report(f("card-token-exfil", "critical", "c.js"))
    r["score_breakdown"] = [{"finding_id": "card-token-exfil-0", "rule_id": "card-token-exfil",
                             "severity": "critical", "points": 60.0}]  # fmt: skip
    out = page(r)
    assert 'class="lvl critical"' in out and "points" not in out
