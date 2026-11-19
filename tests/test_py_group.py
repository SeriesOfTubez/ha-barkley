"""(0.14.1, #19) One "What it can do" finding per Python function, and a note when only an
administrator can run it. Made-up code, parsed only."""

from __future__ import annotations

import textwrap
from pathlib import Path

from sniff_test.analyzers import py_group
from sniff_test.models import Category, Finding, Severity
from sniff_test.scoring import score

CODE = textwrap.dedent(
    """\
    from homeassistant.components import websocket_api

    @websocket_api.websocket_command({"type": "acme/provision"})
    @websocket_api.require_admin
    @websocket_api.async_response
    async def ws_provision(hass, connection, msg):
        user = await hass.auth.async_create_user("acme")
        for old in list(user.refresh_tokens.values()):
            hass.auth.async_remove_refresh_token(old)
        token = await hass.auth.async_create_refresh_token(user)
        connection.send_result(msg["id"], hass.auth.async_create_access_token(token))

    class Helper:
        def other(self, hass):
            return hass.auth.async_create_access_token(None)

    def steal(hass):
        data = hass.auth.async_create_access_token(None)
        send(data)
        send(data)
    """
)


def _f(rule: str, line: int, sev=Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule,
        title=rule,
        severity=sev,
        category=Category.SENSITIVE_ACCESS,
        message="Reaches into the auth store.",
        file="ws.py",
        line=line,
        evidence=f"line {line}",
    )


def _app(tmp_path: Path) -> Path:
    (tmp_path / "ws.py").write_text(CODE)
    return tmp_path


def test_hits_of_one_rule_in_one_function_are_one_finding(tmp_path):
    hits = [_f("ha-auth-internals", n) for n in (8, 9, 10, 11)]
    out = py_group.group(hits, _app(tmp_path))
    assert len(out) == 1
    assert out[0].line == 8
    assert (
        "`ws_provision`, does this 4 times (lines 8, 9, 10, 11); it counts once" in out[0].message
    )
    assert score(out, True).score > score(hits, True).score


def test_the_admin_note_without_a_score_change(tmp_path):
    one = [_f("ha-auth-change-users", 7)]
    out = py_group.group(one, _app(tmp_path))
    assert "Only an administrator can run this command" in out[0].message
    assert out[0].severity is Severity.HIGH
    assert score(out, True).score == score(one, True).score


def test_other_functions_classes_and_threats_stay_apart(tmp_path):
    hits = [
        _f("ha-auth-internals", 8),
        _f("ha-auth-internals", 15),  # Helper.other: another function
        _f("ha-exfil-taint", 18, Severity.CRITICAL),  # a threat: never folded
        _f("ha-exfil-taint", 19, Severity.CRITICAL),
    ]
    out = py_group.group(hits, _app(tmp_path))
    assert [(f.rule_id, f.line) for f in out] == [
        ("ha-auth-internals", 8),
        ("ha-auth-internals", 15),
        ("ha-exfil-taint", 18),
        ("ha-exfil-taint", 19),
    ]
    assert "Only an administrator" not in out[1].message


def test_the_kept_finding_is_the_most_severe(tmp_path):
    hits = [_f("ha-auth-internals", 8, Severity.MEDIUM), _f("ha-auth-internals", 10)]
    out = py_group.group(hits, _app(tmp_path))
    assert len(out) == 1 and out[0].severity is Severity.HIGH and out[0].line == 10


def test_a_file_outside_the_app_or_unparseable_is_left_alone(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n")
    hits = [
        Finding(
            rule_id="ha-auth-internals",
            title="t",
            severity=Severity.HIGH,
            category=Category.SENSITIVE_ACCESS,
            message="m",
            file=name,
            line=1,
        )
        for name in ("bad.py", "../outside.py")
    ]
    assert py_group.group(hits, tmp_path) == hits
