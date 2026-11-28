"""(0.15, issue #26) A host the code names only as an OAuth return address isn't a place
it sends data: such hosts stay listed but don't pair with credential reads into
`possible-exfil`. Hosts are .invalid; the integration shapes are made up."""

import time
from pathlib import Path

import pytest
from conftest import requires_semgrep

from sniff_test.analyzers import endpoints
from sniff_test.models import Target, TargetKind
from sniff_test.scanner import scan

ALLOW = """\
DEFAULT_OAUTH_REDIRECT_ALLOWLIST: tuple[str, ...] = (
    "https://chat.example.invalid/api/mcp/auth_callback",
    "https://agent.example.invalid/oauth-redirect",
)
"""


def _redirects(tmp_path: Path, files: dict[str, str]) -> set[str]:
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    target = Target(source=str(tmp_path), kind=TargetKind.INTEGRATION, root=tmp_path,
                    source_root=tmp_path, domain="acme_bridge")  # fmt: skip
    result = endpoints.run(target)
    return {f.key for f in result.facts if f.attrs.get("redirect_only")}


def test_an_oauth_allowlist_is_a_list_of_return_addresses(tmp_path):
    got = _redirects(tmp_path, {"const.py": ALLOW})
    assert got == {"chat.example.invalid", "agent.example.invalid"}


@pytest.mark.parametrize(
    ("files", "why"),
    [
        ({"const.py": ALLOW.replace("REDIRECT_ALLOWLIST", "ENDPOINTS")}, "name"),
        (
            {
                "const.py": ALLOW.replace("auth_callback", "collect").replace(
                    "oauth-redirect", "upload"
                )
            },
            "path",
        ),
        (
            {"const.py": ALLOW, "api.py": 'URL = "https://chat.example.invalid/v1/upload"\n'},
            "used elsewhere",
        ),
        (
            {
                "const.py": ALLOW,
                "send.py": "from .const import DEFAULT_OAUTH_REDIRECT_ALLOWLIST\n"
                "async def go(s, d):\n"
                "    await s.post(DEFAULT_OAUTH_REDIRECT_ALLOWLIST[0], data=d)\n",
            },
            "sent to",
        ),
        (
            {"const.py": "def f():\n    redirect_url = 'https://chat.example.invalid/callback'\n"},
            "inside a function",
        ),
    ],
)
def test_anything_else_is_still_a_destination(tmp_path, files, why):
    assert "chat.example.invalid" not in _redirects(tmp_path, files), why


def test_the_patterns_stay_linear_on_hostile_input():
    n = 200_000
    for pat, text in ((endpoints._REDIRECT_PATH, "callback" + "-" * n + "!"),
                      (endpoints._REDIRECT_PATH, "callback" * n),
                      (endpoints._REDIRECT_NAME, "x" * n)):  # fmt: skip
        start = time.perf_counter()
        pat.search(text)
        assert time.perf_counter() - start < 0.5


@requires_semgrep
def test_issue_26_shape_has_no_possible_threat_and_the_planted_send_is_caught(fixtures):
    ok = scan(str(fixtures / "oauth_redirects"), offline=True)
    rules = {f.rule_id for f in ok.findings}
    assert "ha-read-secrets" in rules and "possible-exfil" not in rules
    listed = {f.key for f in ok.facts if f.kind == "host"}
    assert {"chat.example.invalid", "agent.example.invalid"} <= listed  # still listed
    bad = scan(str(fixtures / "oauth_redirect_abuse"), offline=True)
    assert "possible-exfil" in {f.rule_id for f in bad.findings}


def test_the_site_s_fold_says_it_is_a_return_address():
    from sniff_test import ui

    edge = {"id": "h" * 16, "source": "s", "relation": "connects_to",
            "target": "host:a.invalid", "samples": [],
            "attrs": {"class": "undeclared", "redirect_only": True}}  # fmt: skip
    nodes = [{"id": "host:a.invalid", "label": "a.invalid"}]
    rep = {"graph": {"subject": "s", "nodes": nodes, "edges": [edge]}}
    html = ui.zones_html(rep)
    assert "a list of sign-in return addresses (OAuth)" in html
    rep["graph"]["edges"][0]["attrs"].pop("redirect_only")
    assert "return addresses" not in ui.zones_html(rep)
