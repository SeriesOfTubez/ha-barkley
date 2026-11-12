"""Host reputation: the shipped list of well-known services, and the one severity it
touches (GuardDog's address-shape heuristic). User decision 2026-11-12."""

import pytest

from sniff_test import known
from sniff_test.analyzers import endpoints, guarddog, python_deps
from sniff_test.deps.uv import Artifact
from sniff_test.models import Severity, Tag
from sniff_test.report import explain

PKG = python_deps.ResolvedPackage("chromadb-client", "1.5.3", {"x86_64", "aarch64"})
ART = Artifact("https://x", "chromadb_client-1.5.3-py3-none-any.whl", None, "wheel")
RULE = "threat-network-exfiltration"


def _hit(
    code, match, loc="chromadb/utils/embedding_functions/together_ai_embedding_function.py:13"
):
    return {"location": loc, "code": code, "match": match, "message": "m"}


# GuardDog 3.2's real output for chromadb-client 1.5.3 (hass-agent-llm v0.9.5's dependency)
TOGETHER = _hit('ENDPOINT = "https://api.together.xyz/v1/embeddings"', "https://api.together.xyz/")


def _findings(*hits):
    return guarddog.to_findings({"results": {RULE: list(hits)}}, PKG, ART)


def test_lookup_matches_the_host_or_a_subdomain_only():
    svc = known.lookup("api.together.xyz")
    assert svc and svc.name == "Together AI" and svc.label == "Together AI, AI model API"
    assert known.lookup("API.Together.XYZ.") == svc
    assert known.lookup("eu.api.together.xyz") == svc
    assert known.lookup("together.xyz") is None  # the entry is the API host, not the domain
    assert known.lookup("evilapi.together.xyz") is None
    assert known.lookup("api.together.xyz.evil.tk") is None
    assert known.lookup("") is None and known.lookup(None) is None
    assert known.lookup("myres.openai.azure.com").shared


def test_no_listed_service_is_a_place_where_anyone_can_receive_data():
    """The list may never overlap the classes that mean "drop box or someone's own
    server" (in either direction: a listed suffix under one of theirs, or one of theirs
    under a listed suffix)."""
    risky = [(c, s) for c, s in endpoints.host_classes()
             if c in ("exfil_service", "messaging", "developer_hosted", "analytics")]  # fmt: skip
    for svc in known.services():
        for cls, suffix in risky:
            assert not (svc.suffix == suffix or svc.suffix.endswith("." + suffix)), (svc, cls)
            assert not suffix.endswith("." + svc.suffix), (svc, cls, suffix)
        assert svc.name and svc.what and "." in svc.suffix and " " not in svc.suffix
        assert not svc.suffix.startswith(("http", "*", "."))
    assert len({s.suffix for s in known.services()}) == len(known.services())
    # nothing as wide as a whole cloud or a public suffix
    assert not {s.suffix for s in known.services()} & {
        "amazonaws.com", "googleapis.com", "azure.com", "cloudflare.com", "github.io",
        "google.com", "microsoft.com", "windows.net", "xyz", "com",
    }  # fmt: skip


def test_the_real_chromadb_hit_is_kept_but_low_and_says_whose_address_it_is():
    [f] = _findings(TOGETHER)
    assert f.rule_id == guarddog.KNOWN_SERVICE_RULE and f.severity is Severity.LOW
    assert Tag.POSSIBLE not in f.tags
    assert "api.together.xyz is Together AI, AI model API" in f.message
    assert "doesn't show what is sent there" in f.message
    assert f.evidence.endswith("https://api.together.xyz/")
    ex = explain.explain(f.rule_id)
    assert ex.title == "A code library it uses names a well-known service at an odd-looking address"
    assert "malware" not in ex.means and "doesn't show what the library sends" in ex.means
    # the unlowered rule no longer claims a data flow the heuristic can't see
    assert "sends it out" not in explain.explain("dep-guarddog-network-exfiltration").title


@pytest.mark.parametrize(
    "hits",
    [
        # an unknown host with the same ending
        [_hit('U = "https://api.togethr.xyz/v1"', "https://api.togethr.xyz/")],
        # a known one and an unknown one: every address must be known
        [TOGETHER, _hit('C2 = "https://cdn-update.top/x"', "https://cdn-update.top/", "a.py:2")],
        # a second URL on the same line that GuardDog didn't report
        [
            _hit(
                'A = ["https://api.together.xyz/v1", "https://203.0.113.9/up"]',
                "https://api.together.xyz/",
            )
        ],
        # userinfo: the client would connect to evil.tk
        [_hit('U = "https://api.together.xyz@evil.tk/"', "https://api.together.xyz@evil.tk/")],
        [_hit('U = "https://api.together.xyz:443@evil.example/"', "https://api.together.xyz:")],
        [_hit('U = "https://user@api.together.xyz/"', "https://user@api.together.xyz/")],
        # a backslash some clients read as a slash
        [_hit('U = "https://evil.tk\\@api.together.xyz/"', "https://evil.tk")],
        # the known name as a mere prefix or path
        [_hit('U = "https://api.together.xyz.evil.tk/"', "https://api.together.xyz.evil.tk/")],
        [_hit('U = "https://evil.xyz/api.together.xyz/"', "https://evil.xyz/")],
        # the rule's other shapes: a drop-box name, a public IP
        [_hit('requests.post("https://webhook.site/abc", data=d)', "webhook.site")],
        [_hit('U = "http://203.0.113.9/up"', "http://203.0.113.9")],
        # no code line to check, or the match isn't in it
        [{"location": "a.py:1", "match": "https://api.together.xyz/"}],
        [_hit("ENDPOINT = BASE", "https://api.together.xyz/")],
        # GuardDog's cap of 5 hits: more matches may exist that it didn't print
        [TOGETHER] * 5,
        # a per-customer host is named, never trusted
        [_hit('U = "https://x.openai.azure.com/"', "https://x.openai.azure.com/")],
    ],
)
def test_anything_unclear_stays_high(hits):
    [f] = _findings(*hits)
    assert f.rule_id == "dep-guarddog-network-exfiltration"
    assert f.severity is Severity.HIGH and Tag.POSSIBLE in f.tags


def test_only_the_address_shape_rule_is_ever_lowered():
    for rule, sev in guarddog.SEVERITY.items():
        if sev is None or rule == RULE:
            continue
        [f] = guarddog.to_findings({"results": {rule: [TOGETHER]}}, PKG, ART)
        assert f.rule_id == "dep-guarddog-" + rule.removeprefix("threat-"), rule
        assert f.severity is sev or (sev is Severity.MEDIUM and f.severity is Severity.LOW), rule


def test_a_known_host_in_the_apps_own_code_gets_a_name_and_keeps_its_class(tmp_path):
    from test_endpoints import _target, _write  # the endpoint tests' own helpers

    root = _write(
        tmp_path / "acme_weather",
        "api.py",
        'A = "https://api.openai.com/v1/chat"\nB = "https://collect.unrelated-vendor.com/x"\n',
    )
    res = endpoints.run(_target(root))
    by = {f.key: f.attrs for f in res.facts if f.kind == "host"}
    assert by["api.openai.com"]["service"] == "OpenAI, AI model API"
    assert by["api.openai.com"]["class"] == "undeclared"  # a name, not a verdict
    assert "service" not in by["collect.unrelated-vendor.com"]
    assert res.findings == []
