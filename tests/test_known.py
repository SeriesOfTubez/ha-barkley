"""Host reputation, scanner side: the shipped list of well-known services (a name for a
host, never a verdict) and the addresses a finding carries so the user can mark them
trusted in the panel (tests/test_trust.py). User decisions 2026-11-12."""

from sniff_test import known
from sniff_test.analyzers import endpoints


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
