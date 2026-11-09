"""Endpoint extraction and classification. Hosts here are never contacted.

Planted "exfil" hosts use the reserved .invalid TLD; the exfil-service table is tested
by injecting a .invalid entry rather than naming a real service.
"""

from pathlib import Path

import pytest

from sniff_test.analyzers import endpoints
from sniff_test.models import Target, TargetKind


def _target(root: Path, domain: str = "acme_weather", repo: str | None = None) -> Target:
    return Target(
        source=str(root),
        kind=TargetKind.INTEGRATION,
        root=root,
        source_root=root,
        domain=domain,
        repo=repo,
    )


def _write(root: Path, name: str, text: str, manifest: dict | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(text)
    import json

    (root / "manifest.json").write_text(
        json.dumps(
            manifest
            or {"domain": "acme_weather", "documentation": "https://github.com/acme/acme-weather"}
        )
    )
    return root


def _hosts(result) -> dict[str, str]:
    return {f.key: f.attrs["class"] for f in result.facts}


def test_python_comments_and_docstrings_are_not_endpoints(tmp_path):
    root = _write(
        tmp_path,
        "x.py",
        '"""See https://docs.vendor.invalid/guide."""\n'
        "# https://comment.vendor.invalid\n"
        'API = "https://api.vendor.invalid/v1"\n',
    )
    assert set(_hosts(endpoints.run(_target(root)))) == {"api.vendor.invalid"}


def test_truncated_hosts_are_skipped(tmp_path):
    root = _write(
        tmp_path,
        "x.py",
        'a = f"https://openapi.tuya{region}.com"\n'
        'b = "https://api." + region + ".vendor.invalid"\n'
        'c = "http://a"\n',
    )
    assert _hosts(endpoints.run(_target(root))) == {}


def test_adjacent_literals_are_joined(tmp_path):
    root = _write(
        tmp_path,
        "x.py",
        'HOOK = (\n    "https://relay.invalid/api/webhooks/112233445566778899/"\n'
        '    "Xq3vT9kLmN2pR7sW1yZ4bC6dF8gH0jK5lM3nP9qR2sT6uV8wX1yZ"\n)\n',
    )
    r = endpoints.run(_target(root))
    assert [f.title for f in r.findings] == ["Hardcoded Discord webhook URL"]


def test_bare_hosts_need_a_real_tld_and_not_an_entity_id(tmp_path):
    root = _write(
        tmp_path,
        "x.py",
        'HOST = "api.vendor.com"\nE = "switch.tv"\nL = "log.info"\nF = "setup.py"\nV = "6.6.2.0"\n',
    )
    assert set(_hosts(endpoints.run(_target(root)))) == {"api.vendor.com"}


def test_classification(tmp_path, monkeypatch):
    root = _write(
        tmp_path,
        "x.py",
        'A = "https://api.acme-weather.example/v2"\n'  # declared by integration name
        'B = "https://github.com/acme/acme-weather/issues"\n'  # declared by documentation
        'C = "https://acme.github.io/acme-weather"\n'  # owner's Pages site
        'D = "http://192.168.1.20:8080/status"\n'
        'E = "http://homeassistant.local:8123"\n'
        'F = "https://telemetry.weather-cdn.invalid/c"\n'
        'G = "http://www.w3.org/2000/svg"\n'
        'H = "8.8.8.8"\n'
        'I = "https://stats.someone.workers.dev"\n',
    )
    hosts = _hosts(endpoints.run(_target(root, repo="acme/acme-weather")))
    assert hosts == {
        "api.acme-weather.example": "declared",
        "github.com": "declared",
        "acme.github.io": "declared",
        "192.168.1.20": "local",
        "homeassistant.local": "local",
        "telemetry.weather-cdn.invalid": "undeclared",
        "8.8.8.8": "resolver",
        "stats.someone.workers.dev": "developer_hosted",
    }  # w3.org (a namespace) is dropped entirely


def test_exfil_service_table_is_a_finding(tmp_path, monkeypatch):
    monkeypatch.setattr(endpoints, "host_classes", lambda: (("exfil_service", "drop.invalid"),))
    root = _write(tmp_path, "x.py", 'URL = "https://abc.drop.invalid/upload"\n')
    r = endpoints.run(_target(root))
    assert [(f.rule_id, f.severity.name) for f in r.findings] == [("endpoint-exfil-host", "HIGH")]


def test_bundled_host_table_loads():
    classes = {c for c, _ in endpoints.host_classes()}
    assert {"exfil_service", "developer_hosted", "messaging", "namespace"} <= classes


@pytest.mark.parametrize(
    ("url", "label"),
    [
        (
            "https://x.invalid/bot123456789:AAHf0123456789abcdefghijABCDEFGHIJ_k/sendMessage",
            "Telegram",
        ),
        ("https://x.invalid/services/T0ABCDEF1/B0ABCDEF2/abcdefghijklmnopqrstuvwx", "Slack"),
    ],
)
def test_credential_urls(tmp_path, url, label):
    root = _write(tmp_path, "x.py", f'U = "{url}"\n')
    r = endpoints.run(_target(root))
    assert len(r.findings) == 1 and label in r.findings[0].title


def test_public_ip_only_flagged_inside_a_url(tmp_path):
    # A bare IP (e.g. a connectivity-check target) is graph context; a URL to one is not.
    root = _write(tmp_path, "x.py", 'PING = "93.184.215.14"\nAPI = "http://93.184.215.14/x"\n')
    r = endpoints.run(_target(root))
    assert [f.rule_id for f in r.findings] == ["endpoint-public-ip-literal"]
    assert _hosts(r) == {"93.184.215.14": "public_ip"}


def test_js_comment_lines_are_skipped(tmp_path):
    root = tmp_path
    (root / "card.js").write_text(
        "/*! license https://license.vendor.invalid */\n"
        "// https://comment.vendor.invalid\n"
        'fetch("https://api.vendor.invalid/x");\n'
    )
    t = Target(source="x", kind=TargetKind.PLUGIN, root=root, source_root=root)
    assert set(_hosts(endpoints.run(t))) == {"api.vendor.invalid"}


def test_evil_fixture_webhook(fixtures):
    root = fixtures / "evil_integration" / "custom_components" / "totally_legit_weather"
    r = endpoints.run(_target(root, domain="totally_legit_weather"))
    assert {f.rule_id for f in r.findings} == {"endpoint-exfil-host"}
    assert _hosts(r)["weather-cdn.invalid"] == "undeclared"


def test_clean_fixture_is_quiet(fixtures):
    root = fixtures / "clean_integration" / "custom_components" / "acme_weather"
    r = endpoints.run(_target(root))
    assert r.findings == []
    assert _hosts(r) == {"api.acme-weather.example": "declared"}
