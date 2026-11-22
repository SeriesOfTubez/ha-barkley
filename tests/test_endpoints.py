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
    return {f.key: f.attrs["class"] for f in result.facts if f.kind in ("host", "ip")}


def _ports(result) -> list[tuple[int, str, str]]:
    return [
        (int(f.key), f.attrs["names"][0], f"{f.file}:{f.line}")
        for f in result.facts
        if f.kind == "port"
    ]


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


def test_analytics_class_stays_unexplained(tmp_path, monkeypatch):
    monkeypatch.setattr(endpoints, "host_classes", lambda: (("analytics", "metrics.invalid"),))
    root = _write(tmp_path, "x.py", 'DSN = "https://o1.ingest.metrics.invalid/api/7"\n')
    r = endpoints.run(_target(root))
    assert _hosts(r) == {"o1.ingest.metrics.invalid": "analytics"}
    assert r.findings == []
    # same weight as "undeclared" in the correlation, so scores don't move
    assert "analytics" in endpoints.UNEXPLAINED


def test_bundled_table_has_analytics():
    assert ("analytics", "sentry.io") in endpoints.host_classes()


def test_url_samples_and_ports(tmp_path):
    root = _write(
        tmp_path,
        "x.py",
        'A = "https://user:pw@api.acme-weather.example:8443/v2/data?key=SECRET#frag"\n'
        'B = "http://192.168.1.20:8080/status"\n'
        'C = "https://api.acme-weather.example/v2/{device}/state"\n'
        'D = "https://x.invalid/bot123456789:AAHf0123456789abcdefghijABCDEFGHIJ_k/send"\n',
    )
    r = endpoints.run(_target(root))
    urls = {f.key: f.attrs.get("urls") for f in r.facts if f.kind in ("host", "ip")}
    ports = {f.key: f.attrs.get("ports") for f in r.facts if f.kind in ("host", "ip")}
    assert urls["192.168.1.20"] == ["http://192.168.1.20:8080/status"]
    assert ports["192.168.1.20"] == [8080]
    api = [f.attrs.get("urls", []) for f in r.facts if f.key == "api.acme-weather.example"]
    assert sorted(u for us in api for u in us) == [
        "https://api.acme-weather.example/v2/…/state",
        "https://api.acme-weather.example:8443/v2/data",
    ]
    assert urls["x.invalid"] == ["https://x.invalid/…"]  # the credential path is hidden
    assert not any("SECRET" in str(f.attrs) or "pw@" in str(f.attrs) for f in r.facts)


def test_url_samples_are_capped_per_host(tmp_path):
    lines = "".join(f'U{i} = "https://api.acme-weather.example/p{i}"\n' for i in range(9))
    r = endpoints.run(_target(_write(tmp_path, "x.py", lines)))
    kept = [u for f in r.facts for u in f.attrs.get("urls", [])]
    assert len(kept) == 5


def test_ports_from_python(tmp_path):
    root = _write(
        tmp_path,
        "client.py",
        "port = 6000\n"
        "class C:\n"
        "    def __init__(self, host: str, mqtt_port: int = 1883):\n"
        "        self._port = 8883\n"
        "        ftp.connect(host=h, port=990, timeout=15)\n"
        'CFG = {"mqtt_port": 1884, CONF_PORT: 502}\n'
        "DEFAULT_MODBUS_PORT = 502\n"
        "SUPPORTS_EARLY_FTP_DOWNLOAD = 24\n"  # not a port name
        "port_count = 4\n"  # a count, not a port
        "if port == 80: pass\n"  # a comparison, not an assignment
        "timeout = 990\n"
        "PORT = 0\n",  # out of range
    )
    assert _ports(endpoints.run(_target(root))) == [
        (6000, "port", "client.py:1"),
        (1883, "mqtt_port", "client.py:3"),
        (8883, "_port", "client.py:4"),
        (990, "port", "client.py:5"),
        (1884, "mqtt_port", "client.py:6"),
        (502, "CONF_PORT", "client.py:6"),
        (502, "DEFAULT_MODBUS_PORT", "client.py:7"),
    ]


def test_ports_skip_test_doubles_and_cards(tmp_path):
    _write(tmp_path, "mock_mqtt_client.py", "def connect(host, port: int = 1883): ...\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "helpers.py").write_text("port = 1883\n")
    assert _ports(endpoints.run(_target(tmp_path))) == []
    (tmp_path / "card.py").write_text("port = 1883\n")
    card = Target(source="x", kind=TargetKind.PLUGIN, root=tmp_path, source_root=tmp_path)
    assert _ports(endpoints.run(card)) == []


def test_ports_never_from_comments_or_broken_files(tmp_path):
    _write(tmp_path, "x.py", '# port = 1883\n"""port = 21"""\nbroken = (\n')
    assert _ports(endpoints.run(_target(tmp_path))) == []


def test_port_direction_from_the_calls_around_it(tmp_path):
    _write(
        tmp_path,
        "net.py",
        "import socket\n"
        "def reachable(ip, port: int = 80):\n"
        "    with socket.create_connection((ip, port)): return True\n"
        "def serve():\n"
        "    port = 8099\n"
        "    srv = socket.socket(); srv.bind(('', port)); srv.listen()\n"
        "def odd():\n"
        "    port = 1234\n"
        "    return port\n",
    )
    (tmp_path / "const.py").write_text("DEFAULT_MODBUS_PORT = 502\n")
    (tmp_path / "hub.py").write_text(
        "from .const import DEFAULT_MODBUS_PORT\n"
        "async def go(h):\n"
        "    c = AsyncModbusTcpClient(h, port=DEFAULT_MODBUS_PORT)\n"
        "    await c.connect()\n"
    )
    r = endpoints.run(_target(tmp_path))
    dirs = {int(f.key): f.attrs.get("directions") for f in r.facts if f.kind == "port"}
    assert dirs == {80: ["out"], 8099: ["in"], 1234: None, 502: ["out"]}


# --- (0.15, his decision 2026-11-20) shared hosting is the app's own only under its owner ---


def _shared(tmp_path, *urls):
    lines = "".join(f'U{i} = "{u}"\n' for i, u in enumerate(urls))
    root = _write(tmp_path / "pkg", "const.py", lines)
    target = _target(root, repo="acme/acme-weather")
    return _hosts(endpoints.run(target))


def test_github_under_the_owner_is_the_app_s_own(tmp_path):
    got = _shared(tmp_path, "https://github.com/acme/acme-weather/issues",
                  "https://raw.githubusercontent.com/acme/acme-weather/main/x.json")  # fmt: skip
    assert got == {"github.com": "declared", "raw.githubusercontent.com": "declared"}


def test_anyone_else_s_path_on_shared_hosting_is_not(tmp_path):
    got = _shared(tmp_path, "https://github.com/acme/acme-weather",
                  "https://github.com/someone-else/tool/releases",
                  "https://raw.githubusercontent.com/someone-else/x/main/y.py",
                  "https://gitlab.com/acme2/x")  # fmt: skip
    assert got == {"github.com": "infrastructure", "raw.githubusercontent.com": "infrastructure",
                   "gitlab.com": "infrastructure"}  # fmt: skip


def test_a_translation_key_is_not_a_site(tmp_path):
    """(0.15, issue #14 bug 4) `Msg("timeline.when.at")` names a key of the app's own
    translation catalog; a scheme-less name that is no JSON key stays a site."""
    root = _write(
        tmp_path / "acme_weather",
        "views.py",
        'def at(i18n, t):\n    return i18n.Msg("timeline.when.at", t=t)\n\n'
        'BACKUP = "api.acme-weather.at"\n',
    )
    i18n = root / "frontend" / "i18n"
    i18n.mkdir(parents=True)
    (i18n / "nl.json").write_text('{"timeline.when.at": "{t}", "timeline": {"x.y": 1}}')
    hosts = {f.key for f in endpoints.run(_target(root)).facts if f.kind == "host"}
    assert "timeline.when.at" not in hosts
    assert "api.acme-weather.at" in hosts
