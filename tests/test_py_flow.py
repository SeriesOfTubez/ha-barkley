"""(0.15, his yes 2026-11-22) Where a run-time address comes from, where the app's own
logins go, and what it hands to a library (py_flow, read through py_requests).

Synthetic integrations with the shapes seen in the full Marketplace run; every host is
.invalid. Parse only: nothing here imports or runs the files it writes.
"""

from __future__ import annotations

import textwrap
import time
from pathlib import Path

import pytest

from sniff_test.analyzers import py_flow, py_requests
from sniff_test.analyzers.py_flow import Origin


def _app(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "custom_components" / "acme"
    root.mkdir(parents=True)
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(textwrap.dedent(text))
    return root


def _origins(root: Path) -> dict[str, set[Origin]]:
    """file:line -> origins of each request whose address isn't in the code."""
    return {f"{r.file}:{r.line}": set(r.origins)
            for r in py_requests.requests_in(root) if r.host is None}  # fmt: skip


# --- where the address comes from -------------------------------------------------------

API = """\
    from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME

    class Api:
        def __init__(self, session, host, username, password):
            self._session = session
            self._base = f"http://{host}:8080"
            self._user = username
            self._password = password
            self._token = None

        async def login(self):
            async with self._session.post(f"{self._base}/login",
                                          json={"user": self._user, "pass": self._password}) as r:
                data = await r.json()
            self._token = data["access_token"]

        async def status(self):
            return await self._session.get(f"{self._base}/status",
                                           headers={"Authorization": f"Bearer {self._token}"})
    """
INIT = """\
    from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
    from .api import Api

    async def async_setup_entry(hass, entry):
        api = Api(hass.session, entry.data[CONF_HOST], entry.data[CONF_USERNAME],
                  entry.data[CONF_PASSWORD])
        await api.login()
    """


def test_address_from_setup_through_the_constructor(tmp_path):
    # entry.data[CONF_HOST] -> Api(host) -> self._base = f"http://{host}…" -> the request
    got = _origins(_app(tmp_path, {"api.py": API, "__init__.py": INIT}))
    assert list(got.values()) == [{Origin(py_flow.SETUP, "host")}] * 2


def test_the_login_and_the_answer_token_are_followed(tmp_path):
    reqs = py_requests.requests_in(_app(tmp_path, {"api.py": API, "__init__.py": INIT}))
    by_line = {r.line: r for r in reqs}
    login = next(r for r in reqs if r.method == "POST")
    status = next(r for r in reqs if r.method == "GET")
    # the setup's password and user name go to the login request
    assert login.logins == ("username", "password")
    # the token read from the login answer goes to the status request; the login answer's
    # address isn't in the code, so the site is "?"
    assert status.tokens == ("?",)
    assert status.logins == ()
    assert by_line


def test_discovery_ha_address_and_a_list_in_the_code(tmp_path):
    flow = """\
        SERVERS = {"eu": "https://eu.api.acme.invalid", "us": "https://us.api.acme.invalid"}

        class Flow:
            async def async_step_zeroconf(self, discovery_info):
                self._host = discovery_info.host
                await self._session.get(f"http://{self._host}/info", timeout=5)

            async def regional(self, region):
                await self._session.get(SERVERS[region] + "/v1", timeout=5)

            async def back_to_ha(self):
                await self._session.post(get_url(self.hass) + "/api/webhook/x", json={})
        """
    got = sorted(_origins(_app(tmp_path, {"config_flow.py": flow})).values(), key=str)
    kinds = sorted(next(iter(o)).kind for o in got)
    assert kinds == [py_flow.DISCOVERY, py_flow.HA, py_flow.LIST]
    listed = next(next(iter(o)) for o in got if next(iter(o)).kind == py_flow.LIST)
    assert listed.detail == "eu.api.acme.invalid,us.api.acme.invalid"


def test_an_address_from_a_server_answer_names_the_site(tmp_path):
    code = """\
        class Cloud:
            async def stream(self):
                async with self._session.get("https://api.acme.invalid/v1/camera") as r:
                    info = await r.json()
                await self._session.get(info["stream"]["url"], timeout=5)
        """
    got = _origins(_app(tmp_path, {"cloud.py": code}))
    assert list(got.values()) == [{Origin(py_flow.ANSWER, "url", "api.acme.invalid")}]


def test_format_strings_and_a_session_base_url(tmp_path):
    code = """\
        from aiohttp import ClientSession

        class C:
            def __init__(self, entry):
                self._base = entry.data["url"]
                self._http = ClientSession(base_url=entry.data["server"])

            async def a(self):
                await self._http.get("%s/me" % self._base, timeout=5)

            async def b(self):
                await self._http.get("{}/v2".format(self._base), timeout=5)

            async def c(self, serial):
                # a path: the session adds the site it was made with
                await self._http.get(f"/api/robot/{serial}", timeout=5)
        """
    got = _origins(_app(tmp_path, {"c.py": code}))
    assert [got[k] for k in sorted(got, key=lambda k: int(k.split(":")[1]))] == [
        {Origin(py_flow.SETUP, "url")},
        {Origin(py_flow.SETUP, "url")},
        {Origin(py_flow.SETUP, "server")},
    ]


def test_unknown_when_nothing_says(tmp_path):
    code = """\
        async def fetch(session, url):
            return await session.get(url, timeout=5)
        """
    # a function nobody in the app calls: the address could be anything
    assert list(_origins(_app(tmp_path, {"x.py": code})).values()) == [{Origin(py_flow.UNKNOWN)}]


# --- logins handed to a library -----------------------------------------------------------


def test_a_login_and_an_address_handed_to_a_library(tmp_path):
    # the shape of the case he reported (2026-11-22): the app makes no request itself; the
    # library gets the login and the site's address
    code = """\
        from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
        from vendor_api import VendorClient

        class Coordinator:
            def __init__(self, hass, entry):
                self.client = VendorClient(
                    username=entry.data[CONF_USERNAME],
                    password=entry.data[CONF_PASSWORD],
                    base_url=entry.data.get("base_url", "https://monitor.vendor.invalid"),
                )

            async def refresh(self):
                await self.client.login()
        """
    reqs, hand = py_requests.read_flow(_app(tmp_path, {"coordinator.py": code}))
    assert reqs == []
    assert [(h.library, h.call, h.logins) for h in hand] == [
        ("vendor_api", "VendorClient", ("username", "password"))
    ]
    ((arg, got),) = hand[0].addresses
    assert arg == "base_url"
    assert set(got) == {
        Origin(py_flow.SETUP, "base_url"),
        Origin(py_flow.SITE, "monitor.vendor.invalid"),
    }


def test_a_method_of_a_library_object_given_the_password(tmp_path):
    code = """\
        import vendor_api

        class Hub:
            def __init__(self, entry):
                self._client = vendor_api.Client()
                self._pw = entry.data["password"]

            async def start(self):
                await self._client.authenticate(self._pw)
        """
    _reqs, hand = py_requests.read_flow(_app(tmp_path, {"hub.py": code}))
    assert [(h.library, h.call, h.logins) for h in hand] == [
        ("vendor_api", "authenticate", ("password",))
    ]


def test_python_and_home_assistant_are_not_libraries_here(tmp_path):
    code = """\
        import logging
        from homeassistant.helpers.storage import Store

        def setup(hass, entry):
            logging.getLogger(__name__).debug("user %s", entry.data["password"])
            Store(hass, 1, entry.data["token"])
        """
    assert py_requests.read_flow(_app(tmp_path, {"s.py": code}))[1] == []


# --- hostile input stays bounded --------------------------------------------------------------


def test_a_long_chain_of_names_stays_within_the_budget(tmp_path):
    # 3,000 names each defined from the one before, and a cycle at the end: the question
    # stops at its step budget
    lines = ["x0 = x2999"] + [f"x{i} = x{i - 1}" for i in range(1, 3000)]
    code = "def go(session):\n" + "".join(f"    {s}\n" for s in lines)
    code += "    session.get(x2999, timeout=5)\n"
    root = _app(tmp_path, {"chain.py": code})
    start = time.perf_counter()
    got = _origins(root)
    assert time.perf_counter() - start < 10
    assert list(got.values()) == [{Origin(py_flow.UNKNOWN)}]


@pytest.mark.parametrize("n", [400])
def test_many_callers_fan_out_within_the_budget(tmp_path, n):
    code = "async def req(session, url):\n    await session.get(url, timeout=5)\n"
    code += "".join(f"async def c{i}(session):\n    await req(session, c{i + 1}(session))\n"
                    for i in range(n))  # fmt: skip
    start = time.perf_counter()
    py_requests.read_flow(_app(tmp_path, {"fan.py": code}))
    assert time.perf_counter() - start < 10


def test_the_report_keeps_hand_offs_and_origins(tmp_path):
    # an app with no request of its own still gets a requests section for its hand-off
    code = """\
        from vendor_api import VendorClient

        def make(entry):
            return VendorClient(password=entry.data["password"], host=entry.data["host"])
        """
    reqs, hand = py_requests.read_flow(_app(tmp_path, {"c.py": code}))
    s = py_requests.summary(reqs, frozenset(), hand)
    assert s is not None and s["total"] == 0
    assert s["handoffs"][0]["library"] == "vendor_api"
    assert s["handoffs"][0]["logins"] == ["password"]
    assert s["handoffs"][0]["addresses"] == [
        {"arg": "host", "from": [{"kind": "setup", "detail": "host"}]}
    ]
    # a hand-off inside a test script Home Assistant never loads isn't the app's
    assert py_requests.summary(reqs, frozenset({"c.py"}), hand) is None
    # each request shape says where its address comes from
    root = _app(tmp_path / "b", {"api.py": API, "__init__.py": INIT})
    shapes = py_requests.summary(py_requests.requests_in(root))["elsewhere"]
    assert {tuple(map(str, x["from"])) for x in shapes} == {
        ("{'kind': 'setup', 'detail': 'host'}",)
    }
    assert any(x.get("logins") == ["username", "password"] for x in shapes)


# --- shapes from the hand check of 2026-11-22 (each was read wrong before) ------------------


def test_a_shared_helper_carries_the_login_only_where_the_login_call_passes_it(tmp_path):
    code = """\
        class Api:
            def __init__(self, session, entry):
                self._session = session
                self._pw = entry.data["password"]
                self._token = None

            async def _request(self, url, body=None):
                return await self._session.post(url, json=body,
                                          headers={"Authorization": f"Bearer {self._token}"})

            async def login(self):
                data = await (await self._request("https://api.acme.invalid/login",
                                                  {"pw": self._pw})).json()
                self._token = data["token"]

            async def devices(self):
                return await self._request("https://api.acme.invalid/devices", {"all": 1})
        """
    reqs = py_requests.requests_in(_app(tmp_path, {"api.py": code}))
    by_url = {r.line: r for r in reqs}
    login = next(r for r in reqs if r.line == 12)
    devices = next(r for r in reqs if r.line == 17)
    assert login.logins == ("password",)
    assert devices.logins == ()  # before: the login call's password, pooled
    assert devices.tokens == ("api.acme.invalid",)
    assert by_url


def test_a_library_answer_is_not_the_secret_that_signed_it(tmp_path):
    code = """\
        import vendor_store

        class Up:
            def __init__(self, entry):
                self._secret = entry.data["api_secret"]

            def upload(self, blob):
                return vendor_store.put(blob, key=self._secret)["hash"]

            async def publish(self, session, blob):
                await session.post("https://feed.acme.invalid/x", json={"h": self.upload(blob)})
        """
    reqs = py_requests.requests_in(_app(tmp_path, {"up.py": code}))
    assert [r.logins for r in reqs] == [()]


def test_one_key_of_a_stored_dict_is_that_value_only(tmp_path):
    init = """\
        DOMAIN = "acme"

        async def async_setup_entry(hass, entry):
            hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
                "base_url": entry.data["url"], "user": entry.data["username"]}
        """
    sensor = """\
        DOMAIN = "acme"

        async def poll(hass, entry, session):
            conf = hass.data[DOMAIN][entry.entry_id]
            await session.get(conf["base_url"] + "/state", timeout=5)
        """
    got = _origins(_app(tmp_path, {"__init__.py": init, "sensor.py": sensor}))
    assert list(got.values()) == [{Origin(py_flow.SETUP, "url")}]


def test_a_host_handed_to_a_library_by_position(tmp_path):
    code = """\
        from vendor_ir import IrDevice

        def make(config):
            return IrDevice(config.get("host"), config.get("token"))

        async def async_setup_platform(hass, config, add, discovery_info=None):
            make(config)
        """
    _reqs, hand = py_requests.read_flow(_app(tmp_path, {"remote.py": code}))
    assert [(h.call, h.logins) for h in hand] == [("IrDevice", ("token",))]
    assert hand[0].addresses == [("", (Origin(py_flow.SETUP, "host"),))]


def test_a_test_script_is_not_where_an_address_comes_from(tmp_path):
    code = """\
        async def fetch(session, base):
            return await session.get(base + "/v1", timeout=5)
        """
    test = """\
        async def test_fetch(session):
            await fetch(session, "https://fixture.acme.invalid")
        """
    got = _origins(_app(tmp_path, {"api.py": code, "tests/test_api.py": test}))
    assert list(got.values()) == [{Origin(py_flow.UNKNOWN)}]


# --- second hand check (2026-11-22) ------------------------------------------------------------


def test_a_value_written_back_adds_to_what_was_stored(tmp_path):
    # the helper writes a fresh cookie back after logging in again: the stored one (from
    # setup) still counts, the write is one more value
    init = """\
        DOMAIN = "acme"

        async def async_setup_entry(hass, entry):
            hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
                "cookie": entry.data["session_cookie"], "partition": entry.data["partition"]}
        """
    api = """\
        DOMAIN = "acme"

        async def call(hass, entry_id, url, session):
            cfg = hass.data[DOMAIN][entry_id]
            headers = {"Cookie": cfg["cookie"]}
            resp = await session.get(url, headers=headers)
            if resp.status == 401:
                cfg["cookie"] = await relogin(session)
            return resp

        async def relogin(session):
            return "fresh"
        """
    reqs = py_requests.requests_in(_app(tmp_path, {"__init__.py": init, "api.py": api}))
    assert [r.logins for r in reqs] == [("session_cookie",)]  # not "partition"


def test_a_dict_made_from_itself_reads_the_parameter_and_cast_is_its_value(tmp_path):
    code = """\
        from typing import cast
        from vendor_charger import Charger

        def connect(data):
            data = {**data, "timeout": 5}
            return Charger(host=data.get("ip_address"), password=data.get("password"))

        def setup(entry):
            connect(cast(dict, entry.data))
        """
    _reqs, hand = py_requests.read_flow(_app(tmp_path, {"c.py": code}))
    assert [(h.call, h.logins) for h in hand] == [("Charger", ("password",))]
    assert hand[0].addresses == [("host", (Origin(py_flow.SETUP, "ip_address"),))]


def test_a_bare_host_name_and_a_signing_helper(tmp_path):
    code = """\
        from vendor_meter import Account
        from vendor_sign import sign_url

        def host_for(hass):
            return "meter.acme.invalid" if hass.config.country == "CA" else "meter.acme.example"

        def make(hass, data, url):
            sign_url(url, data["password"])  # hashes the URL: not somewhere it connects
            return Account(eow_hostname=host_for(hass), password=data["password"])

        async def async_step_user(self, user_input):
            make(self.hass, user_input, "https://login.acme.invalid/x")
        """
    _reqs, hand = py_requests.read_flow(_app(tmp_path, {"flow.py": code}))
    by = {h.call: h for h in hand}
    assert by["Account"].addresses == [
        ("eow_hostname", (Origin(py_flow.LIST, "meter.acme.example,meter.acme.invalid"),))
    ]
    assert by["sign_url"].addresses == []  # a URL given to a hashing helper isn't an address


def test_bare_host_names_are_not_file_names():
    assert py_flow._bare_host("api.acme.example") == "api.acme.example"
    assert py_flow._bare_host("config.json") == ""
    assert py_flow._bare_host("/api/x") == ""
    assert py_flow._bare_host("a" * 70 + ".example") == ""


def test_an_app_importing_its_own_file_by_its_full_path(tmp_path):
    # (2026-11-22, a real integration) `from custom_components.<its folder>.client.wire import
    # URL_LOGIN`, where URL_LOGIN = urljoin(BASE, "/users/auth/login"): the request reader only
    # followed relative imports, so the address was "couldn't trace" and the picture had no site
    root = _app(tmp_path, {
        "client/__init__.py": "",
        "client/wire.py": """\
            from urllib.parse import urljoin
            API_BASE = "https://api.vendor.invalid"
            URL_LOGIN = urljoin(API_BASE, "/users/auth/login")
            """,
        "client/transport.py": """\
            import aiohttp
            from custom_components.acme.client.wire import URL_LOGIN

            class Transport:
                def __init__(self, creds):
                    self._creds = creds

                async def login(self):
                    async with aiohttp.ClientSession() as session:
                        async with session.post(url=URL_LOGIN, json={
                                "email": self._creds.email,
                                "password": self._creds.password}) as r:
                            return await r.json()
            """,
    })  # fmt: skip
    (req,) = py_requests.requests_in(root)
    assert (
        req.host == "api.vendor.invalid"
        or Origin(py_flow.SITE, "api.vendor.invalid") in req.origins
    )
