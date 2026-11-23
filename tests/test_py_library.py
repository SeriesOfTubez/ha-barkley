"""(0.15, his yes 2026-11-22) Where a login goes after the app hands it to a library
(py_library, with py_flow's entry points).

Synthetic apps and libraries shaped like the 62 apps with hand-offs in the full
Marketplace run; every host is .invalid and every name is made up. The libraries are
written as files and read as text: nothing is imported, installed or run. The download step
is tested with the network replaced by a local file (fixtures never reach a real server).
"""

from __future__ import annotations

import textwrap
import time
import zipfile
from pathlib import Path

import pytest

from sniff_test.analyzers import py_flow, py_library, py_requests
from sniff_test.analyzers.py_flow import Origin
from sniff_test.analyzers.python_deps import Resolution, ResolvedPackage
from sniff_test.deps.uv import Artifact
from sniff_test.fetch import http

SETUP = py_flow.SETUP


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(textwrap.dedent(text))
    return root


def _handoffs(tmp_path: Path, app: str) -> list[py_flow.Handoff]:
    root = _write(tmp_path / "custom_components" / "acme", {"__init__.py": app})
    return py_requests.read_flow(root)[1]


def _inside(tmp_path: Path, app: str, lib: dict[str, str], name: str = "vendor_api") -> dict:
    """The app's one hand-off to `name`, read inside the library written from `lib`."""
    folder = _write(tmp_path / "lib" / name, lib)
    (h,) = [h for h in _handoffs(tmp_path, app) if h.library == name]
    return py_library.read(h, py_library._Lib(name, "1.0", folder))


def _sends(got: dict) -> list[tuple[object, list[str]]]:
    """(site, or where the address comes from; the logins) for each request followed."""
    return [(s.get("site") or tuple(f"{o['kind']}:{o['detail']}" for o in s["from"]),
             s.get("logins", [])) for s in got.get("sends", [])]  # fmt: skip


# --- the library's own site -----------------------------------------------------------------

APP = """\
    from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
    from vendor_api import VendorClient

    async def async_setup_entry(hass, entry):
        client = VendorClient(entry.data[CONF_USERNAME], entry.data[CONF_PASSWORD])
        await client.login()
    """
CLIENT = """\
    BASE = "https://cloud.vendor.invalid/api"

    class VendorClient:
        def __init__(self, username, password, session=None):
            self._user = username
            self._password = password
            self._session = session

        async def login(self):
            return await self._session.post(f"{BASE}/login",
                                            json={"user": self._user, "pw": self._password})

        async def check_update(self):  # the library's own request: not what the app sent
            return await self._session.get("https://updates.vendor.invalid/latest")
    """


def test_the_login_is_followed_to_the_librarys_site(tmp_path):
    got = _inside(tmp_path, APP, {"__init__.py": CLIENT})
    assert got["state"] == "followed"
    # the update check carries nothing the app passed in, so it isn't listed
    assert _sends(got) == [("cloud.vendor.invalid", ["username", "password"])]


def test_a_library_split_into_files_imports_itself_absolutely(tmp_path):
    # `from vendor_api.const import BASE` inside vendor_api is its own file
    lib = {
        "__init__.py": "from vendor_api.client import VendorClient\n",
        "const.py": 'BASE = "https://cloud.vendor.invalid/api"\n',
        "client.py": CLIENT.replace(
            'BASE = "https://cloud.vendor.invalid/api"', "from vendor_api.const import BASE"
        ),
    }
    assert _sends(_inside(tmp_path, APP, lib)) == [
        ("cloud.vendor.invalid", ["username", "password"])
    ]


def test_requests_not_linked_to_what_the_app_passed_say_so(tmp_path):
    lib = """\
        class VendorClient:
            def __init__(self, username, password):
                self._u, self._p = username, password

            async def news(self, session):
                return await session.get("https://news.vendor.invalid/feed")
        """
    got = _inside(tmp_path, APP, {"__init__.py": lib})
    assert got == {"package": "vendor_api", "version": "1.0", "state": "requests",
                   "requests": 1, "sites": ["news.vendor.invalid"]}  # fmt: skip


# --- the address the app passes ---------------------------------------------------------------

APP_HOST = """\
    from homeassistant.const import CONF_HOST, CONF_PASSWORD
    from vendor_api import Inverter

    async def async_setup_entry(hass, entry):
        kwargs = {"password": entry.data[CONF_PASSWORD]}
        inverter = Inverter(host=entry.data[CONF_HOST], **kwargs)
    """


def test_a_dataclass_gets_the_host_and_kwargs_the_app_passed(tmp_path):
    # a dataclass has no __init__ to read: its fields are the constructor; `**kwargs` is a
    # dict the app spells out; URL(base).join(URL(path)) starts with the base
    lib = """\
        from dataclasses import dataclass
        from yarl import URL

        @dataclass
        class Inverter:
            host: str
            password: str | None = None
            port: int = 80

            async def request(self, uri):
                url = URL.build(scheme="http", host=self.host).join(URL(uri))
                return await self.session.get(url, auth=("admin", self.password))

            async def status(self):
                return await self.request("status.json")
        """
    got = _inside(tmp_path, APP_HOST, {"__init__.py": lib})
    assert _sends(got) == [((f"{SETUP}:host",), ["password"])]


def test_a_library_default_answers_when_the_app_passes_nothing(tmp_path):
    lib = """\
        class VendorClient:
            def __init__(self, username, password, base_url="https://eu.vendor.invalid"):
                self._base = base_url
                self._auth = (username, password)

            async def login(self, session):
                return await session.post(self._base + "/login", auth=self._auth)
        """
    assert _sends(_inside(tmp_path, APP, {"__init__.py": lib})) == [
        ((f"{py_flow.SITE}:eu.vendor.invalid",), ["username", "password"])
    ]


# --- the shapes the measurement found -------------------------------------------------------


def test_a_sessions_default_headers_go_with_every_request(tmp_path):
    app = """\
        from vendor_api import TrackerClient

        async def async_setup_entry(hass, entry):
            client = TrackerClient(access_token=entry.data["api_token"])
        """
    lib = """\
        import aiohttp

        class TrackerClient:
            def __init__(self, access_token):
                self._token = access_token
                self._session = None

            async def _get_session(self):
                if self._session is None:
                    session = aiohttp.ClientSession(
                        headers={"Authorization": f"Bearer {self._token}"})
                    self._session = session
                return self._session

            async def readings(self):
                session = await self._get_session()
                return await session.get("https://api.tracker.invalid/v1/readings")
        """
    assert _sends(_inside(tmp_path, app, {"__init__.py": lib})) == [
        ("api.tracker.invalid", ["api_token"])
    ]


def test_an_object_passing_itself_through_an_import_alias(tmp_path):
    # `API(session=self)` where API is `HeaterApi` imported under another name; the key
    # is added with `self.headers.update(...)`
    app = """\
        from vendor_api import Heater

        async def async_setup_entry(hass, entry):
            heater = Heater(entry.data["api_key"])
        """
    lib = {
        "__init__.py": """\
            from .api import HeaterApi as API

            class Heater:
                def __init__(self, subscription_key):
                    self.subscription_key = subscription_key
                    self.api = API(owner=self)
            """,
        "api.py": """\
            class HeaterApi:
                def __init__(self, owner=None):
                    self.owner = owner
                    self.headers = {"Accept": "*/*"}

                async def devices(self, websession):
                    self.headers.update({"Subscription-Key": self.owner.subscription_key})
                    return await websession.get("https://api.heater.invalid/devices",
                                                headers=self.headers)
            """,
    }
    assert _sends(_inside(tmp_path, app, lib)) == [("api.heater.invalid", ["api_key"])]


def test_a_base_class_constructor_gets_what_super_passes_not_the_apps_arguments(tmp_path):
    # the class called has its own __init__; the base's (session, base_url) must not take
    # the app's username and password by position (the hand check: a password read as an
    # address)
    app = """\
        from vendor_api import SimpleAuth

        async def async_setup_entry(hass, entry):
            auth = SimpleAuth(entry.data["username"], entry.data["password"], hass.session)
        """
    lib = """\
        BASE = "https://cloud.meter.invalid"

        class AbstractAuth:
            def __init__(self, session, base_url=BASE):
                self._session = session
                self._base_url = base_url

            async def request(self, method, url, **kwargs):
                return await self._session.request(method, f"{self._base_url}/{url}", **kwargs)

        class SimpleAuth(AbstractAuth):
            def __init__(self, username, password, session):
                super().__init__(session)
                self._username = username
                self._password = password

            async def token(self):
                return await self.request("post", "token",
                                          data={"u": self._username, "p": self._password})
        """
    got = _inside(tmp_path, app, {"__init__.py": lib})
    assert _sends(got) == [((f"{py_flow.SITE}:cloud.meter.invalid",), ["username", "password"])]


def test_a_module_function_named_like_a_method(tmp_path):
    # `def login(client)` beside the method `login` that calls it as `login(self)`
    lib = {
        "__init__.py": "from .client import VendorClient\n",
        "auth.py": """\
            def login(client):
                return client._http.post("https://login.vendor.invalid/form",
                                         data={"username": client.username,
                                               "password": client.password})
            """,
        "client.py": """\
            from .auth import login

            class VendorClient:
                def __init__(self, username, password):
                    self.username = username
                    self.password = password

                def login(self):
                    login(self)
            """,
    }
    assert _sends(_inside(tmp_path, APP, lib)) == [
        ("login.vendor.invalid", ["username", "password"])
    ]


def test_a_typed_parameter_with_no_caller_is_that_object(tmp_path):
    # the app makes Account(...) and hands it to another class: `account: Account`
    app = """\
        from vendor_api import Account

        async def async_setup_entry(hass, entry):
            account = Account(username=entry.data["username"], password=entry.data["password"])
        """
    lib = """\
        class Account:
            def __init__(self, username, password):
                self.username = username
                self.password = password

        class Client:
            def __init__(self, websession, account: Account):
                self.websession = websession
                self.account = account

            async def authenticate(self):
                return await self.websession.post(
                    "https://api.meter.invalid/login",
                    data={"user": self.account.username, "pass": self.account.password})
        """
    assert _sends(_inside(tmp_path, app, {"__init__.py": lib})) == [
        ("api.meter.invalid", ["username", "password"])
    ]


def test_a_method_of_an_object_the_library_made(tmp_path):
    app = """\
        from vendor_api import VendorClient

        async def async_setup_entry(hass, entry):
            client = VendorClient()
            await client.send_code(entry.data["pin"])
        """
    lib = """\
        class VendorClient:
            async def send_code(self, pin):
                return await self.session.post("https://auth.vendor.invalid/2fa",
                                               json={"pin": pin})
        """
    assert _sends(_inside(tmp_path, app, {"__init__.py": lib})) == [
        ("auth.vendor.invalid", ["pin"])
    ]


# --- no web request in it ---------------------------------------------------------------------


def test_an_mqtt_library_says_how_it_connects(tmp_path):
    app = """\
        from vendor_api import Client

        async def async_setup_entry(hass, entry):
            c = Client()
            c.username_pw_set(entry.data["username"], entry.data["password"])
        """
    lib = """\
        import socket
        import urllib.parse
        from paho.mqtt import client

        class Client:
            def username_pw_set(self, username, password):
                self._u, self._p = username, password
        """
    got = _inside(tmp_path, app, {"__init__.py": lib})
    # urllib.parse is no web request; MQTT says more than "a direct network connection"
    assert (got["state"], got["other"]) == ("no_requests", ["MQTT"])


def test_a_library_with_no_network_code_lists_nothing(tmp_path):
    app = """\
        from vendor_api import sign

        async def async_setup_entry(hass, entry):
            sig = sign(entry.data["private_key"], b"x")
        """
    lib = """\
        import hashlib

        def sign(private_key, data):
            return hashlib.sha256(private_key.encode() + data).hexdigest()
        """
    got = _inside(tmp_path, app, {"__init__.py": lib})
    assert (got["state"], got["other"], got["uses"]) == ("no_requests", [], [])


# --- the download ---------------------------------------------------------------------------


def _wheel(tmp_path: Path, files: dict[str, str]) -> Path:
    path = tmp_path / "vendor_api-1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as z:
        for rel, text in files.items():
            z.writestr(rel, textwrap.dedent(text))
        z.writestr("vendor_api-1.0.dist-info/METADATA", "Name: vendor-api\n")
    return path


def _resolution(name: str = "vendor-api", url: str = "https://files.invalid/w.whl") -> Resolution:
    pkg = ResolvedPackage(name, "1.0", direct=True)
    art = Artifact(url, "vendor_api-1.0-py3-none-any.whl", None, "wheel")
    pkg.artifacts[art.filename] = art
    return Resolution(packages={(name, "1.0"): pkg})


def test_the_wheel_of_the_resolved_version_is_unpacked_and_read(tmp_path, monkeypatch):
    whl = _wheel(tmp_path, {"vendor_api/__init__.py": CLIENT})
    asked = []

    def fake_download(url, dest, sha256, max_bytes=0):  # no network in tests
        asked.append((url, max_bytes))
        dest.write_bytes(whl.read_bytes())
        return ""

    monkeypatch.setattr(http, "download", fake_download)
    hs = _handoffs(tmp_path, APP)
    py_library.read_inside(hs, _resolution(), tmp_path / "work", offline=False)
    assert asked == [("https://files.invalid/w.whl", py_library.MAX_BYTES)]
    assert hs[0].inside["package"] == "vendor-api"
    assert _sends(hs[0].inside) == [("cloud.vendor.invalid", ["username", "password"])]
    # the report carries it
    assert hs[0].as_dict()["inside"]["state"] == "followed"


def test_a_failed_download_is_no_scan_result(tmp_path, monkeypatch):
    def refused(url, dest, sha256, max_bytes=0):
        raise http.HttpError("429 Too Many Requests")

    monkeypatch.setattr(http, "download", refused)
    hs = _handoffs(tmp_path, APP)
    py_library.read_inside(hs, _resolution(), tmp_path / "work", offline=False)
    assert hs[0].inside == {"state": "unread", "why": "download failed"}


@pytest.mark.parametrize(
    ("resolution", "offline", "why"),
    [
        (None, True, "offline"),
        (Resolution(), False, "not one of its requirements"),  # comes with HA or another package
    ],
)
def test_unread_libraries_say_why(tmp_path, monkeypatch, resolution, offline, why):
    monkeypatch.setattr(http, "download", lambda *a, **k: pytest.fail("no download"))
    hs = _handoffs(tmp_path, APP)
    py_library.read_inside(hs, resolution, tmp_path / "work", offline=offline)
    assert hs[0].inside == {"state": "unread", "why": why}


def test_a_package_with_no_wheel_is_not_read(tmp_path, monkeypatch):
    monkeypatch.setattr(http, "download", lambda *a, **k: pytest.fail("no download"))
    res = _resolution()
    pkg = next(iter(res.packages.values()))
    pkg.artifacts = {"vendor_api-1.0.tar.gz": Artifact("u", "vendor_api-1.0.tar.gz", None, "sdist")}
    hs = _handoffs(tmp_path, APP)
    py_library.read_inside(hs, res, tmp_path / "work", offline=False)
    assert hs[0].inside == {"state": "unread", "why": "no wheel"}


# --- the tracer pieces on their own ---------------------------------------------------------


def test_join_on_a_separator_is_its_list_and_on_a_url_its_base(tmp_path):
    app = """\
        import aiohttp
        from yarl import URL

        async def async_setup_entry(hass, entry):
            base = entry.data["host"]
            async with aiohttp.ClientSession() as session:
                await session.post("/".join([base, "x"]), json={})
                await session.post(URL(base).join(URL("x")), json={})
                await session.post("/".join(["x", entry.data["path"]]), json={})
        """
    root = _write(tmp_path / "custom_components" / "acme", {"__init__.py": app})
    got = [set(r.origins) for r in py_requests.requests_in(root)]
    assert got == [{Origin(SETUP, "host")}, {Origin(SETUP, "host")}, {Origin(SETUP, "path")}]


# --- hostile input stays bounded --------------------------------------------------------------


def test_a_long_chain_and_a_wide_fan_in_a_library_stay_bounded(tmp_path):
    chain = "\n".join(f"        v{i} = v{i - 1}" for i in range(1, 3000))
    fan = "\n".join(f"class C{i}(VendorClient):\n    pass" for i in range(400))
    lib = f"""\
class VendorClient:
    def __init__(self, username, password):
        v0 = password
{chain}
        self.p = v2999

    async def login(self, s):
        return await s.post("https://x.invalid", data=self.p)

{fan}
"""
    start = time.perf_counter()
    got = _inside(tmp_path, APP, {"__init__.py": lib})
    assert time.perf_counter() - start < 10
    assert got["state"] in ("followed", "requests")
