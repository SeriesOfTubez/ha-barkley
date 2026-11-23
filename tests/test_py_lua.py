"""(0.15, his decision 2026-11-23) Lua an integration runs through lupa: where it comes from
and whether it can reach Python (analyzers/py_lua). Made-up apps; every site is .invalid.
Nothing here is imported or run: the analyzer only parses."""

from __future__ import annotations

import time
from pathlib import Path

from sniff_test import readings, ui
from sniff_test.analyzers import py_lua
from sniff_test.report.json_report import finding_json

# The shapes of a real cloud integration (the hand check of 2026-11-23): a base cloud class
# whose download method only raises, two clouds that each download the device's Lua from an
# address the cloud's answer gives and write it to a file, a device made with that file, and
# a codec whose classmethod hands the class to a worker thread, whose constructor passes the
# file to its base, which runs it with dofile in a runtime made with lupa's defaults.
CLOUD = """
import aiofiles

SERVERS = {
    "one": {"api_url": "https://api.one.invalid/proxy?alias="},
    "two": {"api_url": "https://api.two.invalid/proxy?alias="},
}


class Cloud:
    def __init__(self, session, api_url):
        self._session = session
        self._api_url = api_url

    async def _api_request(self, endpoint, data):
        url = self._api_url + endpoint
        r = await self._session.request("POST", url, data=data)
        response = await r.json()
        return response["data"]

    async def download_lua(self, path, device_type):
        raise NotImplementedError()


class OneCloud(Cloud):
    async def download_lua(self, path, device_type):
        fnm = None
        if response := await self._api_request(endpoint="/lua/get", data={"t": device_type}):
            fnm = f"{path}/{response['fileName']}"
            res = await self._session.get(response["url"])
            if res.status == 200:
                lua = await res.text()
                stream = 'local bit = require "bit"\\n' + self._decrypt(lua)
                async with aiofiles.open(fnm, "w", encoding="utf-8") as fp:
                    await fp.write(stream)
        return fnm


class TwoCloud(Cloud):
    async def _api_request(self, endpoint, data):
        return await super()._api_request(endpoint, data)

    async def download_lua(self, path, device_type):
        fnm = None
        if response := await self._api_request(endpoint="/v2/lua/get", data={}):
            res = await self._session.get(response["url"])
            if res.status == 200:
                lua = await res.text()
                fnm = f"{path}/{response['fileName']}"
                async with aiofiles.open(fnm, "w") as fp:
                    await fp.write(self._decrypt(lua))
        return fnm


def make_cloud(session, which):
    if which == "one":
        return OneCloud(session, SERVERS["one"]["api_url"])
    return TwoCloud(session, SERVERS["two"]["api_url"])
"""
RUNTIME = """
import asyncio
import os

import lupa


class LuaRuntime:
    def __init__(self, file):
        self._rt = lupa.lua51.LuaRuntime()
        self._rt.execute("print = function(...) end")
        lua_dir = os.path.dirname(file)
        self._rt.execute(f'package.path = package.path .. ";{lua_dir}/?.lua"')
        self._rt.execute('require "cjson"')
        self._rt.execute(f'dofile("{file}")')
        self._decode = self._rt.eval("function(p) return decode(p) end")


class Codec(LuaRuntime):
    def __init__(self, file, device_type=None):
        super().__init__(file)
        self._type = device_type

    @classmethod
    async def async_create(cls, file, device_type=None):
        return await asyncio.to_thread(cls, file, device_type)
"""
DEVICE = """
from .runtime import Codec


class Device:
    def __init__(self, name, lua_file):
        self._name = name
        self._lua_file = lua_file
        self._codec = None

    async def async_init(self):
        if self._lua_file:
            self._codec = await Codec.async_create(self._lua_file, device_type="T1")
"""
INIT = """
from .cloud import make_cloud
from .device import Device

CJSON_LUA = "bG9jYWwgY2pzb24gPSB7fQ=="


async def async_setup_entry(hass, entry):
    cloud = make_cloud(hass.session, entry.data["region"])
    path = hass.config.path(".storage/demo/lua")
    file = None
    try:
        file = await cloud.download_lua(path=path, device_type=1)
    except Exception:
        pass
    with open(path + "/cjson.lua", "w") as fp:
        fp.write(CJSON_LUA)
    device = Device(name="x", lua_file=file)
    await device.async_init()
    return True
"""


def _app(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "custom_components" / "demo"
    root.mkdir(parents=True)
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def _cloud_app(tmp_path: Path) -> Path:
    return _app(tmp_path, {"__init__.py": INIT, "cloud.py": CLOUD, "runtime.py": RUNTIME,
                           "device.py": DEVICE})  # fmt: skip


def test_lua_downloaded_through_the_whole_chain_is_found(tmp_path: Path) -> None:
    res = py_lua.read(_cloud_app(tmp_path), packed_lua=1)
    sec = res.section()
    assert sec is not None
    assert sec["runtimes"] == [{"file": "runtime.py", "line": 10, "python": "open",
                                "system": "open", "defaults": True}]  # fmt: skip
    dl = [r for r in sec["runs"] if r["source"] == "downloaded"]
    assert len(dl) == 1 and dl[0]["line"] == 15
    # both clouds' requests; the base class's download only raises and is left out
    gets = [i for i, x in enumerate(CLOUD.split("\n"), 1) if "self._session.get(" in x]
    assert dl[0]["at"] == [f"cloud.py:{n}" for n in gets] and len(gets) == 2
    # the address comes from the answer of one of the two sites in the code
    assert dl[0]["from"] == [{"kind": "answer", "detail": "url",
                              "site": "api.one.invalid,api.two.invalid"}]  # fmt: skip
    fs = py_lua.findings(res)
    assert [(f.rule_id, f.file, f.line) for f in fs] == [("py-lua-download", "runtime.py", 15)]
    assert "can use Python and run programs" in fs[0].message


def test_packed_and_in_code_lua_are_facts(tmp_path: Path) -> None:
    sec = py_lua.read(_cloud_app(tmp_path), packed_lua=1).section()
    assert sec is not None
    by = {(r["source"], r.get("name", "")) for r in sec["runs"]}
    assert ("packed", "cjson") in by  # require "cjson", written from a packed constant
    assert ("in-code", "") in by  # print = function(...) end
    # `package.path = …{lua_dir}…` isn't a load
    assert not any(r["line"] == 13 for r in sec["runs"])


def test_without_the_packed_lua_a_required_name_is_unknown(tmp_path: Path) -> None:
    sec = py_lua.read(_cloud_app(tmp_path), packed_lua=0).section()
    assert sec is not None
    assert ("unknown", "cjson") in {(r["source"], r.get("name", "")) for r in sec["runs"]}


def test_shipped_lua_file(tmp_path: Path) -> None:
    root = _app(tmp_path, {
        "__init__.py": "from lupa import LuaRuntime\n"
                       "def setup(hass, config):\n"
                       "    lua = LuaRuntime()\n"
                       "    lua.execute('dofile(\"scripts/codec.lua\")')\n"
                       "    lua.globals().dofile('scripts/other.lua')\n",
        "scripts/codec.lua": "return 1\n",
        "scripts/other.lua": "return 2\n",
    })  # fmt: skip
    res = py_lua.read(root)
    assert [(r.source, r.name) for r in res.runs] == [("shipped", "codec.lua"),
                                                      ("shipped", "other.lua")]  # fmt: skip
    assert py_lua.findings(res) == []


def test_a_file_it_picks_that_cant_be_followed_is_unknown_and_not_counted(tmp_path: Path) -> None:
    root = _app(tmp_path, {"__init__.py": (
        "import lupa\n"
        "def run(path):\n"
        "    rt = lupa.LuaRuntime()\n"
        "    rt.execute(f'dofile(\"{path}\")')\n"
    )})  # fmt: skip
    res = py_lua.read(root)
    assert [r.source for r in res.runs] == ["unknown"]
    assert py_lua.findings(res) == []


def test_code_taken_straight_from_a_web_answer_is_downloaded(tmp_path: Path) -> None:
    root = _app(tmp_path, {"__init__.py": (
        "import lupa\n"
        "async def run(session):\n"
        "    resp = await session.get('https://code.example.invalid/x.lua')\n"
        "    code = await resp.text()\n"
        "    rt = lupa.lua54.LuaRuntime(unpack_returned_tuples=True)\n"
        "    rt.execute(code)\n"
    )})  # fmt: skip
    res = py_lua.read(root)
    assert [(r.source, r.origins) for r in res.runs] == [
        ("downloaded", [{"kind": "site", "detail": "code.example.invalid"}])
    ]
    assert res.runtimes[0].python == "open" and not res.runtimes[0].defaults
    assert [f.rule_id for f in py_lua.findings(res)] == ["py-lua-download"]


def test_a_runtime_that_closes_both_ways_out_keeps_it_a_fact(tmp_path: Path) -> None:
    root = _app(tmp_path, {"__init__.py": (
        "import lupa\n"
        "def deny(obj, name, setting):\n"
        "    raise AttributeError(name)\n"
        "async def run(session):\n"
        "    resp = await session.get('https://code.example.invalid/x.lua')\n"
        "    rt = lupa.LuaRuntime(register_eval=False, register_builtins=False,\n"
        "                         attribute_filter=deny)\n"
        "    rt.execute('os = nil; io = nil')\n"
        "    rt.execute(await resp.text())\n"
    )})  # fmt: skip
    res = py_lua.read(root)
    assert [(r.python, r.system) for r in res.runtimes] == [("closed", "closed")]
    assert "downloaded" in [r.source for r in res.runs]
    assert py_lua.findings(res) == []


def test_python_switched_off_without_a_filter_is_still_open(tmp_path: Path) -> None:
    # without an attribute filter, an object handed to Lua leads back to Python's classes
    root = _app(tmp_path, {"__init__.py": (
        "from lupa.lua54 import LuaRuntime as LR\n"
        "rt = LR(register_eval=False, register_builtins=False)\n"
        "rt.execute('os = nil; io = nil')\n"
    )})  # fmt: skip
    res = py_lua.read(root)
    assert [(r.python, r.system) for r in res.runtimes] == [("open", "closed")]
    assert py_lua.ways_words(res) == "can use Python"


def test_options_it_cant_read_count_as_open(tmp_path: Path) -> None:
    root = _app(tmp_path, {"__init__.py": (
        "import lupa\nOPTS = {}\nrt = lupa.LuaRuntime(**OPTS)\n"
    )})  # fmt: skip
    assert py_lua.read(root).runtimes[0].python == "unknown"


def test_execute_on_something_else_is_not_lua(tmp_path: Path) -> None:
    root = _app(tmp_path, {"__init__.py": (
        "import sqlite3\n"
        "def q(db):\n"
        "    cur = sqlite3.connect(db).cursor()\n"
        "    cur.execute('dofile(\"x.lua\")')\n"
    )})  # fmt: skip
    assert py_lua.read(root).section() is None
    # lupa named but the execute isn't on a runtime
    root2 = _app(tmp_path / "b", {"__init__.py": (
        "import lupa\nimport sqlite3\n"
        "cur = sqlite3.connect('x').cursor()\n"
        "cur.execute('dofile(\"x.lua\")')\n"
    )})  # fmt: skip
    assert py_lua.read(root2).runs == []


def test_patterns_stay_linear_on_hostile_lua_text() -> None:
    runs = ["dofile(" * 20000, "require(" * 20000, "dofile " + " " * 50000,
            "require '" + "a" * 50000, "os =" * 20000 + " nil", "\x00" * 50000,
            "dofile(\x00" + "9" * 50000]  # fmt: skip
    slow = []
    for rx in (py_lua._FILE_LOAD, py_lua._REQUIRE, py_lua._OS_OFF, py_lua._IO_OFF):
        for text in runs:
            t = time.perf_counter()
            for _ in rx.finditer(text):
                pass
            if time.perf_counter() - t > 0.5:
                slow.append((rx.pattern[:20], text[:10]))
    assert slow == []


def test_a_hostile_fan_of_download_methods_is_cut_off(tmp_path: Path) -> None:
    # twelve classes defining the method, each returning another call of it: bounded
    body = "import lupa\n"
    for i in range(12):
        body += (f"class C{i}:\n    def fetch(self, p):\n"
                 + "".join(f"        x{j} = self.o.fetch(p)\n" for j in range(12))
                 + "        return x0 or x1 or x2 or x3\n")  # fmt: skip
    body += ("def run(o):\n    rt = lupa.LuaRuntime()\n"
             "    rt.execute(f'dofile(\"{o.fetch(1)}\")')\n")  # fmt: skip
    root = _app(tmp_path, {"__init__.py": body})
    t = time.perf_counter()
    res = py_lua.read(root)
    assert time.perf_counter() - t < 5
    assert [r.source for r in res.runs] == ["unknown"]


def test_readings_count_downloaded_lua_like_a_cards_remote_code() -> None:
    f = {"rule_id": "py-lua-download", "severity": "medium", "file": "runtime.py", "line": 15}
    r = readings.compute({"findings": [f]})
    assert r.exposure == 5.0 and r.exposure_level == "high"
    assert any("downloads Lua code" in x for x in r.exposure_reasons)
    # not raised by the network setting
    assert readings.compute({"findings": [f]}, network="shared").exposure == 5.0


def test_the_page_says_where_the_lua_comes_from(tmp_path: Path) -> None:
    res = py_lua.read(_cloud_app(tmp_path), packed_lua=1)
    report = {"target": {"kind": "integration"}, "lua": res.section(),
              "findings": [finding_json(f) for f in py_lua.findings(res)]}  # fmt: skip
    lines = ui.lua_lines(report)
    text = " ".join(lines)
    assert lines[0].startswith("<b>Runs Lua code it downloads.</b> The address comes from "
                               "the answer of one of 2 sites in its code")  # fmt: skip
    assert "<code>api.one.invalid</code>, <code>api.two.invalid</code>" in text
    gets = [i for i, x in enumerate(CLOUD.split("\n"), 1) if "self._session.get(" in x]
    assert (
        f"It downloads the code (<code>cloud.py</code> lines {gets[0]} and {gets[1]}), "
        "saves it to a file and runs it (<code>runtime.py</code> line 15)."
    ) in text
    assert (
        "Its Lua runner is left at lupa's out-of-the-box settings, so that code can use "
        "Python and run programs on your system. Barkley never sees that code."
    ) in text
    assert "<b>Runs Lua code packed in its own code</b> (<code>cjson</code>)" in text
    assert "short pieces of Lua written in its Python code" in text
    html = ui._supply_runtime(report)
    assert html.count("Runs Lua code it downloads") == 1  # the finding isn't listed twice


def test_a_local_named_cls_is_not_the_class(tmp_path: Path) -> None:
    # (the hand check of 2026-11-23) an error class picked into a local named `cls`
    # inside an ordinary method isn't a call of the app's own client class: its message
    # mustn't become where the client's address comes from
    from sniff_test.analyzers import py_requests

    root = _app(tmp_path, {"__init__.py": (
        "class ApiError(Exception):\n"
        "    def __init__(self, status, message):\n"
        "        super().__init__(message)\n"
        "class AuthError(ApiError):\n"
        "    pass\n"
        "class Client:\n"
        "    def __init__(self, session, base_url):\n"
        "        self._session = session\n"
        "        self.base_url = base_url\n"
        "    async def _request(self, path):\n"
        "        async with self._session.get(f'{self.base_url}{path}') as resp:\n"
        "            body = await resp.json()\n"
        "            if resp.status >= 400:\n"
        "                cls = AuthError if resp.status == 401 else ApiError\n"
        "                raise cls(resp.status, body.get('detail'))\n"
        "            return body\n"
        "async def async_setup_entry(hass, entry):\n"
        "    client = Client(hass.session, entry.data['base_url'])\n"
        "    await client._request('/info')\n"
    )})  # fmt: skip
    reqs, _h = py_requests.read_flow(root)
    assert {o.kind for r in reqs for o in r.origins} == {"setup"}
