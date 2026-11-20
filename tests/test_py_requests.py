"""(0.15) The method of each web request and what the call carries (analyzers/py_requests.py).
Hosts are made up (.invalid): nothing here is ever requested."""

import time

from sniff_test.analyzers import py_requests

CONST = """\
BASE_URL = "https://api.acme.invalid/v2"
TOKEN_URL = BASE_URL + "/oauth/token"
"""

API = """\
import aiohttp
import requests
from urllib.request import Request, urlopen

from .const import BASE_URL, TOKEN_URL


class Client:
    STATUS = "https://status.acme.invalid/now"

    def __init__(self, session, host):
        self._session = session
        self._base = BASE_URL
        self._host = host

    async def login(self, user, password):
        payload = {"user": user, "password": password}
        async with self._session.post(TOKEN_URL, json=payload) as r:
            return await r.json()

    async def device(self, device_id, token):
        url = f"{self._base}/devices/{device_id}"
        headers = {"Authorization": f"Bearer {token}"}
        return await self._session.get(url, headers=headers, params={"full": 1})

    async def status(self):
        return await self._session.get(self.STATUS)

    async def local(self, path, **kwargs):
        return await self._session.request("PUT", f"http://{self._host}/{path}", **kwargs)

    async def any(self, method, url):
        return await self._session.request(method, url, timeout=5)

    def beacon(self, value):
        return requests.get("https://collect.acme.invalid/p?v=" + value)

    def old(self, body):
        req = Request("https://api.acme.invalid/old", data=body, headers={"X-Key": "1"})
        return urlopen(req)

    def lookups(self, cfg):
        a = cfg.get("https://not-a-request.invalid/")  # a dictionary: no session, no keywords
        b = self._cache.get("key")
        return a, b
"""


def _reqs(tmp_path):
    (tmp_path / "const.py").write_text(CONST)
    (tmp_path / "api.py").write_text(API)
    return py_requests.requests_in(tmp_path)


def test_the_method_and_site_are_read_through_constants(tmp_path):
    by = {(r.method, r.host): r for r in _reqs(tmp_path) if r.headers is None}
    login = by[("POST", "api.acme.invalid")]
    assert login.body == ("user", "password") and login.headers is None
    assert (login.scheme, login.file) == ("https", "api.py")
    assert by[("GET", "status.acme.invalid")].address == ()


def test_what_goes_into_the_address_headers_and_query_is_named(tmp_path):
    got = [r for r in _reqs(tmp_path) if r.host == "api.acme.invalid" and r.method == "GET"]
    assert len(got) == 1
    r = got[0]
    assert r.address == ("device_id",)
    assert r.headers == ("Authorization",) and r.query == ("full",) and r.body is None


def test_a_get_that_carries_data_in_the_address_is_recorded_as_such(tmp_path):
    r = next(r for r in _reqs(tmp_path) if r.host == "collect.acme.invalid")
    assert r.method == "GET" and r.address == ("value",)


def test_an_address_built_while_running_has_no_site(tmp_path):
    reqs = _reqs(tmp_path)
    put = next(r for r in reqs if r.method == "PUT")
    assert put.host is None and put.more  # **kwargs: the caller can add anything
    unknown = next(r for r in reqs if r.method == "")
    assert unknown.host is None


def test_urlopen_with_a_request_object_reads_both_calls(tmp_path):
    r = next(r for r in _reqs(tmp_path) if r.file == "api.py" and r.headers == ("X-Key",))
    assert (r.method, r.host, r.body) == ("POST", "api.acme.invalid", ())


def test_a_dictionary_get_is_not_a_request(tmp_path):
    reqs = _reqs(tmp_path)
    # a dict's .get("https://…") still names a site, so it is listed (the address is in the
    # code); the cache lookup isn't a request at all
    assert sum(r.host == "not-a-request.invalid" for r in reqs) == 1
    assert len(reqs) == 8


def test_the_summary_groups_by_site_and_shape(tmp_path):
    s = py_requests.summary(_reqs(tmp_path))
    assert s["version"] == 1 and s["total"] == 8
    assert set(s["sites"]) == {
        "api.acme.invalid",
        "status.acme.invalid",
        "collect.acme.invalid",
        "not-a-request.invalid",
    }
    shapes = s["sites"]["api.acme.invalid"]
    assert sorted(x["method"] for x in shapes) == ["GET", "POST", "POST"]
    post = next(x for x in shapes if x["body"] == ["user", "password"])
    assert post["count"] == 1 and post["at"] == ["api.py:18"]
    assert sorted(x["method"] for x in s["elsewhere"]) == ["", "PUT"]
    assert py_requests.summary([]) is None


def test_names_from_the_code_are_capped_and_plain(tmp_path):
    keys = ", ".join(f'"k{i}": 1' for i in range(40))
    (tmp_path / "a.py").write_text(
        "def f(session):\n"
        f'    session.post("https://x.invalid/a", json={{{keys}, "<b>bad</b>": 1}})\n'
    )
    r = py_requests.requests_in(tmp_path)[0]
    assert r.body is not None and len(r.body) == 12
    assert all("<" not in n and len(n) <= 60 for n in r.body)


def test_a_host_cut_off_by_a_gap_is_not_a_site(tmp_path):
    (tmp_path / "a.py").write_text(
        "def f(session, region, host):\n"
        '    session.get(f"https://api-{region}.acme.invalid/x", timeout=5)\n'
        '    session.get(f"https://api.acme{region}/x", timeout=5)\n'
        '    session.get(f"https://{host}/x", timeout=5)\n'
    )
    assert [r.host for r in py_requests.requests_in(tmp_path)] == [None, None, None]


def test_broken_or_self_referring_code_never_fails(tmp_path):
    (tmp_path / "bad.py").write_text("def f(:\n")
    (tmp_path / "loop.py").write_text(
        "from .loop import A\nA = A\nB = f'{B}/x'\n"
        "def f(session, url):\n"
        "    url = url + '/x'\n"
        "    session.get(url, timeout=1)\n"
        "    session.get(A, timeout=1)\n"
        "    session.get(B, timeout=1)\n"
    )
    assert [r.host for r in py_requests.requests_in(tmp_path)] == [None, None, None]


def test_long_chains_stay_fast(tmp_path):
    # a long `+` chain and many requests: time grows with the size of the code, no more
    chain = " + ".join(['"a"'] * 400)
    body = "".join(f"    session.get(U + {chain}, timeout=1)\n" for _ in range(200))
    (tmp_path / "big.py").write_text('U = "https://big.invalid/"\ndef f(session):\n' + body)
    t0 = time.monotonic()
    reqs = py_requests.requests_in(tmp_path)
    assert len(reqs) == 200 and reqs[0].host == "big.invalid"
    assert time.monotonic() - t0 < 5


def test_names_that_fan_out_are_cut_off_by_the_budget(tmp_path):
    # each name is built from ten copies of the next: followed in full that is 10**8 steps
    lines = ['N0 = "https://fan.invalid/"']
    lines += [f"N{i} = " + " + ".join([f"N{i - 1}"] * 10) for i in range(1, 9)]
    lines += ["def f(session):", "    session.get(N8, timeout=1)"]
    (tmp_path / "fan.py").write_text("\n".join(lines) + "\n")
    t0 = time.monotonic()
    reqs = py_requests.requests_in(tmp_path)
    assert len(reqs) == 1 and time.monotonic() - t0 < 5
