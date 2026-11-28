"""Standalone mode: Barkley next to Home Assistant without a Supervisor.

HA_URL and a long-lived token reach Core directly; the panel asks for a login with
Home Assistant. Every server here is a fake on 127.0.0.1.
"""

import http.client
import json
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from test_server import Calls
from test_supervisor import FakeSupervisor

from sniff_test import cli, login, memory, server, supervisor, workspace
from sniff_test.store import Store
from sniff_test.supervisor import SupervisorError

# --- configuration -----------------------------------------------------------------------


@pytest.fixture
def env(monkeypatch):
    for k in ("SUPERVISOR_TOKEN", "HA_URL", "HA_TOKEN", "HA_TOKEN_FILE", "HA_CA_FILE",
              "HTTP_PROXY", "http_proxy"):  # fmt: skip
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


def test_the_supervisor_wins_then_ha_url_then_nothing(env, tmp_path):
    assert supervisor.connection() is None and supervisor.token() is None
    env.setenv("HA_URL", "http://ha.lan:8123/")
    assert supervisor.connection() is None
    assert "HA_TOKEN" in supervisor.config_problem()
    env.setenv("HA_TOKEN", "llat")
    c = supervisor.connection()
    assert (c.mode, c.base, c.ws_host, c.ws_port, c.ws_path, c.tls) == (
        "direct", "http://ha.lan:8123", "ha.lan", 8123, "/api/websocket", False)  # fmt: skip
    assert supervisor.token() == "llat" and supervisor.config_problem() is None
    env.setenv("SUPERVISOR_TOKEN", "sup")
    c = supervisor.connection()
    assert (c.mode, c.base, c.token) == ("addon", "http://supervisor/core", "sup")


def test_token_file_https_and_default_ports(env, tmp_path):
    (tmp_path / "tok").write_text("from-a-file\n")
    env.setenv("HA_TOKEN_FILE", str(tmp_path / "tok"))
    env.setenv("HA_URL", "https://ha.example")
    c = supervisor.connection()
    assert (c.token, c.base, c.ws_port, c.tls) == ("from-a-file", "https://ha.example", 443, True)
    env.setenv("HA_URL", "http://[fd00::5]:8123")
    c = supervisor.connection()
    assert (c.ws_host, c.base) == ("fd00::5", "http://[fd00::5]:8123")


@pytest.mark.parametrize("url", [
    "ha.lan:8123", "ftp://ha.lan", "http://user:pw@ha.lan", "http://ha.lan/api",
    "http://ha.lan?x=1", "http://ha.lan#f", "http://ha.lan:99999", "http://ha lan",
])  # fmt: skip
def test_ha_url_is_scheme_host_and_port_only(env, url):
    env.setenv("HA_URL", url)
    env.setenv("HA_TOKEN", "llat")
    assert "HA_URL" in (supervisor.config_problem() or "")
    assert supervisor.connection() is None


def test_tls_verifies_and_never_goes_below_1_2(env):
    import ssl

    env.setenv("HA_URL", "https://ha.example")
    env.setenv("HA_TOKEN", "llat")
    ctx = supervisor.connection().ssl_context()
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


def test_the_redirect_off_the_panel_is_only_ever_ha_login_page():
    ha = "http://ha.lan:8123"
    good = f"{ha}/auth/authorize?response_type=code&state=abc"
    assert login.ha_login_url(ha, good) == good
    for bad in (
        f"{ha}/auth/authorize?x\r\nSet-Cookie: a=b",
        "http://evil.example/auth/authorize?x",
        f"{ha}/other?x",
        f"{ha}.evil.example/auth/authorize?x",
    ):
        assert login.ha_login_url(ha, bad) == f"{ha}/auth/authorize"


def test_missing_token_file_and_ca_file_are_named(env, tmp_path):
    env.setenv("HA_URL", "http://ha.lan:8123")
    env.setenv("HA_TOKEN_FILE", str(tmp_path / "nope"))
    assert "HA_TOKEN_FILE" in supervisor.config_problem()
    env.setenv("HA_TOKEN", "llat")
    env.setenv("HA_CA_FILE", str(tmp_path / "ca.pem"))
    assert "HA_CA_FILE" in supervisor.config_problem()


# --- REST calls go to HA_URL, never anywhere else ---------------------------------------


class FakeCore:
    """Core's REST API on 127.0.0.1; records each request."""

    def __init__(self, routes=None):
        self.seen: list[tuple[str, str, str, str]] = []  # method, path, auth, body
        self.routes = routes or {}
        core = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self, method):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode() if n else ""
                core.seen.append((method, self.path, self.headers.get("Authorization", ""),
                                  body))  # fmt: skip
                status, headers, payload = core.routes.get(
                    (method, self.path), (200, {}, {"version": "2026.11.1"})
                )
                data = json.dumps(payload).encode() if payload is not None else b""
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._answer("GET")

            def do_POST(self):
                self._answer("POST")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def core(env):
    c = FakeCore({("GET", "/api/services"): (200, {}, [
        {"domain": "notify", "services": {"mobile_app_phone": {}, "persistent_notification": {}}},
        {"domain": "light", "services": {"turn_on": {}}},
    ])})  # fmt: skip
    env.setenv("HA_URL", c.url)
    env.setenv("HA_TOKEN", "llat")
    yield c
    c.close()


def test_rest_calls_use_core_paths_and_the_token(core):
    assert supervisor.ha_version() == "2026.11.1"
    supervisor.notify_persistent("T", "M", "barkley_x")
    assert supervisor.notify_targets() == ["mobile_app_phone"]
    paths = [(m, p, a) for m, p, a, _ in core.seen]
    assert paths == [
        ("GET", "/api/config", "Bearer llat"),
        ("POST", "/api/services/persistent_notification/create", "Bearer llat"),
        ("GET", "/api/services", "Bearer llat"),
    ]
    with pytest.raises(SupervisorError, match="only an add-on"):
        supervisor.self_slug()


def test_a_redirect_is_never_followed_with_the_token(core, env):
    elsewhere = FakeCore()
    try:
        core.routes[("GET", "/api/config")] = (302, {"Location": elsewhere.url + "/x"}, None)
        assert supervisor.ha_version() is None
        assert elsewhere.seen == []
    finally:
        elsewhere.close()


def test_proxy_settings_in_the_environment_are_ignored(core, env):
    env.setenv("HTTP_PROXY", "http://127.0.0.1:9")  # nothing listens there
    env.setenv("http_proxy", "http://127.0.0.1:9")
    assert supervisor.ha_version() == "2026.11.1"


def test_login_exchange_and_revoke(core):
    core.routes[("POST", "/auth/token")] = (200, {}, {"access_token": "a1", "refresh_token": "r1",
                                                      "token_type": "Bearer"})  # fmt: skip
    core.routes[("POST", "/auth/revoke")] = (200, {}, None)
    assert supervisor.auth_exchange("c0de", "http://barkley.lan:8099/") == ("a1", "r1")
    supervisor.auth_revoke("r1")
    (m1, p1, a1, b1), (m2, p2, _, b2) = core.seen
    assert (m1, p1, a1) == ("POST", "/auth/token", "")  # no token of ours goes along
    assert urllib.parse.parse_qs(b1) == {"grant_type": ["authorization_code"], "code": ["c0de"],
                                         "client_id": ["http://barkley.lan:8099/"]}  # fmt: skip
    assert (m2, p2, urllib.parse.parse_qs(b2)) == ("POST", "/auth/revoke", {"token": ["r1"]})
    core.routes[("POST", "/auth/token")] = (400, {}, {"error": "invalid_request"})
    with pytest.raises(SupervisorError, match="answered 400"):
        supervisor.auth_exchange("bad", "http://barkley.lan:8099/")


# --- the websocket goes to <HA_URL>/api/websocket ----------------------------------------


def test_installed_list_and_current_user_over_cores_own_websocket(env):
    fake = FakeSupervisor(
        accept_token="llat", ws_path="/api/websocket",
        known=("marketplace/repositories/list", "auth/current_user"),
        results={"auth/current_user": {"id": "u1", "name": "Pat", "is_admin": True}},
    )  # fmt: skip
    env.setenv("HA_URL", f"http://127.0.0.1:{fake.port}")
    env.setenv("HA_TOKEN", "llat")
    items, _ = supervisor.installed_hacs()
    assert [i.repo for i in items] == ["acme/acme-card", "acme/acme_cloud", "acme/no-releases"]
    fake.accept_token = "user-token"
    assert supervisor.current_user("user-token") == supervisor.User("u1", "Pat", True)
    fake.accept_token = "other"
    with pytest.raises(SupervisorError, match="long-lived access token of an administrator"):
        supervisor.installed_hacs()


# --- the login ----------------------------------------------------------------------------


class FakeHA:
    def __init__(self, admin=True, fail=None):
        self.admin, self.fail = admin, fail
        self.revoked: list[str] = []
        self.codes: list[tuple[str, str]] = []

    def exchange(self, code, client_id):
        self.codes.append((code, client_id))
        if self.fail:
            raise SupervisorError(self.fail)
        return "access-" + code, "refresh-" + code

    def user(self, access):
        return supervisor.User("u1", "Pat", self.admin)

    def revoke(self, refresh):
        self.revoked.append(refresh)


def _login(ha, now=None):
    clock = now or [1000.0]
    lg = login.Login("http://barkley.lan:8099/", "http://ha.lan:8123", ha.exchange, ha.user,
                     ha.revoke, lambda: clock[0])  # fmt: skip
    return lg, clock


def test_login_sends_the_browser_to_ha_with_barkleys_own_address():
    lg, _ = _login(FakeHA())
    state, to = lg.start()
    u = urllib.parse.urlsplit(to)
    q = urllib.parse.parse_qs(u.query)
    assert (u.scheme, u.netloc, u.path) == ("http", "ha.lan:8123", "/auth/authorize")
    assert q == {"response_type": ["code"], "client_id": ["http://barkley.lan:8099/"],
                 "redirect_uri": ["http://barkley.lan:8099/auth/callback"],
                 "state": [state]}  # fmt: skip


def test_an_admin_gets_a_session_and_ha_tokens_are_revoked_at_once():
    ha = FakeHA()
    lg, clock = _login(ha)
    state, _ = lg.start()
    sid, s = lg.finish("abc", state, state)
    assert (s.user, ha.codes, ha.revoked) == ("Pat", [("abc", lg.client_id)], ["refresh-abc"])
    assert lg.session(sid) == s
    with pytest.raises(login.LoginError, match="expired"):
        lg.finish("abc", state, state)  # a state works once
    clock[0] += login.SESSION_SECONDS + 1
    assert lg.session(sid) is None


def test_a_non_admin_is_refused_and_still_revoked():
    ha = FakeHA(admin=False)
    lg, _ = _login(ha)
    state, _ = lg.start()
    with pytest.raises(login.LoginError, match="isn't a Home Assistant administrator"):
        lg.finish("abc", state, state)
    assert ha.revoked == ["refresh-abc"]


@pytest.mark.parametrize("case", ["other cookie", "no cookie", "unknown state", "expired"])
def test_the_state_must_be_ours_this_browsers_and_fresh(case):
    ha = FakeHA()
    lg, clock = _login(ha)
    state, _ = lg.start()
    q_state, cookie = state, state
    if case == "other cookie":
        cookie = lg.start()[0]
    elif case == "no cookie":
        cookie = ""
    elif case == "unknown state":
        q_state = cookie = "made-up"
    else:
        clock[0] += login.STATE_SECONDS + 1
    with pytest.raises(login.LoginError, match="expired"):
        lg.finish("abc", q_state, cookie)
    assert ha.codes == []  # nothing was sent to HA


def test_login_error_from_ha_and_logout():
    lg, _ = _login(FakeHA(fail="Home Assistant answered 400"))
    state, _ = lg.start()
    with pytest.raises(login.LoginError, match="didn't accept"):
        lg.finish("abc", state, state)
    lg, _ = _login(FakeHA())
    state, _ = lg.start()
    sid, _ = lg.finish("abc", state, state)
    lg.logout(sid)
    assert lg.session(sid) is None


def test_failed_code_exchanges_stop_reaching_ha_for_a_while():
    ha = FakeHA(fail="Home Assistant answered 400")
    lg, clock = _login(ha)
    for _ in range(login.MAX_FAILURES):
        state, _ = lg.start()
        with pytest.raises(login.LoginError, match="didn't accept"):
            lg.finish("junk", state, state)
    state, _ = lg.start()
    with pytest.raises(login.LoginError, match="Too many failed logins"):
        lg.finish("junk", state, state)
    assert len(ha.codes) == login.MAX_FAILURES  # the sixth never reached HA
    clock[0] += login.FAILURE_WINDOW + 1
    ha.fail = None
    state, _ = lg.start()
    assert lg.finish("good", state, state)[1].user == "Pat"


def test_cookies_are_httponly_lax_and_secure_on_https():
    lg, _ = _login(FakeHA())
    c = lg.cookie(login.SESSION_COOKIE, "v", 60)
    assert "HttpOnly" in c and "SameSite=Lax" in c and "Secure" not in c
    secure = login.Login("https://barkley.example", "https://ha.example")
    assert "; Secure" in secure.cookie(login.SESSION_COOKIE, "v", 60)
    assert login.read_cookie(f"a=b; {login.SESSION_COOKIE}=xyz", login.SESSION_COOKIE) == "xyz"
    assert login.read_cookie('bad"cookie', login.SESSION_COOKIE) == ""


# --- the panel behind the login -----------------------------------------------------------


@pytest.fixture
def gated(tmp_path):
    ha = FakeHA()
    lg = login.Login("http://barkley.lan:8099", "http://ha.lan:8123", ha.exchange, ha.user,
                     ha.revoke)  # fmt: skip
    store = Store(tmp_path / "s.db")
    httpd = server.serve(store, Calls(), "127.0.0.1", 0, None, login_cfg=lg)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1], ha
    httpd.shutdown()


def _req(port, method, path, cookie="", body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Cookie": cookie} if cookie else {}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    c.request(method, path, body=urllib.parse.urlencode(body) if body else None, headers=headers)
    r = c.getresponse()
    out = r.status, r.getheader("Location") or "", r.msg.get_all("Set-Cookie") or [], r.read()
    c.close()
    return out


def _cookie(set_cookies, name):
    for c in set_cookies:
        k, _, rest = c.partition("=")
        if k == name:
            return rest.split(";", 1)[0]
    return None


def test_every_page_needs_the_login_and_the_whole_round_trip_works(gated):
    port, ha = gated
    status, _, _, page = _req(port, "GET", "/")
    assert status == 401 and b"Log in with Home Assistant" in page
    assert _req(port, "GET", "/scan/1")[0] == 401
    assert _req(port, "GET", "/doctor")[0] == 401
    assert _req(port, "POST", "/scan", body={"repo": "a/b"})[0] == 403
    assert _req(port, "GET", "/fonts/Geist-Variable.woff2")[0] in (200, 404)  # no login needed

    status, to, cookies, _ = _req(port, "GET", "/login")
    state = _cookie(cookies, login.STATE_COOKIE)
    assert status == 303 and to.startswith("http://ha.lan:8123/auth/authorize?") and state
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(to).query)["state"] == [state]

    # back from HA without this browser's state cookie: refused, HA never asked
    q = urllib.parse.urlencode({"code": "abc", "state": state})
    assert _req(port, "GET", f"/auth/callback?{q}")[0] == 403 and ha.codes == []

    state = _cookie(_req(port, "GET", "/login")[2], login.STATE_COOKIE)
    q = urllib.parse.urlencode({"code": "abc", "state": state})
    status, to, cookies, _ = _req(port, "GET", f"/auth/callback?{q}",
                                  f"{login.STATE_COOKIE}={state}")  # fmt: skip
    sid = _cookie(cookies, login.SESSION_COOKIE)
    assert status == 303 and to == "/" and sid and ha.revoked == ["refresh-abc"]
    assert _cookie(cookies, login.STATE_COOKIE) == ""  # the state cookie is cleared

    status, _, _, page = _req(port, "GET", "/", f"{login.SESSION_COOKIE}={sid}")
    assert status == 200 and b"You're logged in with Home Assistant as Pat" in page
    import re

    tok = re.search(rb'name=token value="([^"]+)"', page)[1].decode()
    assert _req(port, "POST", "/logout", f"{login.SESSION_COOKIE}={sid}", {"token": tok})[0] == 200
    assert _req(port, "GET", "/", f"{login.SESSION_COOKIE}={sid}")[0] == 401


def test_forms_may_end_at_has_login_page_only_with_a_login(gated, tmp_path):
    # Create token is a form whose redirects end at HA's login page; browsers block that
    # unless form-action allows HA's origin (found in a real browser, 2026-11-18).
    port, _ = gated
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", "/")
    csp = c.getresponse().getheader("Content-Security-Policy")
    c.close()
    assert "form-action 'self' http://ha.lan:8123;" in csp
    assert csp == server.csp_with_login("http://ha.lan:8123")
    assert "script-src" not in csp and "default-src 'none'" in csp
    store = Store(tmp_path / "addon.db")
    httpd = server.serve(store, Calls(), "127.0.0.1", 0, {"127.0.0.1"})
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=5)
        c.request("GET", "/")
        assert c.getresponse().getheader("Content-Security-Policy") == server._CSP
        c.close()
    finally:
        httpd.shutdown()


def test_the_addon_panel_is_unchanged_without_a_login(tmp_path):
    store = Store(tmp_path / "s.db")
    httpd = server.serve(store, Calls(), "127.0.0.1", 0, {"127.0.0.1"})
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        port = httpd.server_address[1]
        status, _, _, page = _req(port, "GET", "/")
        assert status == 200 and b"Logged in" not in page
        assert _req(port, "GET", "/login")[0] == 404
    finally:
        httpd.shutdown()


# --- serve refuses an open panel ----------------------------------------------------------


def test_standalone_serve_needs_a_login_or_an_allow_list(env, tmp_path, capsys):
    env.setenv("HA_URL", "http://127.0.0.1:9")
    env.setenv("HA_TOKEN", "llat")
    env.delenv("BARKLEY_URL", raising=False)
    env.delenv("BARKLEY_ALLOW", raising=False)
    assert cli.main(["serve", "--store", str(tmp_path / "s.db"), "--port", "0"]) == 1
    assert "BARKLEY_URL" in capsys.readouterr().err
    assert cli.main(["serve", "--store", str(tmp_path / "s.db"), "--port", "0",
                     "--public-url", "not a url"]) == 1  # fmt: skip
    env.setenv("HA_URL", "http://ha.lan/api")
    assert cli.main(["serve", "--store", str(tmp_path / "s.db"), "--port", "0"]) == 1
    assert "HA_URL should look like" in capsys.readouterr().err


def test_standalone_without_landlock_refuses_unless_told(env, tmp_path, capsys):
    from sniff_test import sandbox

    env.setenv("HA_URL", "http://127.0.0.1:9")
    env.setenv("HA_TOKEN", "llat")
    env.setattr(sandbox, "abi", lambda: 0)
    args = ["serve", "--store", str(tmp_path / "s.db"), "--port", "0",
            "--public-url", "http://barkley.lan:8099"]  # fmt: skip
    env.delenv(sandbox.UNSANDBOXED_ENV, raising=False)
    assert cli.main(args) == 1
    assert "BARKLEY_UNSANDBOXED=1" in capsys.readouterr().err


# --- memory: a container's limit counts ---------------------------------------------------


def _meminfo(tmp_path, gb):
    p = tmp_path / "meminfo"
    p.write_text(f"MemTotal: 16000000 kB\nMemAvailable: {int(gb * 1024 * 1024)} kB\n")
    return p


def test_a_cgroup_v2_limit_beats_the_machines_free_memory(tmp_path):
    cg = tmp_path / "cg"
    cg.mkdir()
    (cg / "memory.max").write_text(str(3 * memory.GIB) + "\n")
    (cg / "memory.current").write_text(str(int(2.5 * memory.GIB)))
    (cg / "memory.stat").write_text(f"anon 1\ninactive_file {memory.GIB}\n")
    m = memory.check(_meminfo(tmp_path, 12), cg)
    assert (m.level, m.available, m.total, m.limited) == (
        "warn", int(1.5 * memory.GIB), 3 * memory.GIB, True)  # fmt: skip
    assert "the container's limit of 3.0 GB" in m.message()
    (cg / "memory.stat").write_text("inactive_file 0\n")
    m = memory.check(_meminfo(tmp_path, 12), cg)
    assert m.refuse and "Raise its memory limit" in m.message()


def test_no_limit_or_a_v1_unlimited_cgroup_changes_nothing(tmp_path):
    cg = tmp_path / "cg"
    (cg / "memory").mkdir(parents=True)
    (cg / "memory.max").write_text("max\n")
    (cg / "memory" / "memory.limit_in_bytes").write_text(str(1 << 62))
    m = memory.check(_meminfo(tmp_path, 12), cg)
    assert (m.level, m.limited) == ("ok", False)
    (cg / "memory.max").unlink()
    (cg / "memory" / "memory.limit_in_bytes").write_text(str(2 * memory.GIB))
    (cg / "memory" / "memory.usage_in_bytes").write_text(str(int(1.5 * memory.GIB)))
    m = memory.check(_meminfo(tmp_path, 12), cg)
    assert m.refuse and m.limited  # v1: 0.5 GB left of 2 GB


# --- a killed run's workspaces are cleaned up ---------------------------------------------


def test_sweep_removes_only_old_sniff_test_folders(tmp_path):
    old, new, other = (tmp_path / "sniff-test-old"), (tmp_path / "sniff-test-new"), (tmp_path / "x")
    for d in (old, new, other):
        d.mkdir()
    (tmp_path / "sniff-test-file").write_text("not a folder")
    past = time.time() - workspace.STALE_AFTER - 60
    os.utime(old, (past, past))
    os.utime(other, (past, past))
    assert workspace.sweep_stale(tmp_path) == 1
    assert not old.exists() and new.exists() and other.exists()
