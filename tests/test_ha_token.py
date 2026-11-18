"""(0.14.0 part 4) Standalone: Barkley's own Home Assistant token, made with a login or
pasted, and its rotation (user decisions 2026-11-17). HA_TOKEN / HA_TOKEN_FILE always
win and are never rotated; the token file is mode 600, outside the database; a failed
rotation keeps the old token."""

import re
import stat
import threading
import urllib.parse
from datetime import UTC, datetime, timedelta

import pytest
from test_server import get, post, token
from test_standalone import FakeHA, _cookie, _login, _req

from sniff_test import ha_token, login, server, supervisor
from sniff_test import settings as settings_mod
from sniff_test.store import Store
from sniff_test.supervisor import SupervisorError

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


class FakeTokens:
    """HA's three token commands (Core 2026.11.2, components/auth), in memory."""

    def __init__(self, admin=True):
        self.admin = admin
        self.tokens: dict[str, tuple[str, str]] = {}  # token -> (id, name)
        self.n = 0
        self.fail_create = False
        self.calls: list[str] = []

    def add(self, name="login"):
        self.n += 1
        tok = f"tok{self.n}"
        self.tokens[tok] = (f"id{self.n}", name)
        return tok

    def current_user(self, tok, **_):
        if tok not in self.tokens:
            raise SupervisorError("Home Assistant refused the token")
        return supervisor.User("u1", "Pat", self.admin)

    def core_command(self, command, tok, **params):
        self.calls.append(command)
        if tok not in self.tokens:
            raise SupervisorError("Home Assistant refused the token")
        if command == supervisor.LLAT_CREATE:
            if self.fail_create:
                raise SupervisorError("auth/long_lived_access_token: unknown_error: boom")
            assert isinstance(params["lifespan"], int)
            if any(n == params["client_name"] for _, n in self.tokens.values()):
                raise SupervisorError(f"{params['client_name']} already exists")
            return self.add(params["client_name"])
        if command == supervisor.REFRESH_TOKENS:
            mine = self.tokens[tok][0]
            return [{"id": i, "is_current": i == mine, "client_name": n}
                    for i, n in self.tokens.values()]  # fmt: skip
        if command == supervisor.REFRESH_TOKEN_DELETE:
            gone = [t for t, (i, _) in self.tokens.items() if i == params["refresh_token_id"]]
            if not gone:
                raise SupervisorError("invalid_token_id")
            del self.tokens[gone[0]]
            return {}
        raise AssertionError(command)


@pytest.fixture
def ha(monkeypatch, tmp_path):
    for k in ("SUPERVISOR_TOKEN", "HA_TOKEN", "HA_TOKEN_FILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HA_URL", "http://127.0.0.1:1")
    fake = FakeTokens()
    monkeypatch.setattr(supervisor, "core_command", fake.core_command)
    monkeypatch.setattr(supervisor, "current_user", fake.current_user)
    store = Store(tmp_path / "s.db")
    monkeypatch.setattr(supervisor, "OWN_TOKEN_FILE", ha_token.path(store.path))
    return fake, store


def test_no_token_yet_is_a_clear_message_not_a_start_error(ha):
    _fake, _store = ha
    assert supervisor.config_problem() is None
    assert ha_token.source() == ""
    with pytest.raises(SupervisorError, match="no Home Assistant token yet"):
        supervisor.installed_hacs()


def test_a_pasted_token_is_checked_and_kept_in_its_own_private_file(ha):
    fake, store = ha
    tok = fake.add()
    with pytest.raises(SupervisorError):
        ha_token.adopt(store, "not-known", "pasted")
    with pytest.raises(SupervisorError):
        ha_token.adopt(store, "has space", "pasted")
    meta = ha_token.adopt(store, tok, "pasted", now=NOW)
    f = supervisor.OWN_TOKEN_FILE
    assert f.read_text() == tok and stat.S_IMODE(f.stat().st_mode) == 0o600
    assert meta.id == "id1" and ha_token.source() == "barkley"
    assert supervisor.token() == tok
    assert tok not in (store.setting(ha_token.META_KEY) or "")  # never in the database


def test_a_non_admin_token_is_refused(ha):
    fake, store = ha
    fake.admin = False
    with pytest.raises(SupervisorError, match="administrator"):
        ha_token.adopt(store, fake.add(), "pasted")
    assert not supervisor.OWN_TOKEN_FILE.exists()


def test_rotation_makes_the_successor_then_deletes_the_old_one(ha):
    fake, store = ha
    ha_token.adopt(store, fake.add(), "pasted", now=NOW)
    assert not ha_token.due(store, 60, NOW + timedelta(days=59))
    later = NOW + timedelta(days=60)
    assert ha_token.due(store, 60, later)
    assert ha_token.rotate(store, 60, later) == ""
    new = supervisor.OWN_TOKEN_FILE.read_text()
    assert new != "tok1" and list(fake.tokens) == [new]  # old one deleted
    m = ha_token.Meta.load(store)
    assert m.how == "rotated" and m.id == fake.tokens[new][0] and not m.error
    assert m.name.startswith("Barkley ")
    assert not ha_token.due(store, 60, later)


def test_a_failed_rotation_keeps_the_old_token_and_says_why_once_a_day(ha):
    fake, store = ha
    ha_token.adopt(store, fake.add(), "pasted", now=NOW)
    fake.fail_create = True
    said = []
    later = NOW + timedelta(days=61)
    why = ha_token.rotate(store, 60, later, notify=lambda t, m: said.append((t, m)))
    assert "boom" in why and supervisor.OWN_TOKEN_FILE.read_text() == "tok1"
    assert said and "keeps working" in said[0][1]
    assert not ha_token.due(store, 60, later + timedelta(hours=1))  # not every hour
    assert ha_token.due(store, 60, later + timedelta(hours=25))


def test_a_token_the_user_gave_is_never_rotated(ha, monkeypatch):
    fake, store = ha
    ha_token.adopt(store, fake.add(), "pasted", now=NOW)
    monkeypatch.setenv("HA_TOKEN", "theirs")
    assert ha_token.source() == "env" and supervisor.token() == "theirs"
    assert not ha_token.due(store, 60, NOW + timedelta(days=365))
    assert "not Barkley's own" in ha_token.rotate(store, 60, NOW + timedelta(days=365))
    assert "doesn't rotate" in ha_token.status_line(store, 60)


def test_create_token_runs_with_the_login_before_its_tokens_are_revoked():
    ha = FakeHA()
    lg, _ = _login(ha)
    seen = []
    lg.token_fn = lambda access: seen.append((access, list(ha.revoked)))
    state, _ = lg.start()  # an ordinary login makes no token
    lg.finish("a", state, state)
    assert seen == []
    state, _ = lg.start("token")
    assert lg.purpose(state) == "token"
    lg.finish("b", state, state)
    assert seen == [("access-b", ["refresh-a"])]  # before "refresh-b" was revoked
    assert ha.revoked == ["refresh-a", "refresh-b"]


def test_create_token_failure_still_revokes_the_login():
    ha = FakeHA()
    lg, _ = _login(ha)

    def boom(_access):
        raise SupervisorError("nope")

    lg.token_fn = boom
    state, _ = lg.start("token")
    _sid, session = lg.finish("c", state, state)  # the login itself still works
    assert session.token_error == "Couldn't create Barkley's token (nope)."
    assert ha.revoked == ["refresh-c"]


def test_the_settings_page_shows_where_the_token_is_from_never_the_token(ha):
    fake, store = ha
    import threading

    httpd = server.serve(store, lambda r, f: {}, "127.0.0.1", 0, {"127.0.0.1"})
    httpd.panel.standalone = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        _, _, page = get(base + "/")
        assert "Barkley needs its own Home Assistant token" in page
        tok = fake.add()
        _st, hd = post(base + "/ha-token", {"token": token(base), "value": "bogus"})
        assert hd["Location"].endswith("bad=hatoken")
        post(base + "/ha-token", {"token": token(base), "value": tok})
        _, _, page = get(base + "/settings")
        assert "Home Assistant token" in page and "Pasted here" in page and tok not in page
        assert "Rotate now" in page and "Token rotation" in page
        _, _, page = get(base + "/")
        assert "needs its own Home Assistant token" not in page
        assert post(base + "/ha-token/rotate", {"token": token(base)})[0] == 303
        assert supervisor.OWN_TOKEN_FILE.read_text() != tok
    finally:
        httpd.shutdown()


def test_create_token_is_not_offered_to_the_addon(tmp_path):
    import threading

    store = Store(tmp_path / "s.db")
    httpd = server.serve(store, lambda r, f: {}, "127.0.0.1", 0, {"127.0.0.1"})
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        _, _, page = get(base + "/settings")
        assert "Home Assistant token" not in page
        assert post(base + "/ha-token", {"token": token(base), "value": "x"})[0] == 400
    finally:
        httpd.shutdown()


def test_two_tokens_made_in_the_same_second_get_different_names():
    """Found against a real HA: Core refuses a second long-lived token with the same name
    ("unknown_error"), which Create token followed by Rotate now could hit."""
    assert len({ha_token._name(NOW) for _ in range(20)}) > 1


def test_the_no_token_banner_links_to_setup_and_the_row_has_its_anchor(tmp_path, monkeypatch):
    monkeypatch.setattr(ha_token, "source", lambda: "")
    panel = server.Panel(Store(tmp_path / "s.db"), lambda r, f: {}, None)
    panel.standalone = True
    assert 'href="/b/setup"' in server._token_banner("/b", panel)
    row = server.ha_token_block("/b", panel.store, 60, "t")
    assert row.startswith('<div class="setrow" id="ha-token">')


# --- (0.14.0) the first login is held for setup's first step, then a GitHub step ------------


@pytest.fixture
def first_run(ha, monkeypatch):
    fake, store = ha
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    monkeypatch.delenv("GITHUB_TOKEN")  # restored after the test (set_token sets it)
    browser = FakeHA()
    browser.exchange = lambda code, cid: (fake.add(f"login-{code}"), f"refresh-{code}")
    lg = login.Login("http://barkley.lan:8099", "http://ha.lan:8123", browser.exchange,
                     browser.user, browser.revoke)  # fmt: skip

    def make_token(access):
        tok, name = ha_token.create(access, 60)
        ha_token.adopt(store, tok, "created", name)

    lg.token_fn = make_token
    httpd = server.serve(store, lambda r, f: {}, "127.0.0.1", 0, None, login_cfg=lg)
    httpd.panel.standalone = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1], fake, browser, store
    httpd.shutdown()


def _log_in(port, code, path="/login"):
    status, to, cookies, _ = _req(port, "GET", path)
    assert status == 303 and to.startswith("http://ha.lan:8123/auth/authorize?")
    state = _cookie(cookies, login.STATE_COOKIE)
    q = urllib.parse.urlencode({"code": code, "state": state})
    status, to, cookies, _ = _req(port, "GET", f"/auth/callback?{q}",
                                  f"{login.STATE_COOKIE}={state}")  # fmt: skip
    assert status == 303
    return to, f"{login.SESSION_COOKIE}={_cookie(cookies, login.SESSION_COOKIE)}"


def _csrf(page):
    return re.search(r'name=token value="([^"]+)"', page)[1]


def test_the_first_login_is_held_until_the_user_creates_the_token(first_run):
    port, fake, browser, store = first_run
    status, _, _, page = _req(port, "GET", "/")
    assert status == 401 and b"First time:" in page and b"separate" not in page
    to, me = _log_in(port, "a")
    assert to == "/setup" and ha_token.source() == ""  # nothing made without a click
    assert supervisor.LLAT_CREATE not in fake.calls and browser.revoked == []  # held

    page = _req(port, "GET", "/setup", me)[3].decode()
    assert "1 of 2" in page and ">Create token<" in page and "logs you in again" not in page
    assert "Paste a long-lived token" in page and "Skip for now" in page
    assert "separate" not in page
    form = {"token": _csrf(page), "back": "setup"}
    assert _req(port, "POST", "/ha-token/create", me, form)[1] == "/setup?saved=1"
    assert ha_token.source() == "barkley" and browser.revoked == ["refresh-a"]  # let go

    page = _req(port, "GET", "/setup?saved=1", me)[3].decode()
    assert "Barkley has its own Home Assistant token" in page and ">Next<" in page
    assert _req(port, "POST", "/setup/next", me, form)[1] == "/setup?step=github"

    page = _req(port, "GET", "/setup?step=github", me)[3].decode()
    link = urllib.parse.urlsplit(re.search(r'href="(https://github\.com/[^"]+)"', page)[1]
                                 .replace("&amp;", "&"))  # fmt: skip
    q = urllib.parse.parse_qs(link.query)
    assert link.path == "/settings/personal-access-tokens/new"
    assert q["name"][0].startswith("Barkley 20") and len(q["name"][0]) <= 40
    assert q["expires_in"] == ["366"] and set(q) == {"name", "description", "expires_in"}
    assert 'rel="noopener noreferrer"' in page and ">Skip<" in page

    gh = "github_pat_" + "a" * 82
    status, to, _, _ = _req(port, "POST", "/github-token", me,
                            {"token": _csrf(page), "value": gh, "back": "setup"})  # fmt: skip
    assert (status, to) == (303, "/setup?step=github&saved=1")
    assert settings_mod.token_source(store.path) == "settings"
    page = _req(port, "GET", "/setup?step=github&saved=1", me)[3].decode()
    assert "Barkley has a GitHub token." in page and ">Done<" in page

    # with a token, a later login is an ordinary one: revoked at once, onto the list
    assert _log_in(port, "b")[0] == "/" and browser.revoked == ["refresh-a", "refresh-b"]
    assert b"First time" not in _req(port, "GET", "/")[3]


def test_pasting_or_skipping_lets_go_of_the_held_login(first_run):
    port, fake, browser, _store = first_run
    _, me = _log_in(port, "p")
    page = _req(port, "GET", "/setup", me)[3].decode()
    form = {"token": _csrf(page), "value": fake.add(), "back": "setup"}
    assert _req(port, "POST", "/ha-token", me, form)[1] == "/setup?saved=1"
    assert browser.revoked == ["refresh-p"] and supervisor.LLAT_CREATE not in fake.calls

    store_token = supervisor.OWN_TOKEN_FILE
    store_token.unlink()  # back to no token: the next login is a first one again
    _, me = _log_in(port, "s")
    assert browser.revoked == ["refresh-p"]
    form = {"token": _csrf(_req(port, "GET", "/setup", me)[3].decode()), "back": "setup"}
    assert _req(port, "POST", "/setup/next", me, form)[1] == "/setup?step=github"
    assert browser.revoked == ["refresh-p", "refresh-s"]


def test_a_failed_create_keeps_the_login_for_another_try_or_a_paste(first_run):
    port, fake, browser, _store = first_run
    fake.fail_create = True
    _, me = _log_in(port, "c")
    page = _req(port, "GET", "/setup", me)[3].decode()
    form = {"token": _csrf(page), "back": "setup"}
    assert _req(port, "POST", "/ha-token/create", me, form)[1] == "/setup?bad=create"
    page = _req(port, "GET", "/setup?bad=create", me)[3].decode()
    assert "create Barkley" in page and "unknown_error" in page and browser.revoked == []
    fake.fail_create = False
    assert _req(port, "POST", "/ha-token/create", me, form)[1] == "/setup?saved=1"
    assert browser.revoked == ["refresh-c"]


def test_a_held_login_ends_after_ten_minutes_or_at_logout():
    ha = FakeHA()
    lg, clock = _login(ha)
    state, _ = lg.start(login.FIRST)
    sid, _ = lg.finish("h", state, state)
    assert lg.held(sid) == "access-h" and ha.revoked == []
    clock[0] += login.HOLD_SECONDS + 1
    assert lg.held(sid) == "" and ha.revoked == ["refresh-h"]
    state, _ = lg.start(login.FIRST)
    sid, _ = lg.finish("i", state, state)
    lg.logout(sid)
    assert ha.revoked == ["refresh-h", "refresh-i"] and lg.held(sid) == ""
    state, _ = lg.start(login.FIRST)
    lg.finish("j", state, state)
    lg.release_all()  # shutdown
    assert ha.revoked[-1] == "refresh-j"


def test_a_first_login_refused_for_a_non_admin_is_still_revoked_at_once():
    ha = FakeHA(admin=False)
    lg, _ = _login(ha)
    state, _ = lg.start(login.FIRST)
    with pytest.raises(login.LoginError):
        lg.finish("k", state, state)
    assert ha.revoked == ["refresh-k"]


def test_the_no_token_banner_links_to_setup_and_settings_offers_github(first_run):
    port, _fake, _browser, _store = first_run
    _, me = _log_in(port, "d")
    page = _req(port, "GET", "/", me)[3].decode()
    assert 'href="/setup"' in page
    page = _req(port, "GET", "/settings", me)[3].decode()
    assert "github.com/settings/personal-access-tokens/new" in page
