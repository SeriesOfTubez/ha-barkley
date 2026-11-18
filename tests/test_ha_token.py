"""(0.14.0 part 4) Standalone: Barkley's own Home Assistant token, made with a login or
pasted, and its rotation (user decisions 2026-11-17). HA_TOKEN / HA_TOKEN_FILE always
win and are never rotated; the token file is mode 600, outside the database; a failed
rotation keeps the old token."""

import stat
from datetime import UTC, datetime, timedelta

import pytest
from test_server import get, post, token
from test_standalone import FakeHA, _login

from sniff_test import ha_token, login, server, supervisor
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
    with pytest.raises(login.LoginError, match="Couldn't create Barkley's token"):
        lg.finish("c", state, state)
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
