"""The standalone panel's login: "log in with Home Assistant".

An add-on's panel sits behind HA ingress, so HA has already logged the person in and
only the Supervisor can connect. A standalone Barkley (HA Container, HA Core, or Barkley
on another machine) is reachable from the network, so it asks Home Assistant who is
there, using HA's own OAuth2 (https://developers.home-assistant.io/docs/auth_api):

1. `/login` makes a random `state`, keeps it for ten minutes, sets it in a cookie, and
   sends the browser to HA's `/auth/authorize` with `client_id` = Barkley's own URL and
   `redirect_uri` = `<that URL>/auth/callback` (HA accepts a redirect on the client's own
   scheme, host and port, and shows the person which address asks).
2. HA logs the person in and sends the browser back with a one-time `code`.
3. `/auth/callback` checks the state against the cookie and the ones it made, trades the
   code for tokens (server to HA), asks `auth/current_user` with them, and lets in
   **administrators only** (the add-on's panel is admin-only too).
   (0.14.0 part 4) A login started from Create token (`start(purpose="token")`) also
   makes Barkley's own long-lived token with the login's access token, before the
   login's own tokens are revoked (`token_fn`, ha_token.py).
4. It then revokes the refresh token at once: Barkley keeps no token of the person,
   only its own random session id in an HttpOnly, SameSite=Lax cookie (Secure on
   https), valid for `SESSION_SECONDS`, in memory (a restart logs everyone out).

Everything a session can do still needs the panel's per-process form token on POSTs.
"""

from __future__ import annotations

import contextlib
import re
import secrets
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie

from sniff_test import supervisor
from sniff_test.supervisor import SupervisorError

SESSION_COOKIE = "barkley_session"
STATE_COOKIE = "barkley_login"
CALLBACK_PATH = "/auth/callback"
SESSION_SECONDS = 12 * 3600
STATE_SECONDS = 600
_MAX_SESSIONS = 64
_MAX_STATES = 64
# Anyone who can reach the panel can start a login and send any code back, and each
# failed code exchange counts against Barkley's own address in HA's ip_ban (when the
# user set login_attempts_threshold). Past this many failures in the window, codes
# aren't sent to HA until the window passes.
MAX_FAILURES = 5
FAILURE_WINDOW = 600


class LoginError(Exception):
    """The login didn't work; the text is shown to the person."""


@dataclass(frozen=True, slots=True)
class Session:
    user: str  # display name
    user_id: str
    expires: float
    # (0.14.0) why this login couldn't make Barkley's token, if it was asked to: shown on
    # the setup or Settings page; the login itself still succeeds
    token_error: str = ""


def base_url(url: str, what: str) -> str:
    """scheme://host[:port] with no trailing slash, or SupervisorError."""
    scheme, host, port = supervisor.parse_ha_url(url, what)
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}" + ("" if port == default else f":{port}")


# Login purposes that also make Barkley's own Home Assistant token
MAKES_TOKEN = ("token", "setup")
# (0.14.0, his call 2026-11-18) The first login while Barkley has no token: the login's
# tokens are held for the setup's Home Assistant step (Create token without a second
# login), then revoked when that step ends, on logout, or after HOLD_SECONDS at most.
# Revoking the refresh token early isn't possible: HA checks every access token against
# the refresh token that issued it (auth/__init__.py, async_validate_access_token).
FIRST = "first"
HOLD_SECONDS = 600
_MAX_HELD = 4


@dataclass
class Login:
    public_url: str  # Barkley as the browser reaches it: the OAuth client_id
    ha_url: str  # Home Assistant as the browser reaches it
    exchange_fn: Callable[[str, str], tuple[str, str]] = supervisor.auth_exchange
    user_fn: Callable[[str], supervisor.User] = supervisor.current_user
    revoke_fn: Callable[[str], None] = supervisor.auth_revoke
    now_fn: Callable[[], float] = time.time
    # (0.14.0) Create token: called with the login's access token, before it's revoked
    token_fn: Callable[[str], None] | None = None
    _states: dict[str, tuple[float, str]] = field(default_factory=dict)
    _sessions: dict[str, Session] = field(default_factory=dict)
    _failures: list[float] = field(default_factory=list)
    # sid: (access, refresh, until), the first login held for setup
    _held: dict[str, tuple[str, str, float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self.public_url = base_url(self.public_url, "BARKLEY_URL")
        self.ha_url = base_url(self.ha_url, "HA_BROWSER_URL")

    @property
    def client_id(self) -> str:
        return self.public_url + "/"

    @property
    def redirect_uri(self) -> str:
        return self.public_url + CALLBACK_PATH

    @property
    def secure(self) -> bool:
        return self.public_url.startswith("https://")

    def _prune(self, now: float) -> None:
        self._states = {s: t for s, t in self._states.items() if t[0] > now}
        self._sessions = {k: v for k, v in self._sessions.items() if v.expires > now}

    def start(self, purpose: str = "") -> tuple[str, str]:
        """(state, the URL of HA's login page). `purpose` "token" (from Settings) or
        "setup" (the first login, while Barkley has no token): this login also makes
        Barkley's own token. The caller decides when a purpose is allowed."""
        state = secrets.token_urlsafe(24)
        now = self.now_fn()
        with self._lock:
            self._prune(now)
            if len(self._states) >= _MAX_STATES:  # oldest first out
                self._states.pop(min(self._states, key=lambda k: self._states[k][0]))
            self._states[state] = (
                now + STATE_SECONDS,
                purpose if purpose in (*MAKES_TOKEN, FIRST) else "",
            )
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "state": state,
            }
        )
        return state, f"{self.ha_url}/auth/authorize?{query}"

    def purpose(self, state: str) -> str:
        """What a login in progress was started for ("token", "setup" or ""), without
        using it up."""
        with self._lock:
            return self._states.get(state, (0.0, ""))[1]

    def finish(self, code: str, state: str, cookie_state: str) -> tuple[str, Session]:
        """The callback: (new session id, session), or LoginError."""
        now = self.now_fn()
        with self._lock:
            self._prune(now)
            known = state in self._states
            purpose = self._states.pop(state, (0.0, ""))[1]
        same = bool(state) and secrets.compare_digest(state, cookie_state or "")
        if not (known and same):
            raise LoginError("That login link has expired or didn't start here. Try again.")
        if not code:
            raise LoginError("Home Assistant didn't finish the login.")
        with self._lock:
            self._failures = [t for t in self._failures if t > now - FAILURE_WINDOW]
            if len(self._failures) >= MAX_FAILURES:
                raise LoginError(
                    "Too many failed logins in the last few minutes. Wait ten minutes and "
                    "try again."
                )
        try:
            access, refresh = self.exchange_fn(code, self.client_id)
        except SupervisorError as ex:
            with self._lock:
                self._failures.append(now)
            raise LoginError(f"Home Assistant didn't accept the login ({ex}).") from ex
        try:
            try:
                user = self.user_fn(access)
            except SupervisorError as ex:
                raise LoginError(
                    f"Barkley couldn't ask Home Assistant who logged in ({ex})."
                ) from ex
            if not user.is_admin:
                raise LoginError(
                    f"{user.name or 'That user'} isn't a Home Assistant administrator. Barkley "
                    "starts scans and changes notifications, so it's for administrators only."
                )
            token_error = ""
            if purpose in MAKES_TOKEN and self.token_fn is not None:
                try:
                    self.token_fn(access)
                except SupervisorError as ex:
                    token_error = f"Barkley couldn't create its token ({ex})."
            sid = secrets.token_urlsafe(32)
            hold = purpose == FIRST
        except BaseException:
            self.revoke_fn(refresh)
            raise
        if hold:
            with self._lock:
                oldest = min(self._held, key=lambda k: self._held[k][2]) if len(
                    self._held) >= _MAX_HELD else None  # fmt: skip
                self._held[sid] = (access, refresh, now + HOLD_SECONDS)
            if oldest is not None:
                self.release(oldest)
            timer = threading.Timer(HOLD_SECONDS, self.release, (sid,))
            timer.daemon = True
            timer.start()
        else:
            self.revoke_fn(refresh)
        session = Session(
            user.name or "administrator", user.id, now + SESSION_SECONDS, token_error[:300]
        )
        with self._lock:
            if len(self._sessions) >= _MAX_SESSIONS:
                self._sessions.pop(min(self._sessions, key=lambda k: self._sessions[k].expires))
            self._sessions[sid] = session
        return sid, session

    def session(self, sid: str | None) -> Session | None:
        if not sid:
            return None
        now = self.now_fn()
        with self._lock:
            s = self._sessions.get(sid)
            if s is None or s.expires <= now:
                self._sessions.pop(sid, None)
                return None
            return s

    def logout(self, sid: str | None) -> None:
        with self._lock:
            self._sessions.pop(sid or "", None)
        self.release(sid)

    def held(self, sid: str | None) -> str:
        """The access token of this session's first login while it's still held, or ""."""
        with self._lock:
            got = self._held.get(sid or "")
        if got is None:
            return ""
        if got[2] <= self.now_fn():
            self.release(sid)
            return ""
        return got[0]

    def release(self, sid: str | None) -> None:
        """Revoke a held first login (its refresh token, and with it the access token)."""
        with self._lock:
            got = self._held.pop(sid or "", None)
        if got is not None:
            # HA unreachable: an unused refresh token expires there by itself (90 days)
            with contextlib.suppress(SupervisorError):
                self.revoke_fn(got[1])

    def release_all(self) -> None:
        """On shutdown: revoke every held first login."""
        with self._lock:
            sids = list(self._held)
        for sid in sids:
            self.release(sid)

    def cookie(self, name: str, value: str, max_age: int) -> str:
        """A Set-Cookie value: HttpOnly, SameSite=Lax (the way back from HA's login is a
        top-level navigation from another site), Secure on https."""
        return f"{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax" + (
            "; Secure" if self.secure else ""
        )


_PRINTABLE = re.compile(r"^[\x21-\x7e]+$")


def ha_login_url(ha_url: str, to: str) -> str:
    """`to` if it is HA's login page under the configured `ha_url` and one printable
    line (no header can be smuggled into Location), else HA's bare login page."""
    prefix = f"{ha_url}/auth/authorize?"
    if to.startswith(prefix) and _PRINTABLE.match(to):
        return to
    return f"{ha_url}/auth/authorize"


def read_cookie(header: str | None, name: str) -> str:
    if not header:
        return ""
    jar = SimpleCookie()
    try:
        jar.load(header)
    except CookieError:
        return ""
    morsel = jar.get(name)
    return morsel.value[:200] if morsel else ""
