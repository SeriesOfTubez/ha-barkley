"""(0.14.0 part 4) Standalone: Barkley's own Home Assistant token, and its rotation.

Agreed with the user 2026-11-17 (vault: Feedback Plan, part 4). Facts checked in Home
Assistant Core's source (2026.11.2, `homeassistant/components/auth/__init__.py` and
`homeassistant/auth/__init__.py`):
- `auth/long_lived_access_token` (`client_name`, `lifespan` in days) makes a token for the
  user of the connection; a user's long-lived tokens need distinct names.
- `auth/refresh_tokens` lists the user's tokens and marks the connection's own
  (`is_current`); `auth/delete_refresh_token` deletes one of the user's tokens by id.
All three need only a logged-in user, so Barkley's token can replace itself.

Where the token comes from, in order:
1. `HA_TOKEN` or `HA_TOKEN_FILE` (compose): the user's own, never rotated by Barkley.
2. Barkley's own file next to its store (`ha-token`, mode 600): made with the Create
   token button after an administrator logs in, or pasted on the same screen. Rotated.
The file is never in the database, an export or Diagnostics, and no scanner tool can
read it (sandbox.py: tools read only their own workspace and caches). Not encrypted: the
key would have to sit beside it (the docs say why).

Rotation: the token makes its successor, checks it (an administrator's), saves it, then
deletes itself by id. The lifespan is twice the period plus a week, so a missed rotation
breaks nothing. A failed rotation keeps the old token, shows a banner and notifies.
"""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sniff_test import supervisor
from sniff_test.supervisor import SupervisorError

FILE = "ha-token"
META_KEY = "ha_token"
NAME = "Barkley"
PERIODS = (30, 60, 90, 180)
DEFAULT_PERIOD = 60
_MAX = 8192


def lifespan(period_days: int) -> int:
    return period_days * 2 + 7


def path(store_path: Path) -> Path:
    return Path(store_path).parent / FILE


def source() -> str:
    """ "env" (HA_TOKEN), "file" (HA_TOKEN_FILE), "barkley" (its own file) or ""."""
    if os.environ.get(supervisor.HA_TOKEN_ENV, "").strip():
        return "env"
    if os.environ.get(supervisor.HA_TOKEN_FILE_ENV, "").strip():
        return "file"
    own = supervisor.OWN_TOKEN_FILE
    return "barkley" if own is not None and own.exists() else ""


@dataclass
class Meta:
    id: str = ""
    name: str = ""
    created: str = ""  # ISO 8601 UTC
    how: str = ""  # created | pasted | rotated
    error: str = ""  # the last failed rotation, shown until one works
    tried: str = ""

    @classmethod
    def load(cls, store: Any) -> Meta:
        try:
            raw = json.loads(store.setting(META_KEY) or "{}")
        except ValueError:
            raw = {}
        if not isinstance(raw, dict):
            raw = {}
        return cls(**{k: str(raw.get(k) or "")[:300] for k in cls.__dataclass_fields__})

    def save(self, store: Any) -> None:
        store.set_setting(META_KEY, json.dumps(self.__dict__, sort_keys=True))

    def age_days(self, now: datetime) -> float | None:
        try:
            return (now - datetime.fromisoformat(self.created)).total_seconds() / 86400
        except ValueError:
            return None


def _write(file: Path, token: str) -> None:
    tmp = file.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token)
    tmp.replace(file)


def _check(token: str) -> str:
    """The token works and belongs to an administrator: its own refresh-token id."""
    user = supervisor.current_user(token)
    if not user.is_admin:
        raise SupervisorError(
            "that token isn't an administrator's (Barkley lists apps and subscribes to the "
            "Marketplace, which Home Assistant allows administrators only)"
        )
    tokens = supervisor.core_command(supervisor.REFRESH_TOKENS, token)
    own = next((t for t in tokens or [] if isinstance(t, dict) and t.get("is_current")), None)
    tid = (own or {}).get("id")
    if not isinstance(tid, str) or not tid:
        raise SupervisorError("Home Assistant didn't say which token this is")
    return tid[:64]


def _name(now: datetime) -> str:
    # a user's long-lived tokens need distinct names (Core refuses a repeat), so a random
    # suffix: two made in the same second still differ
    return f"{NAME} {now.strftime('%Y-%m-%d %H:%M')} {secrets.token_hex(2)}"


def create(access_token: str, period: int, now: datetime | None = None) -> tuple[str, str]:
    """A new long-lived token for the user of `access_token` (the login's, or Barkley's
    own when rotating): (token, name)."""
    now = now or datetime.now(UTC)
    name = _name(now)
    tok = supervisor.core_command(
        supervisor.LLAT_CREATE, access_token, client_name=name, lifespan=lifespan(period)
    )
    if not isinstance(tok, str) or not tok or len(tok) > _MAX:
        raise SupervisorError("Home Assistant gave no token")
    return tok, name


def adopt(store: Any, token: str, how: str, name: str = "", now: datetime | None = None) -> Meta:
    """Check a token (an administrator's, working) and keep it as Barkley's own."""
    own = supervisor.OWN_TOKEN_FILE
    if own is None:
        raise SupervisorError("Barkley isn't running standalone")
    token = token.strip()
    if not token or len(token) > _MAX or any(c.isspace() for c in token):
        raise SupervisorError("that doesn't look like a Home Assistant token")
    tid = _check(token)
    _write(own, token)
    meta = Meta(id=tid, name=name, created=(now or datetime.now(UTC)).isoformat(
        timespec="seconds"), how=how)  # fmt: skip
    meta.save(store)
    return meta


RETRY_HOURS = 24  # a failed rotation is tried again (and notified) once a day


def due(store: Any, period: int, now: datetime | None = None) -> bool:
    if source() != "barkley":
        return False
    now = now or datetime.now(UTC)
    m = Meta.load(store)
    if m.error and m.tried:
        try:
            if now - datetime.fromisoformat(m.tried) < timedelta(hours=RETRY_HOURS):
                return False
        except ValueError:
            pass
    age = m.age_days(now)
    return age is None or age >= period


def rotate(
    store: Any,
    period: int,
    now: datetime | None = None,
    notify: Callable[[str, str], None] | None = None,
) -> str:
    """Replace Barkley's own token with a new one. "" when done, else why not (the old
    token keeps working; a banner shows it and, with `notify`, a notification)."""
    now = now or datetime.now(UTC)
    own = supervisor.OWN_TOKEN_FILE
    if source() != "barkley" or own is None:
        return "not Barkley's own token (HA_TOKEN or HA_TOKEN_FILE is set), so not rotated"
    old = Meta.load(store)
    try:
        current = own.read_text(encoding="utf-8")[:_MAX].strip()
        new, name = create(current, period, now)
        tid = _check(new)
        _write(own, new)
    except (SupervisorError, OSError) as ex:
        why = f"rotating Home Assistant's token failed: {ex}"[:300]
        old.error, old.tried = why, now.isoformat(timespec="seconds")
        old.save(store)
        if notify is not None:
            notify(
                "Barkley: token not rotated",
                "Barkley couldn't replace its Home Assistant token. The current one keeps "
                "working. Open Barkley's Settings page to see why or to try again.",
            )
        return why
    Meta(id=tid, name=name, created=now.isoformat(timespec="seconds"), how="rotated").save(store)
    if old.id and old.id != tid:  # the old token deletes itself last, with the new one
        try:
            supervisor.core_command(supervisor.REFRESH_TOKEN_DELETE, new, refresh_token_id=old.id)
        except SupervisorError as ex:
            m = Meta.load(store)
            m.error = f"the old token wasn't deleted ({ex}); delete it in your HA profile"[:300]
            m.save(store)
    return ""


def status_line(store: Any, period: int, now: datetime | None = None) -> str:
    """For the Settings page: where the token comes from and when it rotates."""
    src = source()
    if src == "env":
        return "From HA_TOKEN. Barkley doesn't rotate a token you gave it."
    if src == "file":
        return "From HA_TOKEN_FILE. Barkley doesn't rotate a token you gave it."
    if src != "barkley":
        return "None yet."
    m = Meta.load(store)
    now = now or datetime.now(UTC)
    how = {"created": "Made by Barkley", "pasted": "Pasted here", "rotated": "Rotated by Barkley"}
    try:
        nxt = (datetime.fromisoformat(m.created) + timedelta(days=period)).date().isoformat()
    except ValueError:
        nxt = "soon"
    return f"{how.get(m.how, 'Set')} on {m.created[:10] or '?'}; next rotation {nxt}."
