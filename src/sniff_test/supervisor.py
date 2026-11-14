"""What the add-on asks Home Assistant, through the Supervisor (stdlib only).

Three calls, all covered by `homeassistant_api: true` in config.yaml, no other permission:

- `GET http://supervisor/core/api/config`: the installed HA version.
- The Marketplace's installed list, over the Supervisor's Core websocket proxy
  (`ws://supervisor/core/websocket`): installed integrations and cards, with the
  version installed and the version it would install now (`available_version`
  already follows the repo's "show beta" switch). HA 2026.11 ships the Marketplace in
  Core (`marketplace/repositories/list`; it took over `custom_components/hacs`).
  Older HA with the HACS custom integration answers `hacs/repositories/list`, which
  returns the same fields; it is asked only when Core doesn't know the first command.

- (M8) `POST http://supervisor/core/api/services/ai_task/generate_data?return_response`,
  only when the user clicks "Explain this app" and has chosen an AI Task entity in the
  options. It sends findings about a public repo (the report's `ai_brief`), never HA
  data, to whatever AI provider that entity uses.

- (M8) `POST http://supervisor/core/api/template` with one template fixed in code
  (`AI_ENTITIES_TEMPLATE`) that returns only the ids and names of `ai_task` entities, so
  the panel can offer them in a dropdown. HA renders it; no other entity or state ever
  reaches the app (user decision over reading all states via /api/states).

- (auto-sniff) `marketplace/subscribe` on a long-lived websocket, for two fixed signals
  (`WATCH_SIGNALS`): the install progress of a repository (its end, `progress: false`,
  is the cue to read the installed list again) and repository changes (uninstalls).
  Verified in Core's source at 2026.11.0: there is no `hacs/subscribe` any more, and no
  event carries the installed version, so the list is read after each cue.

- (auto-sniff) `POST /core/api/services/persistent_notification/create` and, when the
  user picked a target in the panel, `POST /core/api/services/notify/<target>`: one
  notification per auto-sniffed install or update. The text is built from validated
  names, versions, scores and fixed rule titles, never from scanned text. To offer the
  targets, `GET /core/api/services` is read and only the names of `notify` services
  are kept. `GET /addons/self/info` (allowed for every app without a Supervisor role)
  gives the app's own slug, for the "Open Barkley" link.

The proxy talks to Core as the Supervisor's admin user, so these connections could reach
almost anything in Core. The client sends only the list commands and the subscribe
command with fixed signals, the one AI Task service call, the two notification services
and the one fixed template, all in code (`_ALLOWED_COMMANDS`, `WATCH_SIGNALS`,
`AI_TASK_PATH`, `AI_ENTITIES_TEMPLATE`, `NOTIFY_PATH`); nothing from a request or a
report ever becomes a command, a service name, a template or a URL (a notify target is
checked against the list HA gave and a strict pattern).

Nothing here touches installed code: the Marketplace only reports names and versions.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import re
import secrets
import socket
import struct
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

SUPERVISOR_HOST = "supervisor"
MARKETPLACE_LIST = "marketplace/repositories/list"  # HA 2026.11+: built into Core
HACS_LIST = "hacs/repositories/list"  # older HA: the HACS custom integration
LIST_COMMANDS = (MARKETPLACE_LIST, HACS_LIST)
SUBSCRIBE = "marketplace/subscribe"  # HA 2026.11+: Core's Marketplace dispatcher signals
# The two signals the watcher subscribes to (Core `marketplace/enums.py`, MarketplaceSignal).
SIGNAL_INSTALL_PROGRESS = "marketplace_repository_install_progress"
SIGNAL_REPOSITORY = "marketplace_repository"
WATCH_SIGNALS = (SIGNAL_INSTALL_PROGRESS, SIGNAL_REPOSITORY)
_ALLOWED_COMMANDS = frozenset((*LIST_COMMANDS, SUBSCRIBE))
_MAX_MESSAGE = 64 * 1024 * 1024  # what the Supervisor accepts from Core
_TIMEOUT = 20
# HACS categories Barkley can scan, and what it calls them.
SCANNABLE = {"integration": "integration", "plugin": "card"}
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_VERSION = re.compile(r"^[A-Za-z0-9_.+/-]{1,100}$")


class SupervisorError(Exception):
    """The Supervisor, Core or HACS didn't answer the way we need."""


AI_TASK_PATH = "/core/api/services/ai_task/generate_data?return_response"
_AI_ENTITY = re.compile(r"^ai_task\.[a-z0-9_]{1,100}$")
_AI_TIMEOUT = 180


AI_ENTITIES_TEMPLATE = (
    "{% set ns = namespace(out=[]) %}{% for s in states.ai_task %}"
    "{% set ns.out = ns.out + [[s.entity_id, s.name]] %}{% endfor %}{{ ns.out | tojson }}"
)


def ai_task_entities(tok: str | None = None) -> list[tuple[str, str]]:
    """(entity_id, name) of every ai_task entity, via the one fixed template."""
    tok = tok or token()
    if not tok:
        raise SupervisorError("not running as a Home Assistant add-on")
    req = urllib.request.Request(
        f"http://{SUPERVISOR_HOST}/core/api/template",
        data=json.dumps({"template": AI_ENTITIES_TEMPLATE}).encode(),
        method="POST",
    )
    req.add_header("Authorization", f"Bearer {tok}")
    req.add_header("Content-Type", "application/json")
    try:
        # The host is the constant SUPERVISOR_HOST; the path is a constant of this module.
        # nosemgrep: dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310
            data = json.loads(r.read().decode("utf-8", "replace") or "[]")
    except (OSError, ValueError) as ex:
        raise SupervisorError(f"couldn't list AI Task entities: {ex}") from ex
    out = []
    for item in data if isinstance(data, list) else []:
        ok = isinstance(item, list) and len(item) == 2 and isinstance(item[0], str)
        if ok and ai_entity_ok(item[0]):
            out.append((item[0], str(item[1] or item[0])[:100]))
    return out


def ai_entity_ok(entity_id: str) -> bool:
    return bool(_AI_ENTITY.match(entity_id))


def ai_generate_data(
    entity_id: str,
    instructions: str,
    structure: dict[str, Any],
    task_name: str,
    tok: str | None = None,
    timeout: float = _AI_TIMEOUT,
) -> Any:
    """Call ai_task.generate_data and return its `data` (validated by HA against
    `structure`). Raises SupervisorError with HA's message on any failure."""
    tok = tok or token()
    if not tok:
        raise SupervisorError("not running as a Home Assistant add-on")
    if not ai_entity_ok(entity_id):
        raise SupervisorError(f"{entity_id!r} is not an AI Task entity (ai_task.…)")
    body = json.dumps(
        {
            "task_name": task_name,
            "entity_id": entity_id,
            "instructions": instructions,
            "structure": structure,
        }
    ).encode()
    req = urllib.request.Request(
        f"http://{SUPERVISOR_HOST}{AI_TASK_PATH}", data=body, method="POST"
    )
    req.add_header("Authorization", f"Bearer {tok}")
    req.add_header("Content-Type", "application/json")
    try:
        # The host is the constant SUPERVISOR_HOST; the path is a constant of this module.
        # nosemgrep: dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            answer = json.load(r)
    except urllib.error.HTTPError as ex:
        try:
            msg = json.loads(ex.read() or b"{}").get("message") or ex.reason
        except ValueError:
            msg = ex.reason
        raise SupervisorError(f"Home Assistant answered {ex.code}: {msg}") from ex
    except (OSError, ValueError) as ex:
        raise SupervisorError(f"AI Task call failed: {ex}") from ex
    resp = answer.get("service_response") if isinstance(answer, dict) else None
    if not isinstance(resp, dict) or "data" not in resp:
        raise SupervisorError("AI Task returned no data")
    return resp["data"]


def token() -> str | None:
    return os.environ.get("SUPERVISOR_TOKEN") or None


def ha_version(tok: str | None = None) -> str | None:
    """The installed HA version, via the Supervisor's Core API proxy (add-on only)."""
    tok = tok or token()
    if not tok:
        return None
    req = urllib.request.Request(f"http://{SUPERVISOR_HOST}/core/api/config")
    req.add_header("Authorization", f"Bearer {tok}")
    try:
        # The host is the constant SUPERVISOR_HOST; the path is a constant of this module.
        # nosemgrep: dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 - fixed URL
            version = json.load(r).get("version")
    except (OSError, ValueError):
        return None
    return version if isinstance(version, str) else None


# --- a minimal websocket client (RFC 6455), plain ws:// inside the Supervisor network ---


class _WebSocket:
    def __init__(self, host: str, port: int, path: str, timeout: float = _TIMEOUT):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self._buf = b""
        self._parts: list[bytes] = []
        self._size = 0
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        self.sock.sendall(
            (
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        head = self._read_until(b"\r\n\r\n", 16384)
        status = head.split(b"\r\n", 1)[0]
        if b" 101 " not in status + b" ":
            raise SupervisorError(f"websocket upgrade refused: {status.decode('latin-1')[:120]}")

    def _read_until(self, marker: bytes, limit: int) -> bytes:
        while marker not in self._buf:
            if len(self._buf) > limit:
                raise SupervisorError("websocket handshake too large")
            self._fill()
        head, self._buf = self._buf.split(marker, 1)
        return head

    def _fill(self) -> None:
        chunk = self.sock.recv(65536)
        if not chunk:
            raise SupervisorError("connection closed")
        self._buf += chunk

    def _peek(self, n: int) -> bytes:
        """The next n bytes, left in the buffer (a timeout while filling loses nothing)."""
        while len(self._buf) < n:
            self._fill()
        return self._buf[:n]

    def _read(self, n: int) -> bytes:
        out = self._peek(n)
        self._buf = self._buf[n:]
        return out

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        mask = secrets.token_bytes(4)
        n = len(payload)
        if n < 126:
            head = struct.pack("!BB", 0x80 | opcode, 0x80 | n)
        elif n < 1 << 16:
            head = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
        else:
            head = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(head + mask + masked)

    def send_json(self, obj: dict[str, Any]) -> None:
        self._send_frame(0x1, json.dumps(obj).encode())

    def _frame(self) -> tuple[int, bool, bytes]:
        """One whole frame: (opcode, fin, payload). The header is only peeked at until the
        whole frame is buffered, so a socket timeout in the middle leaves the stream
        intact and the next call starts over at the same frame."""
        head = self._peek(2)
        b0, b1 = head[0], head[1]
        n, off = b1 & 0x7F, 2
        if n == 126:
            (n,) = struct.unpack("!H", self._peek(4)[2:4])
            off = 4
        elif n == 127:
            (n,) = struct.unpack("!Q", self._peek(10)[2:10])
            off = 10
        masked = bool(b1 & 0x80)
        if masked:
            off += 4
        if n > _MAX_MESSAGE:
            raise SupervisorError("websocket message too large")
        raw = self._read(off + n)
        data = raw[off:]
        if masked:
            mask = raw[off - 4 : off]
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return b0 & 0x0F, bool(b0 & 0x80), data

    def recv_json(self, deadline: float | None = None) -> Any:
        """The next JSON message. Pings are answered; a timeout (TimeoutError) keeps the
        fragments read so far, so the caller may simply call again.

        `deadline` (time.monotonic()) bounds the whole wait: without it the socket timeout
        applies per frame, and the Supervisor's proxy pings every 30 s (`heartbeat=30`,
        supervisor/api/proxy.py), so a quiet connection never timed out."""
        while True:
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError("deadline passed")
                self.sock.settimeout(left)
            opcode, fin, data = self._frame()
            if opcode == 0x8:
                raise SupervisorError("websocket closed by the server")
            if opcode == 0x9:
                self._send_frame(0xA, data)
                continue
            if opcode == 0xA:
                continue
            self._parts.append(data)
            self._size += len(data)
            if self._size > _MAX_MESSAGE:
                raise SupervisorError("websocket message too large")
            if fin:
                raw, self._parts, self._size = b"".join(self._parts), [], 0
                try:
                    return json.loads(raw)
                except ValueError as ex:
                    raise SupervisorError("websocket message is not JSON") from ex

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._send_frame(0x8, b"")
        self.sock.close()


def _open_core(tok: str, host: str, port: int, path: str, timeout: float = _TIMEOUT) -> _WebSocket:
    """Connect to Core through the Supervisor's proxy and authenticate as the add-on."""
    try:
        ws = _WebSocket(host, port, path, timeout=timeout)
    except OSError as ex:
        raise SupervisorError(f"can't reach the Supervisor: {ex}") from ex
    try:
        msg = ws.recv_json()
        if msg.get("type") != "auth_required":
            raise SupervisorError(f"unexpected greeting: {str(msg.get('type'))[:40]}")
        ws.send_json({"type": "auth", "access_token": tok})
        msg = ws.recv_json()
        if msg.get("type") != "auth_ok":
            raise SupervisorError("the Supervisor refused the add-on token (homeassistant_api?)")
    except (OSError, AttributeError) as ex:
        ws.close()
        raise SupervisorError(f"websocket failed: {ex}") from ex
    except SupervisorError:
        ws.close()
        raise
    return ws


def core_command(
    command: str,
    tok: str,
    *,
    host: str = SUPERVISOR_HOST,
    port: int = 80,
    path: str = "/core/websocket",
    **params: Any,
) -> Any:
    """Send one allowed command over the Core websocket and return its result."""
    if command not in _ALLOWED_COMMANDS:
        raise SupervisorError(f"command not allowed: {command}")
    ws = _open_core(tok, host, port, path)
    try:
        ws.send_json({"id": 1, "type": command, **params})
        while True:
            msg = ws.recv_json()
            if isinstance(msg, dict) and msg.get("id") == 1 and msg.get("type") == "result":
                break
        if not msg.get("success"):
            err = msg.get("error") or {}
            raise SupervisorError(
                f"{command}: {str(err.get('code'))[:40]}: {str(err.get('message'))[:200]}"
            )
        return msg.get("result")
    except (OSError, AttributeError) as ex:
        raise SupervisorError(f"websocket failed: {ex}") from ex
    finally:
        ws.close()


class Subscription:
    """A long-lived Core websocket subscribed to the Marketplace's signals (auto-sniff).

    Only `WATCH_SIGNALS` can be subscribed (fixed in code). `events()` yields
    `(signal, data)` for each event and `None` whenever `idle` seconds pass without
    one, so the caller can poll the installed list as a fallback in between.
    """

    def __init__(
        self,
        tok: str,
        *,
        signals: tuple[str, ...] = WATCH_SIGNALS,
        host: str = SUPERVISOR_HOST,
        port: int = 80,
        path: str = "/core/websocket",
        idle: float = 60.0,
    ):
        bad = [x for x in signals if x not in WATCH_SIGNALS]
        if bad:
            raise SupervisorError(f"signal not allowed: {bad[0]!r}")
        self.ws = _open_core(tok, host, port, path, timeout=idle)
        self.idle = idle
        self.signals: dict[int, str] = {}
        try:
            for i, sig in enumerate(signals, 1):
                self.ws.send_json({"id": i, "type": SUBSCRIBE, "signal": sig})
                self.signals[i] = sig
            pending = set(self.signals)
            while pending:
                msg = self.ws.recv_json()
                if not isinstance(msg, dict) or msg.get("type") != "result":
                    continue
                mid = msg.get("id")
                if mid not in pending:
                    continue
                if not msg.get("success"):
                    err = msg.get("error") or {}
                    raise SupervisorError(
                        f"{SUBSCRIBE}: {str(err.get('code'))[:40]}: {str(err.get('message'))[:200]}"
                    )
                pending.discard(mid)
        except (OSError, AttributeError) as ex:
            self.ws.close()
            raise SupervisorError(f"websocket failed: {ex}") from ex
        except SupervisorError:
            self.ws.close()
            raise

    def events(self) -> Any:
        """Yields (signal, data) per event, and None at least every `idle` seconds, however
        many pings or events arrive in between (the caller polls the installed list then).
        Raises SupervisorError when the connection ends."""
        due = time.monotonic() + self.idle
        while True:
            if time.monotonic() >= due:
                due = time.monotonic() + self.idle
                yield None
                continue
            try:
                msg = self.ws.recv_json(deadline=due)
            except TimeoutError:
                continue  # `due` has passed: the top of the loop yields None
            except OSError as ex:
                raise SupervisorError(f"websocket failed: {ex}") from ex
            if not isinstance(msg, dict) or msg.get("type") != "event":
                continue
            sig = self.signals.get(msg.get("id"))  # type: ignore[arg-type]
            if sig is None:
                continue
            ev = msg.get("event")
            yield sig, (ev if isinstance(ev, dict) else {})

    def close(self) -> None:
        self.ws.close()


# --- notifications (auto-sniff) ---------------------------------------------------------

NOTIFY_PERSISTENT_PATH = "/core/api/services/persistent_notification/create"
NOTIFY_PATH = "/core/api/services/notify/"  # + a validated target
SERVICES_PATH = "/core/api/services"
SELF_INFO_PATH = "/addons/self/info"
_NOTIFY_TARGET = re.compile(r"^[a-z0-9_]{1,100}$")
_SLUG = re.compile(r"^[a-z0-9_]{1,100}$")
_NOTIFY_TIMEOUT = 20


def notify_target_ok(target: str) -> bool:
    return bool(_NOTIFY_TARGET.match(target))


def _call(path: str, body: dict[str, Any] | None, tok: str, timeout: float, what: str) -> Any:
    req = urllib.request.Request(
        f"http://{SUPERVISOR_HOST}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method="POST" if body is not None else "GET",
    )
    req.add_header("Authorization", f"Bearer {tok}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        # The host is the constant SUPERVISOR_HOST; the path is a constant of this module.
        # nosemgrep: dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed host
            raw = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as ex:
        try:
            msg = json.loads(ex.read() or b"{}").get("message") or ex.reason
        except ValueError:
            msg = ex.reason
        raise SupervisorError(f"{what}: Home Assistant answered {ex.code}: {msg}") from ex
    except OSError as ex:
        raise SupervisorError(f"{what} failed: {ex}") from ex
    try:
        return json.loads(raw) if raw.strip() else None
    except ValueError as ex:
        raise SupervisorError(f"{what}: Home Assistant's answer wasn't JSON") from ex


def notify_persistent(
    title: str, message: str, notification_id: str, tok: str | None = None
) -> None:
    """A bell notification in HA (persistent_notification.create). The same id replaces
    the earlier notification about the same app."""
    tok = tok or token()
    if not tok:
        raise SupervisorError("not running as a Home Assistant add-on")
    if not _NOTIFY_TARGET.match(notification_id):
        raise SupervisorError("bad notification id")
    body = {"notification_id": notification_id, "title": title[:100], "message": message[:1500]}
    _call(NOTIFY_PERSISTENT_PATH, body, tok, _NOTIFY_TIMEOUT, "persistent notification")


def notify_service(
    target: str, title: str, message: str, url: str = "", tok: str | None = None
) -> None:
    """notify.<target> (for example a phone's mobile_app). `url` is the panel path the
    companion app opens from the notification; other platforms ignore it."""
    tok = tok or token()
    if not tok:
        raise SupervisorError("not running as a Home Assistant add-on")
    if not notify_target_ok(target):
        raise SupervisorError(f"{target!r} is not a notify target name")
    body: dict[str, Any] = {"title": title[:100], "message": message[:1500]}
    if url:
        body["data"] = {"url": url}
    _call(NOTIFY_PATH + target, body, tok, _NOTIFY_TIMEOUT, f"notify.{target}")


def notify_targets(tok: str | None = None) -> list[str]:
    """Names of the `notify` services HA offers (GET /api/services, only that domain kept)."""
    tok = tok or token()
    if not tok:
        raise SupervisorError("not running as a Home Assistant add-on")
    data = _call(SERVICES_PATH, None, tok, 15, "listing notify targets")
    out: list[str] = []
    for dom in data if isinstance(data, list) else []:
        if not isinstance(dom, dict) or dom.get("domain") != "notify":
            continue
        services = dom.get("services")
        names = services.keys() if isinstance(services, dict) else []
        out.extend(n for n in names if isinstance(n, str) and notify_target_ok(n))
    return sorted(set(out) - {"persistent_notification"})


def self_slug(tok: str | None = None) -> str:
    """This app's slug (GET /addons/self/info: every app may read its own info), for the
    panel link `/app/<slug>` in notifications."""
    tok = tok or token()
    if not tok:
        raise SupervisorError("not running as a Home Assistant add-on")
    data = _call(SELF_INFO_PATH, None, tok, 10, "reading the app's own info")
    slug = (data or {}).get("data", {}).get("slug") if isinstance(data, dict) else None
    if not isinstance(slug, str) or not _SLUG.match(slug):
        raise SupervisorError("the Supervisor didn't say the app's slug")
    return slug


# --- installed HACS items ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Installed:
    """One HACS repository that is installed, as HACS reports it."""

    repo: str  # owner/name
    kind: str  # integration | card
    name: str
    installed: str  # tag, or a short commit for repos without releases
    available: str  # what HACS would install now (follows "show beta")
    custom: bool  # added by the user, not from HACS's default list

    @property
    def update(self) -> bool:
        return bool(self.available) and self.available != self.installed


def parse_installed(result: Any) -> tuple[list[Installed], dict[str, int]]:
    """Scannable installed items, plus a count of installed ones we don't scan, by category.

    Every value comes from HACS's own data about third-party repos, so names and
    versions are validated before they can become a scan target.
    """
    if not isinstance(result, list):
        raise SupervisorError("HACS returned something other than a list")
    items: list[Installed] = []
    other: dict[str, int] = {}
    for r in result:
        if not isinstance(r, dict) or not r.get("installed"):
            continue
        cat = str(r.get("category") or "")
        repo = str(r.get("full_name") or "")
        if cat not in SCANNABLE:
            other[cat[:30] or "unknown"] = other.get(cat[:30] or "unknown", 0) + 1
            continue
        installed = str(r.get("installed_version") or "")
        available = str(r.get("available_version") or "")
        if not _REPO.match(repo) or not _VERSION.match(installed):
            other["unreadable"] = other.get("unreadable", 0) + 1
            continue
        items.append(
            Installed(
                repo=repo,
                kind=SCANNABLE[cat],
                name=str(r.get("name") or repo)[:100],
                installed=installed,
                available=available if _VERSION.match(available) else "",
                custom=bool(r.get("custom")),
            )
        )
    items.sort(key=lambda i: i.repo.lower())
    return items, other


def _repositories(tok: str | None = None, **kw: Any) -> Any:
    """The Marketplace's whole catalog (installed or not), via the allowlisted command."""
    tok = tok or token()
    if not tok:
        raise SupervisorError("not running as a Home Assistant add-on (no SUPERVISOR_TOKEN)")
    for command in LIST_COMMANDS:
        try:
            return core_command(command, tok, **kw)
        except SupervisorError as ex:
            if "unknown_command" in str(ex):
                continue  # not this HA's Marketplace; try the next one
            if "not_loaded" in str(ex):
                raise SupervisorError("the Marketplace hasn't finished loading yet") from ex
            raise
    raise SupervisorError(
        "neither the Marketplace (HA 2026.11+) nor HACS answered; is either set up?"
    )


def installed_hacs(tok: str | None = None, **kw: Any) -> tuple[list[Installed], dict[str, int]]:
    """Installed Marketplace (HACS) integrations and cards; SupervisorError says why not."""
    return parse_installed(_repositories(tok, **kw))


@dataclass(frozen=True, slots=True)
class CatalogItem:
    """One integration or card the Marketplace offers. Text fields come from third-party
    repos (untrusted): the panel escapes them, and only `repo` can become a scan target,
    after the same validation as the installed list."""

    repo: str
    kind: str  # integration | card
    name: str
    description: str
    stars: int
    downloads: int
    installed: bool
    topics: tuple[str, ...]


def _int(v: Any) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


def parse_catalog(result: Any) -> list[CatalogItem]:
    if not isinstance(result, list):
        raise SupervisorError("the Marketplace returned something other than a list")
    out = []
    for r in result:
        if not isinstance(r, dict) or r.get("category") not in SCANNABLE:
            continue
        repo = str(r.get("full_name") or "")
        if not _REPO.match(repo):
            continue
        topics = r.get("topics") if isinstance(r.get("topics"), list) else []
        out.append(
            CatalogItem(
                repo=repo,
                kind=SCANNABLE[r["category"]],
                name=str(r.get("name") or repo)[:100],
                description=str(r.get("description") or "")[:300],
                stars=_int(r.get("stars")),
                downloads=_int(r.get("downloads")),
                installed=bool(r.get("installed")),
                topics=tuple(str(x)[:40] for x in topics[:20]),
            )
        )
    return out


def catalog(tok: str | None = None, **kw: Any) -> list[CatalogItem]:
    return parse_catalog(_repositories(tok, **kw))


def search(
    items: list[CatalogItem], query: str, kind: str = "", limit: int = 30
) -> list[CatalogItem]:
    """Rank by how well the query matches (name, then repo, then description/topics),
    then by downloads and stars. Plain substring matching on every word."""
    words = [w for w in query.lower().split() if w][:8]
    if not words:
        return []
    scored = []
    for it in items:
        if kind and it.kind != kind:
            continue
        name, repo = it.name.lower(), it.repo.lower()
        text = " ".join([it.description.lower(), *(t.lower() for t in it.topics)])
        score = 0
        for w in words:
            if w == name or w == repo.split("/")[-1]:
                score += 100
            elif w in name:
                score += 40
            elif w in repo:
                score += 25
            elif w in text:
                score += 10
            else:
                score = -1
                break
        if score > 0:
            scored.append((score, it.downloads, it.stars, it))
    scored.sort(key=lambda s: (-s[0], -s[1], -s[2], s[3].repo.lower()))
    return [s[3] for s in scored[:limit]]
