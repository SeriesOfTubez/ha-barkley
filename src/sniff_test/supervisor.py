"""What the add-on reads from Home Assistant, through the Supervisor (stdlib only).

Two reads, both covered by `homeassistant_api: true` in config.yaml, no other permission:

- `GET http://supervisor/core/api/config`: the installed HA version.
- The Marketplace's installed list, over the Supervisor's Core websocket proxy
  (`ws://supervisor/core/websocket`): installed integrations and cards, with the
  version installed and the version it would install now (`available_version`
  already follows the repo's "show beta" switch). HA 2026.11 ships the Marketplace in
  Core (`marketplace/repositories/list`; it took over `custom_components/hacs`).
  Older HA with the HACS custom integration answers `hacs/repositories/list`, which
  returns the same fields; it is asked only when Core doesn't know the first command.

The proxy talks to Core as the Supervisor's admin user, so this connection could send
any non-Supervisor command. The client sends only the two list commands, fixed in code
(`_ALLOWED_COMMANDS`); nothing from a request or a report ever becomes a command.

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
import urllib.request
from dataclasses import dataclass
from typing import Any

SUPERVISOR_HOST = "supervisor"
MARKETPLACE_LIST = "marketplace/repositories/list"  # HA 2026.11+: built into Core
HACS_LIST = "hacs/repositories/list"  # older HA: the HACS custom integration
LIST_COMMANDS = (MARKETPLACE_LIST, HACS_LIST)
_ALLOWED_COMMANDS = frozenset(LIST_COMMANDS)
_MAX_MESSAGE = 64 * 1024 * 1024  # what the Supervisor accepts from Core
_TIMEOUT = 20
# HACS categories Sniff Test can scan, and what it calls them.
SCANNABLE = {"integration": "integration", "plugin": "card"}
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_VERSION = re.compile(r"^[A-Za-z0-9_.+/-]{1,100}$")


class SupervisorError(Exception):
    """The Supervisor, Core or HACS didn't answer the way we need."""


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

    def _read(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._fill()
        out, self._buf = self._buf[:n], self._buf[n:]
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

    def recv_json(self) -> Any:
        parts: list[bytes] = []
        size = 0
        while True:
            b0, b1 = self._read(2)
            fin, opcode, n = b0 & 0x80, b0 & 0x0F, b1 & 0x7F
            if n == 126:
                (n,) = struct.unpack("!H", self._read(2))
            elif n == 127:
                (n,) = struct.unpack("!Q", self._read(8))
            mask = self._read(4) if b1 & 0x80 else b""
            size += n
            if size > _MAX_MESSAGE:
                raise SupervisorError("websocket message too large")
            data = self._read(n)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 0x8:
                raise SupervisorError("websocket closed by the server")
            if opcode == 0x9:
                self._send_frame(0xA, data)
                size -= n
                continue
            if opcode == 0xA:
                size -= n
                continue
            parts.append(data)
            if fin:
                try:
                    return json.loads(b"".join(parts))
                except ValueError as ex:
                    raise SupervisorError("websocket message is not JSON") from ex

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._send_frame(0x8, b"")
        self.sock.close()


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
    try:
        ws = _WebSocket(host, port, path)
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


def installed_hacs(tok: str | None = None, **kw: Any) -> tuple[list[Installed], dict[str, int]]:
    """Installed Marketplace (HACS) integrations and cards; SupervisorError says why not."""
    tok = tok or token()
    if not tok:
        raise SupervisorError("not running as a Home Assistant add-on (no SUPERVISOR_TOKEN)")
    for command in LIST_COMMANDS:
        try:
            return parse_installed(core_command(command, tok, **kw))
        except SupervisorError as ex:
            if "unknown_command" in str(ex):
                continue  # not this HA's Marketplace; try the next one
            if "not_loaded" in str(ex):
                raise SupervisorError("the Marketplace hasn't finished loading yet") from ex
            raise
    raise SupervisorError(
        "neither the Marketplace (HA 2026.11+) nor HACS answered; is either set up?"
    )
