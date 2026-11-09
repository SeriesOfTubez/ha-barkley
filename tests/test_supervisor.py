"""The add-on's reads from HA: the websocket client, HACS's installed list, the memory guard.

A fake Supervisor on 127.0.0.1 speaks the real handshake and HA's websocket protocol, so
nothing here can reach a real server.
"""

import json
import socket
import struct
import threading

import pytest

from sniff_test import doctor, memory, supervisor
from sniff_test.supervisor import Installed, SupervisorError, parse_installed

HACS_ROWS = [
    {"full_name": "acme/acme_cloud", "category": "integration", "installed": True,
     "installed_version": "v1.0.0", "available_version": "v1.1.0", "name": "Acme Cloud",
     "custom": False},
    {"full_name": "acme/acme-card", "category": "plugin", "installed": True,
     "installed_version": "v2.0.0", "available_version": "v2.0.0", "name": "Acme Card"},
    {"full_name": "acme/no-releases", "category": "integration", "installed": True,
     "installed_version": "1a2b3c4", "available_version": "5d6e7f8", "name": "No releases",
     "custom": True},
    {"full_name": "acme/theme", "category": "theme", "installed": True,
     "installed_version": "v1", "available_version": "v1"},
    {"full_name": "acme/not-installed", "category": "integration", "installed": False,
     "installed_version": "", "available_version": "v9"},
]  # fmt: skip


def _recv_frame(conn: socket.socket) -> tuple[int, bytes]:
    def read(n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError
            buf += chunk
        return buf

    b0, b1 = read(2)
    n = b1 & 0x7F
    if n == 126:
        (n,) = struct.unpack("!H", read(2))
    elif n == 127:
        (n,) = struct.unpack("!Q", read(8))
    assert b1 & 0x80, "client frames must be masked"
    mask = read(4)
    data = bytes(b ^ mask[i % 4] for i, b in enumerate(read(n)))
    return b0 & 0x0F, data


def _frame(opcode: int, payload: bytes, fin: bool = True) -> bytes:
    n = len(payload)
    b0 = (0x80 if fin else 0) | opcode
    if n < 126:
        head = struct.pack("!BB", b0, n)
    elif n < 1 << 16:
        head = struct.pack("!BBH", b0, 126, n)
    else:
        head = struct.pack("!BBQ", b0, 127, n)
    return head + payload


class FakeSupervisor:
    """Answers one websocket connection the way the Supervisor's Core proxy does."""

    def __init__(self, result=None, *, accept_token="tok", error=None, fragment=False):
        self.result = HACS_ROWS if result is None else result
        self.accept_token = accept_token
        self.error = error
        self.fragment = fragment
        self.sent: list[dict] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _send_json(self, conn, obj):
        data = json.dumps(obj).encode()
        if self.fragment and len(data) > 10:
            conn.sendall(_frame(0x9, b"ping"))  # a ping in between: must be answered
            conn.sendall(_frame(0x1, data[:10], fin=False) + _frame(0x0, data[10:]))
        else:
            conn.sendall(_frame(0x1, data))

    def _serve(self):
        conn, _ = self.sock.accept()
        with conn:
            req = b""
            while b"\r\n\r\n" not in req:
                req += conn.recv(4096)
            assert b"GET /core/websocket HTTP/1.1" in req
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n"
            )
            self._send_json(conn, {"type": "auth_required", "ha_version": "2026.11.0"})
            try:
                while True:
                    op, data = _recv_frame(conn)
                    if op == 0xA:
                        self.sent.append({"pong": data.decode()})
                        continue
                    if op == 0x8:
                        return
                    msg = json.loads(data)
                    self.sent.append(msg)
                    if msg["type"] == "auth":
                        ok = msg["access_token"] == self.accept_token
                        self._send_json(conn, {"type": "auth_ok" if ok else "auth_invalid"})
                        if not ok:
                            return
                    elif self.error:
                        self._send_json(conn, {"id": msg["id"], "type": "result",
                                               "success": False, "error": self.error})  # fmt: skip
                    else:
                        self._send_json(conn, {"id": 99, "type": "event", "event": {}})
                        self._send_json(conn, {"id": msg["id"], "type": "result",
                                               "success": True, "result": self.result})  # fmt: skip
            except (ConnectionError, OSError):
                return


def _list(fake, tok="tok"):
    return supervisor.installed_hacs(tok, host="127.0.0.1", port=fake.port)


def test_lists_installed_integrations_and_cards():
    fake = FakeSupervisor(fragment=True)
    items, other = _list(fake)
    assert [i.repo for i in items] == ["acme/acme-card", "acme/acme_cloud", "acme/no-releases"]
    cloud = items[1]
    assert (cloud.kind, cloud.installed, cloud.available, cloud.update) == (
        "integration", "v1.0.0", "v1.1.0", True,
    )  # fmt: skip
    assert items[0].kind == "card" and not items[0].update
    assert items[2].custom
    assert other == {"theme": 1}
    # The only command sent was the HACS list, and the ping got a pong.
    cmds = [m for m in fake.sent if "type" in m]
    assert [m["type"] for m in cmds] == ["auth", "hacs/repositories/list"]
    assert {"pong": "ping"} in fake.sent


def test_large_messages_use_the_64_bit_length():
    rows = [{**HACS_ROWS[0], "full_name": f"acme/r{i}", "description": "x" * 200}
            for i in range(400)]  # fmt: skip
    items, _ = _list(FakeSupervisor(rows))
    assert len(items) == 400


def test_only_the_hacs_list_can_be_sent():
    with pytest.raises(SupervisorError, match="not allowed"):
        supervisor.core_command("call_service", "tok", host="127.0.0.1", port=1)


def test_refused_token_and_missing_hacs_say_why():
    with pytest.raises(SupervisorError, match="refused the add-on token"):
        _list(FakeSupervisor(accept_token="other"))
    fake = FakeSupervisor(error={"code": "unknown_command", "message": "Unknown command."})
    with pytest.raises(SupervisorError, match="HACS isn't installed"):
        _list(fake)
    with pytest.raises(SupervisorError, match="no SUPERVISOR_TOKEN"):
        supervisor.installed_hacs(None)


def test_unreachable_supervisor_is_an_error_not_a_crash():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(SupervisorError, match="can't reach"):
        supervisor.installed_hacs("tok", host="127.0.0.1", port=port)


def test_hostile_names_and_versions_never_become_scan_targets():
    rows = [
        {"full_name": "../../etc/passwd", "category": "integration", "installed": True,
         "installed_version": "v1", "available_version": "v2"},
        {"full_name": "acme/x", "category": "integration", "installed": True,
         "installed_version": "v1; rm -rf /", "available_version": "v2"},
        {"full_name": "acme/y", "category": "plugin", "installed": True,
         "installed_version": "v1", "available_version": "<script>"},
        "not a dict",
    ]  # fmt: skip
    items, other = parse_installed(rows)
    assert [(i.repo, i.available) for i in items] == [("acme/y", "")]
    assert not items[0].update  # unreadable "available" means no update offered
    assert other == {"unreadable": 2}
    with pytest.raises(SupervisorError):
        parse_installed({"not": "a list"})


# --- memory guard -------------------------------------------------------------------------


def _meminfo(avail_gb: float) -> str:
    return (
        f"MemTotal:       {16 * 1024 * 1024} kB\nMemFree:  1 kB\n"
        f"MemAvailable:   {int(avail_gb * 1024 * 1024)} kB\n"
    )


@pytest.mark.parametrize(
    ("gb", "level"), [(8, "ok"), (2.0, "ok"), (1.9, "warn"), (1.0, "warn"), (0.9, "refuse")]
)
def test_memory_levels(gb, level):
    mem = memory.parse(_meminfo(gb))
    assert mem.level == level
    assert "16.0 GB" in mem.message()


def test_memory_unknown_without_meminfo(tmp_path):
    mem = memory.check(tmp_path / "missing")
    assert mem.level == "unknown" and not mem.refuse


def test_diagnostics_show_the_memory_guard():
    low = doctor.memory_check(memory.parse(_meminfo(0.5)))
    assert not low.ok and "refused" in low.summary and "TOO LOW" in low.name
    warn = doctor.memory_check(memory.parse(_meminfo(1.5)))
    assert warn.ok and "LOW" in warn.name


def test_diagnostics_say_where_the_ha_version_came_from(monkeypatch):
    monkeypatch.setenv("SUPERVISOR_TOKEN", "tok")
    items = [Installed("acme/a", "integration", "A", "v1", "v2", False)]
    checks = doctor.supervisor_checks(lambda: "2026.11.0", lambda: (items, {"theme": 2}))
    assert checks[0].ok and checks[0].summary == "2026.11.0 (from the Supervisor)"
    assert checks[1].ok and "1 integration(s)/card(s) installed, 1 with an update" in (
        checks[1].summary
    )

    def broken():
        raise SupervisorError("HACS isn't installed or hasn't finished loading")

    checks = doctor.supervisor_checks(lambda: None, broken)
    assert not checks[0].ok and "latest stable" in checks[0].summary
    assert not checks[1].ok and "HACS isn't installed" in checks[1].summary
    monkeypatch.delenv("SUPERVISOR_TOKEN")
    assert "not running as an add-on" in doctor.supervisor_checks()[0].summary
