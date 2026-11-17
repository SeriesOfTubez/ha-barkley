"""The add-on's reads from HA: the websocket client, HACS's installed list, the memory guard.

A fake Supervisor on 127.0.0.1 speaks the real handshake and HA's websocket protocol, so
nothing here can reach a real server.
"""

import contextlib
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

    def __init__(self, result=None, *, accept_token="tok", error=None, fragment=False,
                 known=("marketplace/repositories/list",), ws_path="/core/websocket",
                 results=None):  # fmt: skip
        self.result = HACS_ROWS if result is None else result
        self.results = results or {}  # command -> result, for commands other than the list
        self.ws_path = ws_path
        self.known = known
        self.accept_token = accept_token
        self.error = error
        self.fragment = fragment
        self.sent: list[dict] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self._serve(conn)

    def _send_json(self, conn, obj):
        data = json.dumps(obj).encode()
        if self.fragment and len(data) > 10:
            conn.sendall(_frame(0x9, b"ping"))  # a ping in between: must be answered
            conn.sendall(_frame(0x1, data[:10], fin=False) + _frame(0x0, data[10:]))
        else:
            conn.sendall(_frame(0x1, data))

    def _serve(self, conn):
        with conn:
            req = b""
            while b"\r\n\r\n" not in req:
                req += conn.recv(4096)
            assert f"GET {self.ws_path} HTTP/1.1".encode() in req
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
                    elif self.error or msg["type"] not in self.known:
                        err = self.error or {"code": "unknown_command",
                                             "message": "Unknown command."}  # fmt: skip
                        self._send_json(conn, {"id": msg["id"], "type": "result",
                                               "success": False, "error": err})  # fmt: skip
                    else:
                        self._send_json(conn, {"id": 99, "type": "event", "event": {}})
                        res = self.results.get(msg["type"], self.result)
                        self._send_json(conn, {"id": msg["id"], "type": "result",
                                               "success": True, "result": res})  # fmt: skip
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
    assert [m["type"] for m in cmds] == ["auth", "marketplace/repositories/list"]
    assert {"pong": "ping"} in fake.sent


def test_large_messages_use_the_64_bit_length():
    rows = [{**HACS_ROWS[0], "full_name": f"acme/r{i}", "description": "x" * 200}
            for i in range(400)]  # fmt: skip
    items, _ = _list(FakeSupervisor(rows))
    assert len(items) == 400


def test_only_the_hacs_list_can_be_sent():
    with pytest.raises(SupervisorError, match="not allowed"):
        supervisor.core_command("call_service", "tok", host="127.0.0.1", port=1)


def test_older_ha_falls_back_to_the_hacs_custom_integration():
    fake = FakeSupervisor(known=("hacs/repositories/list",))
    items, _ = _list(fake)
    assert len(items) == 3
    cmds = [m["type"] for m in fake.sent if "type" in m and m["type"] != "auth"]
    assert cmds == ["marketplace/repositories/list", "hacs/repositories/list"]


def test_refused_token_and_missing_marketplace_say_why():
    with pytest.raises(SupervisorError, match="refused the add-on token"):
        _list(FakeSupervisor(accept_token="other"))
    with pytest.raises(SupervisorError, match="neither the Marketplace"):
        _list(FakeSupervisor(known=()))
    fake = FakeSupervisor(error={"code": "not_loaded", "message": "x"})
    with pytest.raises(SupervisorError, match="hasn't finished loading"):
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
    mem = memory.check(tmp_path / "missing", cgroup=tmp_path / "no-cgroup")
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


# --- auto-sniff: the subscription and the notification calls ------------------------------


class EventSupervisor(FakeSupervisor):
    """Answers `marketplace/subscribe` and then sends the given events, in order."""

    def __init__(self, events, **kw):
        super().__init__(known=("marketplace/subscribe",), **kw)
        self.events = list(events)

    def _serve(self, conn):
        with conn:
            req = b""
            while b"\r\n\r\n" not in req:
                req += conn.recv(4096)
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n"
            )
            self._send_json(conn, {"type": "auth_required", "ha_version": "2026.11.0"})
            subs = {}
            try:
                while True:
                    op, data = _recv_frame(conn)
                    if op == 0xA:
                        continue
                    if op == 0x8:
                        return
                    msg = json.loads(data)
                    self.sent.append(msg)
                    if msg["type"] == "auth":
                        self._send_json(conn, {"type": "auth_ok"})
                    elif msg["type"] == "marketplace/subscribe":
                        subs[msg["signal"]] = msg["id"]
                        self._send_json(conn, {"id": msg["id"], "type": "result",
                                               "success": True, "result": None})  # fmt: skip
                        if len(subs) == 2:
                            for sig, ev in self.events:
                                self._send_json(conn, {"id": subs[sig], "type": "event",
                                                       "event": ev})  # fmt: skip
                            self._send_json(conn, {"id": 77, "type": "event", "event": {}})
                            self._send_json(conn, {"type": "pong"})
                    else:
                        self._send_json(conn, {"id": msg["id"], "type": "result",
                                               "success": False,
                                               "error": {"code": "unknown_command"}})  # fmt: skip
            except (ConnectionError, OSError):
                return


def test_subscription_receives_the_marketplace_events_and_idles():
    fake = EventSupervisor([
        (supervisor.SIGNAL_INSTALL_PROGRESS, {"repository": "acme/a", "progress": 30}),
        (supervisor.SIGNAL_INSTALL_PROGRESS, {"repository": "acme/a", "progress": False}),
        (supervisor.SIGNAL_REPOSITORY, {"action": "uninstall", "repository": "acme/b",
                                        "repository_id": "1"}),
    ])  # fmt: skip
    sub = supervisor.Subscription("tok", host="127.0.0.1", port=fake.port, idle=0.3)
    got = []
    for ev in sub.events():
        got.append(ev)
        if ev is None:
            break
    sub.close()
    assert got[:3] == [
        (supervisor.SIGNAL_INSTALL_PROGRESS, {"repository": "acme/a", "progress": 30}),
        (supervisor.SIGNAL_INSTALL_PROGRESS, {"repository": "acme/a", "progress": False}),
        (supervisor.SIGNAL_REPOSITORY, {"action": "uninstall", "repository": "acme/b",
                                        "repository_id": "1"}),
    ]  # fmt: skip
    assert got[3] is None  # idle: the caller polls
    cmds = [m for m in fake.sent if m.get("type") != "auth"]
    assert cmds == [
        {"id": 1, "type": "marketplace/subscribe", "signal": supervisor.SIGNAL_INSTALL_PROGRESS},
        {"id": 2, "type": "marketplace/subscribe", "signal": supervisor.SIGNAL_REPOSITORY},
    ]


def test_subscription_only_takes_the_fixed_signals_and_reports_refusals():
    with pytest.raises(SupervisorError, match="signal not allowed"):
        supervisor.Subscription("tok", signals=("marketplace_config",), host="127.0.0.1", port=1)
    fake = FakeSupervisor(known=("marketplace/repositories/list",))  # no subscribe (older HA)
    with pytest.raises(SupervisorError, match="unknown_command"):
        supervisor.Subscription("tok", host="127.0.0.1", port=fake.port)
    with pytest.raises(SupervisorError, match="refused the add-on token"):
        supervisor.Subscription("other", host="127.0.0.1", port=fake.port)


def test_a_timeout_in_the_middle_of_a_frame_loses_nothing():
    """The long-lived socket times out while idle; a frame split across that moment
    must still arrive whole (the header is only consumed with the whole frame)."""
    import socket as _socket

    srv = _socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    payload = json.dumps({"id": 1, "type": "event", "event": {"progress": False}}).encode()
    frame = _frame(0x1, payload)

    def serve():
        conn, _ = srv.accept()
        req = b""
        while b"\r\n\r\n" not in req:
            req += conn.recv(4096)
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
        conn.sendall(frame[:3])  # header and the first byte, then a pause
        time.sleep(0.5)
        conn.sendall(frame[3:])
        time.sleep(0.5)
        conn.close()

    import time

    threading.Thread(target=serve, daemon=True).start()
    ws = supervisor._WebSocket("127.0.0.1", port, "/core/websocket", timeout=0.2)
    with pytest.raises(TimeoutError):
        ws.recv_json()
    for _ in range(20):  # the server is still pausing; keep asking
        try:
            msg = ws.recv_json()
            break
        except TimeoutError:
            continue
    assert msg == {"id": 1, "type": "event", "event": {"progress": False}}
    ws.close()


class FakeCore:
    """A stand-in for the Supervisor's Core API proxy over HTTP (notifications)."""

    def __init__(self):
        import http.server

        calls = self.calls = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                calls.append((self.path, self.headers.get("Authorization"), body))
                if self.path.endswith("/notify/broken"):
                    return self._reply(500, {"message": "Service notify.broken not found"})
                self._reply(200, [])

            def do_GET(self):
                calls.append((self.path, self.headers.get("Authorization"), None))
                if self.path == "/core/api/services":
                    return self._reply(200, [
                        {"domain": "light", "services": {"turn_on": {}}},
                        {"domain": "notify", "services": {
                            "mobile_app_phone": {}, "persistent_notification": {},
                            "send_message": {}, "Bad Name": {}}},
                    ])  # fmt: skip
                if self.path == "/addons/self/info":
                    return self._reply(
                        200,
                        {
                            "result": "ok",
                            "data": {"slug": "local_sniff_test", "ingress_entry": "/x"},
                        },
                    )
                self._reply(404, {"message": "nope"})

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.port = self.httpd.server_address[1]


def test_notifications_go_through_the_core_api(monkeypatch):
    fake = FakeCore()
    monkeypatch.setattr(supervisor, "SUPERVISOR_HOST", f"127.0.0.1:{fake.port}")
    supervisor.notify_persistent("T", "M", "barkley_acme_a", tok="tok")
    supervisor.notify_service("mobile_app_phone", "T", "P", "/hassio/ingress/x", tok="tok")
    assert fake.calls == [
        ("/core/api/services/persistent_notification/create", "Bearer tok",
         {"notification_id": "barkley_acme_a", "title": "T", "message": "M"}),
        ("/core/api/services/notify/mobile_app_phone", "Bearer tok",
         {"title": "T", "message": "P", "data": {"url": "/hassio/ingress/x"}}),
    ]  # fmt: skip
    assert supervisor.notify_targets(tok="tok") == ["mobile_app_phone", "send_message"]
    assert supervisor.self_slug(tok="tok") == "local_sniff_test"
    with pytest.raises(SupervisorError, match="not a notify target"):
        supervisor.notify_service("../x", "T", "P", tok="tok")
    with pytest.raises(SupervisorError, match=r"answered 500: Service notify\.broken"):
        supervisor.notify_service("broken", "T", "P", tok="tok")
    with pytest.raises(SupervisorError, match="isn't connected"):
        supervisor.notify_persistent("T", "M", "x", tok=None)
    fake.httpd.shutdown()


def _pinging_server(*, ping_every: float, event_every: float | None = None):
    """A Core proxy that has subscribed us and then only pings (and maybe sends events),
    the way the Supervisor's proxy pings every 30 s (`heartbeat=30`)."""
    import time as _time

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    stop = threading.Event()

    def serve():
        conn, _ = srv.accept()
        with conn:
            req = b""
            while b"\r\n\r\n" not in req:
                req += conn.recv(4096)
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
            conn.sendall(_frame(0x1, json.dumps({"type": "auth_required"}).encode()))
            _recv_frame(conn)  # auth
            conn.sendall(_frame(0x1, json.dumps({"type": "auth_ok"}).encode()))
            for i in (1, 2):
                _recv_frame(conn)
                conn.sendall(
                    _frame(
                        0x1,
                        json.dumps(
                            {"id": i, "type": "result", "success": True, "result": None}
                        ).encode(),
                    )
                )
            conn.settimeout(0.01)
            last_ev = _time.monotonic()
            try:
                while not stop.is_set():
                    conn.sendall(_frame(0x9, b"hb"))
                    if event_every and _time.monotonic() - last_ev >= event_every:
                        last_ev = _time.monotonic()
                        ev = {
                            "id": 2,
                            "type": "event",
                            "event": {"action": "update", "repository": "acme/a"},
                        }
                        conn.sendall(_frame(0x1, json.dumps(ev).encode()))
                    _time.sleep(ping_every)
                    with contextlib.suppress(TimeoutError, OSError):
                        conn.recv(65536)  # drain our pongs
            except OSError:
                return

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], stop


def test_idle_turns_come_although_the_proxy_pings_more_often_than_idle():
    """Found on the user's box (2026-11-12): the proxy's 30 s pings kept the 60 s idle
    timeout from ever firing, so the 10-minute re-read of the installed list never ran
    while subscribed, and two offered updates went unsniffed for hours."""
    import time as _time

    port, stop = _pinging_server(ping_every=0.05)
    sub = supervisor.Subscription("tok", host="127.0.0.1", port=port, idle=0.3)
    start = _time.monotonic()
    got = next(sub.events())
    took = _time.monotonic() - start
    stop.set()
    sub.close()
    assert got is None
    assert 0.25 <= took < 1.0


def test_idle_turns_come_although_events_keep_arriving():
    import time as _time

    port, stop = _pinging_server(ping_every=0.03, event_every=0.05)
    sub = supervisor.Subscription("tok", host="127.0.0.1", port=port, idle=0.3)
    start = _time.monotonic()
    seen = []
    for ev in sub.events():
        seen.append(ev)
        if ev is None:
            break
    took = _time.monotonic() - start
    stop.set()
    sub.close()
    assert len(seen) > 1 and seen[-1] is None and all(e is not None for e in seen[:-1])
    assert took < 1.0
