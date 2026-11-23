"""(0.15, his yes 2026-11-22) Where a login goes after the app hands it to a library.

Many integrations make no web request of their own: they give your login (and often the
address) to a library, `VendorClient(username, password, base_url)`, and the library does
the connecting. py_flow stops there (`Handoff`). This reads one step further: the library's
own code, as data.

1. Which libraries: only one the app hands a setup login or an address to, and only one of
   the app's own requirements, at the exact version the scan's dependency step resolved
   (python_deps: the version Home Assistant would install). The ready-made package (a
   wheel) is downloaded with its checksum checked and unpacked as files. Nothing in it is
   installed, imported or run; a package with no wheel is not read (its source archive
   would need building to be sure of its files). At most MAX_LIBS packages of at most
   MAX_BYTES each per scan.
2. Inside the library, the function the app called is the start: the class's constructor
   (or one it inherits), the function, or the method of an object the library made. Its
   parameters hold what the app passed in, with the app's own origins (a setup field, a
   site in the code, a server's answer); one the app didn't pass is the library's default.
   py_flow then follows the library's requests from there, with the same budgets.
3. What a hand-off gets (`inside`):
   - "followed": the library's requests that carry the app's login, or whose address is
     what the app passed in (`sends`). Only those: the library's other requests (an update
     check, a download) are not what the app sent;
   - "requests": it makes web requests, but none Barkley could link to what the app passed
     in (`sites`: the ones it spells out);
   - "no_requests": no web request in its code. `other`: the other ways it connects that its
     imports show (MQTT, a direct network connection, a serial port, Bluetooth…), `uses`:
     the libraries it hands on to. Neither means "local only": Barkley reads one library
     deep;
   - "unread", with `why`: offline, not one of the app's requirements (it comes with Home
     Assistant or through another package), no wheel, too big, a failed download.
   A download that fails or is refused is never a scan result: the row says Barkley
   couldn't read the library, as it did before this step.

Context only, never scored: nothing here becomes a finding.
"""

from __future__ import annotations

import ast
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sniff_test.analyzers import py_flow, py_requests
from sniff_test.deps import reqs
from sniff_test.fetch import http
from sniff_test.workspace import UnsafeArchiveError, extract_zip

if TYPE_CHECKING:
    from sniff_test.analyzers.python_deps import Resolution, ResolvedPackage
    from sniff_test.deps.uv import Artifact

MAX_LIBS = 4  # packages downloaded per scan
MAX_BYTES = 40 * 1024 * 1024  # per wheel
MAX_READS = 8  # hand-offs read per scan
_MAX_SENDS = 8
_MAX_LIST = 6
_BASES = 4  # how far up a class's bases its constructor is looked for

_DIRECT_WORDS = "a direct network connection"
# the other ways a library connects, by what it imports (top-level module -> plain words)
_OTHER = {
    "socket": _DIRECT_WORDS,
    "asyncio": "",  # only with the calls below
    "paho": "MQTT", "aiomqtt": "MQTT", "asyncio_mqtt": "MQTT", "gmqtt": "MQTT",
    "amqtt": "MQTT", "hbmqtt": "MQTT",
    "websockets": "a websocket", "websocket": "a websocket",
    "serial": "a serial port", "serial_asyncio": "a serial port",
    "serial_asyncio_fast": "a serial port", "aioserial": "a serial port",
    "pymodbus": "Modbus", "pyModbusTCP": "Modbus",
    "bleak": "Bluetooth", "bleak_retry_connector": "Bluetooth", "bluetooth": "Bluetooth",
    "grpc": "gRPC", "paramiko": "SSH", "asyncssh": "SSH", "telnetlib": "telnet",
    "telnetlib3": "telnet", "smtplib": "email", "aiosmtplib": "email", "ftplib": "FTP",
    "aiocoap": "CoAP", "pysnmp": "SNMP", "zeroconf": "local network discovery",
    "aiohttp": "", "requests": "", "httpx": "", "urllib": "", "urllib3": "",
    "http": "",  # web clients (their requests are read above) and their helpers
}  # fmt: skip
# the modules that send web requests (`urllib.parse`, `http.HTTPStatus` don't)
_WEB = frozenset({"aiohttp", "requests", "httpx", "urllib3", "urllib.request", "http.client",
                  "pycurl"})  # fmt: skip
_DIRECT = _DIRECT_WORDS
_CONNECT_CALLS = {
    "open_connection": _DIRECT_WORDS,
    "create_connection": _DIRECT_WORDS,
    "create_datagram_endpoint": _DIRECT_WORDS,
    "ws_connect": "a websocket",
}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "", name).lower()


@dataclass
class _Lib:
    package: str
    version: str
    root: Path | None = None  # the module's folder (or a folder holding the one file)
    why: str = ""  # why it wasn't read


def _wheel(pkg: ResolvedPackage) -> Artifact | None:
    wheels = [a for a in pkg.artifacts.values() if a.kind == "wheel"]
    wheels.sort(key=lambda a: (not a.filename.endswith("-none-any.whl"), a.filename))
    return wheels[0] if wheels else None


def _download(art: Artifact, dest: Path) -> str:
    """Unpack the wheel into `dest`; "" or why not. Never installs or imports it."""
    archive = dest.parent / f"{dest.name}.whl"  # not with_suffix: "1.0" and "1.1" differ
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        http.download(art.url, archive, art.sha256, max_bytes=MAX_BYTES)
        dest.mkdir(parents=True)
        extract_zip(archive, dest)
    except http.HttpError as e:
        shutil.rmtree(dest, ignore_errors=True)
        return "too big" if "bigger than" in str(e) else "download failed"
    except (UnsafeArchiveError, OSError, ValueError):
        shutil.rmtree(dest, ignore_errors=True)
        return "download failed"
    finally:
        archive.unlink(missing_ok=True)
    return ""


def _module_root(unpacked: Path, module: str) -> Path | None:
    """The folder to read for `module` in an unpacked wheel, or None if it isn't there."""
    folder = unpacked / module
    if folder.is_dir() and not folder.is_symlink():
        return folder
    one = unpacked / f"{module}.py"
    if one.is_file() and not one.is_symlink():
        holder = unpacked.parent / f"{unpacked.name}-{module}" / module
        holder.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(one, holder / "__init__.py")
        return holder
    return None


class _Fetcher:
    def __init__(self, resolution: Resolution | None, work: Path, offline: bool):
        self.work = work / "library-code"
        self.offline = offline
        self.direct = [p for p in (resolution.packages.values() if resolution else [])
                       if p.direct]  # fmt: skip
        self.unpacked: dict[tuple[str, str], tuple[Path | None, str]] = {}
        self.found: dict[str, _Lib] = {}

    def lib(self, module: str) -> _Lib:
        if module not in self.found:
            self.found[module] = self._find(module)
        return self.found[module]

    def _find(self, module: str) -> _Lib:
        if self.offline:
            return _Lib("", "", why="offline")
        # the package named like the module first (`vendor-api` for vendor_api)
        m = _norm(module)
        order = sorted(self.direct, key=lambda p: (_norm(p.name) != m, m not in _norm(p.name)))
        why = "not one of its requirements"
        for p in order:
            key = (p.name, p.version)
            if key not in self.unpacked:
                art = _wheel(p)
                if art is None:
                    self.unpacked[key] = (None, "no wheel")
                elif sum(1 for d, _w in self.unpacked.values() if d) >= MAX_LIBS:
                    self.unpacked[key] = (None, "too many libraries")
                else:
                    dest = self.work / re.sub(r"[^A-Za-z0-9._-]", "_", f"{p.name}-{p.version}")
                    failed = _download(art, dest)
                    self.unpacked[key] = (None if failed else dest, failed)
            dest, failed = self.unpacked[key]
            if dest is None:
                if _norm(p.name) == _norm(module):
                    why = failed
                continue
            root = _module_root(dest, module)
            if root is not None:
                return _Lib(reqs.normalize(p.name), p.version, root)
        return _Lib("", "", why=why)


def _entry(tracer: py_flow.Tracer, h: py_flow.Handoff) -> py_flow.Entry | None:
    """The function the app called, inside the library."""
    ix = tracer.index()
    name = h.call
    if h.method:
        return py_flow.Entry(name, None, True, h.passed)
    if name not in ix.classes:  # `from .client import Client as VendorClient` in __init__
        alias = tracer.res.imports("__init__.py").get(name)
        if alias is not None and alias[1] in ix.classes | ix.funcs:  # type: ignore[operator]
            name = alias[1]
    if name in ix.classes:
        # the constructor that runs: the class's own, or the first one up its bases (a
        # base's constructor further up gets what `super().__init__(…)` passes it)
        classes, todo = {name}, [name]
        for _ in range(_BASES):
            if any(_has_init(c) for n in todo for _r, c in ix.classes.get(n, [])[:1]):
                break
            todo = [py_flow._tail(b) for n in todo for _r, c in ix.classes.get(n, [])[:1]
                    for b in c.bases if py_flow._tail(b) in ix.classes]  # fmt: skip
            classes.update(todo)
        return py_flow.Entry("__init__", frozenset(classes), False, h.passed, _fields(ix, name))
    if name in ix.funcs:
        return py_flow.Entry(name, None, False, h.passed)
    return None


def _has_init(c: ast.ClassDef) -> bool:
    return any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "__init__"
               for n in c.body)  # fmt: skip


def _fields(ix: Any, name: str) -> tuple[str, ...]:
    """A class with no `__init__` up its own bases (a dataclass, a pydantic model): its
    annotated fields, the bases' first, as the constructor it gets takes them."""
    chain: list[ast.ClassDef] = []
    todo = [name]
    for _ in range(_BASES + 1):
        found = [c for n in todo for _r, c in ix.classes.get(n, [])[:1]]
        chain[:0] = found  # bases before the class
        todo = [py_flow._tail(b) for c in found for b in c.bases]
        if not todo:
            break
    out: list[str] = []
    for c in chain:
        for n in c.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "__init__":
                return ()
            if (isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)
                    and "ClassVar" not in ast.unparse(n.annotation)
                    and n.target.id not in out):  # fmt: skip
                out.append(n.target.id)
    return tuple(out)


def _ways(root: Path, reader: py_requests.Reader) -> tuple[list[str], list[str], bool]:
    """(other ways it connects, the libraries it hands on to, uses a web client)."""
    other: dict[str, None] = {}
    uses: dict[str, None] = {}
    web = False
    for p in sorted(root.rglob("*.py"))[: py_requests._MAX_FILES]:
        tree = reader.module(p.relative_to(root).as_posix()).tree
        for n in ast.walk(tree) if tree is not None else ():
            tops: list[str] = []
            full: list[str] = []
            if isinstance(n, ast.Import):
                full = [a.name for a in n.names]
            elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                full = [n.module, *(f"{n.module}.{a.name}" for a in n.names)]
            elif isinstance(n, ast.Call):
                way = _CONNECT_CALLS.get(py_flow._call_name(n))
                if way:
                    other[way] = None
            tops = list(dict.fromkeys(f.split(".")[0] for f in full))
            if any(f in _WEB or f.split(".")[0] in _WEB for f in full):
                web = True
            for t in tops:
                if _OTHER.get(t):
                    other[_OTHER[t]] = None
                elif t not in _OTHER and t not in py_flow._NOT_LIB and t != root.name:
                    uses[t] = None
    if _OTHER.get(root.name):  # the library is itself an MQTT, websocket… library
        other = {_OTHER[root.name]: None, **other}
        web = False
    if len(other) > 1:  # MQTT or a websocket says more than "a direct network connection"
        other.pop(_DIRECT, None)
    return list(other)[:_MAX_LIST], list(uses)[:_MAX_LIST], web


def _origins(got: tuple[py_flow.Origin, ...]) -> list[dict[str, str]]:
    return [o.as_dict() for o in got if o.kind != py_flow.UNKNOWN][:_MAX_LIST]


def read(h: py_flow.Handoff, lib: _Lib) -> dict[str, Any]:
    """What the library does with what the app passed in (see the module docstring)."""
    base = {"package": lib.package, "version": lib.version}
    reader = py_requests.Reader(lib.root, package=lib.root.name)  # type: ignore[arg-type]
    tracer = py_flow.Tracer(reader)
    entry = _entry(tracer, h)
    if entry is None:
        return {**base, "state": "unread", "why": "the function the app calls isn't in it"}
    tracer.entries = [entry]
    found, _ = py_requests._read(reader, None, tracer=tracer)
    passed = {o for lead, _held in h.passed.values() for o in lead}
    sends: dict[tuple[object, ...], dict[str, Any]] = {}
    for r in found:
        from_app = [o for o in r.origins if o in passed]
        if not (r.logins or from_app):  # a token alone is the library's own
            continue
        k = (r.host, r.origins if r.host is None else (), r.logins, r.tokens)
        if k in sends or len(sends) >= _MAX_SENDS:
            continue
        sends[k] = {
            **({"site": r.host} if r.host else {"from": _origins(r.origins)}),
            **({"logins": list(r.logins)} if r.logins else {}),
            **({"tokens": list(r.tokens)} if r.tokens else {}),
            "at": f"{r.file}:{r.line}",
        }
    if sends:
        return {**base, "state": "followed", "sends": list(sends.values())}
    if found:
        sites = sorted({r.host for r in found if r.host})[:_MAX_LIST]
        return {**base, "state": "requests", "requests": len(found), "sites": sites}
    other, uses, web = _ways(lib.root, reader)  # type: ignore[arg-type]
    if web:
        other = ["web requests Barkley couldn't read", *other][:_MAX_LIST]
    return {**base, "state": "no_requests", "other": other, "uses": uses}


def read_inside(
    handoffs: list[py_flow.Handoff], resolution: Resolution | None, work: Path, offline: bool
) -> None:
    """Fill `inside` on each hand-off (the module docstring says what it holds)."""
    if not handoffs:
        return
    fetcher = _Fetcher(resolution, work, offline)
    reads = 0
    for h in handoffs:
        lib = fetcher.lib(h.library)
        if lib.root is None:
            h.inside = {"state": "unread", "why": lib.why}
            continue
        if reads >= MAX_READS:
            h.inside = {"state": "unread", "why": "too many libraries"}
            continue
        reads += 1
        try:
            h.inside = read(h, lib)
        except RecursionError:
            h.inside = {"state": "unread", "why": "too deeply nested to read"}
