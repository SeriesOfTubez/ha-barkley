"""Declared-endpoint check: which hosts and IPs does the shipped code talk about?

Every host literal becomes a neutral inventory fact (the network ring of the hooks
graph), classified as declared, infrastructure, local, undeclared and so on. Only three
things are findings, because the rest proved to be noise on real repos (Bubble-Card
ships 14 donation/doc links; iCloud3 pings a dict of public DNS servers):

- `endpoint-exfil-host` (high): a paste site, request catcher, OOB interaction server
  or tunnel; or a chat webhook URL that carries its credential (Discord webhook token,
  Telegram bot token, Slack hook), i.e. data goes to the developer's channel, not yours;
- `endpoint-public-ip-literal` (high): a URL whose host is a hardcoded public IP.

Undeclared hosts feed the possible-exfil correlation (`correlate.py`).

Host edges also carry up to five URL samples (scheme, host, port and path; userinfo,
query and fragment dropped, and the path of a credential URL hidden) and the URL ports.
A host on the shipped list of well-known services (`known.py`) also carries `service`,
who runs it in plain words; that never changes its class.
Port numbers assigned in Python (`port = 6668`, `port=990`, `"mqtt_port": 1883`) become
`port` facts. Neither is scored; the panel shows them and builds privacy notes on them.

Nothing is executed: Python is split into tokens with `tokenize` (a lexer) so comments
and docstrings are skipped; JS is matched with regexes.
"""

from __future__ import annotations

import ast
import io
import ipaddress
import json
import re
import tokenize
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

from sniff_test import known
from sniff_test.models import (
    AnalyzerResult,
    AnalyzerState,
    Category,
    Evidence,
    Fact,
    Finding,
    Ring,
    Severity,
    Tag,
    Target,
    TargetKind,
)

NAME = "endpoints"
_PY = {".py"}
_JS = {".js", ".mjs", ".cjs", ".ts"}
_MAX_FILE = 50 * 1024 * 1024
_URL_MAX = 300

_URL = re.compile(
    r"(?i)(?<![a-z0-9+.-])(?P<scheme>https?|wss?)://"
    r"(?:[^\s/@\"'`<>]*@)?"  # userinfo
    r"(?P<host>\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)"
    r"(?::(?P<port>\d{1,5}))?"
    r"(?P<path>[/?#][^\s\"'`<>\\]*)?"
)
_BARE_HOST = re.compile(
    r"(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_IPV4 = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)
# Credentials embedded in a chat-webhook URL. Matched on the path, on any host, so a
# lookalike or proxy domain doesn't dodge it.
_CRED_PATHS = (
    ("Discord webhook", re.compile(r"/api/webhooks/\d{15,22}/[\w-]{40,}")),
    ("Telegram bot token", re.compile(r"/bot\d{6,12}:[\w-]{30,}")),
    ("Slack webhook", re.compile(r"/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}")),
)
_TELEGRAM_TOKEN = re.compile(r"^\d{6,12}:[\w-]{30,}$")
# TLDs accepted for scheme-less hostnames in Python strings. Deliberately excludes TLDs
# that look like file extensions (.py, .md, .sh, .zip, .json is not a TLD anyway).
_BARE_TLDS = frozenset(
    "com net org io co dev app cloud ai biz us uk de fr nl eu ru cn jp kr tw hk sg au "
    "nz ca br in it es se no fi dk pl cz at ch be pt ie gr tr il za mx ar cl vn th my id ph "
    "ua kz lt lv ee ro hu bg hr si sk xyz tech online site tv cc gg ly fm invalid "
    "example test local lan home internal arpa".split()
)
# First labels that make "x.y" an HA entity id or config key, not a host.
_HA_DOMAINS = frozenset(
    "sensor light switch person zone sun fan cover lock climate camera vacuum scene script "
    "automation group timer counter select number button text siren valve event update "
    "weather calendar todo image notify device_tracker media_player alarm_control_panel "
    "binary_sensor input_boolean input_number input_select input_text input_datetime "
    "input_button water_heater humidifier lawn_mower remote tts stt conversation "
    "homeassistant log logger logging self cls os sys hass".split()
)
_LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".home.arpa", ".localdomain")
_TWO_LEVEL = frozenset(
    "co.uk org.uk ac.uk gov.uk com.au net.au org.au co.jp ne.jp co.nz com.br com.cn "
    "com.tw co.kr co.in com.mx co.za com.tr com.ua com.sg com.hk".split()
)
# Public resolvers used for connectivity checks; never interesting as endpoints.
_KNOWN_RESOLVERS = frozenset(
    "8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 208.67.222.222 "
    "208.67.220.220 114.114.114.114 114.114.115.115".split()
)


@cache
def host_classes() -> tuple[tuple[str, str], ...]:
    text = (resources.files("sniff_test") / "data" / "endpoint_hosts.txt").read_text("utf-8")
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            cls, suffix = line.split()
            out.append((cls, suffix.lower()))
    return tuple(out)


def _suffix_class(host: str, table: tuple[tuple[str, str], ...]) -> tuple[str, str] | None:
    for cls, suffix in table:
        if host == suffix or host.endswith("." + suffix):
            return cls, suffix
    return None


def registrable(host: str) -> str:
    """Approximate registrable domain (no PSL in stdlib). Shared-hosting suffixes keep
    one more label, so `alice.github.io` is not the same site as `bob.github.io`."""
    labels = host.split(".")
    if len(labels) < 2:
        return host
    hit = _suffix_class(host, host_classes())
    if hit and hit[0] == "developer_hosted":
        base = hit[1]
    elif host.endswith((".github.io", ".gitlab.io")) or ".".join(labels[-2:]) in _TWO_LEVEL:
        base = ".".join(labels[-2:])
    else:
        return ".".join(labels[-2:])
    return ".".join(labels[-(base.count(".") + 2) :])


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


_NAME_PREFIXES = ("homeassistant-", "home-assistant-", "hass-", "ha-", "lovelace-")


@dataclass
class Declared:
    """What the item itself says it talks to."""

    hosts: set[str]  # registrable domains from manifest / package.json URLs
    names: set[str]  # normalized integration domain / repo name

    def matches(self, host: str) -> bool:
        reg = registrable(host)
        if reg in self.hosts:
            return True
        first = _norm(reg.split(".")[0])
        return bool(first) and first in self.names


def _url_host(url: Any) -> str | None:
    if not isinstance(url, str):
        return None
    m = _URL.match(url.strip())
    return m["host"].lower() if m else None


def declared_for(target: Target) -> Declared:
    hosts: set[str] = set()
    names: set[str] = set()
    manifest = (
        _read_json(target.root / "manifest.json") if target.kind is TargetKind.INTEGRATION else {}
    )
    owners: set[str] = set()
    for key in ("documentation", "issue_tracker"):
        url = manifest.get(key)
        if h := _url_host(url):
            hosts.add(registrable(h))
            if h == "github.com" and (m := re.match(r"(?i)https?://github\.com/([\w.-]+)", url)):
                owners.add(m[1].lower())
    if target.repo:
        owners.add(target.repo.split("/", 1)[0].lower())
    hosts.update(f"{o}.github.io" for o in owners)  # the maintainer's own Pages site
    if target.source_root is not None:
        pkg = _read_json(target.source_root / "package.json")
        repo = pkg.get("repository")
        for url in (pkg.get("homepage"), repo.get("url") if isinstance(repo, dict) else repo):
            if h := _url_host(url):
                hosts.add(registrable(h))
    if target.domain:
        names.add(_norm(target.domain))
    repo_name = (target.repo or "").rsplit("/", 1)[-1] or (
        target.source_root.name if target.source_root and target.kind is TargetKind.PLUGIN else ""
    )
    if repo_name:
        lowered = repo_name.lower()
        for prefix in _NAME_PREFIXES:
            lowered = lowered.removeprefix(prefix)
        names.add(_norm(lowered))
    names.discard("")
    return Declared(hosts, names)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


# --- extraction --------------------------------------------------------------------


@dataclass(frozen=True)
class HostRef:
    host: str
    file: str
    line: int
    url: str | None  # None for a scheme-less host / bare IP
    scheme: str | None


def _unquote(tok: str) -> str:
    i = 0
    while i < len(tok) and tok[i] in "rRbBuUfFtT":
        i += 1
    body = tok[i:]
    for q in ('"""', "'''", '"', "'"):
        if body.startswith(q) and body.endswith(q) and len(body) >= 2 * len(q):
            return body[len(q) : -len(q)]
    return body


_FSTRING_MIDDLE = {
    t
    for t in (getattr(tokenize, "FSTRING_MIDDLE", None), getattr(tokenize, "TSTRING_MIDDLE", None))
    if t is not None
}
_STMT_START = {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, None}


def py_strings(text: str) -> Iterator[tuple[int, str, bool]]:
    """(line, value, whole_literal) for string literals, skipping comments and docstrings.

    f-string pieces come back with whole_literal=False: they end where an interpolation
    starts, so a host running to the end of one is incomplete.

    Falls back to whole-text lines if the file doesn't tokenize (hostile or broken code
    still gets checked, just less precisely).
    """
    try:
        toks = [
            t
            for t in tokenize.generate_tokens(io.StringIO(text).readline)
            if t.type not in (tokenize.NL, tokenize.COMMENT, tokenize.ENCODING)
        ]
    except (tokenize.TokenError, SyntaxError, ValueError, RecursionError):
        for n, line in enumerate(text.splitlines(), 1):
            yield n, line, False
        return
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok.type == tokenize.STRING:
            # Adjacent literals ("https://a.example/" "path") are one string to Python.
            j = i
            while j + 1 < len(toks) and toks[j + 1].type == tokenize.STRING:
                j += 1
            prev = toks[i - 1].type if i else None
            nxt = toks[j + 1].type if j + 1 < len(toks) else None
            if not (prev in _STMT_START and nxt in (tokenize.NEWLINE, tokenize.ENDMARKER)):
                # (otherwise a docstring or bare string statement: documentation, not code)
                value = "".join(_unquote(t.string) for t in toks[i : j + 1])
                yield tok.start[0], value, True
            i = j + 1
            continue
        if tok.type in _FSTRING_MIDDLE:
            yield tok.start[0], tok.string, False
        i += 1


def _js_chunks(text: str) -> Iterator[tuple[int, str]]:
    for n, line in enumerate(text.split("\n"), 1):
        s = line.lstrip()
        if s.startswith(("//", "*", "/*")) and len(line) < 2000:
            continue  # comment line in readable source (license headers, JSDoc)
        yield n, line


def _host_ok(host: str) -> bool:
    if host.startswith("[") or _IPV4.match(host):
        return True
    labels = host.split(".")
    if len(labels) == 1:
        return len(host) >= 3 and not host.isdigit()  # "http://a" placeholders are noise
    return all(labels) and not labels[-1].isdigit()


def _refs_in(chunk: str, rel: str, line: int, fragment: bool = False) -> Iterator[HostRef]:
    for m in _URL.finditer(chunk):
        host = m["host"].lower()
        end = m.end("host")
        # "https://api." + region or f"https://openapi.tuya{region}.com": host is cut off
        if chunk[end : end + 1] in (".", "-", "{", "$") or (fragment and end == len(chunk)):
            continue
        if not _host_ok(host):
            continue
        url = m.group(0)[:_URL_MAX]
        yield HostRef(host, rel, line, url, m["scheme"].lower())


def _bare_ref(value: str, rel: str, line: int) -> HostRef | None:
    v = value.strip().lower()
    if _IPV4.match(v):
        last = int(v.rsplit(".", 1)[1])
        if last in (0, 255):  # network / broadcast / netmask / version-like "6.6.2.0"
            return None
        return HostRef(v, rel, line, None, None)
    if not _BARE_HOST.match(v) or v.count(".") > 6:
        return None
    labels = v.split(".")
    if (
        labels[-1] not in _BARE_TLDS
        or labels[0] in _HA_DOMAINS
        or any(lbl.isdigit() for lbl in labels)
    ):
        return None
    return HostRef(v, rel, line, None, None)


def extract(root: Path) -> tuple[list[HostRef], list[tuple[str, int]]]:
    """All host references under root, plus (file, line) of Telegram bot-token literals."""
    refs: list[HostRef] = []
    tokens: list[tuple[str, int]] = []
    for p in sorted(root.rglob("*")):
        if p.suffix not in _PY | _JS or not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > _MAX_FILE:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = p.relative_to(root).as_posix()
        if p.suffix in _PY:
            for line, value, whole in py_strings(text):
                refs.extend(_refs_in(value, rel, line, fragment=not whole))
                if whole:
                    if bare := _bare_ref(value, rel, line):
                        refs.append(bare)
                    if _TELEGRAM_TOKEN.match(value.strip()):
                        tokens.append((rel, line))
        else:
            for line, chunk in _js_chunks(text):
                refs.extend(_refs_in(chunk, rel, line))
                for q in re.finditer(r"[\"'`](\d{1,3}(?:\.\d{1,3}){3})[\"'`]", chunk):
                    if bare := _bare_ref(q[1], rel, line):
                        refs.append(bare)
    return refs, tokens


# --- classification ------------------------------------------------------------------


def classify(host: str, declared: Declared) -> str:
    """One of: namespace, local, public_ip, resolver, exfil_service, messaging,
    developer_hosted, analytics, infrastructure, link, declared, undeclared."""
    bare = host.strip("[]")
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global:
            return "local"
        return "resolver" if str(ip) in _KNOWN_RESOLVERS else "public_ip"
    if "." not in host or host == "localhost" or host.endswith(_LOCAL_SUFFIXES):
        return "local"
    hit = _suffix_class(host, host_classes())
    if hit and hit[0] in ("namespace", "exfil_service", "messaging"):
        return hit[0]
    if declared.matches(host):
        return "declared"
    return hit[0] if hit else "undeclared"


# Classes the correlation treats as "data could leave to somewhere unexplained".
# `analytics` was `undeclared` before it had a class of its own; keeping it here keeps
# the correlation (and so every score) exactly as it was.
UNEXPLAINED = frozenset(
    {"undeclared", "developer_hosted", "analytics", "public_ip", "exfil_service"}
)

_URL_SAMPLES = 5
_SAMPLE_MAX = 200


def url_sample(url: str | None, credential: bool = False) -> str | None:
    """scheme://host[:port]/path, with userinfo, query and fragment dropped (they can hold
    keys). A credential URL keeps only scheme://host/…"""
    if not url or not (m := _URL.match(url)):
        return None
    base = f"{m['scheme'].lower()}://{m['host'].lower()}"
    if m["port"]:
        base += f":{int(m['port'])}"
    if credential:
        return base + "/…"
    path = re.split(r"[?#]", m["path"] or "", maxsplit=1)[0]
    path = re.sub(r"\$\{[^}]*\}?|\{[^}]*\}?", "…", path)  # template holes
    path = path.rstrip(").,;:!]")  # prose / markdown around the URL
    return (base + path)[:_SAMPLE_MAX]


# --- ports from Python code (a lexer, never executed) ----------------------------------

_PORT_NAME = re.compile(r"(?i)(?:^|_)ports?(?:$|_)")
_NOT_A_PORT = re.compile(r"(?i)(?:^|_)(?:count|num|number|index|idx|len|max|min|range)(?:$|_)")
# name -> (plain name, encrypted?). None: depends on the device or protocol version.
WELL_KNOWN_PORTS: dict[int, tuple[str, bool | None]] = {
    21: ("FTP", False),
    22: ("SSH", True),
    23: ("Telnet", False),
    80: ("HTTP", False),
    443: ("HTTPS", True),
    502: ("Modbus", False),
    554: ("RTSP video", False),
    990: ("FTPS", True),
    1883: ("MQTT", False),
    5683: ("CoAP", False),
    6668: ("Tuya local", None),
    8080: ("HTTP (alternate)", False),
    8443: ("HTTPS (alternate)", True),
    8883: ("MQTT over TLS", True),
    47808: ("BACnet", False),
}


@dataclass
class PortRef:
    port: int
    name: str  # the variable or key it was assigned to (untrusted)
    file: str
    line: int
    direction: str | None = None  # "out" (connects to it), "in" (listens on it), unknown


def _port_value(tok: tokenize.TokenInfo) -> int | None:
    if tok.type != tokenize.NUMBER:
        return None
    try:
        n = int(tok.string.replace("_", ""), 0)
    except ValueError:
        return None
    return n if 1 <= n <= 65535 else None


def _port_named(name: str) -> bool:
    return bool(_PORT_NAME.search(name)) and not _NOT_A_PORT.search(name)


def py_ports(text: str, rel: str) -> Iterator[PortRef]:
    """`port = 6668`, `self._port = 8883`, `port=990` (keyword), `port: int = 1883`,
    `{"mqtt_port": 1883}` and `{CONF_PORT: 502}`."""
    try:
        toks = [
            t
            for t in tokenize.generate_tokens(io.StringIO(text).readline)
            if t.type not in (tokenize.NL, tokenize.COMMENT, tokenize.ENCODING)
        ]
    except (tokenize.TokenError, SyntaxError, ValueError, RecursionError):
        return
    for i, tok in enumerate(toks[:-2]):
        if tok.type == tokenize.NAME:
            name = tok.string
        elif tok.type == tokenize.STRING:
            name = _unquote(tok.string)
            if not re.fullmatch(r"[A-Za-z_][\w-]{0,60}", name):
                continue
        else:
            continue
        if not _port_named(name):
            continue
        op = toks[i + 1]
        if op.type != tokenize.OP or op.string not in ("=", ":"):
            continue
        if tok.type == tokenize.STRING and op.string != ":":
            continue
        j = i + 2
        if op.string == ":" and tok.type == tokenize.NAME and _port_value(toks[j]) is None:
            # an annotation: `port: int = 1883` / `port: int | None = 1883`
            while j < len(toks) and j < i + 10 and toks[j].string != "=":
                if toks[j].type in (tokenize.NEWLINE, tokenize.ENDMARKER) or toks[j].string in (
                    ",",
                    ")",
                ):
                    break
                j += 1
            if j >= len(toks) or toks[j].string != "=":
                continue
            j += 1
        if j < len(toks) and (port := _port_value(toks[j])) is not None:
            yield PortRef(port, name, rel, toks[j].start[0])


def _skip_for_ports(rel: str) -> bool:
    """Test doubles say nothing about where the shipped code connects."""
    parts = rel.lower().split("/")
    name = parts[-1]
    return (
        any(p in ("tests", "test", "testing") for p in parts[:-1])
        or name.startswith(("test_", "mock_", "fake_"))
        or name.endswith(("_test.py", "_mock.py"))
        or name == "conftest.py"
    )


# Direction of a port (M8, user decision): read from the calls around it, parse only.
_CONNECT_CALLS = frozenset(
    "connect connect_async connect_ex create_connection open_connection ws_connect "
    "urlopen ftp ftp_tls clientsession".split()
)
_LISTEN_CALLS = frozenset(
    "bind listen start_server create_server serve_forever tcpsite run_app".split()
)


@dataclass
class _Func:
    start: int
    end: int
    calls: frozenset[str]  # lower-cased call names (`ftp.connect(...)` -> "connect")
    names: frozenset[str]  # names and attribute names it references


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id.lower()
    if isinstance(f, ast.Attribute):
        return f.attr.lower()
    return ""


def _functions(text: str) -> list[_Func] | None:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        calls, names = set(), set()
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and (c := _call_name(n)):
                calls.add(c)
            elif isinstance(n, ast.Name):
                names.add(n.id)
            elif isinstance(n, ast.Attribute):
                names.add(n.attr)
        out.append(_Func(fn.lineno, fn.end_lineno or fn.lineno, frozenset(calls), frozenset(names)))
    return out


def _direction(calls: set[str]) -> str | None:
    """ "out", "in", or None when the calls say neither or both."""
    out = any(c in _CONNECT_CALLS or c.endswith("client") for c in calls)
    inn = any(c in _LISTEN_CALLS or c.endswith("server") for c in calls)
    if out == inn:
        return None
    return "out" if out else "in"


def port_direction(pr: PortRef, funcs: dict[str, list[_Func]]) -> str | None:
    """The calls in the function around the port decide. Only if they say nothing, look
    at functions that use its name: in the same file, or in any file for an UPPER_CASE
    constant (e.g. DEFAULT_MODBUS_PORT in const.py, used by a Modbus client elsewhere)."""
    calls: set[str] = set()
    for f in funcs.get(pr.file, []):
        if f.start <= pr.line <= f.end:
            calls |= f.calls
    if d := _direction(calls):
        return d
    files = funcs if pr.name.isupper() else {pr.file: funcs.get(pr.file, [])}
    calls = set()
    for fs in files.values():
        for f in fs:
            if pr.name in f.names and not (f.start <= pr.line <= f.end):
                calls |= f.calls
    return _direction(calls)


def extract_ports(root: Path) -> list[PortRef]:
    out: list[PortRef] = []
    funcs: dict[str, list[_Func]] = {}
    for p in sorted(root.rglob("*.py")):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(root).as_posix()
        if _skip_for_ports(rel):
            continue
        try:
            if p.stat().st_size > _MAX_FILE:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found = list(py_ports(text, rel))
        out.extend(found)
        if (fs := _functions(text)) is not None:
            funcs[rel] = fs
    for pr in out:
        pr.direction = port_direction(pr, funcs)
    return out


def _cred_kind(url: str | None) -> str | None:
    if not url:
        return None
    for label, rx in _CRED_PATHS:
        if rx.search(url):
            return label
    return None


def _finding(
    rule: str, title: str, msg: str, ref: HostRef, addresses: tuple[str, ...] = ()
) -> Finding:
    return Finding(
        rule_id=rule,
        title=title,
        severity=Severity.HIGH,
        category=Category.ENDPOINT,
        message=msg,
        file=ref.file,
        line=ref.line,
        evidence=ref.url or ref.host,
        tags=frozenset({Tag.POSSIBLE}),
        analyzer=NAME,
        addresses=addresses,
    )


def never_trustable(host: str) -> bool:
    """Drop boxes and chat webhooks: the user can't mark these trusted (anyone can
    receive data there, so knowing the service says nothing about who gets it)."""
    hit = _suffix_class(host.lower(), host_classes())
    return bool(hit and hit[0] in ("exfil_service", "messaging"))


def run(target: Target) -> AnalyzerResult:
    declared = declared_for(target)
    refs, bot_tokens = extract(target.root)
    findings: list[Finding] = []
    facts: list[Fact] = []
    hosts = {r.host for r in refs}
    for ref in refs:
        cls = classify(ref.host, declared)
        if cls == "namespace":
            continue
        cred = _cred_kind(ref.url)
        if cls == "exfil_service":
            findings.append(
                _finding(
                    "endpoint-exfil-host",
                    "Talks to a paste site, request catcher or tunnel",
                    f"{ref.host} is a service used to collect data or tunnel traffic "
                    "(paste site, request bin, OOB interaction server or tunnel). Shipped "
                    "integrations and cards have no reason to send anything there.",
                    ref,
                )
            )
        elif cred:
            findings.append(
                _finding(
                    "endpoint-exfil-host",
                    f"Hardcoded {cred} URL",
                    f"The URL embeds a {cred} credential, so whatever is sent goes to a "
                    "channel the developer controls, not one you configured. That's a "
                    "common way to collect stolen data.",
                    ref,
                )
            )
        elif cls == "public_ip" and ref.url:
            findings.append(
                _finding(
                    "endpoint-public-ip-literal",
                    "URL with a hardcoded public IP address",
                    f"Connects to {ref.host} by IP instead of a hostname. Legitimate cloud "
                    "APIs use DNS names; hardcoded IPs are typical of command-and-control.",
                    ref,
                    addresses=(ref.host.strip("[]").lower(),),
                )
            )
        attrs: dict[str, Any] = {"class": cls}
        if svc := known.lookup(ref.host):  # a name only; the class above is untouched
            attrs["service"] = svc.label
        if ref.scheme:
            attrs["schemes"] = [ref.scheme]
        if cred:
            attrs["credential"] = cred
        if sample := url_sample(ref.url, credential=bool(cred)):
            attrs["urls"] = [sample]
            m = _URL.match(ref.url or "")
            if m and m["port"]:
                attrs["ports"] = [int(m["port"])]
        facts.append(
            Fact(
                ring=Ring.NETWORK,
                kind="ip" if _IPV4.match(ref.host) or ref.host.startswith("[") else "host",
                key=ref.host,
                relation="connects_to",
                evidence=Evidence.DECLARED if cls == "declared" else Evidence.POSSIBLE,
                file=ref.file,
                line=ref.line,
                attrs=attrs,
                analyzer=NAME,
            )
        )
    if bot_tokens and any(h == "api.telegram.org" for h in hosts):
        for rel, line in bot_tokens:
            findings.append(
                _finding(
                    "endpoint-exfil-host",
                    "Hardcoded Telegram bot token",
                    "A Telegram bot token is hardcoded next to the Telegram API, so "
                    "messages go to a bot the developer controls, not one you configured.",
                    HostRef("api.telegram.org", rel, line, None, None),
                )
            )
    distinct = {f.key for f in facts}
    _cap_url_samples(facts)
    ports = extract_ports(target.root) if target.kind is TargetKind.INTEGRATION else []
    for pr in ports:
        facts.append(
            Fact(
                ring=Ring.NETWORK,
                kind="port",
                key=str(pr.port),
                relation="uses_port",
                evidence=Evidence.POSSIBLE,
                file=pr.file,
                line=pr.line,
                attrs={"names": [pr.name[:80]]}
                | ({"directions": [pr.direction]} if pr.direction else {}),
                analyzer=NAME,
            )
        )
    detail = f"{len(distinct)} hosts/IPs"
    if ports:
        detail += f", {len({p.port for p in ports})} ports"
    return AnalyzerResult(NAME, AnalyzerState.OK, findings=findings, facts=facts, detail=detail)


def _cap_url_samples(facts: list[Fact]) -> None:
    """At most five distinct URL samples per host, across all its facts."""
    seen: dict[str, list[str]] = {}
    for f in facts:
        urls = f.attrs.get("urls")
        if not urls:
            continue
        kept = seen.setdefault(f.key, [])
        if urls[0] in kept or len(kept) >= _URL_SAMPLES:
            del f.attrs["urls"]
        else:
            kept.append(urls[0])
