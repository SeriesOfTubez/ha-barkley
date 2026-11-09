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

Nothing is executed: Python is split into tokens with `tokenize` (a lexer) so comments
and docstrings are skipped; JS is matched with regexes.
"""

from __future__ import annotations

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
    """One of: namespace, local, public_ip, exfil_service, messaging, developer_hosted,
    infrastructure, link, declared, undeclared."""
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
UNEXPLAINED = frozenset({"undeclared", "developer_hosted", "public_ip", "exfil_service"})


def _cred_kind(url: str | None) -> str | None:
    if not url:
        return None
    for label, rx in _CRED_PATHS:
        if rx.search(url):
            return label
    return None


def _finding(rule: str, title: str, msg: str, ref: HostRef) -> Finding:
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
    )


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
                )
            )
        attrs: dict[str, Any] = {"class": cls}
        if ref.scheme:
            attrs["schemes"] = [ref.scheme]
        if cred:
            attrs["credential"] = cred
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
    return AnalyzerResult(
        NAME,
        AnalyzerState.OK,
        findings=findings,
        facts=facts,
        detail=f"{len(distinct)} hosts/IPs",
    )
