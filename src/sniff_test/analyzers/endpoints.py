"""Declared-endpoint check: which hosts and IPs does the shipped code talk about?

Every host literal becomes a neutral inventory fact (the network ring of the hooks
graph), classified as declared, infrastructure, local, undeclared and so on. Only three
things are findings, because the rest proved to be noise on real repos (one card ships
14 donation/doc links; one integration pings a dict of public DNS servers):

- `endpoint-exfil-host` (high): a paste site, request catcher, OOB interaction server
  or tunnel; or a chat webhook URL that carries its credential (Discord webhook token,
  Telegram bot token, Slack hook), i.e. data goes to the developer's channel, not yours;
- `endpoint-public-ip-literal` (high): a URL whose host is a hardcoded public IP.

Undeclared hosts feed the possible-exfil correlation (`correlate.py`), except a host the
code names only as an OAuth return address (0.15, issue #26): every place it appears is a
string inside a Python constant whose name says REDIRECT or CALLBACK, and the URL's path
ends in a callback or redirect segment (`redirect_only` on its facts). The browser is
sent there after a sign-in; the app doesn't connect to it. It is still listed. Found with
`ast.parse`, which only parses.

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
from dataclasses import dataclass, field
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
    # (0.15) lowercase owners (the repo's, the manifest's GitHub links'): on shared hosting
    # only their own paths are the app's own (see SHARED_HOSTING)
    owners: set[str] = field(default_factory=set)

    def matches(self, host: str) -> bool:
        reg = registrable(host)
        if reg in self.hosts:
            return True
        first = _norm(reg.split(".")[0])
        if first and first in self.names:
            return True
        # (0.14.0) A name that spans the top-level domain: `acme.energy` for an
        # integration named acme_energy. The whole registrable domain must equal the
        # name; no prefix matching.
        whole = _norm(reg)
        return bool(whole) and whole in self.names


# (0.15, his decision 2026-11-20) Shared hosting: anyone can put anything there, so a site
# here is the app's own only when every address the code names is under the repo owner's
# path (github.com/<owner>/…, raw.githubusercontent.com/<owner>/…). The owner's Pages site
# (<owner>.github.io) is its own host and already handled.
SHARED_HOSTING = frozenset(
    {"github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "codeberg.org",
     "sourceforge.net"}
)  # fmt: skip


def owner_path(url: str | None, owners: set[str]) -> bool:
    """Whether a URL's path starts with one of `owners` (`/acme/…`)."""
    m = _URL.match(url or "")
    if not m or not owners:
        return False
    first = (m["path"] or "/").lstrip("/").split("/", 1)[0].lower()
    return bool(first) and first in owners


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
        if (h := _url_host(url)) and registrable(h) not in SHARED_HOSTING:
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
            if (h := _url_host(url)) and registrable(h) not in SHARED_HOSTING:
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
    return Declared(hosts, names, owners)


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


_MAX_JSON = 2 * 1024 * 1024
_MAX_JSON_FILES = 400


def _json_keys(root: Path) -> set[str]:
    """(0.15, issue #14) Dotted keys in the app's own JSON files (translation catalogs):
    `i18n.Msg("timeline.when.at")` names a key of `frontend/i18n/.../nl.json`, not a site
    in Austria. Parsed only; bounded by size and count."""
    import json

    keys: set[str] = set()
    seen = 0
    for p in sorted(root.rglob("*.json")):
        if seen >= _MAX_JSON_FILES or not p.is_file() or p.is_symlink():
            continue
        seen += 1
        try:
            if p.stat().st_size > _MAX_JSON:
                continue
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError, RecursionError):
            continue
        stack = [data]
        while stack and len(keys) < 200_000:
            node = stack.pop()
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(k, str) and "." in k:
                        keys.add(k.strip().lower())
                    stack.append(v)
            elif isinstance(node, list):
                stack.extend(node)
    return keys


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
    if any(r.url is None for r in refs):
        keys = _json_keys(root)
        refs = [r for r in refs if r.url is not None or r.host not in keys]
    return refs, tokens


# --- OAuth return addresses (0.15, issue #26) ---------------------------------------------

# Both must hold, so a send to a path merely named /callback still counts as a destination.
_REDIRECT_NAME = re.compile(r"(?i)redirect|callback")
_REDIRECT_PATH = re.compile(r"(?i)(?:callback|redirect)[\w-]{0,40}$")


def _target_names(node: ast.AST) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]  # type: ignore[attr-defined]
    out = []
    for t in targets:
        if isinstance(t, ast.Name):
            out.append(t.id)
        elif isinstance(t, ast.Attribute):
            out.append(t.attr)
    return out


def redirect_lines(text: str) -> dict[str, set[int]]:
    """Constant name -> lines of its string constants, for module- or class-level
    assignments whose name says REDIRECT or CALLBACK (`DEFAULT_OAUTH_REDIRECT_ALLOWLIST =
    ("https://…/auth_callback", …)`). Parse only; a file that doesn't parse has none."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return {}
    out: dict[str, set[int]] = {}
    bodies = [tree.body] + [n.body for n in tree.body if isinstance(n, ast.ClassDef)]
    for body in bodies:
        for node in body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
                continue
            for name in _target_names(node):
                if not _REDIRECT_NAME.search(name):
                    continue
                for sub in ast.walk(node.value):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                        out.setdefault(name, set()).add(sub.lineno)
    return out


# A call that sends or connects: a redirect constant handed to one is a destination.
_SEND_CALLS = frozenset(
    {"post", "get", "put", "patch", "delete", "request", "urlopen", "fetch", "send",
     "ws_connect", "connect", "create_connection", "stream", "head", "options"}
)  # fmt: skip


def sent_names(text: str) -> set[str]:
    """Names that appear anywhere inside a send or connect call (its arguments or what
    it's called on): `session.post(REDIRECTS[0], …)` gives REDIRECTS. Parse only."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return set()
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
        if name.lower() not in _SEND_CALLS:
            continue
        for part in [*node.args, *(k.value for k in node.keywords)]:
            for sub in ast.walk(part):
                if isinstance(sub, ast.Name):
                    out.add(sub.id)
                elif isinstance(sub, ast.Attribute):
                    out.add(sub.attr)
    return out


def _redirect_ref(ref: HostRef, lines: dict[str, set[int]]) -> bool:
    if not ref.url or ref.line not in lines.get(ref.file, set()):
        return False
    m = _URL.match(ref.url)
    path = (m["path"] or "") if m else ""
    path = path.split("?", 1)[0].split("#", 1)[0].rstrip("/")[-200:]
    return bool(_REDIRECT_PATH.search(path))


def redirect_only_hosts(root: Path, refs: list[HostRef]) -> set[str]:
    """Hosts every reference to which is an OAuth return address (see the module doc). A
    constant that any Python file of the app hands to a send or connect call doesn't
    count: its addresses are destinations."""
    texts: dict[str, str] = {}
    for p in sorted(root.rglob("*.py")):
        try:
            if p.is_symlink() or not p.is_file() or p.stat().st_size > _MAX_FILE:
                continue
            texts[p.relative_to(root).as_posix()] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    ref_files = {r.file for r in refs}
    per_file = {rel: redirect_lines(t) for rel, t in texts.items() if rel in ref_files}
    if not any(per_file.values()):
        return set()
    sent: set[str] = set()
    for t in texts.values():
        sent |= sent_names(t)
    lines = {rel: {ln for name, ls in consts.items() if name not in sent for ln in ls}
             for rel, consts in per_file.items()}  # fmt: skip
    by_host: dict[str, list[bool]] = {}
    for r in refs:
        by_host.setdefault(r.host, []).append(_redirect_ref(r, lines))
    return {h for h, marks in by_host.items() if marks and all(marks)}


# --- what the developer's own docs say (0.15, his question) ------------------------------

# A host the README or .github/FUNDING.yml names gets `readme_line` / `funding` on its facts:
# the developer's words, shown as such, never changing its class or what's scored (a
# README could name a collection site to make it look expected).
_DOC_MAX = 1024 * 1024
_FUNDING_HOSTS = {
    "github": "github.com", "patreon": "patreon.com", "ko_fi": "ko-fi.com",
    "buy_me_a_coffee": "buymeacoffee.com", "liberapay": "liberapay.com",
    "open_collective": "opencollective.com", "polar": "polar.sh", "thanks_dev": "thanks.dev",
    "tidelift": "tidelift.com", "community_bridge": "funding.communitybridge.org",
    "issuehunt": "issuehunt.io", "lfx_crowdfunding": "crowdfunding.lfx.linuxfoundation.org",
}  # fmt: skip
_FUNDING_KEY = re.compile(r"^[ \t]*+([a-z_]{2,30})[ \t]*+:", re.M)


def _plain(host: str) -> str:
    return host.lower().removeprefix("www.")


def doc_mentions(source_root: Path | None) -> tuple[dict[str, int], set[str]]:
    """(host -> first README line naming it, hosts FUNDING.yml lists). Text only."""
    readme: dict[str, int] = {}
    funding: set[str] = set()
    if source_root is None:
        return readme, funding

    def text_of(rel: str) -> str | None:
        p = source_root / rel
        try:
            if p.is_symlink() or not p.is_file() or p.stat().st_size > _DOC_MAX:
                return None
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    for name in ("README.md", "README.rst", "README.txt", "README", "readme.md"):
        if (text := text_of(name)) is not None:
            for n, line in enumerate(text.splitlines(), 1):
                for m in _URL.finditer(line[:5000]):
                    readme.setdefault(_plain(m["host"]), n)
            break
    gh = source_root / ".github"
    names = []  # GitHub reads FUNDING.yml in any case, .yml or .yaml
    if gh.is_dir() and not gh.is_symlink():
        wanted = ("funding.yml", "funding.yaml")
        names = sorted(p.name for p in gh.iterdir() if p.name.lower() in wanted)
    if names and (text := text_of(f".github/{names[0]}")) is not None:
        lines = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
        funding |= {_plain(m["host"]) for m in _URL.finditer(lines[:20000])}
        funding |= {_FUNDING_HOSTS[k] for k in _FUNDING_KEY.findall(lines) if k in _FUNDING_HOSTS}
    return readme, funding


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
    redirects = redirect_only_hosts(target.root, refs)
    readme, funding = doc_mentions(target.source_root)
    # (0.15) shared hosting is the app's own only when every address is under the owner
    shared: dict[str, bool] = {}
    for r in refs:
        if registrable(r.host) in SHARED_HOSTING:
            shared[r.host] = shared.get(r.host, True) and owner_path(r.url, declared.owners)
    for ref in refs:
        cls = classify(ref.host, declared)
        if ref.host in shared and cls not in ("namespace", "exfil_service", "messaging"):
            # code hosting: the owner's own paths are the app's, the rest are where code
            # lives (as github.com always was), never "undeclared"
            cls = "declared" if shared[ref.host] else "infrastructure"
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
        if ref.host in redirects and not cred:
            attrs["redirect_only"] = True
        if (line := readme.get(_plain(ref.host))) is not None:
            attrs["readme_line"] = line
        if _plain(ref.host) in funding:
            attrs["funding"] = True
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
