"""(0.15, batch 2026-11-21) Code a dashboard card loads from a code CDN while it runs.

The Semgrep rule `card-remote-script` sees `import("https://…")` and a `<script>` made with
`document.createElement("script")` whose `src` is a fixed address. Real cards also load
code through a loader of their own (`createElement(tag)`, `el[attr] = url`), from an
address put together while they run, or in a Web Worker, which no single pattern sees. A
code CDN serves an npm package's files by name, so the address itself says what it is:
this reads every string in the card's JavaScript that points to a JavaScript file or a
package on one of those sites, wherever it is used.

Each one is either:

- `card-remote-script`: the version is decided while the card runs (no version in the
  address, a range such as `@6` or `@latest`, or a version the card works out, such as
  the newest one it asks the npm registry for). Exposure 5: whoever can publish that
  package decides what runs in your dashboard, now and later.
- `card-remote-pinned`: one exact version (`@3.2.1`, a commit), written in the address or
  in a constant the address uses. Exposure 2: the code can't change under you, but Barkley
  never read it.

Decided with him 2026-11-21 (vault: Roadmap "Decided 2026-11-21 (thirty-first session)").

Never run, never parsed as a program: plain text scanning. Every host is looked for with
`str.find`, and each hit reads fixed windows around it, so a hostile file costs time in
proportion to its size (tests/test_js_remote.py).

(0.15, full Marketplace run 2026-11-22) An address in a comment isn't loaded: a real card
kept a debugging console's `<script>` inside `/* ... */`. When a file has any address, it
is read once with js_fold's tokenizer (strings, templates, comments and regular
expressions read whole, linear), and only addresses inside a string or template count.
A mistake there could only hide an address someone could hide anyway by building it
from pieces, which this text reading never sees.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from pathlib import Path

from sniff_test.models import Category, Finding, Severity

NAME = "js_remote"
UNPINNED = "card-remote-script"
PINNED = "card-remote-pinned"

# Sites that serve npm packages (or a GitHub repository's files) as code by name.
CDN_HOSTS = (
    "cdn.jsdelivr.net",
    "fastly.jsdelivr.net",
    "unpkg.com",
    "esm.sh",
    "esm.run",
    "cdn.skypack.dev",
    "ga.jspm.io",
    "jspm.dev",
    "cdnjs.cloudflare.com",
    "raw.githubusercontent.com",
)
_JS = {".js", ".mjs", ".cjs"}
_NOT_CODE = (".css", ".json", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
             ".woff", ".woff2", ".ttf", ".otf", ".map", ".md", ".html", ".txt", ".wasm",
             ".geojson", ".pbf")  # fmt: skip
_MAX_FILE = 50 * 1024 * 1024
_MAX_LITERAL = 2000
_MAX_HOLE = 200  # characters of one `${…}` kept
_MAX_HITS = 5000  # addresses read per file; past it the rest count as one unknown load
_MAX_LOOKUPS = 40  # constants looked up per file
_BACK = 12  # characters before the host where the opening quote must be (`"https://`)
_IDENT = re.compile(r"[A-Za-z_$][\w$]{0,63}")
_EXACT = re.compile(r"v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]{1,40})?|[0-9a-f]{40}")
_HOLE = "\x00"


@dataclass(frozen=True)
class Load:
    file: str
    line: int
    address: str  # the literal as written, each `${…}` shown as `${…}`
    host: str
    pinned: bool
    package: str = ""  # host + the package and version part: files of one package are one load


def _literal(text: str, q: int) -> tuple[str, list[str], int] | None:
    """The literal opening at text[q]: (text with each `${…}` as _HOLE, the holes' code,
    index after the closing quote); None when it doesn't close within _MAX_LITERAL."""
    quote = text[q]
    out: list[str] = []
    holes: list[str] = []
    j, end = q + 1, min(len(text), q + 1 + _MAX_LITERAL)
    while j < end:
        c = text[j]
        if c == "\\":
            out.append(text[j + 1 : j + 2])
            j += 2
        elif c == quote:
            return "".join(out), holes, j + 1
        elif quote == "`" and c == "$" and text[j + 1 : j + 2] == "{":
            depth, k = 1, j + 2
            while k < end and depth:
                depth += (text[k] == "{") - (text[k] == "}")
                k += 1
            holes.append(text[j + 2 : k - 1][:_MAX_HOLE])
            out.append(_HOLE)
            j = k
        elif c == "\n" and quote != "`":
            return None
        else:
            out.append(c)
            j += 1
    return None


def _next_name(text: str, i: int) -> str | None:
    """`"…@" + version`: the name added right after a literal, if any."""
    k = i
    while k < len(text) and k < i + 8 and text[k] in " \t\r\n":
        k += 1
    if text[k : k + 1] != "+":
        return None
    k += 1
    while k < len(text) and k < i + 16 and text[k] in " \t\r\n":
        k += 1
    m = _IDENT.match(text, k)
    return m.group(0) if m else None


def _split_spec(spec: str) -> str | None:
    """`name@version` (`@scope/name@version`): the version, "" when the text stops at the
    `@` (the rest is added while it runs), None when there is none."""
    at = spec.find("@", 1)
    return None if at == -1 else spec[at + 1 :]


def _path_parts(host: str, path: str) -> tuple[str | None] | None:
    """(the version part of the address,) for a path after the host that names a package
    or a JavaScript file; None when it names something else (a stylesheet, an image, a
    bare site address)."""
    path = re.split(r"[?#\"'`\s)]", path, maxsplit=1)[0]  # a quote: the address ended there
    if not path or path.endswith("/"):  # a folder (`…/fonts/`), not a file or a package
        return None
    if path.lower().endswith(_NOT_CODE):
        return None
    segs = [s for s in path.split("/") if s]
    last = segs[-1] if segs else ""
    ext = Path(last).suffix.lower()
    if ext[1:].isalpha() and ext not in _JS and "@" not in last and _HOLE not in last:
        return None  # some other kind of file (a version such as `@3.2.1` isn't one)
    if path == _HOLE:  # the whole path is worked out while it runs
        return (None,)
    if host == "cdnjs.cloudflare.com":  # ajax/libs/<name>/<version>/<file>
        return (segs[3],) if len(segs) >= 5 and segs[:2] == ["ajax", "libs"] else None
    if host == "raw.githubusercontent.com":  # <owner>/<repo>/<ref>/<file>
        ok = len(segs) >= 4 and Path(segs[-1]).suffix.lower() in _JS
        return (segs[2],) if ok else None
    if host.endswith("jsdelivr.net"):
        if not segs or segs[0] not in ("npm", "gh"):
            return None
        if segs[0] == "gh":  # gh/<owner>/<repo>[@ref]/<file>
            if len(segs) < 3:
                return None
            return (_split_spec(f"{segs[1]}/{segs[2]}"),)
        segs = segs[1:]
    elif host == "ga.jspm.io":
        segs = [x.removeprefix("npm:") for x in segs]
    elif segs and re.fullmatch(r"v\d{1,4}", segs[0]):
        segs = segs[1:]  # esm.sh's build prefix (`/v135/…`)
    if not segs:
        return None
    spec = f"{segs[0]}/{segs[1]}" if segs[0].startswith("@") and len(segs) > 1 else segs[0]
    return (_split_spec(spec),)


def _package(host: str, address: str) -> str:
    """`unpkg.com/acme-html@1` for `https://unpkg.com/acme-html@1/directives/x.js?module`:
    the address up to the segment holding the version (or the package name)."""
    path = address.split("//" + host + "/", 1)[-1].split("?", 1)[0]
    segs = [x for x in path.split("/") if x]
    for n, seg in enumerate(segs):
        if "@" in seg[1:] or seg == "${…}":
            return host + "/" + "/".join(segs[: n + 1])
    keep = 4 if host in ("cdnjs.cloudflare.com", "raw.githubusercontent.com") else 2
    return host + "/" + "/".join(segs[:keep])


class _Constants:
    """Exact versions a card keeps in a constant (`const MAP_LIB_VERSION = "4.7.1"`,
    minified `DZ="6.7.0"`). One search per name, at most _MAX_LOOKUPS per file."""

    def __init__(self, text: str):
        self.text = text
        self.seen: dict[str, str | None] = {}

    def exact(self, name: str) -> bool:
        if name not in self.seen:
            if len(self.seen) >= _MAX_LOOKUPS:
                return False
            m = re.search(
                r"(?<![\w$.])" + re.escape(name) + r"[ \t]*+[=:][ \t]*+([\"'`])([^\"'`\n]{1,60})\1",
                self.text,
            )
            self.seen[name] = m.group(2) if m else None
        v = self.seen[name]
        return v is not None and bool(_EXACT.fullmatch(v))


def _pinned(version: str | None, holes: list[str], after: str | None, c: _Constants) -> bool:
    if version is None:
        return False
    if version == "" and after:  # "…/pkg@" + VERSION
        return c.exact(after)
    if version == _HOLE and len(holes) >= 1:
        hole = holes[0].strip()
        return bool(_IDENT.fullmatch(hole)) and c.exact(hole)
    return bool(_EXACT.fullmatch(version))


def _openings(text: str) -> tuple[list[tuple[int, str, str]], int | None]:
    """(index of the opening quote, host, needle) of every literal that starts with a code
    CDN address, in file order, at most _MAX_HITS; and where the first one past that is."""
    found: dict[int, tuple[str, str]] = {}
    past: int | None = None
    for host in CDN_HOSTS:
        needle = "//" + host + "/"
        i = text.find(needle)
        while i != -1:
            if len(found) >= _MAX_HITS:
                past = i if past is None else min(past, i)
                break
            q = next((k for k in range(i - 1, max(-1, i - _BACK), -1) if text[k] in "\"'`"), -1)
            # the quote opens the literal: `"https://host/` or `"//host/`
            if q != -1 and text[q + 1 : i].lower() in ("", "http:", "https:"):
                found.setdefault(q, (host, needle))
            i = text.find(needle, i + len(needle))
    return [(q, *found[q]) for q in sorted(found)], past


def _in_code(text: str, openings: list[tuple[int, str, str]]) -> list[tuple[int, str, str]]:
    """The openings that start, or sit inside, a string or template: not in a comment."""
    from sniff_test.analyzers import js_fold

    if not openings:
        return openings
    spans = [(t.start, t.end) for t in js_fold.tokens(text) if t.kind in (js_fold.STR, js_fold.TPL)]
    starts = [s for s, _e in spans]
    out = []
    for o in openings:
        k = bisect.bisect_right(starts, o[0]) - 1
        if k >= 0 and spans[k][0] <= o[0] < spans[k][1]:
            out.append(o)
    return out


def read(text: str, rel: str) -> list[Load]:
    out: list[Load] = []
    consts = _Constants(text)
    line, at = 1, 0  # lines counted once, in file order
    openings, past = _openings(text)
    openings = _in_code(text, openings)
    if past is not None:  # never a way to hide one: the rest count as one unknown load
        out.append(Load(rel, text.count("\n", 0, past) + 1,
                        "more code addresses than Barkley reads in one file", "a code CDN",
                        False, "(more)"))  # fmt: skip
    for q, host, needle in openings:
        line += text.count("\n", at, q)
        at = q
        lit = _literal(text, q)
        if lit is None:
            continue
        body, holes, end = lit
        path = body[body.find(needle) + len(needle) :]
        stray = re.search(r"[\"'`\s)]", path)
        if stray:  # `'url("https://…/fonts/'`: the address stops at the quote
            body = body[: body.find(needle) + len(needle) + stray.start()]
        parts = _path_parts(host, path)
        if parts is None:
            continue
        version = parts[0]
        if version is not None and version.startswith(_HOLE):
            version = _HOLE
        after = _next_name(text, end) if version == "" else None
        shown = body.replace(_HOLE, "${…}")[:300]
        pinned = _pinned(version, holes, after, consts)
        out.append(Load(rel, line, shown, host, pinned, _package(host, shown)))
    return out


def loads_in(root: Path) -> list[Load]:
    """Every code CDN address in the card's JavaScript files under `root`."""
    found: list[Load] = []
    for p in sorted(root.rglob("*")):
        if p.suffix not in _JS or not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > _MAX_FILE:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found.extend(read(text, p.relative_to(root).as_posix()))
    return found


_TITLE = {
    UNPINNED: "Card loads code from another site, version picked while it runs",
    PINNED: "Card loads a fixed version of code from another site",
}
_MESSAGE = {
    UNPINNED: (
        "While it runs, the card loads JavaScript from {host}. Which version it gets is "
        "only decided then, so whoever publishes it decides what runs in your dashboard, "
        "with your Home Assistant login. Barkley never read that code."
    ),
    PINNED: (
        "While it runs, the card loads one fixed version of JavaScript from {host}. It "
        "can't change under you, but Barkley never read it, and it runs with your Home "
        "Assistant login."
    ),
}


def finding(load: Load) -> Finding:
    rule = PINNED if load.pinned else UNPINNED
    return Finding(
        rule_id=rule,
        title=_TITLE[rule],
        severity=Severity.LOW if load.pinned else Severity.MEDIUM,
        category=Category.CODE_EXEC,
        message=_MESSAGE[rule].format(host=load.host),
        file=load.file,
        line=load.line,
        evidence=load.address,
        analyzer=NAME,
    )


def merge(findings: list[Finding], loads: list[Load]) -> list[Finding]:
    """Semgrep's `card-remote-script` findings take the version reading of a CDN address
    on the same line (pinned → `card-remote-pinned`); every other address becomes a
    finding of its own. A Semgrep match with an address on no code CDN keeps its rule: a
    server of the card's choosing decides what it sends each time."""
    import dataclasses

    by_place: dict[tuple[str, int], list[Load]] = {}
    for x in loads:
        by_place.setdefault((x.file, x.line), []).append(x)
    used: set[int] = set()
    out: list[Finding] = []
    for f in findings:
        here = by_place.get((f.file or "", f.line or 0)) if f.rule_id == UNPINNED else None
        if here:
            match = next((x for x in here if x.address.split("${")[0] in (f.evidence or "")),
                         here[0])  # fmt: skip
            used.update(id(x) for x in here)
            if match.pinned:
                text = _MESSAGE[PINNED].format(host=match.host)
                f = dataclasses.replace(
                    f, rule_id=PINNED, title=_TITLE[PINNED], severity=Severity.LOW, message=text
                )
        out.append(f)
    seen = {x.package for x in loads if id(x) in used}
    for x in loads:  # one finding per package and version, at its first place
        if id(x) not in used and x.package not in seen:
            seen.add(x.package)
            out.append(finding(x))
    return out
