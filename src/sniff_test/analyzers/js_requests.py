"""(0.15, his report 2026-11-21) What a dashboard card's JavaScript asks other sites for.

The Python reader (py_requests) parses an integration's code. A card ships one built,
usually minified file, so this reads the text itself and states only what the text
proves:

- `fetch("https://site/…", {method: "POST", body: …, headers: {…}})`: a request to that
  site, with the method (GET when no `method` is given, which is what `fetch` does), whether
  it has a body, and the names of the headers written in the call;
- `x.open("GET", "https://site/…")` (XMLHttpRequest) and `navigator.sendBeacon("https://…")`;
- `fetch(someName, …)`: a request whose address is put together while the card runs
  (counted, no site);
- an address with `{z}` in it (`https://tiles.site/{z}/{x}/{y}.png`): a map-tile address.
  A map library loads those as images, so there is no call to find; the site is listed as
  "loads map images".

Not read: a method that isn't the browser's own (`this.fetch(…)`, `api.fetch(…)`), an
address relative to the page (it goes to Home Assistant itself), and anything a bundled
library does through its own wrappers.

Never run, never parsed as a program: plain text scanning. Every scan is one pass with
fixed look-ahead windows, so a hostile file costs time in proportion to its size
(tests/test_js_requests.py).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sniff_test.analyzers import py_requests
from sniff_test.analyzers.endpoints import _host_ok
from sniff_test.analyzers.py_requests import Request

_JS = {".js", ".mjs", ".cjs"}
_MAX_FILE = 50 * 1024 * 1024
_MAX_LITERAL = 2000  # characters of one address literal
_MAX_OPTIONS = 1500  # characters of the options object that are looked at
_MAX_ARG = 300  # characters of a first argument that isn't a literal
_MAX_HITS = 5000  # calls read per file
_MAX_HEADERS = 12
_MAX_TILE_SITES = 200
_MAX_AT = 3
_IDENT = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")
_HOST = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")
_GLOBALS = ("window", "globalThis", "self")
_HOLE = "\x00"  # stands for a `${…}` piece of a template literal
# Names kept for examples and tests (RFC 2606, RFC 6761): a map library's own docs use
# them, and nothing is ever loaded from them
_EXAMPLE = ("example.com", "example.org", "example.net")
_EXAMPLE_TLDS = (".example", ".invalid", ".test", ".localhost")


def _example(host: str) -> bool:
    return (host in _EXAMPLE or host.endswith(tuple("." + x for x in _EXAMPLE))
            or host.endswith(_EXAMPLE_TLDS))  # fmt: skip


def _literal(text: str, i: int) -> tuple[str, int] | None:
    """The string literal starting at text[i] (a quote), as (its text with each `${…}`
    replaced by _HOLE, the index after the closing quote); None when it doesn't close
    within _MAX_LITERAL characters."""
    q = text[i]
    out: list[str] = []
    j, end = i + 1, min(len(text), i + 1 + _MAX_LITERAL)
    while j < end:
        c = text[j]
        if c == "\\":
            out.append(text[j + 1 : j + 2])
            j += 2
        elif c == q:
            return "".join(out), j + 1
        elif q == "`" and c == "$" and text[j + 1 : j + 2] == "{":
            depth, j = 1, j + 2
            while j < end and depth:
                depth += (text[j] == "{") - (text[j] == "}")
                j += 1
            out.append(_HOLE)
        elif c == "\n" and q != "`":
            return None
        else:
            out.append(c)
            j += 1
    return None


def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    return i


def site_of(address: str) -> tuple[str, str, int | None] | None:
    """(host, scheme, port) of an address literal whose site is written out in full, else
    None: a relative address, a site with a `${…}` piece in it, or a name that can't be a
    site."""
    low = address[:8].lower()
    scheme = "https" if low.startswith("https://") else "http" if low.startswith("http://") else ""
    if not scheme:
        return None
    rest = address[len(scheme) + 3 :]
    n = 0
    while n < len(rest) and n < 254 and rest[n].lower() in _HOST:
        n += 1
    host, after = rest[:n].lower().rstrip("."), rest[n : n + 1]
    if not host or after not in ("", "/", "?", "#", ":") or not _host_ok(host):
        return None
    port = None
    if after == ":":
        digits = rest[n + 1 : n + 6]
        k = 0
        while k < len(digits) and digits[k].isdigit():
            k += 1
        if k == 0 or rest[n + 1 + k : n + 2 + k] not in ("", "/", "?", "#"):
            return None  # `:${port}` or something else: not certain
        port = int(digits[:k])
    return host, scheme, port


def _query_names(address: str) -> tuple[str, ...] | None:
    """The field names written after the `?` of an address literal."""
    _, mark, tail = address.partition("?")
    if not mark:
        return None
    names = []
    for part in tail.split("#", 1)[0].split("&")[:40]:
        name = part.split("=", 1)[0]
        if name and len(name) <= 60 and all(c in _IDENT or c in "-.[]" for c in name):
            names.append(name)
    return tuple(dict.fromkeys(names))


def _object(text: str, i: int) -> str | None:
    """The object literal starting at text[i] == "{", braces included, when it closes
    within _MAX_OPTIONS characters. Strings inside are skipped whole."""
    depth, j, end = 0, i, min(len(text), i + _MAX_OPTIONS)
    while j < end:
        c = text[j]
        if c in "\"'`":
            lit = _literal(text, j)
            if lit is None:
                return None
            j = lit[1]
            continue
        depth += (c == "{") - (c == "}")
        j += 1
        if depth == 0:
            return text[i:j]
    return None


def _keys(obj: str) -> list[tuple[str, int]]:
    """(key, index of its value) for each key at the top level of an object literal's
    text: `name:` or `"name":`. A `...spread` is reported as the key "..."."""
    out: list[tuple[str, int]] = []
    depth, j, n = 0, 0, len(obj)
    expect = False  # at the start of a property
    while j < n:
        c = obj[j]
        if c in "{[(":
            depth += 1
            expect = depth == 1 and c == "{"
            j += 1
        elif c in "}])":
            depth -= 1
            j += 1
        elif c == "," and depth == 1:
            expect = True
            j += 1
        elif c in " \t\r\n":
            j += 1
        elif depth == 1 and expect:
            expect = False
            if obj.startswith("...", j):
                out.append(("...", j + 3))
                j += 3
            elif c in "\"'":
                lit = _literal(obj, j)
                if lit is None:
                    return out
                k = _skip_ws(obj, lit[1])
                if obj[k : k + 1] == ":":
                    out.append((lit[0], k + 1))
                j = lit[1]
            else:
                k = j
                while k < n and obj[k] in _IDENT:
                    k += 1
                name, k2 = obj[j:k], _skip_ws(obj, k)
                if name and obj[k2 : k2 + 1] == ":":
                    out.append((name, k2 + 1))
                elif name and obj[k2 : k2 + 1] in (",", "}"):
                    out.append((name, -1))  # shorthand: `{method, body}`
                j = max(k, j + 1)
        elif c in "\"'`":
            lit = _literal(obj, j)
            if lit is None:
                return out
            j = lit[1]
        else:
            j += 1
    return out


def _options(text: str, i: int) -> dict[str, Any]:
    """What the call's second argument says, read from text[i] (just after the first
    argument). No second argument: a plain GET."""
    i = _skip_ws(text, i)
    if text[i : i + 1] != ",":
        return {"method": "GET"}
    i = _skip_ws(text, i + 1)
    obj = _object(text, i) if text[i : i + 1] == "{" else None
    if obj is None:
        return {"method": "", "more": True}  # options held in a name: can't be read here
    out: dict[str, Any] = {"method": "GET"}
    for key, at in _keys(obj):
        if key == "...":
            out["more"] = True
        elif key == "method":
            v = _skip_ws(obj, at) if at >= 0 else -1
            lit = _literal(obj, v) if v >= 0 and obj[v : v + 1] in ('"', "'", "`") else None
            name = lit[0].upper() if lit else ""
            out["method"] = name if name in py_requests.METHODS else ""
        elif key == "body":
            out["body"] = ()
        elif key == "headers":
            v = _skip_ws(obj, at) if at >= 0 else -1
            inner = _object(obj, v) if v >= 0 and obj[v : v + 1] == "{" else None
            names = [k for k, _ in _keys(inner)] if inner else []
            out["headers"] = tuple(
                k[:60] for k in names[:_MAX_HEADERS] if k != "..." and len(k) <= 60
            )
    return out


def _first_arg(text: str, i: int) -> tuple[str | None, int] | None:
    """The call's first argument from text[i] (just after the "("): (the address literal
    or None when it isn't one, the index after the argument). None: nothing to read."""
    i = _skip_ws(text, i)
    if text[i : i + 1] in ('"', "'", "`"):
        lit = _literal(text, i)
        if lit is None:
            return None
        k = _skip_ws(text, lit[1])
        if text[k : k + 1] in (",", ")"):
            return lit[0], lit[1]
        # "https://site/" + path: the site is written out, the rest is added
        j = lit[1]
        depth, end = 0, min(len(text), j + _MAX_ARG)
        while j < end:
            c = text[j]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif c == "," and depth == 0:
                break
            j += 1
        return lit[0] + _HOLE, j
    if text[i : i + 1] in (")", ""):
        return None  # fetch(): a method of the card's own with that name
    depth, j, end = 0, i, min(len(text), i + _MAX_ARG)
    while j < end:
        c = text[j]
        if c in "\"'`":
            lit = _literal(text, j)
            if lit is None:
                return None
            j = lit[1]
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return None, j
            depth -= 1
        elif c == "," and depth == 0:
            return None, j
        j += 1
    return None


def _own_call(text: str, i: int) -> bool:
    """text[i:] starts a call of the browser's own function: not `this.fetch(`,
    `x._fetch(` or `prefetch(`, but `fetch(`, `window.fetch(`, `await fetch(`."""
    prev = text[i - 1 : i] if i else ""
    if prev in _IDENT and prev:
        return False
    if prev != ".":
        return True
    return any(text.endswith(g, 0, i - 1) and (text[i - 1 - len(g) - 1 : i - 1 - len(g)]
                                               not in _IDENT or i - 1 - len(g) == 0)
               for g in _GLOBALS)  # fmt: skip


def _request(address: str | None, opts: dict[str, Any], rel: str, line: int) -> Request | None:
    site = site_of(address) if address is not None else None
    if address is not None and site is None and not address.startswith(_HOLE):
        low = address[:8].lower()
        if not low.startswith(("http://", "https://")):
            return None  # relative to the page: Home Assistant itself
    return Request(
        host=site[0] if site else None,
        method=str(opts.get("method", "")),
        file=rel,
        line=line,
        body=opts.get("body"),
        headers=opts.get("headers"),
        query=_query_names(address.replace(_HOLE, "")) if address and site else None,
        more=bool(opts.get("more")),
        scheme=site[1] if site else "",
        port=site[2] if site else None,
    )


def read(text: str, rel: str) -> tuple[list[Request], dict[str, list[int]]]:
    """(requests, map-tile sites -> lines) of one JavaScript file's text."""
    reqs: list[Request] = []
    hits: list[tuple[int, str]] = []
    for needle in ("fetch(", ".open(", "sendBeacon("):
        i = text.find(needle)
        while i >= 0 and len(hits) < _MAX_HITS:
            hits.append((i, needle))
            i = text.find(needle, i + len(needle))
    hits.sort()
    line, pos = 1, 0
    tiles: dict[str, list[int]] = {}

    def line_at(i: int) -> int:
        nonlocal line, pos
        line += text.count("\n", pos, i)
        pos = i
        return line

    for i, needle in hits:
        after = i + len(needle)
        if needle == "fetch(":
            if not _own_call(text, i) or (arg := _first_arg(text, after)) is None:
                continue
            req = _request(arg[0], _options(text, arg[1]), rel, line_at(i))
        elif needle == ".open(":
            j = _skip_ws(text, after)
            lit = _literal(text, j) if text[j : j + 1] in ('"', "'", "`") else None
            if lit is None or lit[0].upper() not in py_requests.METHODS:
                continue  # window.open(url), db.open(name): not a request
            k = _skip_ws(text, lit[1])
            if text[k : k + 1] != "," or (arg := _first_arg(text, k + 1)) is None:
                continue
            req = _request(arg[0], {"method": lit[0].upper()}, rel, line_at(i))
        else:
            if (arg := _first_arg(text, after)) is None:
                continue
            req = _request(arg[0], {"method": "POST", "body": ()}, rel, line_at(i))
        if req is not None:
            reqs.append(req)

    line, pos = 1, 0
    i = text.find("{z}")
    seen = 0
    while i >= 0 and seen < _MAX_HITS:
        seen += 1
        start = max(text.rfind("https://", max(0, i - 300), i),
                    text.rfind("http://", max(0, i - 300), i))  # fmt: skip
        if start >= 0 and not any(c in text[start:i] for c in " \t\n\"'`<>"):
            address = text[start:i]
            # "https://{s}.tiles.site/…": the map library fills {s} with a, b or c
            scheme, _, rest = address.partition("://")
            if rest.startswith("{s}."):
                rest = rest[4:]
            site = site_of(f"{scheme}://{rest}")
            if (
                site
                and not _example(site[0])
                and (site[0] in tiles or len(tiles) < _MAX_TILE_SITES)
            ):
                tiles.setdefault(site[0], []).append(line_at(i))
        i = text.find("{z}", i + 3)
    return reqs, tiles


def requests_in(root: Path) -> tuple[list[Request], dict[str, list[str]]]:
    """Every request and map-tile site in the card's JavaScript files under `root`
    (tile sites -> "file:line" places)."""
    reqs: list[Request] = []
    tiles: dict[str, list[str]] = {}
    for p in sorted(root.rglob("*")):
        if p.suffix not in _JS or not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > _MAX_FILE:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = p.relative_to(root).as_posix()
        found, sites = read(text, rel)
        reqs.extend(found)
        for host, lines in sites.items():
            tiles.setdefault(host, []).extend(f"{rel}:{n}" for n in lines)
    return reqs, tiles


def summary(reqs: list[Request], tiles: dict[str, list[str]]) -> dict[str, Any] | None:
    """The report's `requests` section for a card: py_requests' shape, plus `images`
    (site -> how many map-tile addresses name it, and the first places)."""
    base = py_requests.summary(reqs)
    if base is None and not tiles:
        return None
    out = base or {"version": py_requests.VERSION, "sites": {}, "elsewhere": [], "total": 0}
    out["code"] = "card"
    if tiles:
        out["images"] = {
            host: {"count": len(at), "at": at[:_MAX_AT]} for host, at in sorted(tiles.items())
        }
    return out
