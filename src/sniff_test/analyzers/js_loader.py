"""(0.15, full Marketplace run 2026-11-22) A loader: code that downloads and runs whatever
address it is handed.

Eight map cards ship a map library whose worker has one: `async function load(url) {
const code = await (await fetch(url)).text(); eval(code) }`, called with an address the
page sends it. `card-eval-remote` read that as a sign of malice. His decision (2026-11-22):
it is a door, not malice, graded like other code a card loads from elsewhere:

- `card-eval-remote` where the downloaded address is a parameter of the function that
  runs the code, never given another value there, becomes `card-code-loader` (info): it
  can run code from an address it is given. Code downloaded from a fixed address and run
  stays `card-eval-remote` (a Threat sign), as before.
- When an app has a loader, every address of a JavaScript file written in its code is
  code it may load: `card-remote-script` (Exposure 5) unless the address names one exact
  version (`card-remote-pinned`, Exposure 2). The app's own domain doesn't lower it (the
  code still skips review and can change without an update, and domains lapse). Code-CDN
  addresses are read by js_remote already, for cards.
- A loader no address can be seen for stays a note: what it would load isn't known, and
  nothing in the app hands it one Barkley can read.

Read only: text and js_fold tokens, linear in the file size.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path

from sniff_test.analyzers import js_remote, js_wrapper
from sniff_test.models import Category, Finding, Severity

RULE = "card-code-loader"
_MAX_ADDRESSES = 5
_SCRIPT_URL = re.compile(
    r"""https?://[A-Za-z0-9.-]{1,253}(?::\d{1,5})?/[^\s"'`<>\\]{0,300}?\.m?js(?:\?[^\s"'`<>\\]{0,200})?(?=["'`])"""
)
_EXACT = re.compile(r"[@/]v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]{1,40})?/|[@/][0-9a-f]{40}/")


@dataclass
class Hit:
    finding: Finding
    path: Path
    start: int


def _fetches_param(body: str, params: list[str | None]) -> str | None:
    for p in params:
        if not p:
            continue
        n = re.escape(p)
        if re.search(
            rf"(?<![\w$.])(?:fetch|importScripts)\s*+\(\s*+{n}\s*+[,)]"
            rf"|(?<![\w$.])import\s*+\((?:\s*+/\*[^*]{{0,200}}\*/)?\s*+{n}\s*+\)",
            body,
        ) and not js_wrapper._param_reassigned(body, p):
            return p
    return None


def loaders(hits: list[Hit], root: Path) -> set[int]:
    """ids of the `card-eval-remote` findings that are a loader's."""
    index = js_wrapper._Index(root.resolve())
    out: set[int] = set()
    for h in hits:
        path = h.path.resolve()
        text = index.text(path)
        inner = sorted(
            (f for f in js_wrapper._fn_records(index, path) if f.start <= h.start < f.end),
            key=lambda f: f.end - f.start,
        )
        if inner and _fetches_param(text[inner[0].start : inner[0].end], inner[0].params):
            out.add(id(h.finding))
    return out


def as_note(f: Finding) -> Finding:
    return replace(
        f,
        rule_id=RULE,
        title="Can run code from an address it is given",
        severity=Severity.INFO,
        category=Category.CODE_EXEC,
        tags=frozenset(),
        supersedes=frozenset({"card-eval"}),
        message=(
            "This code downloads JavaScript from an address it is handed and runs it. "
            "Barkley lists any script address it sees written in the app as code the app may "
            "load. Code a loader gets from an address Barkley can't see was never read."
        ),
    )


def script_addresses(root: Path) -> list[Finding]:
    """Every address of a JavaScript file written in the app's JavaScript (in a string or
    template, not a comment), graded like js_remote's: exact version 2, else 5."""
    from sniff_test.analyzers import js_fold

    out: list[Finding] = []
    seen: set[str] = set()
    for p in sorted(root.rglob("*")):
        if p.suffix not in js_wrapper._JS or not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > 50 * 1024 * 1024:
                continue
            text = p.read_text("utf-8", "replace")
        except OSError:
            continue
        if "://" not in text:
            continue
        spans = [(t.start, t.end) for t in js_fold.tokens(text)
                 if t.kind in (js_fold.STR, js_fold.TPL)]  # fmt: skip
        for a, b in spans:
            for m in _SCRIPT_URL.finditer(text, a, b):
                url = m.group(0)
                host = url.split("/", 3)[2].split(":")[0].lower()
                if host in js_remote.CDN_HOSTS or url in seen:
                    continue  # CDN addresses: js_remote's reading
                seen.add(url)
                pinned = bool(_EXACT.search(url))
                load = js_remote.Load(p.relative_to(root).as_posix(),
                                      text.count("\n", 0, m.start()) + 1, url[:300], host,
                                      pinned, package=url[:300])  # fmt: skip
                out.append(js_remote.finding(load))
                if len(out) >= _MAX_ADDRESSES:
                    return out
    return out
