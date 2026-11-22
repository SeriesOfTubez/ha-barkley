"""(0.15, his decision 2026-11-21) A card that takes its settings from the page address and
runs a setting as code: a link can make it run code (`card-eval-address`, Exposure 5).

The Semgrep rule follows the page address straight into `eval`/`Function`. A real card
went through its settings instead: it copied every `?wp_<setting>=` parameter of the
address over its dashboard settings, and later ran one setting with
`new Function("bmp", config.<setting>)`. Names are minified and the copy is a function
of its own, so no single pattern follows it. This reads what the text proves:

- the file copies *every* parameter of the address (`for (… of params)`,
  `params.forEach(…)`, `.entries()`, `Object.fromEntries(params)` close after
  `params = new URLSearchParams(location.search)` or `location.hash`). Reading one named
  parameter (`params.get("mode")`) isn't a copy of the settings;
- and the same file runs text that isn't fixed as code (a `card-eval` or
  `card-eval-config` finding there).

Then the first such place becomes `card-eval-address`. Never run, never parsed as a
program: a few searches over the text with bounded patterns, so a hostile file costs
time in proportion to its size (tests/test_js_address.py).
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

from sniff_test.models import Category, Finding, Severity

RULE = "card-eval-address"
CODE_RULES = ("card-eval", "card-eval-config")
_MAX_FILE = 50 * 1024 * 1024
_MAX_NAMES = 20
_WHERE = r"(?:(?:window|document|self|globalThis)\.){0,2}location\.(?:search|hash)"
_PARAMS = r"new[ \t]{1,3}URLSearchParams\([ \t]{0,3}" + _WHERE
_NAMED = re.compile(r"([A-Za-z_$][\w$]{0,40})[ \t]{0,3}=[ \t]{0,3}" + _PARAMS)
_WHOLE = re.compile(
    r"(?:\bof[ \t]{1,3}|fromEntries\([ \t]{0,3})" + _PARAMS
    + r"|" + _PARAMS + r"[^)\n]{0,40}\)[ \t]{0,3}\.(?:forEach|entries|keys)\("
)  # fmt: skip
TITLE = "A link can make the card run code"
MESSAGE = (
    "The card takes its settings from the page address and runs one of them as code. "
    "Anyone who gets you to open a link to your dashboard can make it run code there, "
    "with your Home Assistant login."
)


_NEAR = 1500  # characters after `params = new URLSearchParams(…)` where its loop must be


def copies_address(text: str) -> bool:
    """Does the text copy every parameter of the page address? A loop over a name counts
    only in the rest of the block where the name gets the parameters (at most _NEAR
    characters): minified code reuses one-letter names (`t.forEach(…)` in the next
    function is another `t`)."""
    if _WHOLE.search(text):
        return True
    for k, m in enumerate(_NAMED.finditer(text)):
        if k >= _MAX_NAMES:
            break
        n = re.escape(m.group(1))
        pat = (rf"\bof[ \t]{{1,3}}{n}\b|(?<![\w$.]){n}\.(?:forEach|entries|keys)\("
               rf"|fromEntries\([ \t]{{0,3}}{n}\b")  # fmt: skip
        if re.search(pat, _block_rest(text, m.end())):
            return True
    return False


def _block_rest(text: str, i: int) -> str:
    """The text after `i` up to the end of the block it is in (the first `}` that closes
    more than it opened), at most _NEAR characters: the name's own scope, roughly."""
    depth = 0
    end = min(len(text), i + _NEAR)
    for k in range(i, end):
        c = text[k]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth < 0:
                return text[i:k]
    return text[i:end]


def add(findings: list[Finding], root: Path) -> list[Finding]:
    """Turn the first place in each file that runs code into `card-eval-address` when the
    file also copies the page address into an object."""
    files = sorted({f.file for f in findings if f.rule_id in CODE_RULES and f.file})
    hit: set[str] = set()
    for rel in files:
        p = (root / rel).resolve()
        try:
            p.relative_to(root.resolve())
            if not p.is_file() or p.stat().st_size > _MAX_FILE:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue
        if copies_address(text):
            hit.add(rel)
    if not hit:
        return findings
    out, done = [], set()
    for f in findings:
        if f.rule_id in CODE_RULES and f.file in hit and f.file not in done:
            done.add(f.file)
            f = dataclasses.replace(
                f, rule_id=RULE, title=TITLE, severity=Severity.HIGH,
                category=Category.CODE_EXEC, message=MESSAGE,
            )  # fmt: skip
        out.append(f)
    return out
