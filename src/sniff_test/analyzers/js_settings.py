"""(0.15, his yes 2026-11-22) A card that sends your login token to the address in its own
settings.

From the full Marketplace run: a real card posts with your login token to
`this._hass.hassUrl(this._config.endpoint)`, where `endpoint` is one of the card's
settings with the default "/api/<its integration>/enroll". `hassUrl(path)` is Home
Assistant's own address with the path added, so with the default the token stays on
your Home Assistant; it could only go elsewhere if someone typed a full address into that
card's settings on your dashboard. `card-token-exfil` read it as a sign of malice.

His decision: when the path comes from the card's settings and the card's own default for
that setting is a "/" path, or the card sets no default, the finding becomes a note
(`card-token-settings`, not a Threat). A default that is an outside address
(`https://…`, `//host`) or one Barkley can't read keeps the finding: then the developer
chose where it goes, or Barkley can't tell.

What counts as the card's default: every place in the file that gives the setting a value
(`endpoint: DEFAULT_ENDPOINT` in an object, `config.endpoint || "/api/x"`,
`{ endpoint = "/api/x" } = config`), with a name read as the constant the file assigns it
once. All of them must be "/" paths; any other value keeps the finding.

Read only, never run: text checks, linear in the file size (every pattern is anchored or
uses possessive quantifiers; tests/test_js_settings.py feeds them hostile input).
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from sniff_test.analyzers import js_wrapper
from sniff_test.models import Category, Finding, Severity

RULE = "card-token-settings"
# `this._config.endpoint`, `this.config.url`, `config.endpoint`, `this.__config.x`
_SETTING = re.compile(r"^(?:this\.)?_{0,2}config\??\.([A-Za-z_$][\w$]{0,40})$")
_PATH = re.compile(r"""^(["'`])/[^/\\"'`$\s][^"'`\\$\n]{0,300}\1$|^(["'`])/\2$""")
_STRING = re.compile(r"""^(["'`])[^"'`\\\n]{0,300}\1$""")
_CONST = r"(?<![\w$.])(?:const|let|var)\s++{name}\s*+=\s*+([^;\n]{{1,320}})"
_MAX_VALUES = 50


def _value_after(text: str, start: int) -> str:
    """The value written at text[start:]: up to the next `,` `;` `}` `)` or line end at
    the top level of brackets (a string's own commas are kept)."""
    out = []
    depth = 0
    quote = ""
    for c in text[start : start + 320]:
        if quote:
            out.append(c)
            if c == quote:
                quote = ""
            continue
        if c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif c in ",;\n" and depth == 0:
            break
        out.append(c)
    return "".join(out).strip()


def _resolve(text: str, value: str) -> str | None:
    """A string literal, or a name the file assigns a string literal once."""
    if _STRING.match(value):
        return value
    if re.fullmatch(r"[A-Za-z_$][\w$]{0,60}", value):
        got = re.findall(_CONST.format(name=re.escape(value)), text)
        if len(got) == 1 and _STRING.match(got[0].strip()):
            return got[0].strip()
    return None


def defaults(text: str, key: str) -> list[str | None]:
    """Each value the file gives the setting `key` (None: one Barkley can't read)."""
    esc = re.escape(key)
    starts = []
    for rx in (
        rf"(?<![\w$.]){esc}\s*+:(?!:)\s*+",  # { endpoint: X }
        rf"config\??\.{esc}\s*+(?:\|\||\?\?)\s*+",  # config.endpoint || X
        rf"[{{,]\s*+{esc}\s*+=(?![=>])\s*+",  # { endpoint = X } = config
    ):
        for m in re.finditer(rx, text):
            starts.append(m.end())
            if len(starts) > _MAX_VALUES:
                return [None]
    return [_resolve(text, _value_after(text, s)) for s in sorted(starts)]


def setting_of(text: str, arg: str, at: int) -> str | None:
    """The card setting a token URL comes from: `X.hassUrl(<setting>)`, directly or through
    a name given only that value before the use; else None."""
    expr = js_wrapper._unwrap(arg)
    if js_wrapper._IDENT.match(expr):
        values = js_wrapper._assignments(expr, js_wrapper._HaContext(text, at, None))
        keys = {setting_of(text, v, at) for v in values or []}
        return keys.pop() if len(keys) == 1 and None not in keys else None
    m = js_wrapper._HASS_URL_CALL.match(expr)
    if (
        m is None
        or js_wrapper._closing(expr[: js_wrapper._HA_WINDOW], m.end() - 1) != len(expr) - 1
    ):
        return None
    s = _SETTING.match(js_wrapper._unwrap(expr[m.end() : -1]))
    return s.group(1) if s else None


def settings_note(hits: list[js_wrapper.Hit]) -> dict[int, tuple[str, str]]:
    """id(finding) -> (setting, its default path or "") for token findings whose address is
    a path from the card's own settings with a "/" default or none."""
    out: dict[int, tuple[str, str]] = {}
    texts: dict[Path, str] = {}
    for h in hits:
        path = h.path.resolve()
        if path not in texts:
            try:
                texts[path] = path.read_text(encoding="utf-8", errors="replace")[
                    : js_wrapper._MAX_TEXT
                ]
            except OSError:
                continue
        text = texts[path]
        span = js_wrapper._url_arg(text, h.start, h.end)
        if span is None:
            continue
        key = setting_of(text, js_wrapper._arg_text(text, span), span[0])
        if key is None:
            continue
        values = defaults(text, key)
        if any(v is None or not _PATH.match(v) for v in values):
            continue  # an outside address, or one Barkley can't read: the finding stays
        out[id(h.finding)] = (key, values[0][1:-1] if values else "")
    return out


def as_note(f: Finding, key: str, default: str) -> Finding:
    where = (f"By default that is {default} on your own Home Assistant." if default
             else "The card sets no default, so it is your own Home Assistant unless "
                  "someone enters another address.")  # fmt: skip
    return replace(
        f,
        rule_id=RULE,
        title="Sends your login token to the address in its settings",
        severity=Severity.INFO,
        category=Category.SENSITIVE_ACCESS,
        tags=frozenset(),
        message=(
            f"This card sends your login token to the path in its '{key}' setting, added "
            f"to your Home Assistant's own address. {where} It would go to another site "
            "only if someone typed a full address into that setting on your dashboard."
        ),
    )
