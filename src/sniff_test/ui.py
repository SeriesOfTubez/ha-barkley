"""The panel's pages: the card grid and each app's detail page (M8).

Pure functions from stored reports to HTML. No scripts anywhere (the CSP forbids them):
the reading dials and the data-flow diagram are inline SVG drawn here, and filters are
links. Every string that came from a scanned repo (names, hosts, URLs, files, evidence)
goes through `e()`. Plain-English text comes from `report.explain` and
`report.privacy`; nothing here changes a reading.
"""

from __future__ import annotations

import base64
import html
import re
import textwrap
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime
from importlib import resources
from typing import TYPE_CHECKING, Any

from sniff_test import __version__, devnote, kinds, known, readings, scancache
from sniff_test.analyzers.correlate import CREDENTIAL_SOURCES, SENSITIVE_NODES
from sniff_test.analyzers.endpoints import WELL_KNOWN_PORTS
from sniff_test.fetch import retry
from sniff_test.models import STALE_YEARS, fix_phrase, version_key, years_since
from sniff_test.report import explain, privacy
from sniff_test.report.json_report import sanitize_untrusted

if TYPE_CHECKING:
    from sniff_test.store import ScanRow


def _asset_uri(name: str) -> str:
    try:
        data = (resources.files("sniff_test") / "assets" / name).read_bytes()
    except OSError:
        return ""
    return "data:image/png;base64," + base64.b64encode(data).decode("ascii")


# Barkley's head for the panel header, inline (the CSP allows img-src data:).
LOGO_URI = _asset_uri("barkley-80.png")


def logo_img(size: int = 40) -> str:
    if not LOGO_URI:
        return ""
    return f'<img class="logo" src="{LOGO_URI}" width="{size}" height="{size}" alt="">'


# item id (, part="both"|"inline"|"sheet") -> "Explain in context" HTML ("" for none)
DeepFn = Callable[..., str]


def e(text: Any, limit: int = 300) -> str:
    """Escape for HTML text and attribute values (untrusted text is also truncated)."""
    return html.escape(sanitize_untrusted(str(text), limit) if text is not None else "")


# --- icons: a small inline-SVG set (Lucide paths, stroke 1.75) ---------------------------
# 14 px inline with text, 16 px inside controls and headings; one stroke width everywhere.
# The OS used to draw about twenty emoji and glyphs at whatever size and colour it liked.

_ICONS = {
    "search": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    "refresh": '<path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "x": '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    "minus": '<path d="M5 12h14"/>',
    "alert": '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/>'
    '<path d="M12 9v4"/><path d="M12 17h.01"/>',
    "clock": '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    "grid": '<rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/>'
    '<rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/>',
    "list": '<path d="M3 12h.01"/><path d="M3 18h.01"/><path d="M3 6h.01"/><path d="M8 12h13"/>'
    '<path d="M8 18h13"/><path d="M8 6h13"/>',
    "sparkle": '<path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936'
    "A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 "
    '1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z"/>',
    "home": '<path d="M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8"/><path d="M3 10a2 2 0 0 1 '
    ".709-1.528l7-5.999a2 2 0 0 1 2.582 0l7 5.999A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1"
    '-2-2z"/>',
    "cloud": '<path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/>',
    "wrench": '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1'
    "-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 "
    '3.76z"/>',
    "chart": '<path d="M3 3v16a2 2 0 0 0 2 2h16"/><path d="M18 17V9"/><path d="M13 17V5"/>'
    '<path d="M8 17v-3"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 '
    '0 0 0-20"/><path d="M2 12h20"/>',
    "link": '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>'
    '<path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    "plug": '<path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 '
    '0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/>',
    "lock": '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 '
    '1 10 0v4"/>',
    "star": '<path d="M11.525 2.295a.53.53 0 0 1 .95 0l2.31 4.679a2.123 2.123 0 0 0 1.595 1.16l5'
    ".166.756a.53.53 0 0 1 .294.904l-3.736 3.638a2.123 2.123 0 0 0-.611 1.878l.882 5.14a.53"
    ".53 0 0 1-.771.56l-4.618-2.428a2.122 2.122 0 0 0-1.973 0L6.396 21.01a.53.53 0 0 1-.77-.5"
    "6l.881-5.139a2.122 2.122 0 0 0-.611-1.879L2.16 9.795a.53.53 0 0 1 .294-.906l5.165-.755a2"
    '.122 2.122 0 0 0 1.597-1.16z"/>',
    "back": '<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>',
    # (0.15) beside a package with a known bug (Lucide "bug"); malware uses "alert"
    "bug": '<path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/>'
    '<path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 '
    '0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/><path d="M12 20v-9"/>'
    '<path d="M6.53 9C4.6 8.8 3 7.1 3 5"/><path d="M6 13H2"/>'
    '<path d="M3 21c0-2.1 1.7-3.9 3.8-4"/><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4"/>'
    '<path d="M22 13h-4"/><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4"/>',
    # (0.15) the head's facts row: GitHub's mark (Lucide "github"), downloads, version
    "github": '<path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5'
    ".28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 "
    "0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23"
    '-.15 1.85v4"/><path d="M9 18c-4.51 2-5-2-7-2"/>',
    "download": '<path d="M12 15V3"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>'
    '<path d="m7 10 5 5 5-5"/>',
    "tag": '<path d="M12.586 2.586A2 2 0 0 0 11.172 2H4a2 2 0 0 0-2 2v7.172a2 2 0 0 0 .586 '
    '1.414l8.704 8.704a2.426 2.426 0 0 0 3.42 0l6.58-6.58a2.426 2.426 0 0 0 0-3.42z"/>'
    '<circle cx="7.5" cy="7.5" r=".5" fill="currentColor"/>',
}


def icon(name: str, size: int = 14, cls: str = "") -> str:
    """An inline icon: `size` 14 beside text, 16 inside a control or heading."""
    return (
        f'<svg class="i{" " + cls if cls else ""}" width="{size}" height="{size}" '
        'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" '
        f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{_ICONS[name]}</svg>'
    )


# --- look --------------------------------------------------------------------------------

CSS = """
@font-face { font-family:"Geist"; src:url("__BASE__/fonts/Geist-Variable.woff2") format("woff2");
  font-weight:100 900; font-display:swap; }
@font-face { font-family:"Geist Mono"; src:url("__BASE__/fonts/GeistMono-Variable.woff2")
  format("woff2"); font-weight:100 900; font-display:swap; }
:root {
  /* type: four sizes (meta · body · titles · page title) */
  --t-xs:12px; --t-sm:13px; --t-md:15px; --t-lg:20px;
  /* spacing: the 4/8 scale; related things sit closer than unrelated ones */
  --s1:4px; --s2:8px; --s3:12px; --s4:16px; --s6:24px;
  /* radius: chip · control · box · card; nested elements go one step smaller */
  --r1:4px; --r2:6px; --r3:8px; --r4:12px;
  --font:"Geist",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --mono:"Geist Mono",ui-monospace,"SF Mono",Menlo,monospace;
  /* neutrals tinted toward the brand hue (OKLCH 208°); the accent sits 65° from the
     "no concerns" green and at least 40° from every severity hue */
  --bg:#edf1f2; --card:#fff; --soft:#e6eeef; --line:#c9d3d5; --fg:#141c1d; --muted:#5a6768;
  --brand:#006b77; --brand-bg:#d8f5f9; --brand-fg:#fff;
  /* light mode, second pass (the user, 2026-11-12: "colors are a bit difficult to discern
     and the cards look mostly the same"): the page a step darker than the cards and a
     firmer card line; amber instead of olive for "look", on a tint you can see; deeper
     tints for green/orange/red; `--*-edge` is the brighter hue for outlines, where text
     contrast doesn't apply */
  --green:#256b29; --yellow:#8a5a00; --orange:#b34a00; --red:#b71c1c; --grey:#788284;
  --green-bg:#dcefdd; --yellow-bg:#ffe9a8; --orange-bg:#ffdcc2; --red-bg:#fbd5d2;
  --yellow-edge:#d99a00; --orange-edge:#e0660a; --red-edge:#d32f2f;
  --priv:#6a4fb3; --priv-bg:#efeafa; --ai:#a3267f; --ai-bg:#fbeaf5;
  --dur-in:180ms; --dur-out:100ms; color-scheme:light; }
@media (prefers-color-scheme: dark) { :root { --bg:#101516; --card:#191e1f; --soft:#202829;
  --line:#2c3536; --fg:#e2e9eb; --muted:#94a1a3;
  --brand:#66d0df; --brand-bg:#0b2e33; --brand-fg:#070b0c;
  --green:#6fcf74; --yellow:#e3c04f; --orange:#ff9f5a; --red:#ff7b72; --grey:#7e888a;
  --green-bg:#18291a; --yellow-bg:#2e2810; --orange-bg:#33210f; --red-bg:#351a19;
  --yellow-edge:#e3c04f; --orange-edge:#ff9f5a; --red-edge:#ff7b72;
  --priv:#b9a4f0; --priv-bg:#251f38; --ai:#f07acb; --ai-bg:#33172b; color-scheme:dark; } }
* { box-sizing:border-box; }
body { background:var(--bg); color:var(--fg); font:400 var(--t-sm)/1.5 var(--font);
  margin:0 auto; max-width:1100px; padding:var(--s4) var(--s4) var(--s6); }
a { color:var(--brand); }
.i { display:inline-block; vertical-align:-0.125em; flex:none; }
.i.ok { color:var(--green); } .i.bad { color:var(--red); } .i.muted { color:var(--muted); }
.i.warn { color:var(--yellow); }
h1 { font-size:var(--t-lg); font-weight:600; letter-spacing:-0.01em; margin:0; }
h2 { font-size:var(--t-md); font-weight:600; letter-spacing:-0.01em; margin:0 0 var(--s1); }
h3 { font-size:var(--t-sm); font-weight:600; margin:0; }
p { margin:0; }
code { font:var(--t-xs)/1.5 var(--mono); overflow-wrap:anywhere; }
b, strong { font-weight:600; }
main { display:flex; flex-direction:column; gap:var(--s6); }
.stack { display:flex; flex-direction:column; gap:var(--s3); }
.muted { color:var(--muted); } .small { font-size:var(--t-xs); }
.mt2 { margin-top:var(--s2); } .mt3 { margin-top:var(--s3); }
.box { background:var(--card); border:1px solid var(--line); border-radius:var(--r4);
  padding:var(--s4); min-width:0; }
.sub { color:var(--muted); margin-bottom:var(--s2); }
.head { display:flex; flex-wrap:wrap; gap:var(--s2) var(--s4); align-items:center; }
.head h1 { display:flex; align-items:center; gap:var(--s2); }
.head img.logo { display:block; flex:none; }
.summary { display:flex; flex-wrap:wrap; gap:var(--s2) var(--s6); }
.summary b { font-variant-numeric:tabular-nums; }
a.sum { color:var(--fg); text-decoration:none; border-bottom:2px solid transparent; }
a.sum:hover { border-bottom-color:var(--line); }
a.sum.on { border-bottom-color:currentColor; font-weight:600; }
.bar { display:flex; flex-wrap:wrap; gap:var(--s2) var(--s4); align-items:center;
  justify-content:space-between; }
.bar > :last-child { margin-left:auto; }
.lead { display:flex; flex-wrap:wrap; gap:var(--s2) var(--s3); align-items:center; }
.lead form { margin:0; }
details.legend-d summary { color:var(--muted); }
details.legend-d .legend { margin-top:var(--s2); }
button.link { border:0; background:none; padding:0; color:var(--brand); font-weight:400;
  text-decoration:underline; line-height:inherit; }
button.link:hover { background:none; color:var(--fg); }
.foot { font-size:var(--t-xs); color:var(--muted); }
.tablebox { padding:var(--s1) var(--s2); overflow-x:auto; }
table.apps td { vertical-align:middle; }
table.apps td.actcell { width:1%; white-space:nowrap; overflow-wrap:normal; }
table.apps td.actcell .act { flex-wrap:nowrap; }
.again { display:flex; flex-wrap:wrap; gap:var(--s2) var(--s3); align-items:center; }
.again form { margin:0; }
.status { display:flex; flex-direction:column; gap:var(--s1); }
.status .row { display:flex; flex-wrap:wrap; gap:var(--s1) var(--s2); align-items:baseline; }
.filters { display:flex; flex-wrap:wrap; gap:var(--s1); }
.pill { font-size:var(--t-xs); line-height:16px; padding:var(--s1) var(--s3);
  border-radius:var(--r2); border:1px solid var(--line); background:var(--card);
  color:var(--fg); white-space:nowrap; text-decoration:none; }
.pill.on { background:var(--fg); color:var(--card); border-color:var(--fg); }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(236px,1fr)); gap:var(--s3); }
.app { position:relative; background:var(--card); border:1px dashed var(--grey);
  border-radius:var(--r4); padding:var(--s3) var(--s4); display:flex; flex-direction:column;
  gap:var(--s2); min-width:0; }
.app:hover, .app:focus-within { box-shadow:0 0 0 3px var(--soft); }
/* an outline only where it changes a decision: not on "no concerns found" */
.app.green { border:1px solid var(--line); }
.app.yellow { border:1px solid var(--yellow-edge); box-shadow:inset 0 0 0 1px var(--yellow-edge); }
.app.orange { border:1px solid var(--orange-edge); box-shadow:inset 0 0 0 1px var(--orange-edge); }
.app.red { border:1px solid var(--red-edge); box-shadow:inset 0 0 0 1px var(--red-edge); }
.app.yellow:hover, .app.orange:hover, .app.red:hover { box-shadow:inset 0 0 0 1px currentColor,
  0 0 0 3px var(--soft); }
.app-top { display:flex; gap:var(--s2); align-items:flex-start; justify-content:space-between; }
.app-name { font-weight:600; font-size:var(--t-md); line-height:1.25; color:var(--fg);
  text-decoration:none; overflow-wrap:anywhere; }
a.app-name::after { content:""; position:absolute; inset:0; border-radius:var(--r4); }
.app-kind { font-size:var(--t-xs); color:var(--muted); overflow-wrap:anywhere; }
.badge { flex:none; display:inline-block; white-space:nowrap; overflow-wrap:normal;
  min-width:44px; text-align:center; border-radius:var(--r3); padding:var(--s1) var(--s2);
  font-weight:700; font-size:var(--t-lg); font-variant-numeric:tabular-nums; line-height:1.1;
  background:var(--soft); color:var(--fg); text-decoration:none; }
.badge small { display:block; font-size:var(--t-xs); font-weight:600; letter-spacing:0.03em;
  text-transform:uppercase; color:var(--muted); }
.badge.grey { color:var(--muted); }
.say { line-height:1.45; }
.chips { display:flex; flex-wrap:wrap; gap:var(--s1); margin-top:auto; }
.chip { font-size:var(--t-xs); line-height:16px; padding:var(--s1) var(--s2);
  border-radius:var(--r1); background:var(--soft); color:var(--fg); white-space:nowrap; }
.chip.priv { background:var(--priv-bg); color:var(--priv); }
.chip.warn { background:var(--yellow-bg); color:var(--yellow); }
.chip.bad { background:var(--red-bg); color:var(--red); }
.act { position:relative; z-index:1; display:flex; gap:var(--s2); align-items:center; }
.act form { margin:0; }
button { font:500 var(--t-sm)/20px var(--font); padding:var(--s1) var(--s3);
  border-radius:var(--r2); border:1px solid var(--line); background:var(--card);
  color:var(--fg); cursor:pointer; }
button:hover { background:var(--soft); }
button.primary { background:var(--brand); color:var(--brand-fg); border-color:var(--brand); }
button.primary:hover { filter:brightness(1.08); }
a.button { display:inline-block; font:500 var(--t-sm)/20px var(--font);
  padding:var(--s2) var(--s4); border-radius:var(--r2); background:var(--brand);
  color:var(--brand-fg); text-decoration:none; }
a.button:hover { filter:brightness(1.08); }
.legend { display:flex; flex-wrap:wrap; gap:var(--s2) var(--s4); font-size:var(--t-xs);
  color:var(--muted); }
.sw { display:inline-block; width:12px; height:12px; border-radius:var(--r1);
  border:1px solid; vertical-align:-1px; margin-right:var(--s1); }
.banner { border-radius:var(--r3); padding:var(--s2) var(--s3); border:1px solid var(--line); }
.banner.warn { background:var(--yellow-bg); color:var(--fg); border-color:var(--yellow); }
.banner.bad { background:var(--red-bg); border-color:var(--red); }
.crumb { font-size:var(--t-xs); }
.dhead { display:grid; grid-template-columns:auto 1fr; gap:var(--s2) var(--s4);
  align-items:center; }
/* (preview) the proposed Threat and Exposure readings beside Barkley's score */
.rd { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1fr); gap:var(--s2); }
.rdial { display:grid; grid-template-columns:auto minmax(0,1fr); gap:var(--s2); align-items:center;
  padding:var(--s2); border-radius:var(--r3); background:var(--soft); min-width:0; }
.rdial svg { width:72px; height:72px; }
/* the ring's 48-unit box is drawn at 72 px, so 13 here shows at about 20 px */
.rdial text { font:700 var(--t-sm) var(--font); font-variant-numeric:tabular-nums; }
.rdial .k { display:block; font-size:var(--t-sm); font-weight:600; letter-spacing:0.06em;
  text-transform:uppercase; color:var(--muted); }
.rdial .w { display:block; font-weight:600; font-size:var(--t-lg); line-height:1.25; }
@media (max-width:480px) { .rd { grid-template-columns:minmax(0,1fr); } }
.dhead.rdhead { grid-template-columns:minmax(0,1fr); }
.rdhead .rd { margin-top:var(--s3); }
/* the list's compact form: two short lines, a small ring and "Threat · None found" */
.rdc { display:grid; gap:var(--s1); margin-top:var(--s2); }
.rdi { display:flex; align-items:center; gap:var(--s2); font-size:var(--t-sm); min-width:0; }
.rdi svg { width:36px; height:36px; flex:none; }
.rdi text { font:700 var(--t-xs) var(--font); font-variant-numeric:tabular-nums; }
.rdi .k { color:var(--muted); font-weight:600; }
.rdi .w { font-weight:600; }
.rd-green { color:var(--green); } .rd-yellow { color:var(--yellow); }
.rd-orange { color:var(--orange); } .rd-red { color:var(--red); }
.rdwhy { margin:0 0 var(--s2); padding-left:var(--s4); display:flex;
  flex-direction:column; gap:var(--s1); }
.finding.ctx { grid-template-columns:minmax(0,1fr); }
/* (preview) where a sentence comes from: Barkley's scan, the developer's words, the AI */
.src { display:inline-block; font-size:var(--t-xs); font-weight:600; line-height:1.5;
  padding:0 var(--s2); border-radius:var(--r1); white-space:nowrap; vertical-align:middle;
  letter-spacing:0; text-transform:none; }
.src.scan { background:var(--brand-bg); color:var(--brand); }
.src.dev { background:var(--soft); color:var(--fg); border:1px solid var(--line);
  white-space:normal; overflow-wrap:anywhere; }
.src.ai { background:var(--ai-bg); color:var(--ai); }
.devq { border-left:1px solid var(--line); padding:var(--s1) 0 var(--s1) var(--s3);
  margin:var(--s2) 0 0; display:flex; flex-direction:column; gap:var(--s1); max-width:72ch; }
.devq .cite { font-size:var(--t-xs); color:var(--muted); }
.banner.threat { background:var(--red-bg); border:1px solid var(--red-edge); padding:var(--s3) var(--s4); }
.banner.threat b { display:block; color:var(--red); font-size:var(--t-lg); line-height:1.25; }
.verdict { font-weight:600; }
.inshort { font-size:var(--t-md); line-height:1.55; max-width:72ch; }
.two { display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:var(--s4);
  align-items:start; }
.finding { border-top:1px solid var(--line); padding:var(--s3) 0 var(--s1); display:grid;
  grid-template-columns:6.5em 1fr; gap:var(--s1) var(--s4); }
.finding:first-of-type { border-top:0; padding-top:var(--s1); }
.lvl { font-size:var(--t-xs); font-weight:600; text-transform:uppercase; letter-spacing:0.05em;
  padding:var(--s1) 0; color:var(--muted); }
.lvl.critical { color:var(--red); } .lvl.high { color:var(--orange); }
.lvl.medium { color:var(--yellow); } .lvl.p { color:var(--priv); }
.finding h3 { font-size:var(--t-md); }
.finding dl { margin:var(--s2) 0 0; display:grid; grid-template-columns:9.5em 1fr;
  gap:var(--s1) var(--s3); }
.finding dt { color:var(--muted); } .finding dd { margin:0; min-width:0; }
.finding.quiet { color:var(--muted); padding:var(--s2) 0 0; }
.finding.quiet details { margin-top:0; }
.facts { display:flex; flex-wrap:wrap; align-items:center; gap:var(--s1) var(--s4);
  font-size:var(--t-md); margin:var(--s2) 0 var(--s1); }
.facts > * { display:inline-flex; align-items:center; gap:var(--s1); min-width:0;
  overflow-wrap:anywhere; }
.kindh { margin:var(--s4) 0 0; }
.kindh:first-of-type { margin-top:var(--s2); }
.kindh + .sub { margin-bottom:0; }
.rev { display:flex; flex-wrap:wrap; gap:var(--s2); align-items:center; margin-top:var(--s2); }
.rev form { margin:0; display:flex; flex-wrap:wrap; gap:var(--s2); align-items:center; }
.setrow select, .setrow input {
  font:inherit; padding:var(--s1) var(--s2); border-radius:var(--r2);
  border:1px solid var(--line); background:var(--card); color:var(--fg); max-width:100%; }
.rev a, .rev .muted { font-size:var(--t-xs); }

.aplus { display:flex; align-items:center; gap:var(--s2); font-weight:600;
  margin:0 0 var(--s2); }
.aplus .i { color:var(--yellow-edge); fill:currentColor; }
.setrow { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1.2fr);
  gap:var(--s2) var(--s4); padding:var(--s3) 0; border-top:1px solid var(--line); }
.setrow:first-of-type { border-top:0; }
.setrow:target { background:var(--soft); box-shadow:0 0 0 var(--s2) var(--soft); border-radius:var(--r1); }
.setrow > div { min-width:0; overflow-wrap:anywhere; }
.setrow .ctl { display:flex; flex-wrap:wrap; gap:var(--s2); align-items:center; }
.setrow p.muted { margin-top:var(--s1); }
.setrow details.more { margin-top:var(--s1); }
.setrow details.more p { margin-top:var(--s1); max-width:60ch; color:var(--fg); }
.setform { margin:0; }
.diffcode { font:var(--t-xs)/1.5 var(--mono); white-space:pre-wrap; overflow-wrap:anywhere;
  background:var(--soft); border-radius:var(--r3); padding:var(--s2) var(--s3); margin:0; }
.diffcode .add { color:var(--green); } .diffcode .del { color:var(--red); }
@media (max-width:640px) { .setrow { grid-template-columns:1fr; } }
.aib { display:inline-block; font-size:var(--t-xs); line-height:16px; font-weight:600;
  letter-spacing:0.04em; color:var(--card); background:var(--ai); border-radius:var(--r1);
  padding:0 var(--s1); margin-right:var(--s1); vertical-align:1px; }
.ai dt { color:var(--ai); font-weight:600; } .ai dd { border-left:2px solid var(--ai);
  padding-left:var(--s2); }
.aibox { border-left:2px solid var(--ai); background:var(--ai-bg);
  border-radius:0 var(--r3) var(--r3) 0; padding:var(--s2) var(--s3); margin-top:var(--s2); }
button.ai, .deepi button, .sheet button { color:var(--ai); border-color:var(--ai); background:var(--ai-bg);
  font-weight:500; }
.deepi { margin-top:var(--s2); display:flex; flex-wrap:wrap; gap:var(--s1) var(--s2);
  align-items:center; }
.deepi form { margin:0; }
a.aichip { display:inline-block; font-size:var(--t-xs); line-height:16px; font-weight:500;
  color:var(--ai); background:var(--ai-bg); border:1px solid var(--ai);
  border-radius:var(--r2); padding:var(--s1) var(--s2); text-decoration:none; }
a.aichip.warn { color:var(--orange); border-color:var(--orange); }
div.modal { display:none !important; position:fixed; inset:0; z-index:50; overflow:auto;
  padding:var(--s6) var(--s3); }
div.modal:target { display:block !important; }
.modal .shade { position:fixed; inset:0; background:rgba(0,0,0,0.55); }
.modal .sheet { position:relative; max-width:880px; margin:0 auto; background:var(--card);
  color:var(--fg); border:1px solid var(--line); border-top:3px solid var(--ai);
  border-radius:var(--r4); padding:var(--s4) var(--s6) var(--s6); }
.sheet .sh { display:flex; align-items:center; gap:var(--s1); color:var(--ai); }
.sheet .sh .x { margin-left:auto; font-size:var(--t-xs); }
.sheet .st { color:var(--muted); font-size:var(--t-xs); margin:0 0 var(--s2); }
.modal .sheet h3 { margin:var(--s4) 0 var(--s1); }
.modal .sheet ul { list-style:disc; margin:0 0 var(--s2); padding-left:var(--s4);
  display:flex; flex-direction:column; gap:var(--s1); }
.modal .sheet li { display:list-item; }
.sheet .cite { font-size:var(--t-xs); color:var(--muted); white-space:nowrap; }
.sheet form { margin-top:var(--s3); }
pre.code { margin:var(--s1) 0 0; padding:var(--s2) var(--s3); background:var(--soft);
  border-radius:var(--r2); font:var(--t-xs)/1.5 var(--mono); white-space:pre-wrap;
  overflow-wrap:anywhere; max-height:420px; overflow:auto; }
pre.code .nc { color:var(--muted); } pre.code .fn { color:var(--brand); font-weight:600; }
pre.code .add { color:var(--green); } pre.code .del { color:var(--red); }
.sheet .opinion { border-left:3px solid var(--ai); padding-left:var(--s3); }
.tech { font-size:var(--t-xs); color:var(--muted); margin-top:var(--s2);
  overflow-wrap:anywhere; }
details summary { cursor:pointer; color:var(--muted); font-size:var(--t-xs); }
.ev { display:block; white-space:pre-wrap; background:var(--soft); padding:var(--s2);
  border-radius:var(--r2); margin-top:var(--s1); }
@media (max-width:560px) { .finding { grid-template-columns:1fr; }
  .finding dl { grid-template-columns:1fr; } .finding dt { margin-top:var(--s1); } }
.zones { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:var(--s3); }
.zone { border-radius:var(--r3); padding:var(--s3); border:1px solid var(--line); min-width:0; }
.zone h3 { margin:0; }
.zone .zs { font-size:var(--t-xs); color:var(--muted); margin-bottom:var(--s2); }
:is(.zone, .libs) ul { list-style:none; margin:0; padding:0; display:flex;
  flex-direction:column; gap:var(--s2); }
:is(.zone, .libs) .u { font-size:var(--t-xs); color:var(--muted); display:block;
  overflow-wrap:anywhere; }
:is(.zone, .libs) details.site > summary { color:var(--fg); font-size:var(--t-sm);
  overflow-wrap:anywhere; }
:is(.zone, .libs) details.site > summary code { word-break:break-all; }
:is(.zone, .libs) details.site .in { padding:var(--s1) 0 0 var(--s4); display:flex;
  flex-direction:column; gap:var(--s1); min-width:0; }
:is(.zone, .libs) details.more > summary { margin-top:var(--s1); }
:is(.zone, .libs) details.more > .in { padding:var(--s1) 0 0 var(--s4); display:flex;
  flex-direction:column; gap:var(--s1); }
.pkchk { display:flex; flex-wrap:wrap; gap:var(--s1) var(--s4); align-items:center;
  margin-bottom:var(--s2); }
.pk { display:inline-flex; align-items:center; gap:var(--s1); }
.pk.ok svg { color:var(--green); } .pk.bad { color:var(--red); }
.pk.bug { color:var(--orange); } li > .pk { margin-left:var(--s2); font-weight:600; }
.req { border-left:1px solid var(--line); padding-left:var(--s2); font-size:var(--t-sm);
  display:flex; flex-direction:column; }
:is(.zone, .libs) details.more > ul { margin-top:var(--s2); }
.zone.home { background:var(--soft); }
.zone.dev, .zone.ana { border-color:var(--priv); }
.lock { font-size:var(--t-xs); white-space:nowrap; } .lock.ok { color:var(--green); }
.lock.no { color:var(--orange); }
.flowwrap { overflow-x:auto; }
.flow-h svg { display:block; max-width:700px; margin:0 auto; }
.flow text { fill:var(--fg); font:var(--t-xs) var(--font); }
.flow .sm { fill:var(--muted); }
.flow .nm { font-weight:600; }
.flow-v { display:none; }
@media (max-width:560px) { .flow-h { display:none; } .flow-v { display:block; } }
.privbox { border:1px solid var(--priv); background:var(--priv-bg); border-radius:var(--r4);
  padding:var(--s3) var(--s4); }
.privbox h2 { color:var(--priv); }
.noteai { margin-top:var(--s2); }
.noteai p { margin:0; }
ul.plain { margin:0; padding-left:var(--s4); display:flex; flex-direction:column;
  gap:var(--s1); }
ul.marks { list-style:none; padding-left:0; }
table { border-collapse:collapse; width:100%; }
td, th { text-align:left; padding:var(--s2); border-bottom:1px solid var(--line);
  vertical-align:top; }
th { font-weight:600; }
td.wrap { overflow-wrap:anywhere; } td.nowrap { white-space:nowrap; }
td.actcol { width:1%; white-space:nowrap; text-align:right; vertical-align:top; }
.tablebox table { min-width:0; }
.tools form { display:flex; gap:var(--s2); flex-wrap:wrap; margin:var(--s2) 0; }
input, select { padding:var(--s1) var(--s2); min-width:0; font:inherit; line-height:20px;
  background:var(--card); color:var(--fg); border:1px solid var(--line);
  border-radius:var(--r2); }
.tools input, .tools select { flex:1 1 180px; }
.tools select { flex:0 1 auto; }
form.search { display:flex; gap:var(--s2); flex-wrap:wrap; margin:0; }
/* motion (CSS only): the sheet grows from its top edge, details fade in, hover rings and
   buttons ease, a dot pulses while a scan runs, and a busy card wears a moving bar. Close
   is instant: it gets out of the way. */
@keyframes sheet-in { from { opacity:0; transform:translateY(-8px) scaleY(0.97); }
  to { opacity:1; transform:none; } }
@keyframes fade-in { from { opacity:0; } to { opacity:1; } }
@keyframes pulse { 0%, 100% { opacity:0.3; } 50% { opacity:1; } }
@keyframes slide { from { transform:translateX(-100%); } to { transform:translateX(100%); } }
div.modal:target .sheet { transform-origin:top center;
  animation:sheet-in var(--dur-in) ease-out; }
div.modal:target .shade { animation:fade-in var(--dur-in) ease-out; }
details[open] > :not(summary) { animation:fade-in var(--dur-in) ease-out; }
.app, button, .pill, a.sum { transition:box-shadow var(--dur-in) ease-out,
  border-color var(--dur-in) ease-out, background-color var(--dur-out) ease-out,
  filter var(--dur-out) ease-out; }
.dot { display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--brand);
  margin-right:var(--s2); vertical-align:0; animation:pulse 1.4s ease-in-out infinite; }
.app.busy { overflow:hidden; }
.app.busy::after { content:""; position:absolute; left:0; right:0; bottom:0; height:2px;
  background:linear-gradient(90deg, transparent, var(--brand), transparent);
  animation:slide 1.6s linear infinite; }
tr.busy .badge { background:linear-gradient(90deg, var(--soft) 30%, var(--line) 50%,
  var(--soft) 70%); background-size:300% 100%; animation:shimmer 1.6s linear infinite; }
@keyframes shimmer { from { background-position:100% 0; } to { background-position:-100% 0; } }
@media (prefers-reduced-motion: reduce) { *, ::before, ::after { animation:none !important;
  transition:none !important; } }
.sev-critical { color:var(--red); font-weight:600; } .sev-high { color:var(--orange);
  font-weight:600; }
.sev-medium { color:var(--yellow); } .ok { color:var(--green); } .bad { color:var(--red); }
"""


def page(title: str, body: str, refresh: int = 0, base: str = "", refresh_url: str = "") -> bytes:
    """`refresh`: reload after N seconds (a meta tag, not a script: the CSP allows it).
    `refresh_url`: where to (escaped); needed when the page's URL carries a fragment, since
    a refresh to the very same URL with a fragment never reloads (Chromium treats it as a
    same-document navigation: the AI sheet stayed "reading" until a hard reload).
    `base`: the ingress path prefix, so the panel's own font files resolve from any page."""
    meta = ""
    if refresh:
        to = f"; url={refresh_url}" if refresh_url else ""
        meta = f'<meta http-equiv="refresh" content="{int(refresh)}{to}">'
    fonts = (
        f'<link rel="preload" href="{base}/fonts/Geist-Variable.woff2" as="font" '
        'type="font/woff2" crossorigin>'
    )
    return (
        f"<!doctype html><html lang=en><head><meta charset=utf-8>{meta}"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{e(title)}</title>{fonts}<style>{CSS.replace('__BASE__', base)}</style>"
        f"</head><body><main>{body}</main></body></html>"
    ).encode()


KIND = {"integration": "Integration", "plugin": "Dashboard card", "card": "Dashboard card"}
_SOURCE = {
    "release_asset": "the exact release zip the Marketplace installs",
    "tag_source": "the tagged source the Marketplace installs",
    "default_branch": "the default branch, pinned to one commit",
    "local": "a local folder",
}


# --- what a report says, in usable shapes ------------------------------------------------------

INTERNET_SKIP = {"local", "namespace", "link", "resolver"}  # not "sites it talks to"


@dataclass
class Host:
    name: str  # untrusted
    cls: str
    schemes: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)  # untrusted
    ports: list[int] = field(default_factory=list)
    where: list[str] = field(default_factory=list)  # untrusted
    flagged: bool = False  # a finding is attached to the edge
    edge_id: str = ""
    service: str = ""  # who runs it, from the shipped list of well-known services (0.8.0)
    redirect: bool = False  # (0.15) only an OAuth return address (endpoints.redirect_only)
    readme_line: int | None = None  # (0.15) the README names it (the developer's words)
    funding: bool = False  # (0.15) .github/FUNDING.yml lists it


@dataclass
class Port:
    port: int
    names: list[str]  # untrusted
    where: list[str]
    directions: list[str] = field(default_factory=list)  # "out" / "in" (0.5.1+)
    edge_id: str = ""

    @property
    def direction(self) -> str | None:
        """One clear direction, else None (unknown, mixed, or a pre-0.5.1 scan)."""
        return self.directions[0] if len(set(self.directions)) == 1 else None


def _loc(s: dict[str, Any]) -> str:
    return f"{s['file']}:{s['line']}" if s.get("line") else str(s.get("file"))


def _graph(report: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    g = report.get("graph") or {}
    return g, {n["id"]: n for n in g.get("nodes", [])}


def hosts(report: dict[str, Any]) -> list[Host]:
    g, nodes = _graph(report)
    out = []
    for edge in g.get("edges", []):
        if edge["relation"] != "connects_to" or edge["source"] != g.get("subject"):
            continue
        n = nodes.get(edge["target"], {})
        a = edge.get("attrs", {})
        out.append(
            Host(
                n.get("label", edge["target"]),
                str(a.get("class", "undeclared")),
                list(a.get("schemes", [])),
                list(a.get("urls", [])),
                list(a.get("ports", [])),
                [_loc(s) for s in edge.get("samples", [])],
                bool(edge.get("finding_ids")),
                str(edge.get("id", "")),
                str(a.get("service", "")),
                bool(a.get("redirect_only")),
                a.get("readme_line") if isinstance(a.get("readme_line"), int) else None,
                bool(a.get("funding")),
            )
        )
    return sorted(out, key=lambda h: h.name)


def ports(report: dict[str, Any]) -> list[Port]:
    g, _ = _graph(report)
    out = []
    for edge in g.get("edges", []):
        if edge["relation"] == "uses_port":
            out.append(
                Port(
                    int(edge["target"].split(":", 1)[1]),
                    list(edge.get("attrs", {}).get("names", [])),
                    [_loc(s) for s in edge.get("samples", [])],
                    list(edge.get("attrs", {}).get("directions", [])),
                    str(edge.get("id", "")),
                )
            )
    return sorted(out, key=lambda p: p.port)


def internet(hs: list[Host]) -> list[Host]:
    return [h for h in hs if h.cls not in INTERNET_SKIP]


def reads(report: dict[str, Any]) -> list[tuple[str, str, bool]]:
    """(node id, label, sensitive) of the user's data the item reads."""
    g, nodes = _graph(report)
    sensitive = {f"{k}:{v}" for k, v in SENSITIVE_NODES.values()}
    out = []
    for edge in g.get("edges", []):
        if edge["relation"] == "reads" and edge["source"] == g.get("subject"):
            n = nodes.get(edge["target"], {})
            if n.get("kind") in ("data", "auth"):
                out.append((edge["target"], n.get("label", ""), edge["target"] in sensitive))
    return sorted(out, key=lambda r: (not r[2], r[1]))


def flows(report: dict[str, Any]) -> list[dict[str, Any]]:
    g, _ = _graph(report)
    return [x for x in g.get("edges", []) if x["relation"] == "flows_to"]


def scored_findings(report: dict[str, Any]) -> list[tuple[dict[str, Any], list[dict], int]]:
    """Findings grouped by rule (most severe first): (first finding, all, points)."""
    points: Counter[str] = Counter()
    for d in report.get("score_breakdown", []):
        points[d["rule_id"]] += int(d["points"])
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in report.get("findings", []):
        groups[f["rule_id"]].append(f)
    order = ["critical", "high", "medium", "low", "info"]
    out = [(fs[0], fs, points.get(rule, 0)) for rule, fs in groups.items()]
    return sorted(out, key=lambda t: (order.index(t[0]["severity"]), -t[2], t[0]["rule_id"]))


# --- the card grid -------------------------------------------------------------------------------


@dataclass
class Card:
    repo: str
    name: str
    kind: str  # integration | card | plugin
    installed: str
    available: str | None  # set when an update is offered
    scan: ScanRow | None  # scan of the installed version (current tool version)
    report: dict[str, Any] | None
    group: str = "current"  # classify(): attention | unchecked | checked | current
    reasons: list[str] = field(default_factory=list)
    busy: str = ""
    diff_link: str = ""  # "old=..&new=.." when an update check exists
    action: str = ""  # rendered form/button HTML (built by the server)
    stale: bool = False  # sniffed with earlier rules (an app that isn't installed)

    @property
    def readings(self) -> dict[str, Any] | None:
        """(0.15) Threat and Exposure: from the shown report, else the index row's."""
        rd = (self.report or {}).get("readings")
        return rd or (self.scan.readings if self.scan else None)

    @property
    def band(self) -> str:
        """The outline follows the readings; grey for an app Barkley hasn't checked."""
        rd = self.readings
        return readings_band(rd) if rd and self.scan else "grey"

    def notes(self) -> list[privacy.Note]:
        return privacy.notes(self.report) if self.report else []

    @property
    def worth_a_look(self) -> bool:
        return self.band in ("yellow", "orange", "red") or self.group == "attention"


def card_sentence(c: Card) -> str:
    if c.scan is None:
        return f"Barkley {__version__} hasn't checked this yet."
    if not c.scan.complete:
        return (
            "The last check didn't finish, so Barkley can't say whether it's safe yet. "
            "Sniff it again."
        )
    rep = c.report or {}
    big = [t for t in scored_findings(rep) if t[0]["severity"] in ("critical", "high", "medium")]
    # (0.15) a sign of malicious behavior leads; only Threat is scored now
    big.sort(key=lambda t: not kinds.is_threat(str(t[0]["rule_id"])))
    if big:
        first = explain.explain(big[0][0]["rule_id"]).title + "."
        if len(big) > 1 and rep.get("readings"):  # (preview) plain words
            first += f" There {'is' if len(big) == 2 else 'are'} {len(big) - 1} more."
        elif len(big) > 1:
            first += f" Barkley found {len(big) - 1} more thing{'s' * (len(big) > 2)} to check."
    else:
        first = "Barkley found no security concerns."
    notes = c.notes()
    if notes:
        second = notes[0].title + "."
        if len(notes) > 1:
            second = (
                second[:-1] + f", plus {len(notes) - 1} more privacy note{'s' * (len(notes) > 2)}."
            )
    else:
        second = connection_sentence(rep)
    return f"{first} {second}"


def port_phrase(pts: list[Port]) -> str:
    """'port 6668 (Tuya local)' / 'ports 502 (Modbus) and 8000'."""
    named = []
    for p in pts[:3]:
        known = WELL_KNOWN_PORTS.get(p.port)
        named.append(f"{p.port} ({known[0]})" if known else str(p.port))
    s = ("port " if len(pts) == 1 else "ports ") + explain._join(named)
    return s + (f" and {len(pts) - 3} more" if len(pts) > 3 else "")


def ports_sentence(pts: list[Port]) -> str:
    """'Connects to port 6668 (Tuya local)' / 'Listens on port 8080' / mixed or unknown."""
    if not pts:
        return ""
    dirs = {p.direction for p in pts}
    if dirs == {"out"}:
        return (f"It connects out to {port_phrase(pts)} on another machine. That machine's "
                "address isn't in the code: it comes from the app's settings or from another "
                "server.")  # fmt: skip
    if dirs == {"in"}:
        return f"It listens on {port_phrase(pts)}."
    return f"Its code mentions {port_phrase(pts)}."


def connection_sentence(rep: dict[str, Any]) -> str:
    hs = hosts(rep)
    net = internet(hs)
    home = [h for h in hs if h.cls == "local"]
    pts = ports(rep)
    if net:
        s = f"Its code mentions {len(net)} internet site{'s' * (len(net) != 1)}"
        s += " and addresses on your own network." if home else "."
    elif home:
        s = "Its code mentions no internet sites, only addresses on your own network."
    else:
        s = "Its code mentions no internet sites."
    if pts:
        s += " " + ports_sentence(pts)
    return s


def card_chips(c: Card) -> list[tuple[str, str]]:
    """Each chip is there because it can change a decision; the sentence above already
    says where the app connects, so no chip repeats that."""
    chips: list[tuple[str, str]] = []
    if c.stale:
        chips.append(("", "Sniffed with earlier rules"))
    if c.report and (gone := quiet(c.report)[0]):
        chips.append(("", gone))
    # colour means a threat: a threat is red, the rest are neutral (his note 2026-11-20).
    # Privacy notes keep their own colour (a kind).
    if c.available:  # an update whose diff has headline changes: say so, in neutral grey
        attention = c.group == "attention" and c.reasons
        chips.append(("", f"Update {c.available}" + (": check it first" if attention else "")))
    if c.report and c.scan and c.scan.complete:
        for f, _fs, _p in scored_findings(c.report):
            if f["severity"] in ("critical", "high", "medium") and len(chips) < 4:
                cls = "bad" if kinds.is_threat(str(f["rule_id"])) else ""
                chip = explain.explain(f["rule_id"]).chip
                if (cls, chip) not in chips:
                    chips.append((cls, chip))
        for n in c.notes():
            chips.append(("priv", n.label))
    return chips


def card_html(base: str, c: Card) -> str:
    b = c.band
    href = f"{base}/scan/{c.scan.id}" if c.scan else ""
    name = (
        f'<a class="app-name" href="{href}">{e(c.name, 80)}</a>'
        if href
        else f'<span class="app-name">{e(c.name, 80)}</span>'
    )
    chips = "".join(f'<span class="chip {cls}">{e(t, 60)}</span>' for cls, t in card_chips(c))
    act = f'<span class="muted">{_busy_text(c)}</span>' if c.busy else c.action
    links = ""
    if c.diff_link:
        links = f'<a href="{base}/diff?{c.diff_link}">what the update changes</a>'
    actions = f'<div class="act">{act}{links}</div>' if (act or links) else ""
    top = f"</div>{_readings_cell(c)}"
    return (
        f'<div class="app {b}{" busy" if c.busy else ""}"><div class="app-top"><div>{name}'
        f'<div class="app-kind">{e(KIND.get(c.kind, c.kind))} · {e(c.installed, 40)}</div></div>'
        f"{top}"
        f'<div class="say">{e(card_sentence(c), 400)}</div>'
        f'<div class="chips">{chips}</div>{actions}</div>'
    )


FILTERS = {
    "all": "All",
    "look": "Needs a look",
    "fine": "No concerns found",
    "privacy": "Privacy notes",
    "updates": "Updates",
    "unchecked": "Not checked",
}
VIEWS = ("cards", "table")
PER_PAGE = {"cards": 12, "table": 25}


@dataclass(frozen=True)
class View:
    """What the installed list shows: a filter, cards or a table, and a page. All in the URL."""

    f: str = "all"
    view: str = "cards"
    pg: int = 1
    pg2: int = 1  # the page of "Sniffed, not installed", under the installed list

    @classmethod
    def parse(cls, q: dict[str, list[str]], default_view: str = "cards") -> View:
        f = (q.get("f") or ["all"])[0]
        view = (q.get("view") or [default_view])[0]
        def num(key: str) -> int:
            try:
                return max(1, min(int((q.get(key) or ["1"])[0]), 10_000))
            except ValueError:
                return 1

        return cls(
            f if f in FILTERS else "all",
            view if view in VIEWS else "cards",
            num("page"),
            num("page2"),
        )

    def qs(self, sep: str = "&amp;", **kw: Any) -> str:
        """The query string for this view with some parts changed (only known values).
        `sep` is "&amp;" inside HTML, "&" in a Location header."""
        v = replace(self, **kw)
        parts = []
        if v.f != "all":
            parts.append(f"f={v.f}")
        parts.append(f"view={v.view}")
        if v.pg > 1:
            parts.append(f"page={v.pg}")
        if v.pg2 > 1:
            parts.append(f"page2={v.pg2}")
        return sep.join(parts)


def _keep(c: Card, f: str) -> bool:
    return {
        "all": True,
        "look": c.worth_a_look,
        "fine": c.band == "green" and not c.worth_a_look,
        "privacy": bool(c.notes()),
        "updates": bool(c.available),
        "unchecked": c.band == "grey",
    }.get(f, True)


def _sort_key(c: Card) -> tuple[Any, ...]:
    """Not checked first, then what needs a look; within those the highest Threat, then
    the highest Exposure (0.15: the readings in place of the score)."""
    rd = c.readings or {}
    return (c.band != "grey", not c.worth_a_look, -float(rd.get("threat") or 0),
            -float(rd.get("exposure") or 0), c.name.lower())  # fmt: skip


def _readings_cell(c: Card) -> str:
    """The two readings in a card or table row; a grey "Not checked" before the first
    sniff, and "Unfinished" under them when the check didn't finish."""
    rd = c.readings
    if c.scan is None or not rd:
        return '<div class="badge grey">–<small>Not checked</small></div>'
    done = "" if c.scan.complete else '<span class="muted small">Unfinished</span>'
    return readings_compact(rd) + done


def _busy_text(c: Card) -> str:
    text = {"running": "checking…", "waiting": "waiting for GitHub…"}.get(c.busy, "queued…")
    return f'<span class="dot"></span>{text}'


def card_row(base: str, c: Card) -> str:
    """One app as a table row: the same facts as its card, in less space."""
    name = (
        f'<a href="{base}/scan/{c.scan.id}"><b>{e(c.name, 80)}</b></a>'
        if c.scan
        else f"<b>{e(c.name, 80)}</b>"
    )
    chips = "".join(f'<span class="chip {cls}">{e(t, 60)}</span>' for cls, t in card_chips(c))
    act = f'<span class="muted">{_busy_text(c)}</span>' if c.busy else c.action
    if c.diff_link:
        act += f' <a href="{base}/diff?{c.diff_link}">what the update changes</a>'
    act = f'<div class="act">{act}</div>' if act else ""
    return (
        f"<tr{' class=busy' if c.busy else ''}><td>{_readings_cell(c)}</td>"
        f'<td>{name}<div class="app-kind">{e(KIND.get(c.kind, c.kind))} · {e(c.installed, 40)}'
        f'</div><div class="small">{e(card_sentence(c), 400)}</div></td>'
        f'<td><div class="chips">{chips}</div></td>'
        f'<td class="actcell">{act}</td></tr>'
    )


def _pager(base: str, v: View, pages: int, key: str = "pg", anchor: str = "") -> str:
    """Page links. `key`: which of the view's two page numbers these links change."""
    if pages <= 1:
        return ""
    at = getattr(v, key)

    def href(n: int) -> str:
        return f"{base}/?{v.qs(**{key: n})}{anchor}"

    links = []
    if at > 1:
        links.append(f'<a class="pill" href="{href(at - 1)}">‹ Previous</a>')
    for n in range(1, pages + 1):
        on = " on" if n == at else ""
        links.append(f'<a class="pill{on}" href="{href(n)}">{n}</a>')
    if at < pages:
        links.append(f'<a class="pill" href="{href(at + 1)}">Next ›</a>')
    return f'<nav class="filters pager" aria-label="pages">{"".join(links)}</nav>'


def render_grid(base: str, cards: list[Card], v: View | None = None, lead: str = "") -> str:
    """`lead`: the list's one primary action (server-built form HTML), shown in the bar."""
    v = v or View()
    counts = {k: sum(_keep(c, k) for c in cards) for k in FILTERS}

    def item(k: str, text: str, color: str = "") -> str:
        style = f' style="color:var(--{color})"' if color else ""
        n = counts[k]
        inner = f"<b>{n}</b> {text}"
        if not n and k != "all":
            return f'<span class="muted">{inner}</span>'
        on = " on" if v.f == k else ""
        cur = ' aria-current="true"' if on else ""
        return f'<a class="sum{on}"{style}{cur} href="{base}/?{v.qs(f=k, pg=1)}">{inner}</a>'

    ups = counts["updates"]
    summary = [item("all", "apps installed from the Marketplace")]
    if counts["look"]:
        summary.append(item("look", "need a look" if counts["look"] != 1 else "needs a look",
                            "yellow"))  # fmt: skip
    summary.append(item("fine", "no concerns found", "green"))
    if counts["privacy"]:
        summary.append(item("privacy", "with privacy notes", "priv"))
    summary.append(item("updates", f"update{'s' * (ups != 1)} waiting"))
    if counts["unchecked"]:
        summary.append(item("unchecked", "not checked"))
    views = "".join(
        f'<a class="pill{" on" if v.view == k else ""}" href="{base}/?{v.qs(view=k, pg=1)}">'
        f"{label}</a>"
        for k, label in (("cards", f"{icon('grid')} Cards"), ("table", f"{icon('list')} Table"))
    )
    shown = sorted((c for c in cards if _keep(c, v.f)), key=_sort_key)
    per = PER_PAGE[v.view]
    pages = max(1, -(-len(shown) // per))
    v = replace(v, pg=min(v.pg, pages))
    window = shown[(v.pg - 1) * per : v.pg * per]
    showing = ""
    if v.f != "all":
        showing = (
            f'<span class="muted small">Showing {len(shown)}: {e(FILTERS[v.f].lower())} · '
            f'<a href="{base}/?{v.qs(f="all", pg=1)}">show all</a></span>'
        )
    elif pages > 1:
        showing = f'<span class="muted small">Page {v.pg} of {pages}</span>'
    if not window:
        body = '<p class="muted">Nothing here.</p>'
    elif v.view == "table":
        body = (
            '<div class="box tablebox"><table class="apps"><tr><th>Readings</th><th>App</th>'
            "<th>Notes</th><th></th></tr>"
            + "".join(card_row(base, c) for c in window)
            + "</table></div>"
        )
    else:
        body = '<div class="grid">' + "".join(card_html(base, c) for c in window) + "</div>"
    legend = (
        '<details class="legend-d"><summary>What the readings and colours mean</summary>'
        '<p class="small">Threat counts only signs of malicious behavior: none found, '
        "possible, or found. Exposure, from 0 to 10, counts what lets someone who isn't an "
        "administrator in: pages that skip Home Assistant's login, login tokens it may hand "
        "out, and published bugs in its libraries.</p>"
        '<div class="legend">'
        '<span><span class="sw" style="border-color:var(--red)"></span>a threat found</span>'
        '<span><span class="sw" style="border-color:var(--yellow)"></span>a possible threat'
        "</span>"
        '<span><span class="sw" style="border-color:var(--orange)"></span>high exposure</span>'
        '<span><span class="sw" style="border-color:var(--grey);border-style:dashed"></span>'
        "not checked</span>"
        '<span><span class="chip priv">purple</span> privacy note (never changes a reading)'
        "</span></div></details>"
    )
    left = f'<span class="lead">{lead}{showing}</span>' if (lead or showing) else ""
    return (
        f'<nav class="box summary" aria-label="filters">{"".join(summary)}</nav>'
        f'<div class="bar">{left}<span class="filters">{views}</span></div>'
        f"{body}{_pager(base, v, pages)}{legend}"
    )


# --- the detail page ---------------------------------------------------------------------------


def in_short(report: dict[str, Any]) -> str:
    """A deterministic summary built only from the report (escaped HTML), in plain words."""
    return _in_short_plain(report)


def _missing_html(a: dict[str, Any]) -> str:
    """One analyzer that didn't finish. (0.14.0) Files it couldn't fetch are said in plain
    English (fetch.retry.plain: which file, from where, tries, time, the error, what it
    means); the analyzer's own detail stays underneath as the technical line."""
    problems = [p for p in a.get("problems") or [] if isinstance(p, dict)][:5]
    state = str(a.get("state"))
    did = {"skipped": "was skipped", "error": "stopped with an error"}.get(state, f"was {state}")
    head = f"The <b>{e(a.get('name'))}</b> check {e(did)}"
    if not problems:
        return f"<li>{head}: {e(a.get('detail'), 300)}</li>"
    more = len(a.get("problems") or []) - len(problems)
    return (
        f"<li>{head}. It couldn't fetch {len(problems) + more} "
        f"file{'s' * (len(problems) + more != 1)}.<ul class=plain>"
        + "".join(f"<li>{e(retry.plain(p), 700)}</li>" for p in problems)
        + (f"<li>and {more} more</li>" if more > 0 else "")
        + f'</ul><span class="muted small">{e(a.get("detail"), 300)}</span></li>'
    )


def _lower1(s: str) -> str:
    return s[:1].lower() + s[1:]


def _where(fs: list[dict[str, Any]]) -> str:
    locs: list[str] = []
    for f in fs:
        if f.get("file"):
            loc = f"{f['file']}, line {f['line']}" if f.get("line") else str(f["file"])
            if loc not in locs:
                locs.append(loc)
    if not locs:
        return ""
    shown = ", ".join(f"<code>{e(x, 160)}</code>" for x in locs[:3])
    more = f" and {len(locs) - 3} more" if len(locs) > 3 else ""
    times = f" ({len(fs)} times)" if len(fs) > 1 and len(locs) == 1 else ""
    test = ""
    if all("test-code" in (f.get("tags") or []) for f in fs if f.get("file")):
        test = (
            '<br><span class="muted">This is test code. No part of the app that Home Assistant '
            "loads imports this file. Barkley still shows it, because code can hide anywhere.</span>"
        )
    return shown + more + times + test


def patch_html(patch: Any) -> str:
    """What a monkeypatch finding replaces and whose code that is (report.context
    .patch_fact: read from the app's imports during the scan, no AI). Names are the
    scanned code's, so escaped."""
    if not isinstance(patch, dict) or not patch.get("object"):
        return ""
    obj = str(patch["object"])
    what = f"<code>{e(obj.rsplit('.', 1)[-1], 100)}</code>"
    if patch.get("attr"):
        what = f"<code>{e(patch['attr'], 100)}</code> of {what}"
    text = f"{what}, which is part of {e(patch.get('origin'), 200)}"
    if "." in obj:
        text += f" (<code>{e(obj, 200)}</code>)"
    text += "."
    if patch.get("replacement"):
        text += f" The replacement is this app's <code>{e(patch['replacement'], 100)}</code>"
        at = patch.get("replacement_at")
        if isinstance(at, list) and len(at) == 2:
            text += f", defined at <code>{e(at[0], 200)}:{int(at[1])}</code>"
        text += "."
    return (
        f"<dt>What it replaces</dt><dd>It replaces {text} "
        '<span class="muted">Barkley read this from the code\'s imports. No AI was used.</span></dd>'
        + compare_html(patch)
    )


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def diff_html(cmp: dict[str, Any]) -> str:
    """Barkley's line-by-line comparison as escaped text: original line number, replacement
    line number, the line; removed lines red with "-", added lines green with "+"."""
    out = []
    for i, hunk in enumerate(cmp.get("hunks") or []):
        if i:
            out.append('<span class="nc">…</span>')
        for row in hunk:
            if not isinstance(row, list) or len(row) != 4:
                continue
            tag, old, new, text = row
            line = (f"{int(old) if old else '':>5} {int(new) if new else '':>5} "
                    f"{e(tag, 1)} {e(text, 400)}")  # fmt: skip
            cls = {"+": "add", "-": "del"}.get(tag)
            out.append(f'<span class="{cls}">{line}</span>' if cls else line)
    return '<pre class="code">' + "\n".join(out) + "</pre>"


def compare_html(patch: dict[str, Any]) -> str:
    """Under "What it replaces": Barkley's comparison of the replaced Home Assistant function
    with the replacement (report.compare; made during the scan, no AI), or why there is
    none; then what else of the scan sits on the replacement's lines. Says what was
    compared and checked, never that the code is safe."""
    from sniff_test.report import compare

    out = ""
    cmp = patch.get("compare")
    if isinstance(cmp, dict) and cmp.get("state") == "ok":
        a, b = (int(x) for x in cmp["original"])
        added, removed = int(cmp.get("added") or 0), int(cmp.get("removed") or 0)
        if added or removed:
            result = (f"{_plural(added, 'line')} {'is' if added == 1 else 'are'} only in the "
                      f"replacement, and {_plural(removed, 'line')} "
                      f"{'is' if removed == 1 else 'are'} only in the original")  # fmt: skip
        else:
            result = "The two are the same, line for line"
        cut = (
            " The comparison is long, so its last changes are left out here."
            if cmp.get("cut")
            else ""
        )
        out += (
            "<dt>How it differs from the original</dt><dd>Barkley compared the replacement "
            f"line by line with <code>{e(cmp.get('name'), 200)}</code> in Home Assistant "
            f"{e(cmp.get('ha_version'), 20)} (<code>{e(cmp.get('file'), 200)}</code>, lines "
            f"{a}–{b}). {result}."
            + (
                f"<details><summary>Show the comparison</summary>{diff_html(cmp)}"
                '<p class="tech">Left number: the line in Home Assistant\'s file. Right number: '
                "the line in the app's file. Red lines with − are only in the original, green "
                f"lines with + only in the replacement.{cut} A line that is only wrapped "
                "differently counts as removed and added.</p></details>"
                if added or removed
                else ""
            )
            + ' <span class="muted">Compared by Barkley, not by AI.</span></dd>'
        )
    elif isinstance(cmp, dict):
        why = compare.WHY.get(str(cmp.get("why")), "it couldn't be made")
        again = (" Sniff this version again to try once more."
                 if cmp.get("why") == "unreachable" else "")  # fmt: skip
        out += (
            "<dt>How it differs from the original</dt><dd>Barkley has no comparison with "
            f"Home Assistant's original, because {e(why, 200)}.{again}</dd>"
        )
    inside = patch.get("inside")
    if isinstance(inside, dict) and isinstance(inside.get("lines"), list):
        a, b = (int(x) for x in inside["lines"][:2])
        at = patch.get("replacement_at")
        where = f" of <code>{e(at[0], 200)}</code>" if isinstance(at, list) and at else ""
        rules = [str(r) for r in inside.get("findings") or []]
        n_f = len(rules) + int(inside.get("more_findings") or 0)
        n_a, n_p = int(inside.get("addresses") or 0), int(inside.get("ports") or 0)
        if not (n_f or n_a or n_p):
            found = ("Barkley's other checks found nothing there. Nothing else was flagged, "
                     "and there's no address or port from Barkley's list.")  # fmt: skip
        else:
            bits = []
            if n_f:
                titles = ", ".join(e(explain.explain(r).title, 120) for r in rules)
                bits.append(f"{n_f} other thing{'s' * (n_f != 1)} Barkley flagged ({titles})")
            if n_a:
                bits.append(_plural(n_a, "address") if n_a == 1 else f"{n_a} addresses")
            if n_p:
                bits.append(_plural(n_p, "port"))
            found = f"This scan also found these in those lines: {', '.join(bits)}."
        out += (
            f"<dt>The rest of the replacement</dt><dd>The replacement is lines {a}–{b}"
            f"{where}. {found} "
            '<span class="muted">That covers only what Barkley\'s rules look for. It '
            "doesn't mean the code is safe.</span></dd>"
        )
    return out


def finding_html(
    f: dict[str, Any],
    fs: list[dict[str, Any]],
    points: int,
    ai: str = "",
    deep: str = "",
    fact: str = "",
    means: str | None = None,
    controls: str = "",
    context: bool = False,
    note: str = "",
) -> str:
    """`means`: text for "What it means" in place of the rule's general one (a
    monkeypatch whose target the scan resolved: explain.patch_means). `controls`: the
    row under it (Report a false positive).
    (preview) `context`: shown as context, not scored: no severity, points or "Should you
    worry?". `note`: the developer's note (devnote_html), already escaped."""
    ex = explain.explain(f["rule_id"])
    where = _where(fs)
    tech = [e(f["rule_id"])] if context else [e(f["rule_id"]), e(f["severity"])]
    if points and not context:
        tech.append(f"−{points} points" + (" (repeats count less)" if len(fs) > 1 else ""))
    tech.append(e(f["title"], 200))
    evid = [x for x in fs if x.get("evidence")][:3]
    code = ""
    if evid:
        code = (
            "<details><summary>Technical details</summary>"
            + "".join(
                f'<p class="tech">{e(x.get("message"), 600)}</p>'
                f'<code class="ev">{e(x.get("evidence"), 300)}</code>'
                for x in evid
            )
            + "</details>"
        )
    ai_html = f"<dt>{AI_BADGE}explanation</dt><dd>{e(ai, 1200)}</dd>" if ai else ""
    deps = [x["dependency"] for x in fs if isinstance(x.get("dependency"), dict)][:6]
    dep_html = (
        "<dt>Fix and newer versions</dt><dd>"
        + "<br>".join(dependency_line(d) for d in deps)
        + "</dd><dt>The bug</dt><dd>"
        + "<br>".join(advisory_lines(d) for d in deps)
        + f"</dd><dt>What you can do</dt><dd>{e(_DEP_ACTION.get(deps[0].get('ecosystem'), ''))}</dd>"
        if deps
        else ""
    )
    lvl = ("" if context else
           f'<div class="lvl {e(f["severity"])}">{e(explain.level(f["severity"]))}</div>')  # fmt: skip
    worry = "" if context else f"<dt>Should you worry?</dt><dd>{e(ex.worry, 600)}</dd>"
    return (
        f'<div class="finding{" ctx" if context else ""}">{lvl}'
        f"<div><h3>{e(ex.title)}</h3><dl{' class=ai' if ai else ''}>"
        f"<dt>What it means</dt><dd>{e(means or ex.means, 800)}</dd>"
        f"{worry}"
        + (f"<dt>Where Barkley saw it</dt><dd>{where}</dd>" if where else "")
        + fact
        + _links_html(ex.links)
        + dep_html
        + ai_html
        + f"</dl>{note}{deep}"
        + f'<div class="tech">{" · ".join(tech)}</div>{code}{controls}</div></div>'
    )


def _links_html(links: tuple[tuple[str, str], ...]) -> str:
    """explain.Explanation.links: fixed https links, shown as "Read more"."""
    items = [
        f'<a href="{e(url, 300)}" target="_blank" rel="noopener noreferrer">{e(label, 120)}</a>'
        for label, url in links
        if url.startswith("https://")
    ]
    return f"<dt>Read more</dt><dd>{'<br>'.join(items)}</dd>" if items else ""


_DEP_ACTION = {
    "npm": "The library is built into the card's JavaScript, so you can't update it yourself. "
    "If the bug matters for how the card uses it, open an issue on the developer's "
    "repository and ask them to update, patch or replace it. Before you switch to a "
    "replacement library someone suggests online, check who publishes it.",
    "PyPI": "Home Assistant installs the version the integration asks for, so if you change it "
    "yourself, the change doesn't last. If the bug matters for how the integration uses it, "
    "open an issue on the developer's repository and ask them to update or replace it.",
}


def advisory_lines(d: dict[str, Any]) -> str:
    """Each advisory: its id (and CVE), what OSV says it is, and a link to the record."""
    out = []
    for a in [a for a in d.get("advisories") or [] if isinstance(a, dict)][:4]:
        vid = str(a.get("id", ""))
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,60}", vid):
            continue
        cves = [x for x in a.get("aliases") or [] if str(x).startswith("CVE-")][:2]
        label = e(vid) + (f" ({e(', '.join(cves), 60)})" if cves else "")
        link = (f'<a href="https://osv.dev/vulnerability/{vid}" target="_blank" '
                f'rel="noopener noreferrer">{label}</a>')  # fmt: skip
        summary = str(a.get("summary") or "") or str(a.get("details") or "")[:200]
        line = f"{link}: {e(summary, 300)}" if summary else link
        if cisa := ssvc_phrase(a.get("ssvc")):
            line += f' <span class="muted">({cisa})</span>'
        out.append(line)
    return "<br>".join(out)


_EXPLOITATION = {
    "active": "attackers are using it",
    "poc": "public code to exploit it exists",
    "none": "no known attacks",
}


def ssvc_phrase(v: Any) -> str:
    """(0.14.1) CISA's assessment of the CVE in plain words; only SSVC's own values."""
    if not isinstance(v, dict):
        return ""
    bits = []
    if v.get("kev") is True:
        bits.append("it's on CISA's Known Exploited Vulnerabilities list")
    if (x := _EXPLOITATION.get(str(v.get("exploitation")))) and not (
        v.get("kev") is True and x != _EXPLOITATION["active"]
    ):
        bits.append(x)
    if v.get("automatable") in ("yes", "no"):
        bits.append(
            "attacks can be automated"
            if v["automatable"] == "yes"
            else "attacks can't be automated"
        )
    if v.get("impact") in ("partial", "total"):
        bits.append(
            "it can give an attacker full control or all of its data"
            if v["impact"] == "total"
            else "it can give an attacker some control or some of its data"
        )
    if not bits:
        return ""
    said = (
        bits[0]
        if len(bits) == 1
        else ", ".join(bits[:-1]) + ("," * (len(bits) > 2)) + " and " + bits[-1]
    )
    return "CISA says: " + said


def dependency_line(d: dict[str, Any]) -> str:
    """One vulnerable package: is there a fix, is the app on the newest release, and does
    the app list it itself. Checked facts from OSV and the package registry."""
    name = f"<b>{e(d.get('package'), 120)} {e(d.get('version'), 60)}</b>"
    advisories = [a for a in d.get("advisories") or [] if isinstance(a, dict)]
    fixes = [(str(a.get("id", "")), a.get("fixed")) for a in advisories]
    parts = [e(fix_phrase(str(d.get("ecosystem", "")), fixes), 300)]
    latest, when = d.get("latest"), d.get("latest_date")
    on = f" ({e(when, 20)})" if when else ""
    if latest and latest == d.get("version"):
        parts.append(f"the newest release{on}")
    elif latest:
        n = d.get("behind")
        ahead = (
            f", {int(n)} release{'s' if n != 1 else ''} after this one"
            if isinstance(n, int) and n
            else ""
        )
        parts.append(f"newest is {e(latest, 60)}{on}{ahead}")
    elif d.get("lookup_error"):
        parts.append("Barkley couldn't look up the newest release")
    age = years_since(when) if latest else None
    if age is not None and age >= STALE_YEARS:
        stale = f"no release in over {age} years, so it's likely unmaintained"
        if not d.get("fixed_in"):
            stale += " and a fix may never come"
        parts.append(f"<b>{stale}</b>")
    if d.get("direct") is True:
        parts.append("the app lists it itself")
    elif d.get("direct") is False:
        parts.append("another library brings it in")
    return f"{name}: " + " · ".join(parts)


_TICK = re.compile(r"`([^`<>]{1,80})`")


def _ai_text(text: str, limit: int) -> str:
    """Escaped AI text; `names` become <code> (after escaping, so nothing else can)."""
    return _TICK.sub(r"<code>\1</code>", e(text, limit))


def _cite(cites: list[list[Any]]) -> str:
    parts = [f"{f}:{a}" if a == b else f"{f}:{a}–{b}" for f, a, b in cites[:4]]
    return f' <span class="cite">({e(", ".join(parts), 200)})</span>' if parts else ""


def code_html(snip: dict[str, Any]) -> str:
    """The code we sent, as escaped lines with numbers; comment/docstring lines dimmed."""
    out = []
    last = None
    for seg in snip.get("segments", []):
        f = str(seg.get("file"))
        if "line" in seg and f != last:
            out.append(
                f'<span class="fn">{e(f, 200)}</span> <span class="nc">line {int(seg["line"])} '
                "is one very long line. It's shown reformatted, and the line numbers count the "
                "reformatted text.</span>"
            )
            last = f
        elif "col" in seg:
            out.append(
                f'<span class="fn">{e(f, 200)}</span> <span class="nc">line {int(seg["start"])}, '
                f"characters {int(seg['col']):,}–{int(seg['end']):,}</span>"
            )
            last = f
        elif f != last:
            out.append(f'<span class="fn">{e(f, 200)}</span>')
            last = f
        else:
            out.append('<span class="nc">…</span>')
        noncode = set(snip.get("noncode", {}).get(f, []))
        for i, line in enumerate(seg.get("code", [])):
            n = int(seg["start"]) + i
            text = f"{n:>5}  {e(line, 4000)}"
            out.append(f'<span class="nc">{text}</span>' if n in noncode else text)
    return '<pre class="code">' + "\n".join(out) + "</pre>"


AI_BADGE = f'<span class="aib">{icon("sparkle", 12)} AI</span>'


def more_note(snip: dict[str, Any], missing: dict[str, Any] | None) -> str:
    """One sentence for the sheet on whether the AI can ask to see more code (0.11.0).
    `missing`: None when the scan has stored source, else the report's `context.source`
    note ({} for a scan from before 0.11.0)."""
    if snip.get("lang") != "python" or (missing or {}).get("why") in ("cards", "no Python"):
        return ""  # cards and non-Python files: never offered
    if missing is None:
        return (
            " If the AI asks to see more, Barkley adds up to 150 more lines of this app's code "
            "and asks again. The AI can only pick those lines by name, from a list Barkley "
            "offers. Your one click covers both rounds."
        )
    if missing.get("why") == "too big":
        return (
            " Barkley keeps no copy of this app's Python because it's too big (over 1 MB "
            "compressed, or more than 3,000 files). So the AI can't ask to see more than these "
            "lines."
        )
    return (
        " Barkley has no copy of this version's code, so the AI can't ask to see more than "
        "these lines. Barkley keeps a copy only for the installed version and a waiting "
        "update, from scans made by version 0.11.0 or later."
    )


def also_note(cmp: dict[str, Any] | None, doc: dict[str, Any] | None) -> str:
    """What an "Explain in context" request carries besides the code (0.12.0), as one
    escaped sentence for the sheet, or ""."""
    bits = []
    if cmp:
        bits.append(
            "its comparison with the original in Home Assistant "
            f"{e(cmp.get('ha_version'), 20)} (shown on the page under “How it differs from "
            "the original”)"
        )
    if doc:
        n = len(doc.get("code") or [])
        bits.append(
            f"the first {n} line{'' if n == 1 else 's'} of the app's "
            f"<code>{e(doc.get('file'), 40)}</code>, marked as the author's own description of the app"
        )
    return f"Barkley also sends {' and '.join(bits)}." if bits else ""


def _names(labels: list[Any]) -> str:
    return ", ".join(f"<code>{e(x, 200)}</code>" for x in labels[:3])


def deep_html(
    form: str,
    *,
    item_id: str,
    title: str,
    answer: dict[str, Any] | None,
    state: str,
    error: str,
    snip: dict[str, Any],
    entity: str,
    open_url: str = "",
    close_url: str = "",
    asking: list[str] | None = None,
    more: str = "",
    also: str = "",
    part: str = "both",
) -> str:
    """One item's "Explain in context": a compact chip or button where the item is, and
    a full-width sheet (`#ai-<id>`, opened with CSS :target, no script) with the answer
    and the code. `form` is the server-built button form with a `{label}` placeholder.
    Everything from the AI or the repo is escaped.

    `open_url` / `close_url` (escaped, from the server; set only while the page refreshes
    itself because a reading runs): the sheet's links are then real URLs, not fragments.
    Only the query (`?open=<id>`) tells the server which sheet is open, so a fragment-only
    Close kept `?open=` in the address and the next refresh reopened the sheet (the user's
    report, 2026-11-12), and a fragment-only open would stop the plain reload (a page at a
    fragment never reloads).
    `asking`: while the second round runs, what the AI asked to see. `more`: more_note().
    `also`: also_note(), what else the request carries (the comparison, the README).
    `part` (0.13.0): "inline" is only the chip or button, without the sheet or the item's
    anchor, for a second place on the page that opens the same reading (a privacy note);
    "sheet" is only the sheet, for an item whose own place isn't on the page."""
    from sniff_test.report.context import line_count

    mid = f"ai-{e(item_id, 40)}"
    to = open_url or f"#{mid}"
    lines = line_count(snip)
    nseg = len(snip.get("segments", []))
    extra = (answer or {}).get("more") if isinstance((answer or {}).get("more"), dict) else None
    added = line_count(extra) if extra else 0
    parts_txt = f", {nseg} parts" if nseg > 1 else ""
    if added:
        parts_txt += f", plus {added} it asked for"
    sent = (
        f"<details{'' if answer else ' open'}><summary>The code it reads ({lines} line"
        f"{'s' if lines != 1 else ''}{parts_txt})</summary>{code_html(snip)}"
        + (
            f'<p class="small">Added because the AI asked to see '
            f"{_names((answer or {}).get('asked') or [])}:</p>{code_html(extra)}"
            if extra
            else ""
        )
        + (f'<p class="small">{also}</p>' if also else "")
        + "</details>"
    )
    if state == "running":
        inline = (f'<a class="aichip" href="{to}">{icon("sparkle")} AI is reading the code… '
                  "(can take minutes)</a>")  # fmt: skip
        body = (
            '<p class="small"><b>Reading the code…</b> This can take a few minutes, depending '
            "on your AI. You don't have to wait here. Close this and carry on. The answer is "
            "saved, and the button for this item changes to the AI's reading when it's "
            "ready. While it works, this page refreshes by itself.</p>"
            + (
                f'<p class="small">The AI asked to see more code ({_names(asking)}), so '
                "Barkley added it and asked again.</p>"
                if asking
                else ""
            )
            + sent
        )
    elif error:
        inline = f'<a class="aichip warn" href="{to}">{icon("sparkle")} The AI didn\'t answer</a>'
        body = (f'<p class="small">{e(error, 400)}</p>{form.replace("{label}", f"{icon('sparkle', 16)} Try again")}'
                + sent)  # fmt: skip
    elif not answer:
        inline = (
            form.replace("{label}", f"{icon('sparkle', 16)} Explain in context")
            + f'<a class="small" href="{to}">see the {lines} lines it would send</a>'
        )
        body = (
            f'<p class="small">Explain in context sends these {lines} lines of the app\'s own '
            f"code to the AI set up as <code>{e(entity, 120)}</code>. The code is public on "
            "GitHub, and no Home Assistant data is sent. Nothing is sent until you click."
            f"{more}</p>"
            + form.replace("{label}", f"{icon('sparkle', 16)} Explain in context")
            + sent
        )
    else:
        claims = answer.get("claims") or []
        questions = answer.get("questions") or []
        n_c, n_q = len(claims), len(questions)
        summary = f"{n_c} statement{'s' if n_c != 1 else ''}"
        if n_q:
            summary += f", {n_q} question{'s' if n_q != 1 else ''}"
        inline = (f'<a class="aichip" href="{to}">{icon("sparkle")} AI\'s reading of the code '
                  f"({summary})</a>")  # fmt: skip
        out = []
        asked = answer.get("asked") or []
        if asked and answer.get("second_failed"):
            out.append(
                f'<p class="small">The AI asked to see more code ({_names(asked)}). Barkley '
                "added it and asked again, but the second answer didn't arrive "
                f"({e(answer.get('second_failed'), 200)}). This is the AI's first reading, made "
                "without that code.</p>"
            )
        elif asked and answer.get("both"):
            out.append(
                f'<p class="small">The AI read the code, asked to see more ({_names(asked)}), '
                "and read again with that code added. The statements below come from both "
                "readings. The questions come from the second.</p>"
            )
        elif asked:  # an answer saved before both readings were kept: only the second
            out.append(
                f'<p class="small">The AI asked to see more code ({_names(asked)}) before '
                "answering. Barkley added it and asked again. Only the second answer is "
                "shown.</p>"
            )
        if claims:
            out.append(
                "<ul>"
                + "".join(f"<li>{_ai_text(c['text'], 400)}{_cite(c['cites'])}</li>" for c in claims)
                + "</ul>"
            )
        else:
            out.append(
                '<p class="small">The AI gave no statement Barkley could check against the code.</p>'
            )
        if questions:
            out.append(
                "<h3>Questions the AI raised</h3><ul>"
                + "".join(
                    f"<li>{_ai_text(q['text'], 300)}{_cite(q['cites'])}</li>" for q in questions
                )
                + "</ul>"
            )
        opinion = answer.get("alignment")
        if isinstance(opinion, dict) and opinion.get("text"):
            out.append(
                "<h3>The AI thinks the code matches the README</h3>"
                f'<p class="opinion">{_ai_text(opinion["text"], 400)}'
                f"{_cite(opinion.get('cites') or [])}</p>"
                "<p class=\"tech\">This is the AI's opinion. It isn't one of Barkley's checks. "
                "The app's author wrote both the README and the code. Code that matches the "
                "README does what the author says, but that doesn't make it safe. What Barkley "
                "flagged and the readings stay the same.</p>"
            )
        refused = int(answer.get("refused") or 0)
        if refused:
            asks = [a for a in answer.get("refused_asks") or [] if isinstance(a, str)][:3]
            named = (
                ": " + ", ".join(f"<code>{e(a, 60)}</code>" for a in asks) + "." if asks else "."
            )
            one = refused == 1
            out.append(
                f'<p class="tech">The AI also asked for {refused} thing{"" if one else "s"} '
                f"that {'was' if one else 'were'}n't on Barkley's list, so Barkley ignored "
                f"{'it' if one else 'them'}{named}</p>"
            )
        repeats = answer.get("repeats")
        if isinstance(repeats, int) and repeats > 0:
            out.append(
                f'<p class="tech">{repeats} statement{"s" if repeats != 1 else ""} in the second '
                f"reading said the same as {'one' if repeats == 1 else 'ones'} above, "
                f"so {'it isn' if repeats == 1 else 'they aren'}'t shown again.</p>"
            )
        dropped = answer.get("dropped") or []
        if dropped:
            why = ", ".join(e(w, 60) for w in sorted(set(dropped)))
            n = len(dropped)
            out.append(f'<p class="tech">Barkley left out {n} statement{"s" if n != 1 else ""} that '
                       f"didn't check out ({why}).</p>")  # fmt: skip
        out.append(
            f'<p class="tech">Written by <code>{e(answer.get("entity_id"), 120)}</code> on '
            f"{e(str(answer.get('created', ''))[:16].replace('T', ' '))} UTC. Each statement "
            "points to lines Barkley sent, and those lines contain the code it names (comments "
            "don't count). The AI can still be wrong, and it can't change the readings or clear "
            "anything Barkley flagged.</p>"
        )
        body = "".join(out) + sent + form.replace("{label}", f"{icon('sparkle', 16)} Ask again")
    close = close_url or f"#item-{e(item_id, 40)}"
    sheet = (
        f'<div class="modal" id="{mid}"><a class="shade" href="{close}" '
        'aria-label="Close"></a><div class="sheet" role="dialog">'
        f'<div class="sh">{AI_BADGE}<b>The AI\'s reading of the code</b>'
        f'<a class="x" href="{close}">Close {icon("x")}</a></div>'
        f'<div class="st">{e(title, 200)}</div>{body}</div></div>'
    )
    if part == "inline":
        return f'<div class="deepi">{inline}</div>'
    if part == "sheet":
        return sheet
    return f'<div class="deepi" id="item-{e(item_id, 40)}">{inline}</div>{sheet}'


TrustFn = Callable[[dict[str, Any]], str]


def known_text(address: str) -> str:
    """Who runs an address, from the shipped list of well-known services, or that we
    don't know. A hint for the user's own decision; it never changes a reading."""
    svc = known.lookup(address)
    if svc:
        return f"Barkley knows this as {e(svc.label, 160)}."
    return "Barkley doesn't know who runs this address."


def address_line(address: str) -> str:
    return f"<li><code>{e(address, 253)}</code> · {known_text(address)}</li>"


def note_reading(note: privacy.Note, inline: DeepFn) -> str:
    """(0.13.0) A privacy note's way to the AI's reading: the "Explain in context" button
    or chip of the address or port behind it (`inline(edge_id)`, the same item, answer and
    sheet as under "Where it connects"; the user's pick, 2026-11-16), or a line saying
    why there is none."""
    links = []
    for i, edge in enumerate(note.edges):
        html = inline(edge) if edge else ""
        if not html:
            continue
        what = f"<code>{e(note.hosts[i], 120)}</code>" if i < len(note.hosts) else "port 1883"
        links.append((what, html))
    if links:
        place = "port" if note.kind == "mqtt" else "address"
        lead = (
            f'<p class="small">The AI\'s reading of this {place} is the same one as under '
            "“Where it connects”.</p>"
            if len(links) == 1
            else '<p class="small">The AI\'s reading of each address is the same one as under '
            "“Where it connects”.</p>"
        )
        body = "".join(
            (f'<div class="small">{what}</div>' if len(links) > 1 else "") + html
            for what, html in links[:4]
        )
        return f'<div class="noteai">{lead}{body}</div>'
    if note.classes and all(c == "declared" for c in note.classes):
        why = (
            ". Its addresses are linked from the app's manifest or package.json, and Barkley "
            "only offers a reading for addresses that aren't"
        )
    else:
        why = ", because none of its addresses has one on this page"
    return f'<p class="small muted noteai">This note has no “Explain in context”{why}.</p>'


def privacy_html(notes: list[privacy.Note], inline: DeepFn | None = None) -> str:
    """`inline(edge_id)`: the chip or button only (deep(..., part="inline")); None when
    the AI's code reading is off, and then the notes show none."""
    if not notes:
        return ""
    parts = [
        f'<section class="privbox"><h2>{icon("lock", 16)} Privacy notes ({len(notes)})</h2>'
        '<p class="sub">These notes are about your privacy. They never change the readings.</p>'
    ]
    for n in notes:
        hosts_html = ""
        if n.hosts:
            hosts_html = " " + ", ".join(f"<code>{e(h, 120)}</code>" for h in n.hosts[:4])
            if len(n.hosts) > 4:
                hosts_html += f" and {len(n.hosts) - 4} more"
        where = ", ".join(f"<code>{e(w, 160)}</code>" for w in n.where)
        parts.append(
            f'<div class="finding"><div class="lvl p">{e(n.label)}</div><div>'
            f"<h3>{e(n.title)}</h3><dl>"
            f"<dt>What it means</dt><dd>{e(n.means, 600)}{(' Address:' if len(n.hosts) == 1 else ' Addresses:') + hosts_html if hosts_html else ''}</dd>"
            f"<dt>What Barkley can't tell</dt><dd>{e(n.unknown, 400)}</dd>"
            + (f"<dt>Where Barkley saw it</dt><dd>{where}</dd>" if where else "")
            + "</dl>"
            + (note_reading(n, inline) if inline else "")
            + "</div></div>"
        )
    parts.append("</section>")
    return "".join(parts)


# --- what an update changes, in plain words ------------------------------------------------------

_HOST_CLASS_WORDS = {
    "declared": "one of the app's own",
    "undeclared": "not one of the app's own sites",
    "developer_hosted": "run by the developer",
    "analytics": "an analytics or crash-report service",
    "exfil_service": "a data-collection site",
    "messaging": "a messaging service",
    "public_ip": "a public IP address",
    "local": "on your own network",
    "link": "a project or help link",
    "infrastructure": "a package or project site",
    "resolver": "a DNS resolver",
}
_RELATION_WORDS = {
    "registers": "registers",
    "exposes": "opens",
    "calls_service": "calls the action",
    "listens_to": "listens for the event",
    "fires_event": "sends the event",
    "reads": "reads",
    "writes": "writes",
    "imports": "imports",
    "executes": "runs",
    "depends_on": "depends on",
    "bundles": "bundles",
}
_KIND_WORDS = {
    "http_view": "a web page or API route",
    "http_static": "a route that serves files",
    "webhook": "a webhook",
    "ws_command": "a live-connection command",
    "inbound": "a way in from the network",
    "service": "an action",
    "panel": "a sidebar page",
    "event": "an event",
    "package": "a package",
    "host": "a site",
    "data": "data",
    "auth": "login data",
    "port": "a port",
}
_SIGN_WORDS = {"+": "New", "-": "Gone", "~": "Changed"}


def _rules_words(note: str) -> str:
    """` · rule-a, rule-b` (the diff's note of the findings an edge carries) → titles."""
    ids = [r.strip() for r in note.split(",") if r.strip()]
    titles = []
    for rid in ids:
        if not re.fullmatch(r"[a-z0-9-]{3,60}", rid):
            continue
        if rid in explain.RULES or rid.startswith("dep-guarddog-"):
            titles.append(_lower1(explain.explain(rid).title))
    return explain._join(titles)


def _split_note(text: str) -> tuple[str, str]:
    """The diff's text and its trailing ` · rule, rule` note, if any."""
    if " · " in text:
        head, note = text.rsplit(" · ", 1)
        if all(re.fullmatch(r"[a-z0-9-]{3,60}", r.strip()) for r in note.split(",")):
            return head, note
    return text, ""


def _node_words(nid: str) -> str:
    kind, _, label = str(nid).partition(":")
    if kind == "data" or kind == "auth":
        return explain.data_label(label)
    if kind == "package":
        return label.split("/", 1)[-1]
    return label or nid


def change_line(c: dict[str, Any]) -> tuple[str, str, str]:
    """One diff change as (lead word, plain sentence as escaped HTML, the raw text).
    Everything from the reports is escaped; rule ids become their plain titles."""
    kind, text, sign = str(c.get("kind", "")), str(c.get("text", "")), str(c.get("sign", "+"))
    d = c.get("detail") or {}
    sev = c.get("severity")
    head, note = _split_note(text)
    why = _rules_words(note) if note else ""
    lead = explain.level(sev) if sev and sign == "+" else _SIGN_WORDS.get(sign, "Changed")
    out = ""
    if kind == "new_finding":
        rule = str(d.get("rule_id", ""))
        where = head.rsplit(" (", 1)[1].rstrip(")") if head.endswith(")") and " (" in head else ""
        out = e(explain.explain(rule).title) + (f" (<code>{e(where, 160)}</code>)" if where else "")
    elif kind == "resolved_finding":
        rule = str(d.get("rule_id", ""))
        title = explain.explain(rule).title
        verb = title.partition(" ")[0]
        if verb.endswith("s") and not verb.endswith("ss") and verb not in ("Its", "This", "Is"):
            out = f"It no longer {e(_lower1(title))}"  # titles start with a verb: "Reads …"
        else:
            out = f"No longer flagged: {e(_lower1(title))}"
    elif kind in ("severity_up", "severity_down"):
        rule = str(d.get("rule_id", ""))
        was = explain.level(str(d.get("from", "")))
        now = explain.level(str(sev or ""))
        out = f"{e(explain.explain(rule).title)}: now {e(now.lower())}, was {e(was.lower())}"
        lead = "Changed"
    elif kind == "new_flow":
        ev = str(d.get("evidence", ""))
        src = _node_words(str(d.get("source", "")))
        targets = [_node_words(t) for t in d.get("targets") or []]
        shown = explain._join([e(t, 80) for t in targets[:3]]) + (
            f" and {len(targets) - 3} more" if len(targets) > 3 else ""
        )
        if ev == "proven":
            out = f"<b>Barkley traced {e(_lower1(src))} being sent to {shown}</b>"
        else:
            out = (f"It now reads {e(_lower1(src))} and can reach {shown}, which Barkley "
                   "can't explain. The path isn't proven")  # fmt: skip
    elif kind == "new_read":
        out = f"It now reads {e(_lower1(_node_words(str(d.get('target', '')))))}"
    elif kind == "new_package":
        if "new dependencies" in head or "new bundled packages" in head:
            out = e(head)
        else:
            rel = "bundles" if head.startswith("bundles") else "depends on"
            rest = head.split(" ", 1)[1] if " " in head else head
            what = "A new bundled library" if rel == "bundles" else "A new dependency"
            out = f"{what}: <code>{e(rest, 120)}</code>"
            if "now resolves" in head:
                out = e(head)
    elif kind == "new_inbound":
        words = head.split(" ", 2)
        kw = _KIND_WORDS.get(words[1].replace(" ", "_"), words[1]) if len(words) > 1 else ""
        label = words[2] if len(words) > 2 else ""
        out = f"Opens a new way in: {e(kw)} <code>{e(label, 120)}</code>"
    elif kind == "new_hook":
        rel = str(d.get("relation", ""))
        target = str(d.get("target", ""))
        tk = target.partition(":")[0]
        out = (f"Now {e(_RELATION_WORDS.get(rel, rel.replace('_', ' ')))} "
               f"{e(_KIND_WORDS.get(tk, tk.replace('_', ' ')))} "
               f"<code>{e(_node_words(target), 120)}</code>")  # fmt: skip
    elif kind == "new_host":
        cls = str(d.get("class", "undeclared"))
        cw = _HOST_CLASS_WORDS.get(cls, cls.replace("_", " "))
        if "targets" in d:
            names = [_node_words(t) for t in d["targets"]]
            shown = ", ".join(f"<code>{e(n, 80)}</code>" for n in names[:4])
            out = f"Its code now mentions {len(names)} new sites ({e(cw)}): {shown}" + (
                ", …" if len(names) > 4 else ""
            )
        else:
            host = _node_words(str(d.get("target", "")))
            out = f"Its code now mentions a new site, <code>{e(host, 120)}</code>, which is {e(cw)}"
    elif kind.startswith("removed_"):
        rel = str(d.get("relation", ""))
        target = str(d.get("target", ""))
        verb = {"flows_to": "sends data to", "connects_to": "names the site",
                "reads": "reads", "depends_on": "depends on", "bundles": "bundles"}.get(
            rel, _RELATION_WORDS.get(rel, rel.replace("_", " ")))  # fmt: skip
        out = f"No longer {e(verb)} <code>{e(_node_words(target), 120)}</code>"
    elif kind in ("evidence_up", "evidence_down"):
        what = head.rsplit(":", 1)[0] if ":" in head else head
        out = (f"{e(what, 160)}: the evidence is now {e(str(d.get('to', '')))} "
               f"(was {e(str(d.get('from', '')))})")  # fmt: skip
    elif kind == "host_class":
        out = (f"<code>{e(_node_words(str(d.get('target', ''))), 120)}</code> now counts as "
               f"{e(_HOST_CLASS_WORDS.get(str(d.get('to')), str(d.get('to'))))} "
               f"(was {e(_HOST_CLASS_WORDS.get(str(d.get('from')), str(d.get('from'))))})")  # fmt: skip
    elif kind == "package_version":
        out = (f"<code>{e(_node_words(str(d.get('target', ''))), 120)}</code> goes from "
               f"{e(str(d.get('from')), 60)} to {e(str(d.get('to')), 60)}")  # fmt: skip
    elif kind == "repo_moved":
        out = "The repository moved: " + e(head.split(": ", 1)[-1], 200)
    elif kind == "new_publisher":
        out = "A new publisher: " + e(head, 300)
    elif kind == "publisher_changed":
        out = "A different publisher: " + e(head, 300)
    elif kind in ("signature_stopped", "signature_changed", "signature_started"):
        out = e(head, 300)  # fixed words from diff.signature_changes
    elif kind in ("new_request", "request_carries", "new_env", "new_library",
                  "library_version", "library_read", "library_gone"):  # fmt: skip
        out = e(text, 400)  # (0.15) a whole sentence from diff.py; the names in it are untrusted
        lead = _SIGN_WORDS.get(sign, "Changed")
    elif kind == "coverage_lost":
        out = "Part of the new check didn't finish, so changes may be missing: " + e(head, 300)
    elif kind == "install_source":
        a, _, b = head.removeprefix("installed from ").partition(" → ")
        out = (f"The Marketplace now installs {e(_SOURCE.get(b, b))} "
               f"(it was {e(_SOURCE.get(a, a))})")  # fmt: skip
    else:
        out = e(head, 300)
    if why and why.lower() not in html.unescape(re.sub(r"<[^>]+>", "", out)).lower():
        out += f". Barkley flagged it for: {e(why, 300)}"
    return lead, out, text


# --- data-flow diagram -------------------------------------------------------------------------


def _clip(s: str, n: int = 26) -> str:
    s = sanitize_untrusted(s, 200)
    return s if len(s) <= n else s[: n - 1] + "…"


@dataclass
class _Flow:
    """What the diagram shows, laid out two ways (wide and narrow screens)."""

    rd: list[tuple[str, str, bool]]  # (node id, label, sensitive) the app reads
    right: list[tuple[str, str, str, str]]  # (key, title, subtitle, style) it can reach
    fl: list[dict[str, Any]]  # flows_to edges
    extra: int  # flow destinations beyond the three drawn
    port_dirs: set[str | None]
    kind: str
    flow_src: set[str]


def _flow_data(report: dict[str, Any]) -> _Flow | None:
    rd = reads(report)[:6]
    fl = flows(report)
    hs = hosts(report)
    pts = ports(report)
    _g, nodes = _graph(report)
    right: list[tuple[str, str, str, str]] = []
    flow_targets = []
    for x in fl:
        if x["target"] not in flow_targets:
            flow_targets.append(x["target"])
    for t in flow_targets[:3]:
        n = nodes.get(t, {})
        if n.get("kind") == "network":
            right.append((t, "Off your HA machine", "the code doesn't show where", "bad"))
        else:
            right.append((t, str(n.get("label", t)), "site Barkley can't explain", "bad"))
    extra = len(flow_targets) - 3
    home = [h for h in hs if h.cls == "local"]
    if home:
        right.append(
            ("home", "Your own network", f"{len(home)} address{'es' * (len(home) != 1)}", "")
        )
    if pts:
        dirs = {p.direction for p in pts}
        if dirs == {"in"}:
            title = (
                f"Listens on port {pts[0].port}"
                if len(pts) == 1
                else f"Listens on {len(pts)} ports"
            )
            sub = "others connect to this machine"
        elif len(pts) == 1:
            known = WELL_KNOWN_PORTS.get(pts[0].port)
            title = (
                f"{known[0]} server, port {pts[0].port}"
                if known
                else f"A server on port {pts[0].port}"
            )
            sub = "its address isn't in the code"
        else:
            title = f"{len(pts)} servers or devices"
            nums = ", ".join(str(p.port) for p in pts[:4]) + (" …" if len(pts) > 4 else "")
            sub = f"{nums} · address unknown"
        right.append(("ports", title, sub, ""))
    flowing = {nodes.get(t, {}).get("label") for t in flow_targets}
    net = [h for h in internet(hs) if h.name not in flowing]
    dev = [h for h in net if h.cls in ("developer_hosted", "analytics")]
    if dev:
        kinds = {h.cls for h in dev}
        if len(dev) == 1:
            title = (
                "Server the developer runs" if "developer_hosted" in kinds else "Analytics service"
            )
        elif kinds == {"developer_hosted"}:
            title = f"{len(dev)} servers the developer runs"
        elif kinds == {"analytics"}:
            title = f"{len(dev)} analytics services"
        else:
            title = f"{len(dev)} developer or analytics servers"
        right.append(("dev", title, dev[0].name, "priv"))
    rest = [h for h in net if h not in dev]
    if rest:
        own = sum(1 for h in rest if h.cls == "declared")
        sub = f"{own} of them the app's own" if own else "none of them the app's own"
        label = "Other internet sites" if dev else "Internet sites"
        right.append(("net", f"{label}: {len(rest)}", sub, ""))
    if not rd and not right:
        return None
    return _Flow(
        rd,
        right,
        fl,
        extra,
        {p.direction for p in pts},
        KIND.get(str(report.get("target", {}).get("kind")), ""),
        {x["source"] for x in fl},
    )


_BOX_STYLE = {"bad": ("var(--card)", "var(--red)"), "priv": ("var(--priv-bg)", "var(--priv)")}


def _flow_defs(suffix: str) -> str:
    return (
        f'<defs><marker id="arr{suffix}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
        'markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" '
        'fill="var(--red)"/></marker>'
        f'<marker id="arrg{suffix}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" '
        'markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" '
        'fill="var(--muted)"/></marker></defs>'
    )


_CHAR_PX = 6.6  # 12 px Geist, about this wide per character on average
_MAX_LINES = 3  # per part of a label; longer text (untrusted, up to 253) ends in "…"


def _wrap(text: str, chars: int, most: int = _MAX_LINES) -> list[str]:
    """(0.15, his report: labels cut to fit a fixed box were lost, with no hover on a phone)
    A label in as many lines as it needs, breaking long names anywhere."""
    text = sanitize_untrusted(text, 300)
    lines = textwrap.wrap(text, max(chars, 8), break_long_words=True,
                          break_on_hyphens=False) or [""]  # fmt: skip
    if len(lines) > most:
        lines = [*lines[: most - 1], _clip(lines[most - 1] + "…", chars)]
    return lines


def _label_lines(title: str, sub: str, w: int) -> list[tuple[str, bool]]:
    """(text, small) lines for a box `w` wide. A second line that only repeats the first
    ("Home Assistant's environment variables" / "environment variables") is left out."""
    chars = int((w - 24) / _CHAR_PX)
    out = [(x, False) for x in _wrap(title, chars)]
    if sub and sub.strip().lower() not in title.lower():
        out += [(x, True) for x in _wrap(sub, chars)]
    return out


def _read_lines(item: tuple[str, str, bool], w: int) -> list[tuple[str, bool]]:
    _nid, label, _sens = item
    return _label_lines(explain.data_label(label), label, w)


def _dest_lines(item: tuple[str, str, str, str], w: int) -> list[tuple[str, bool]]:
    return _label_lines(item[1], item[2], w)


def _box_h(d: _Flow, rw: int, dw: int) -> int:
    """One height for every box in a diagram: the tallest label's (at least two lines)."""
    n = max([2] + [len(_read_lines(x, rw)) for x in d.rd]
            + [len(_dest_lines(x, dw)) for x in d.right])  # fmt: skip
    return 12 + 16 * n


def _box(lines: list[tuple[str, bool]], x: int, y: float, w: int, h: int, fill: str,
         stroke: str) -> str:  # fmt: skip
    text = "".join(
        f'<text{' class="sm"' if small else ""} x="{x + 12}" y="{y + 19 + 16 * i:.0f}">'
        f"{e(t, 300)}</text>"
        for i, (t, small) in enumerate(lines)
    )
    return (f'<rect x="{x}" y="{y:.0f}" width="{w}" height="{h}" rx="6" fill="{fill}" '
            f'stroke="{stroke}"/>{text}')  # fmt: skip


def _read_box(d: _Flow, item: tuple[str, str, bool], x: int, y: float, w: int, h: int) -> str:
    nid, _label, sens = item
    fill, stroke = (
        ("var(--red-bg)", "var(--red)")
        if nid in d.flow_src
        else (("var(--yellow-bg)", "var(--yellow)") if sens else ("var(--soft)", "var(--line)"))
    )
    return _box(_read_lines(item, w), x, y, w, h, fill, stroke)


def _dest_box(item: tuple[str, str, str, str], x: int, y: float, w: int, h: int) -> str:
    fill, stroke = _BOX_STYLE.get(item[3], ("var(--soft)", "var(--line)"))
    return _box(_dest_lines(item, w), x, y, w, h, fill, stroke)


def _app_box(d: _Flow, name: str, x: int, cy: float) -> str:
    # 12 px semibold Geist is about 7 px per character; the box has 154 px for text
    names = _wrap(name, 21, 2)
    top = cy - 3 - 7 * (len(names) - 1)
    text = "".join(f'<text class="nm" x="{x + 85}" y="{top + 14 * i:.0f}" '
                   f'text-anchor="middle">{e(t, 300)}</text>' for i, t in enumerate(names))  # fmt: skip
    return (
        f'<rect x="{x}" y="{cy - 28:.0f}" width="170" height="56" rx="8" fill="var(--card)" '
        f'stroke="var(--fg)" stroke-width="1.5"/>{text}'
        f'<text class="sm" x="{x + 85}" y="{top + 14 * len(names) + 2:.0f}" '
        f'text-anchor="middle">{e(d.kind)}</text>'
    )


def _flow_way(d: _Flow, key: str) -> str | None:
    """Who opens the connection: "out" to a site or server, "in" for a port it listens on,
    None when the code doesn't make the direction clear."""
    if key != "ports":
        return "out"
    return next(iter(d.port_dirs)) if len(d.port_dirs) == 1 else None


def _flow_caption(d: _Flow) -> list[str]:
    if d.fl:
        cap = ["Solid line: Barkley traced it in the code.",
               "Dashed line: it reads the data and can reach a site Barkley can't explain, but "
               "the path isn't proven."]  # fmt: skip
        if d.extra > 0:
            cap.append(f"{d.extra} more place{'s' * (d.extra != 1)} your data may go "
                       f"{'are' if d.extra != 1 else 'is'} listed below.")  # fmt: skip
        return cap
    return ["Arrows show which way the connection goes.", "Barkley found no path from your data "
            "to the internet."]  # fmt: skip


def _flow_wide(d: _Flow, name: str) -> str:
    """Left: reads. Middle: the app. Right: destinations. Red lines left to right."""
    top, w = 16, 700
    bh = _box_h(d, 176, 194)
    mid_y, row_h = bh / 2, bh + 12
    rows = max(len(d.rd), len(d.right), 2)
    caption = [ln for part in _flow_caption(d) for ln in textwrap.wrap(part, 110)]
    height = top * 2 + rows * row_h + 22 + 14 * (len(caption) - 1)
    cy = top + rows * row_h / 2
    parts = [
        f'<svg class="flow" viewBox="0 0 {w} {height:.0f}" width="100%" style="min-width:560px" '
        f'role="img" aria-label="Data flow for {e(name, 80)}">',
        _flow_defs(""),
    ]

    def ys(n: int) -> list[float]:
        start = cy - n * row_h / 2
        return [start + i * row_h + 6 for i in range(n)]

    lpos: dict[str, float] = {}
    for item, y in zip(d.rd, ys(len(d.rd)), strict=False):
        parts.append(_read_box(d, item, 6, y, 176, bh))
        parts.append(
            f'<line x1="182" y1="{y + mid_y:.0f}" x2="258" y2="{cy:.0f}" '
            'stroke="var(--muted)" stroke-dasharray="3 3" marker-end="url(#arrg)"/>'
        )
        lpos[item[0]] = y + mid_y
    if not d.rd:
        parts.append(
            f'<text class="sm" x="6" y="{cy + 4:.0f}">Reads none of your private data</text>'
        )
    center_at = len(parts)
    parts.append(_app_box(d, name, 260, cy))
    rpos: dict[str, float] = {}
    for item, y in zip(d.right, ys(len(d.right)), strict=False):
        parts.append(_dest_box(item, w - 200, y, 194, bh))
        way = _flow_way(d, item[0])
        if way == "in":
            parts.append(
                f'<line x1="{w - 200}" y1="{y + mid_y:.0f}" x2="432" y2="{cy:.0f}" '
                'stroke="var(--muted)" marker-end="url(#arrg)"/>'
            )
        else:
            mark = ' marker-end="url(#arrg)"' if way == "out" else ""
            x2 = w - 202 if way == "out" else w - 200
            parts.append(
                f'<line x1="430" y1="{cy:.0f}" x2="{x2}" y2="{y + mid_y:.0f}" '
                f'stroke="var(--muted)"{mark}/>'
            )
        rpos[item[0]] = y + mid_y
    lines: list[str] = []
    for x in d.fl:
        y1, y2 = lpos.get(x["source"]), rpos.get(x["target"])
        if y1 is None or y2 is None:
            continue
        dash = "" if x["evidence"] == "proven" else ' stroke-dasharray="6 4"'
        width = "2.4" if x["evidence"] == "proven" else "1.6"
        lines.append(
            f'<path d="M182 {y1:.0f} C 330 {y1:.0f}, 380 {y2:.0f}, {w - 202} {y2:.0f}" fill="none" '
            f'stroke="var(--red)" stroke-width="{width}"{dash} marker-end="url(#arr)"/>'
        )
    parts[center_at:center_at] = lines  # under the app's box, so its name stays readable
    for i, line in enumerate(caption):  # one sentence per line: they don't fit on one
        y = height - 8 - 14 * (len(caption) - 1 - i)
        parts.append(f'<text class="sm" x="6" y="{y:.0f}">{e(line)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _flow_narrow(d: _Flow, name: str) -> str:
    """The same picture stacked for a phone: reads on top, the app, then destinations.
    Grey connectors run as one spine down the right margin (so no line crosses a box);
    red data paths run down the left margin."""
    top, w, bx, bw = 12, 360, 40, 280
    bh = _box_h(d, bw, bw)
    m, row_h = bh // 2, bh + 8
    spine, red_x = w - 20, 12
    n_r, n_d = len(d.rd), len(d.right)
    y_reads = top
    reads_end = y_reads + n_r * row_h if n_r else y_reads + 24
    cy = reads_end + 56  # app box centre: 28 of gap, 28 of half height
    y_dest = cy + 28 + 28
    caption = [ln for part in _flow_caption(d) for ln in textwrap.wrap(part, 46)]
    height = y_dest + max(n_d, 1) * row_h + 14 * len(caption) + 6
    mid = w / 2
    parts = [
        f'<svg class="flow" viewBox="0 0 {w} {height:.0f}" width="100%" '
        f'role="img" aria-label="Data flow for {e(name, 80)}">',
        _flow_defs("v"),
    ]
    lpos: dict[str, float] = {}
    for i, item in enumerate(d.rd):
        y = y_reads + i * row_h
        parts.append(_read_box(d, item, bx, y, bw, bh))
        parts.append(
            f'<line x1="{bx + bw}" y1="{y + m}" x2="{spine}" y2="{y + m}" '
            'stroke="var(--muted)" stroke-dasharray="3 3"/>'
        )
        lpos[item[0]] = y + m
    if d.rd:
        y0, y1 = y_reads + m, cy - 44
        parts.append(
            f'<path d="M{spine} {y0} V{y1} H{mid:.0f} V{cy - 30:.0f}" fill="none" '
            'stroke="var(--muted)" stroke-dasharray="3 3" marker-end="url(#arrgv)"/>'
        )
    else:
        parts.append(
            f'<text class="sm" x="{bx}" y="{y_reads + 14}">Reads none of your private data</text>'
        )
    center_at = len(parts)
    parts.append(_app_box(d, name, int(mid - 85), cy))
    rpos: dict[str, float] = {}
    if d.right:
        last = y_dest + (n_d - 1) * row_h + m
        parts.append(
            f'<path d="M{mid:.0f} {cy + 28:.0f} V{cy + 44:.0f} H{spine} V{last}" fill="none" '
            'stroke="var(--muted)"/>'
        )
    for i, item in enumerate(d.right):
        y = y_dest + i * row_h
        parts.append(_dest_box(item, bx, y, bw, bh))
        way = _flow_way(d, item[0])
        if way == "in":  # others connect in: the arrow points from the box to the spine
            parts.append(
                f'<line x1="{bx + bw}" y1="{y + m}" x2="{spine - 1}" y2="{y + m}" '
                'stroke="var(--muted)" marker-end="url(#arrgv)"/>'
            )
        else:
            mark = ' marker-end="url(#arrgv)"' if way == "out" else ""
            x2 = bx + bw + 2 if way == "out" else bx + bw
            parts.append(
                f'<line x1="{spine}" y1="{y + m}" x2="{x2}" y2="{y + m}" '
                f'stroke="var(--muted)"{mark}/>'
            )
        rpos[item[0]] = y + m
    lines: list[str] = []
    for x in d.fl:
        y1, y2 = lpos.get(x["source"]), rpos.get(x["target"])
        if y1 is None or y2 is None:
            continue
        dash = "" if x["evidence"] == "proven" else ' stroke-dasharray="6 4"'
        width = "2.4" if x["evidence"] == "proven" else "1.6"
        lines.append(
            f'<path d="M{bx} {y1:.0f} C {red_x} {y1:.0f}, {red_x} {y2:.0f}, {bx - 2} {y2:.0f}" '
            f'fill="none" stroke="var(--red)" stroke-width="{width}"{dash} '
            'marker-end="url(#arrv)"/>'
        )
    parts[center_at:center_at] = lines
    for i, line in enumerate(caption):
        y = height - 6 - 14 * (len(caption) - 1 - i)
        parts.append(f'<text class="sm" x="{bx}" y="{y:.0f}">{e(line)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def flow_svg(report: dict[str, Any], name: str) -> str:
    """Left: what it reads. Middle: the app. Right: where it can connect. Lines between
    left and right only for flows the scanner found (proven solid, possible dashed). Drawn
    twice: side by side for wide screens, stacked for narrow ones (CSS shows one)."""
    d = _flow_data(report)
    if d is None:
        return '<p class="muted">It reads none of your private data, and its code names no network addresses.</p>'
    return (
        f'<div class="flowwrap"><div class="flow-h">{_flow_wide(d, name)}</div>'
        f'<div class="flow-v">{_flow_narrow(d, name)}</div></div>'
    )


# --- where it connects -------------------------------------------------------------------------

ZONES = [
    ("home", "home", "Your home network", "Addresses on your own network", {"local"}),
    (
        "own",
        "cloud",
        "The app's own sites",
        "Its manifest or package.json links to them, or they match its name",
        {"declared"},
    ),
    (
        "dev",
        "wrench",
        "Servers the developer runs",
        "On free app-hosting services",
        {"developer_hosted"},
    ),
    (
        "ana",
        "chart",
        "Analytics and crash reports",
        "Services that collect usage or errors",
        {"analytics"},
    ),
    (
        "other",
        "globe",
        "Other sites",
        "Not linked from its manifest or package.json",
        {"undeclared", "public_ip", "exfil_service", "messaging"},
    ),
    (
        "links",
        "link",
        "Project and help links",
        "GitHub, Home Assistant, package sites, donations",
        {"infrastructure", "link", "resolver"},
    ),
]


def _lock(scheme_or_port: str | int) -> str:
    if isinstance(scheme_or_port, int):
        known = WELL_KNOWN_PORTS.get(scheme_or_port)
        enc = known[1] if known else None
    else:
        enc = {"https": True, "wss": True, "http": False, "ws": False}.get(scheme_or_port)
    if enc is True:
        return ' <span class="lock ok">encrypted</span>'
    if enc is False:
        return ' <span class="lock no">unencrypted</span>'
    return ""


_DEFAULT_PORT = {"https": 443, "wss": 443, "http": 80, "ws": 80}


def threat_destinations(report: dict[str, Any]) -> frozenset:
    """The sites a possible threat names (`possible-exfil`'s "destinations: a, b"): the
    developer's words about them are left out (his rule 2026-11-20)."""
    out: set[str] = set()
    for f in report.get("findings") or []:
        if f.get("rule_id") == "possible-exfil":
            ev = str(f.get("evidence") or "")
            if "destinations: " in ev:
                out |= {x.strip() for x in ev.split("destinations: ", 1)[1].split(",")}
    return frozenset(out)


ZONE_SHOWN = 5  # sites per zone before "N more" (his decision 2026-11-20: dense panels)
REQUESTS_SHOWN = 4  # kinds of request per site before "and N more"


def _names(values: Any, limit: int = 6) -> str:
    """Field names from the scanned code, as code, the first few."""
    names = [v for v in values if isinstance(v, str) and v][:limit]
    more = len(values) - len(names)
    out = ", ".join(f"<code>{e(n, 60)}</code>" for n in names)
    return out + (f" and {more} more" if more > 0 and names else "")


def request_line(shape: dict[str, Any], here: bool = True, parts: bool = False) -> Any:
    """One kind of request in plain words: the method, how often, and what the call puts
    into the body, the headers and the address (analyzers/py_requests). Names come from the
    scanned code: escaped. `here`: the line sits under the site it goes to."""
    method = str(shape.get("method") or "")
    n = shape.get("count") if isinstance(shape.get("count"), int) else 1
    where = f"from {n} places in the code" if n != 1 else "from one place in the code"
    to = " here" if here else ""
    if method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        out = [f"Sends <b>{method}</b> requests{to} {where}."]
    else:
        out = [f"Sends requests{to} {where}. The code picks the method (GET, POST and so on) "
               "while it runs."]  # fmt: skip
    for key, named, unnamed in (
        ("body", "The body carries {}.", "It has a body that is put together elsewhere in the code."),
        ("headers", "It sets the header {}.", "It sets headers that are put together elsewhere."),
        ("query", "After the <code>?</code> in the address it adds {}.",
         "It adds fields after the <code>?</code> in the address."),
    ):  # fmt: skip
        v = shape.get(key)
        if isinstance(v, list):
            text = named.format(_names(v)) if v else unnamed
            if key == "headers" and len(v) > 1:
                text = text.replace("the header ", "the headers ")
            out.append(text)
    via = shape.get("via")
    if isinstance(via, str) and via:  # (0.15) read at a call of the app's own wrapper
        out.insert(1, f"It goes through the app's own function <code>{e(via, 60)}</code>.")
    by = shape.get("body_by")
    if isinstance(by, str) and by:
        out.append(f"The body is built by the app's function <code>{e(by, 60)}</code>.")
    addr = shape.get("address")
    if isinstance(addr, list) and addr:
        out.append(f"Into the address itself it puts {_names(addr)}." if here else
                   f"The address is made from {_names(addr)}.")  # fmt: skip
    if shape.get("auth"):
        out.append("It passes a login for the site (<code>auth</code>).")
    if shape.get("more"):
        out.append("The code that calls it can add more.")
    at = [a for a in shape.get("at") or [] if isinstance(a, str)]
    if at:
        rest = n - len(at)
        out.append(f'<span class="muted">{e(", ".join(at), 300)}'
                   f'{f" and {rest} more" if rest > 0 else ""}</span>')  # fmt: skip
    return out if parts else " ".join(out)


def request_block(shape: dict[str, Any], here: bool = True) -> str:
    """One kind of request as a block of its own: the method on the first line, then one
    line per fact (his report: one paragraph per request ran together)."""
    head, *rest = request_line(shape, here, parts=True)
    return (f'<div class="req"><div>{head}</div>'
            + "".join(f'<span class="u">{x}</span>' for x in rest) + "</div>")  # fmt: skip


def _requests_spans(shapes: Any, elsewhere: bool = False) -> str:
    """The requests under one site. A site the code names without any request Barkley
    could read says so (`shapes` is [] then; None: the scan didn't read requests)."""
    if shapes is None:
        return ""
    shapes = [x for x in shapes or [] if isinstance(x, dict)]
    if not shapes:
        more = (" The app also sends requests whose address it works out while it runs, so it "
                "may still reach it." if elsewhere else
                " The code may only mention it, for example as a link.")  # fmt: skip
        return f'<span class="u">Barkley saw no request in the code that names this address.{more}</span>'
    out = "".join(request_block(x) for x in shapes[:REQUESTS_SHOWN])
    if len(shapes) > REQUESTS_SHOWN:
        rest = "".join(request_block(x) for x in shapes[REQUESTS_SHOWN:])
        out += (f'<details class="more"><summary>{len(shapes) - REQUESTS_SHOWN} more kinds of '
                f'request to this site</summary><div class="in">{rest}</div></details>')  # fmt: skip
    return out


def requests_note(report: dict[str, Any]) -> str:
    """One sentence for the box, once the scan read the requests (integrations, 0.15)."""
    if not isinstance(report.get("requests"), dict):
        return ""
    return (" Open a site to see how the code sends requests to it. GET or POST alone doesn't "
            "tell you what is sent: a GET can carry data too, in the address or in a header.")  # fmt: skip


def site_requests(report: dict[str, Any]) -> dict[str, Any]:
    r = report.get("requests")
    sites = r.get("sites") if isinstance(r, dict) else None
    return sites if isinstance(sites, dict) else {}


def _test_requests(r: Any) -> str:
    """Requests in the developer's own test scripts, which Home Assistant never loads:
    counted, not listed as the app's."""
    t = r.get("test_code") if isinstance(r, dict) else None
    if not isinstance(t, dict) or not isinstance(t.get("count"), int) or t["count"] < 1:
        return ""
    files = ", ".join(f"<code>{e(f, 120)}</code>" for f in t.get("files") or []
                      if isinstance(f, str))  # fmt: skip
    return (f'<div class="zs mt2">{_count(t["count"], "more request is", "more requests are")} '
            "in the developer's test scripts, which Home Assistant never loads"
            f"{f' ({files})' if files else ''}. They aren't listed here.</div>")  # fmt: skip


def requests_elsewhere_html(report: dict[str, Any]) -> str:
    """Requests whose address isn't in the code: counted apart, under the sites."""
    r = report.get("requests")
    shapes = [x for x in (r.get("elsewhere") if isinstance(r, dict) else None) or []
              if isinstance(x, dict)]  # fmt: skip
    if not shapes:
        note = _test_requests(r)
        return f'<div class="zone">{note}</div>' if note else ""
    by: dict[str, int] = {}
    for x in shapes:
        m = str(x.get("method") or "")
        m = (
            m
            if m in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
            else "with the method picked while it runs"
        )
        by[m] = by.get(m, 0) + (x["count"] if isinstance(x.get("count"), int) else 1)
    total = sum(by.values())
    kinds = ", ".join(f"{n} {m}" for m, n in sorted(by.items(), key=lambda kv: -kv[1]))
    blocks = "".join(request_block(x, here=False) for x in shapes)
    return (
        f'<div class="zone"><h3>{icon("plug")} Requests to addresses that aren\'t in the code</h3>'
        f'<div class="zs">{_count(total, "request goes", "requests go")} to an address the code '
        f"only works out while the app runs ({e(kinds)}), for example from a device or a server "
        "you entered during setup. Barkley can't say where they go.</div>"
        f'<details class="more"><summary>Where in the code</summary><div class="in">{blocks}'
        f"</div></details>{_test_requests(r)}</div>"
    )


def _fold(item_id: str, summary: str, body: str, open_: bool) -> str:
    """One site or port as one line that folds open (script-free <details>). The id is the
    anchor the AI sheet's Close goes back to."""
    anchor = f' id="item-{e(item_id, 40)}"' if item_id else ""
    return (f'<li><details class="site"{anchor}{" open" if open_ else ""}><summary>{summary}'
            f"</summary><div class=\"in\">{body}</div></details></li>")  # fmt: skip


def _host_li(
    h: Host,
    deep: str = "",
    open_: bool = False,
    dev_words: bool = True,
    near: frozenset = frozenset(),
    reqs: Any = None,
    elsewhere: bool = False,
) -> str:
    """One line per site: the name and whether Barkley flagged it. Inside: scheme, port (the
    URL's own, else the scheme's default) and encryption, who runs it, the addresses, where
    the code names it, and Explain in context. The port is said per site, so a port listed
    under "address not in the code" is never mistaken for this one."""
    bits = []
    explicit = sorted(set(h.ports))
    for s in sorted(set(h.schemes)):
        nums = explicit or [_DEFAULT_PORT[s]] if s in _DEFAULT_PORT else explicit
        port = f" · port {', '.join(map(str, nums))}" if nums else ""
        lock = _lock(s) if h.cls not in ("link", "infrastructure") else ""
        bits.append(e(s) + port + lock)
    if not h.schemes and explicit:
        bits.append("port " + ", ".join(map(str, explicit)))
    flag = ' <span class="chip bad">see findings</span>' if h.flagged else ""
    # whose address it is: a name from our own list, never a verdict
    who = f'<span class="u">{e(h.service, 120)}</span>' if h.service else ""
    how = f'<span class="u">{" · ".join(bits)}</span>' if bits else ""
    urls = "".join(f'<span class="u"><code>{e(u, 200)}</code></span>' for u in h.urls[:3])
    if len(h.urls) > 3:
        rest = "".join(f'<span class="u"><code>{e(u, 200)}</code></span>' for u in h.urls[3:50])
        n = len(h.urls) - 3
        urls += (f'<details class="more"><summary>{n} more address{"es" * (n != 1)}</summary>'
                 f'<div class="in">{rest}</div></details>')  # fmt: skip
    where = (f'<span class="u">In the code at {e(", ".join(h.where[:3]), 300)}'
             f"{f' and {len(h.where) - 3} more places' if len(h.where) > 3 else ''}</span>"
             if h.where else "")  # fmt: skip
    back = ('<span class="u">Barkley found it only in a list of sign-in return addresses '
            "(OAuth): your browser goes there after you approve access. Barkley found no "
            "code that sends anything there.</span>") if h.redirect else ""  # fmt: skip
    said = []  # (0.15) what the developer's own docs say: shown as theirs, never scored
    if h.readme_line:
        said.append(f"Its README mentions this site (line {int(h.readme_line)}).")
    if h.funding:
        said.append("The repository lists it as a way to support the developer.")
    # (his rule 2026-11-20) never beside a threat: not on a flagged site, nor on a page
    # with a found threat (dev_words False)
    dev = (f'<span class="u">{src_tag("dev")} {e(" ".join(said))}</span>'
           if said and dev_words and not h.flagged and h.name not in near else "")  # fmt: skip
    return _fold(h.edge_id, f"<code>{e(h.name, 120)}</code>{flag}", who + back + dev + how
                 + _requests_spans(reqs, elsewhere) + urls + where + deep, open_)  # fmt: skip


def _zone_list(items: list[str], shown: int = ZONE_SHOWN) -> str:
    """The first `shown` lines, then the rest behind "N more" (a fold, no script)."""
    head = "".join(items[:shown])
    rest = items[shown:]
    if not rest:
        return f"<ul>{head}</ul>"
    return (f'<ul>{head}<li><details class="more"><summary>{len(rest)} more</summary>'
            f'<ul>{"".join(rest)}</ul></details></li></ul>')  # fmt: skip


def zones_html(
    report: dict[str, Any],
    deep: DeepFn | None = None,
    open_id: str = "",
    dev_words: bool = True,
    part: str = "",
) -> str:
    near = threat_destinations(report)
    """`deep(edge_id, part=)` adds "Explain in context" to an address or port: the button
    inside the site's fold, the sheet after the zones (a sheet inside a closed fold
    wouldn't show). `open_id`: the item whose sheet is open (?open=), so its fold is too."""
    hs = hosts(report)
    pts = ports(report)
    reqs = site_requests(report)
    elsewhere = requests_elsewhere_html(report)
    read = isinstance(report.get("requests"), dict)  # the scan read the requests
    # (0.15, his decision 2026-11-21) `part`: "connects" = the sites Barkley read a request
    # to (and any site with a threat item, so none is ever tucked away), the ports and the
    # requests without a site; "mentioned" = every other address in the code. "" = all.
    if part == "connects":
        hs = [h for h in hs if h.name in reqs or h.flagged or h.name in near]
        if not hs and not pts and not elsewhere:
            return '<p class="muted">Barkley read no request to a site named in the code.</p>'
    elif part == "mentioned":
        hs = [h for h in hs if not (h.name in reqs or h.flagged or h.name in near)]
        pts, elsewhere, read = [], "", False
        if not hs:
            return ""
    if not hs and not pts:
        none = '<p class="muted">Its code names no sites, IP addresses or ports.</p>'
        return none + (f'<div class="zones">{elsewhere}</div>' if elsewhere else "")

    def inline(item_id: str) -> str:
        return deep(item_id, part="inline") if deep and item_id else ""

    out = ['<div class="zones">']
    for key, ic, title, sub, classes in ZONES:
        zh = [h for h in hs if h.cls in classes]
        if not zh:
            continue
        lis = [_host_li(h, inline(h.edge_id), bool(open_id) and h.edge_id == open_id,
                        dev_words, near,
                        reqs.get(h.name, [] if read and not h.redirect else None),
                        bool(elsewhere)) for h in zh]  # fmt: skip
        out.append(f'<div class="zone {key}"><h3>{icon(ic)} {title}</h3><div class="zs">{sub}'
                   f"</div>{_zone_list(lis)}</div>")  # fmt: skip
    if pts:
        items = []
        for p in pts:
            known = WELL_KNOWN_PORTS.get(p.port)
            label = f"{known[0]}, port {p.port}" if known else f"Port {p.port}"
            names = ", ".join(f"<code>{e(n, 60)}</code>" for n in p.names[:2])
            where = (f'<span class="u">In the code at {e(", ".join(p.where[:3]), 300)}</span>'
                     if p.where else "")  # fmt: skip
            how = {
                "out": "It connects out to it.",
                "in": "It listens on it, so others connect in.",
            }.get(p.direction or "", "The code doesn't make the direction clear.")
            body = (f'<span class="u">{_lock(p.port).strip()}</span><span class="u">{e(how)}'
                    f"</span>{f'<span class=\"u\">Named {names}</span>' if names else ''}"
                    f"{where}{inline(p.edge_id)}")  # fmt: skip
            items.append(_fold(p.edge_id, e(label), body, bool(open_id) and p.edge_id == open_id))
        out.append(
            f'<div class="zone"><h3>{icon("plug")} Connections whose address isn\'t in the code</h3>'
            '<div class="zs">The code sets these ports, but the server\'s address comes from '
            "setup or from another server while the app runs. So Barkley can't tie them to any "
            f"site listed here.</div>{_zone_list(items)}</div>"
        )
    out.append(elsewhere)
    out.append("</div>")
    if deep:  # every sheet outside the folds, once
        out.extend(deep(i, part="sheet") for i in dict.fromkeys(
            [h.edge_id for h in hs if h.edge_id] + [p.edge_id for p in pts if p.edge_id]))  # fmt: skip
    return "".join(out)


# --- history -----------------------------------------------------------------------------------


_SCAN_KIND = {"code": "code", "deps": "dependencies", "secrets": "leaked secrets",
              "practices": "security practices"}  # fmt: skip
_ECO = {"pip": "Python packages", "npm": "JavaScript packages", "github-actions": "GitHub "
        "Actions", "docker": "Docker images"}  # fmt: skip


def _ago(days: int | None) -> str:
    if days is None:
        return ""
    if days < 1:
        return "opened today"
    if days < 60:
        return f"{days} day{'s' * (days != 1)} old"
    return f"{days // 30} months old"


_SIGNATURE_LINE = {
    "github": "This version's commit was made on github.com, and GitHub signed it.",
    "developer": "This version's commit is signed with the developer's own key, and GitHub "
    "verified the signature.",
    "unsigned": "This version's commit isn't signed. That's common, and says nothing bad on "
    "its own.",
    "unverified": "This version's commit has a signature that GitHub couldn't verify.",
}


def hygiene_html(report: dict[str, Any]) -> str:
    """The repo's own security habits: context, never scored, inferred from public signs."""
    h = report.get("hygiene")
    if not isinstance(h, dict):
        return ""
    repo = str(report.get("target", {}).get("repo") or "")
    yes, no = icon("check", 14, "ok"), icon("minus", 14, "muted")
    li = []
    sc = [x for x in h.get("scanners") or [] if isinstance(x, dict)]

    def listed(items: list[dict[str, Any]]) -> str:
        return ", ".join(
            f"{e(x.get('name'))} ({_SCAN_KIND.get(x.get('kind'), 'checks')})" for x in items
        )

    in_ci = [x for x in sc if not x.get("via")]
    # (0.15) switched on in the repository's settings: no workflow file to read
    by_github = [x for x in sc if x.get("via") == "github"]
    hooks = [x for x in sc if x.get("via") and x not in by_github]  # pre-commit, lefthook, husky
    if in_ci:
        li.append(f"{yes} Runs security scans in its GitHub workflows: {listed(in_ci)}.")
    if by_github:
        li.append(f"{yes} GitHub's code scanning is switched on in the repository's settings: "
                  f"{listed(by_github)}.")  # fmt: skip
    for via in dict.fromkeys(str(x.get("via")) for x in hooks):
        mine = [x for x in hooks if x.get("via") == via]
        tool = e(via)
        if any(x.get("ci") for x in mine):
            li.append(f"{yes} Runs security checks with {tool}, and in its GitHub workflows: "
                      f"{listed(mine)}.")  # fmt: skip
        else:
            li.append(f"{yes} Runs security checks before each commit with {tool}: "
                      f"{listed(mine)}. Barkley didn't see them in its GitHub workflows.")  # fmt: skip
    if not sc:
        li.append(f"{no} Its GitHub workflows and commit hooks run no security scanner, "
                  "such as CodeQL, Semgrep, Bandit, Trivy, OSV-Scanner, pip-audit or "
                  "Gitleaks.")  # fmt: skip
    dep = h.get("dependabot")
    if dep is not None:
        what = ", ".join(_ECO.get(x, x) for x in dep) or "its dependencies"
        li.append(f"{yes} Dependabot is set up to propose updates for {e(what)}.")
    if h.get("renovate"):
        li.append(f"{yes} Renovate is set up to propose dependency updates.")
    if dep is None and h.get("dependabot_updates"):
        li.append(f"{yes} Dependabot's updates are switched on in the repository's settings.")
    elif dep is None and not h.get("renovate"):
        li.append(f"{no} Neither Dependabot nor Renovate is set up to propose dependency updates.")
    if h.get("security_policy"):
        li.append(f"{yes} Has a security policy (<code>{e(h['security_policy'])}</code>) that "
                  "says how to report a problem privately.")  # fmt: skip
    else:
        li.append(f"{no} It has no SECURITY.md that tells people how to report a problem "
                  "privately.")  # fmt: skip
    prs = h.get("update_prs")
    if isinstance(prs, dict) and prs.get("off"):
        li.append(f"{no} Pull requests are turned off on this repository.")
    elif isinstance(prs, dict):
        n = int(prs.get("open") or 0)
        oldest = prs.get("oldest_days")
        if n and isinstance(oldest, int) and oldest < HABITS_GRACE_DAYS:
            li.append(f"{yes} No dependency-update pull requests left waiting. {n} "
                      + ("is open, opened" if n == 1 else "are open, all opened")
                      + f" in the last {HABITS_GRACE_DAYS} days.")  # fmt: skip
        elif n:
            old = _ago(oldest)
            if old == "opened today":
                old = "was opened today"
            elif old:
                old = f"is {old}"
            li.append(f"<b>{n}</b> dependency-update pull "
                      + ("request is" if n == 1 else "requests are") + " waiting to be merged."
                      + (f" {'It' if n == 1 else 'The oldest'} {old}." if old else ""))  # fmt: skip
        elif dep is not None or h.get("renovate"):
            li.append(f"{yes} No dependency-update pull requests left waiting.")
    iss = h.get("security_issues")
    if isinstance(iss, dict) and iss.get("off"):
        li.append(f"{no} Issues are turned off on this repository, so there's no public place "
                  "to report a problem.")  # fmt: skip
    elif isinstance(iss, dict):
        n, of = int(iss.get("open") or 0), int(iss.get("of") or 0)
        among = " (among the 100 newest open issues)" if of >= 100 else ""
        if n:
            items = "".join(
                f'<li><a href="https://github.com/{e(repo)}/issues/{int(it["number"])}">'
                f"#{int(it['number'])}</a> {e(it.get('title'), 200)} "
                f'<span class="muted">{_ago(it.get("age_days"))}</span></li>'
                for it in iss.get("items") or []
                if isinstance(it.get("number"), int)
            )
            li.append(f"<b>{n}</b> open issue{'s' * (n != 1)} look{'s' * (n == 1)} "
                      f"security-related{among}:"
                      f'<ul class="plain">{items}</ul>')  # fmt: skip
        else:
            li.append(f"{yes} No open issue labeled or titled as a security problem "
                      f"({of} open issue{'s' * (of != 1)} checked).")  # fmt: skip
    if h.get("dependabot_but_known_vulns"):
        li.append(
            f"{icon('alert', 14, 'warn')} Dependabot watches these dependencies, but this "
            "release ships some with known vulnerabilities (listed above). Either nobody acted "
            "on an alert, or the fix came after this release."
        )
    for err in h.get("errors") or []:
        li.append(f'<span class="muted">Not checked: {e(err, 300)}</span>')
    star = (f'<p class="aplus">{icon("star", 16)} A+ security habits</p>'
            if all_green(h) else "")  # fmt: skip
    return (
        '<section class="box"><h2>The developer\'s security habits</h2>'
        + star
        + '<p class="sub">This is what the '
        "app's own repository shows about how it's kept safe. It never changes "
        "the readings. GitHub keeps scan alerts private, so Barkley reads public signs instead.</p>"
        '<ul class="plain marks">' + "".join(f"<li>{x}</li>" for x in li) + "</ul></section>"
    )


def libraries_html(report: dict[str, Any], inner: bool = False) -> str:
    """(0.14.1) Files identical to a published npm file, not read as code
    (analyzers/libraries.py). Names, versions and dates come from jsDelivr and npm and the
    file names from the app: all escaped. `inner`: as a part of "Where its code comes
    from" (a sub-heading, no box of its own)."""
    libs = [x for x in report.get("libraries") or [] if isinstance(x, dict)]
    lk = report.get("library_lookups") if isinstance(report.get("library_lookups"), dict) else {}
    read = [x for x in lk.get("read") or [] if isinstance(x, dict)]
    said = [x for x in lk.get("headers") or [] if isinstance(x, dict) and x.get("says")]
    if (report.get("readings") or {}).get("threat_level") == "found":
        said = []  # the developer's text is never shown beside a found threat
    if not libs and not read and not said:
        return ""

    def line(lib: dict[str, Any], was_read: bool) -> str:
        # (0.15) one line per package; the dates, downloads and files fold open, and a long
        # list shows 5 then "N more" (his decision 2026-11-20: long lists aren't dumped)
        files = [f for f in lib.get("files") or [] if isinstance(f, str)]
        facts = []
        if was_read:
            why = _LIB_WHY.get(str(lib.get("why")), "it didn't pass every check")
            facts.append(f"Barkley read this as code, because {why}.")
        if lib.get("published"):
            facts.append(f"Published {e(lib['published'], 20)}.")
        weekly = lib.get("weekly_downloads")
        if isinstance(weekly, int):
            facts.append(f"{weekly:,} downloads last week.")
        known = lib.get("advisories")
        if isinstance(known, int) and not isinstance(known, bool):
            facts.append("No known security problems are listed for this version." if known == 0
                         else f"{known} known security problem{'s are' if known != 1 else ' is'} "
                         "listed for this version.")  # fmt: skip
        n = len(files)
        shown = "".join(f'<span class="u"><code>{e(f, 300)}</code></span>' for f in files[:50])
        if n > 50:
            shown += f'<span class="u">and {n - 50} more files</span>'
        tag = "read as code" if was_read else "not read"
        bugs = ""
        if isinstance(known, int) and not isinstance(known, bool) and known > 0:
            bugs = (f' <span class="pk bug">{icon("bug", 14)} '
                    f'{_count(known, "known bug", "known bugs")}</span>')  # fmt: skip
        return (
            f'<li><details class="site"><summary><b>{e(lib.get("name"), 120)} '
            f'{e(lib.get("version"), 80)}</b> <span class="muted">· {n} file{"s" * (n != 1)}'
            f' · {tag}</span>{bugs}</summary><div class="in">'
            + (f'<span class="u">{" ".join(facts)}</span>' if facts else "")
            + f"{shown}</div></details></li>"
        )

    items = [line(x, False) for x in libs] + [line(x, True) for x in read]
    counts = []
    for key, one, many in (
        ("no_match", "One large JavaScript file matched no published file",
         "{} large JavaScript files matched no published file"),
        ("not_npm", "One matched a file that isn't from npm", "{} matched files that aren't from npm"),
        ("unanswered", "One lookup got no answer", "{} lookups got no answer"),
    ):  # fmt: skip
        n = lk.get(key)
        if isinstance(n, int) and not isinstance(n, bool) and n > 0:
            counts.append(one if n == 1 else many.format(n))
    rest = (f'<p class="sub mt2">{". ".join(counts)}. Barkley read all of those as code.</p>'
            if counts else "")  # fmt: skip
    if said:  # (0.15) what an unrecognised file says it is: the developer's text, a note
        rows = []
        for x in said[:10]:
            n = x.get("advisories")
            osv_says = ""
            if isinstance(n, int) and not isinstance(n, bool):
                osv_says = (" If that is right, no known security problems are listed for that "
                            "version." if n == 0 else
                            f" If that is right, {n} known security problem{'s are' if n != 1 else ' is'}"
                            " listed for that version.")  # fmt: skip
            rows.append(f"<li><code>{e(x.get('file'), 200)}</code> says in its first lines that "
                        f"it is <b>{e(x.get('says'), 60)} {e(x.get('version'), 30)}</b>."
                        f"{osv_says}</li>")  # fmt: skip
        rest += (f'<p class="sub mt2">{src_tag("dev")} Barkley can\'t confirm what these files '
                 "say about themselves, so it read them as code and counts nothing from this.</p>"
                 f'<ul class="plain">{"".join(rows)}</ul>')  # fmt: skip
    intro = (
        "These "
        "files are exact copies of files that npm packages publish. Barkley doesn't read a "
        "copy as code when the package is well known: at least a month old, at least 10,000 "
        "downloads a week and no malware warning. It still checks that package for known "
        "security problems, like any dependency. Every other file is read as code, and so is "
        "a file that differs by even one byte."
    )
    body = f'<div class="libs">{_zone_list(items)}</div>{rest}'
    if inner:
        return (f'<h3 class="kindh">Published libraries it ships ({len(items)})</h3>'
                f'<p class="sub">{intro}</p>{body}')  # fmt: skip
    return (f'<section class="box"><h2>Published libraries it ships</h2><p class="sub">{intro}'
            f"</p>{body}</section>")  # fmt: skip


_LIB_WHY = {
    "new": "this version was published less than a month ago",
    "few_downloads": "the package has fewer than 10,000 downloads a week",
    "no_facts": "npm didn't say when this version was published or how often it's downloaded",
    "malware": "there is a malware warning for this package version",
    "unchecked": "Barkley couldn't check it for malware warnings",
}


def environment_html(report: dict[str, Any]) -> str:
    """(0.15) The environment variables the code reads and sets, by name
    (analyzers/py_env). Names are plain names from the scanned code: still escaped."""
    env = report.get("environment")
    if not isinstance(env, dict):
        return ""

    def at(d: dict[str, Any]) -> str:
        places = [a for a in d.get("at") or [] if isinstance(a, str)]
        n = d.get("count") if isinstance(d.get("count"), int) else len(places)
        rest = n - len(places)
        return (f' <span class="muted">{e(", ".join(places), 300)}'
                f'{f" and {rest} more" if rest > 0 else ""}</span>') if places else ""  # fmt: skip

    li = []
    for d in [x for x in env.get("reads") or [] if isinstance(x, dict)]:
        own = " The app sets this one itself." if d.get("own") else ""
        li.append(f"Reads <code>{e(d.get('name'), 80)}</code>.{own}{at(d)}")
    for d in [x for x in env.get("writes") or [] if isinstance(x, dict)]:
        li.append(f"Sets or removes <code>{e(d.get('name'), 80)}</code>.{at(d)}")
    n = env.get("unnamed_reads")
    if isinstance(n, int) and n > 0:
        li.append(f"Reads {'one' if n == 1 else n} more whose name{'s are' if n != 1 else ' is'} "
                  "put together while the app runs.")  # fmt: skip
    n = env.get("unnamed_writes")
    if isinstance(n, int) and n > 0:
        li.append(f"Sets {'one' if n == 1 else n} more whose name{'s are' if n != 1 else ' is'} "
                  "put together while the app runs.")  # fmt: skip
    whole = env.get("whole") if isinstance(env.get("whole"), dict) else {}
    if isinstance(whole.get("count"), int) and whole["count"] > 0:
        li.append("Uses all of them at once, for example to copy them or hand them to another "
                  f"program.{at(whole)}")  # fmt: skip
    if not li:
        if not isinstance(env.get("reads"), list) or not isinstance(env.get("writes"), list):
            return ""
        return ('<section class="box"><h2>Environment variables it uses</h2><p>'
                f'{icon("check", 14, "ok")} This app neither reads nor sets any environment '
                "variables.</p></section>")  # fmt: skip
    items = [f'<li><span class="u">{x}</span></li>' for x in li]
    return (
        '<section class="box"><h2>Environment variables it uses</h2><p class="sub">These are '
        "settings of the system Home Assistant runs on. Most are harmless, like the time zone. "
        "On Home Assistant OS one of them holds the Supervisor's key, and Barkley lists a read "
        "of that one under What it can do.</p>"
        f'<div class="libs">{_zone_list(items)}</div></section>'
    )


PACKAGES_LISTED = 300  # package lines drawn (a real integration has 78)
RUNTIME_CODE_RULES = (  # code that arrives some other way than the release Barkley read
    "py-runtime-pip",
    "py-runtime-pip-listed",
    "card-remote-script",
    "card-eval-remote",
    "dep-vcs-or-url-requirement",
)
_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")


def _day(value: Any) -> str:
    """The date part of a timestamp from GitHub, or "" when it isn't one."""
    m = _DAY.match(str(value or ""))
    return m[0] if m else ""


def quiet(report: dict[str, Any], today: date | None = None) -> tuple[str, str]:
    """(chip, sentence) when the project is archived, or nothing was pushed to it for as
    long as the Quiet projects setting says (report.shown.quiet_months; 0: never). From
    GitHub's repository record as it was when the scan ran; ("", "") otherwise."""
    prov = report.get("provenance") if isinstance(report.get("provenance"), dict) else {}
    shown = report.get("shown") if isinstance(report.get("shown"), dict) else {}
    months = shown.get("quiet_months", 12)
    months = months if isinstance(months, int) and not isinstance(months, bool) else 12
    if prov.get("archived") is True:
        return ("Archived project", "The owner has archived the project on GitHub: it is "
                "read-only and gets no more updates.")  # fmt: skip
    day = _day(prov.get("pushed_at"))
    if not day or months <= 0:
        return "", ""
    try:
        then = date.fromisoformat(day)
    except ValueError:
        return "", ""
    today = today or datetime.now(UTC).date()
    gone = (today.year - then.year) * 12 + today.month - then.month - (today.day < then.day)
    if gone < months:
        return "", ""
    span = (_count(gone // 12, "year", "years") if gone >= 24
            else "a year" if gone >= 12 else _count(gone, "month", "months"))  # fmt: skip
    over = "" if gone % 12 == 0 and gone >= 12 else "over " if gone >= 12 else ""
    return (f"No changes in {over}{span}",
            f"The project has gone quiet: when Barkley sniffed it, the last push to it on "
            f"GitHub was on {day}, {over}{span} ago.")  # fmt: skip


def _count(n: int, one: str, many: str) -> str:
    return f"one {one}" if n == 1 else f"{n:,} {many}"


def _supply_repo(report: dict[str, Any]) -> str:
    """The project and this release: what the Marketplace installs, whose project it is,
    who published the release, how the commit is signed. All from GitHub's API, read
    during the scan (report.provenance, report.target)."""
    t = report.get("target") if isinstance(report.get("target"), dict) else {}
    prov = report.get("provenance") if isinstance(report.get("provenance"), dict) else {}
    ref = f"<code>{e(t.get('ref'), 80)}</code>" if t.get("ref") else "this version"
    li = []
    src = str(t.get("install_source") or "")
    if src == "release_asset":
        li.append(f"The Marketplace installs a file attached to release {ref}. Barkley read "
                  "that file.")  # fmt: skip
    elif src == "tag_source":
        li.append(f"The Marketplace installs the code as it is at {ref}. Barkley read that code.")
    elif src == "default_branch":
        li.append("The project has no release the Marketplace can use, so it installs the "
                  "newest code. Barkley read that code as it was at one commit.")  # fmt: skip
    full = str(prov.get("full_name") or "")
    if full:
        whose = {"Organization": "an organization's account",
                 "User": "one person's account"}.get(str(prov.get("owner_type")), "")  # fmt: skip
        made = _day(prov.get("created_at"))
        li.append(f"The project is <code>{e(full, 200)}</code> on GitHub"
                  + (f", under {whose}" if whose else "")
                  + (f". It was created on {made}." if made else "."))  # fmt: skip
    for f in [x for x in prov.get("former_names") or [] if isinstance(x, dict)][:5]:
        if f.get("name"):
            li.append(f"It used to be at <code>{e(f['name'], 200)}</code>.")
    _chip, gone_quiet = quiet(report)
    if gone_quiet:
        bugs = any(m["bugs"] or m["malware"] for m in _package_marks(report).values())
        li.append(f"<b>{e(gone_quiet)}</b>"
                  + (" The known bugs in its packages are unlikely to be fixed." if bugs else ""))
    elif _day(prov.get("pushed_at")):
        li.append("When Barkley sniffed it, the last push to the project on GitHub was on "
                  f"{_day(prov.get('pushed_at'))}.")  # fmt: skip
    rels = [x for x in prov.get("releases") or [] if isinstance(x, dict)]
    mine = next((x for x in rels if x.get("installed")), None)
    if mine and mine.get("publisher"):
        when = _day(mine.get("published_at"))
        bot = ", an automated workflow" if mine.get("bot") else ""
        li.append(f"This release was published by <code>{e(mine['publisher'], 80)}</code>{bot}"
                  + (f"{',' if bot else ''} on {when}." if when else "."))  # fmt: skip
        other = [u for u in mine.get("asset_uploaders") or []
                 if isinstance(u, str) and u != mine["publisher"]]  # fmt: skip
        if other:
            li.append("Its files were uploaded by "
                      + ", ".join(f"<code>{e(u, 80)}</code>" for u in other[:5]) + ".")  # fmt: skip
    pubs = [p for p in prov.get("publishers") or []
            if isinstance(p, dict) and isinstance(p.get("releases"), int)]  # fmt: skip
    if pubs:
        total = sum(p["releases"] for p in pubs)
        rows = "".join(
            f"<li><code>{e(p.get('login'), 80)}</code>"
            f"{' (an automated workflow)' if p.get('bot') else ''}: "
            f"{_count(p['releases'], 'release', 'releases')}"
            + (f", {_day(p.get('first'))} to {_day(p.get('last'))}"
               if _day(p.get("first")) and _day(p.get("last")) != _day(p.get("first"))
               else f", {_day(p.get('first'))}" if _day(p.get("first")) else "")
            + "</li>"
            for p in pubs[:20]
        )  # fmt: skip
        li.append(
            f"The project has {_count(total, 'release', 'releases')}, from "
            f"{_count(len(pubs), 'publisher', 'publishers')}."
            f'<details class="more"><summary>Who published them</summary>'
            f'<ul class="plain">{rows}</ul></details>'
        )
    sig = (t.get("signature") or {}).get("state") if isinstance(t.get("signature"), dict) else ""
    if sig in _SIGNATURE_LINE:  # GitHub's verdict on this version's commit
        li.append(_SIGNATURE_LINE[sig])
    noted = dict.fromkeys(
        explain.explain(str(f.get("rule_id"))).title
        for f in report.get("findings") or []
        if str(f.get("rule_id")).startswith("repo-")
    )
    li.extend(f"<b>{e(x)}.</b> More about it above, under How it's made." for x in noted)
    if not li:
        return ""
    return ('<h3 class="kindh">The project and this release</h3><ul class="plain">'
            + "".join(f"<li>{x}</li>" for x in li) + "</ul>")  # fmt: skip


def _checked_line(report: dict[str, Any], analyzer: str) -> str:
    """ "Checked for malware warnings: 0 · known bugs: 0" above a package list, from the
    scan's own items, when the advisory check ran; what didn't run otherwise."""
    state = next((a.get("state") for a in report.get("analyzers") or []
                  if a.get("name") == analyzer), None)  # fmt: skip
    if state is None:
        return ""
    if state != "ok":
        return (f'<p class="pkchk">{icon("minus", 14, "muted")} Barkley couldn\'t check these '
                "packages for malware warnings and known bugs in this scan.</p>")  # fmt: skip
    marks = _package_marks(report).values()
    counts = (
        ("malware warnings", sum(1 for m in marks if m["malware"])),
        ("with known bugs", sum(1 for m in marks if m["bugs"])),
    )
    bits = "".join(
        f'<span class="pk {"bad" if n else "ok"}">{icon("alert" if n else "check", 14)} '
        f"<b>{n}</b> {label}</span>"
        for label, n in counts
    )
    return (f'<p class="pkchk">{bits}<span class="muted">Every package checked against OSV\'s '
            "list of malware and known bugs.</span></p>")  # fmt: skip


# What the advisory check writes as a package finding's evidence: "name@1.2.3 (npm): IDS"
_DEP_EVIDENCE = re.compile(r"(@?[^@\s]{1,214})@(\S{1,80}) \((PyPI|npm)\): (.{0,2000})")


def _dep_of(f: dict[str, Any]) -> tuple[str, str, str, list[str]] | None:
    """(ecosystem, package, version, advisory ids) of a package finding: from its checked
    facts, else from its evidence line (malware warnings and build tools carry no facts)."""
    d = f.get("dependency")
    if isinstance(d, dict) and d.get("package"):
        ids = [str(a.get("id")) for a in d.get("advisories") or [] if isinstance(a, dict)]
        return (str(d.get("ecosystem") or ""), str(d["package"]), str(d.get("version") or ""),
                ids or [str(f.get("id"))])  # fmt: skip
    m = _DEP_EVIDENCE.fullmatch(str(f.get("evidence") or ""))
    if not m:
        return None
    return m[3], m[1], m[2], [x.strip() for x in m[4].split(",") if x.strip()] or [m[2]]


def _package_marks(report: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """What the advisory check found, per (ecosystem, package name): how many known bugs
    (each advisory once, however many versions have it), whether a malware warning names
    it, and the versions (a lock file can hold several)."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    seen: dict[tuple[str, str], set[str]] = {}
    for f in report.get("findings") or []:
        rule = str(f.get("rule_id"))
        if rule != "dep-malicious" and rule not in kinds.VULNERABILITY_RULES:
            continue
        if (dep := _dep_of(f)) is None:
            continue
        eco, name, version, ids = dep
        key = (eco.lower(), name.lower())
        m = out.setdefault(key, {"name": name, "bugs": 0, "malware": False, "versions": [],
                                 "build": True})  # fmt: skip
        if rule == "dep-malicious":
            m["malware"] = True
        else:
            seen.setdefault(key, set()).update(ids)
            m["bugs"] = len(seen[key])
        m["build"] = m["build"] and rule == "dep-build-tool-vuln"
        if version and version not in m["versions"]:
            m["versions"].append(version)
    return out


def _mark_html(m: dict[str, Any] | None) -> str:
    """The icons beside an affected package: a warning sign for malware, a bug with the
    number of known bugs."""
    if not m:
        return ""
    out = ""
    if m["malware"]:
        out += f'<span class="pk bad">{icon("alert", 14)} malware warning</span>'
    if m["bugs"]:
        out += (f'<span class="pk bug">{icon("bug", 14)} '
                f'{_count(m["bugs"], "known bug", "known bugs")}</span>')  # fmt: skip
    return out


def _supply_packages(report: dict[str, Any]) -> str:
    """Every package the app is installed or built with: for an integration what Home
    Assistant would install (worked out by uv during the scan, the packages those bring
    along included), for a card the packages its package.json lists, and the ones its lock
    file brings along that have a known bug or a malware warning. Affected packages come
    first, each with an icon. Names and versions come from the scanned repo's files and the
    package index: escaped."""
    g, nodes = _graph(report)
    marks = _package_marks(report)
    py, npm = [], []
    for edge in g.get("edges", []):
        if edge.get("source") != g.get("subject"):
            continue
        label = str(nodes.get(edge.get("target"), {}).get("label", ""))
        eco, _, name = label.partition("/")
        a = edge.get("attrs") if isinstance(edge.get("attrs"), dict) else {}
        if edge.get("relation") == "depends_on" and eco == "pypi" and name:
            py.append((name, a, marks.get(("pypi", name.lower()))))
        elif edge.get("relation") == "bundles" and eco == "npm" and name:
            npm.append((name, a, marks.get(("npm", name.lower()))))

    def line(name: str, facts: list[str], m: dict[str, Any] | None) -> str:
        tail = "".join(f" · {e(x, 80)}" for x in facts)
        return (f'<li><code>{e(name, 120)}</code><span class="muted">{tail}</span>'
                f"{_mark_html(m)}</li>")  # fmt: skip

    def first(m: dict[str, Any] | None) -> tuple[bool, bool]:
        return (not (m and m["malware"]), not m)  # malware, then known bugs, then the rest

    out = []
    if py:
        py.sort(key=lambda x: (*first(x[2]), not x[1].get("direct"), x[0]))
        n = len(py)
        direct = sum(1 for _n, a, _m in py if a.get("direct"))
        if any("version" in a for _n, a, _m in py):
            shipped = sum(1 for _n, a, _m in py if a.get("ha_provided"))
            ha = e(report.get("ha_version") or "", 20)
            rest = n - direct
            text = (f"Home Assistant installs {_count(n, 'Python package', 'Python packages')} "
                    "for this app. "
                    + ("The app asks for all of them itself." if not rest else
                       f"The app asks for {'one' if direct == 1 else direct} of them itself, and "
                       f"the other {'one comes' if rest == 1 else f'{rest} come'} along with "
                       f"{'it' if direct == 1 else 'those'}.")
                    + (f" Home Assistant{' ' + ha if ha else ''} already ships "
                       f"{'all of them' if shipped == n else f'{shipped} of them'} at the same "
                       "version." if shipped else ""))  # fmt: skip
        else:  # a scan that couldn't work out the full list (offline)
            text = (f"The app asks for {_count(n, 'Python package', 'Python packages')}. "
                    "Barkley didn't work out what those bring along in this scan.")  # fmt: skip
        items = []
        for name, a, m in py[:PACKAGES_LISTED]:
            facts = [str(a["version"])] if a.get("version") else []
            if a.get("requirement") and not a.get("version"):
                facts.append(str(a["requirement"]))
            facts.append("the app asks for it" if a.get("direct") else "comes along")
            if a.get("ha_provided"):
                facts.append("Home Assistant already ships it")
            items.append(line(name, facts, m))
        if n > PACKAGES_LISTED:
            items.append(f"<li>and {n - PACKAGES_LISTED:,} more</li>")
        out.append(f'<h3 class="kindh">Python packages ({n:,})</h3>'
                   f'<p class="sub">{text}</p>{_checked_line(report, "osv-python")}'
                   f'<div class="libs">{_zone_list(items)}</div>')  # fmt: skip
    listed = {name.lower() for name, _a, _m in npm}
    # (0.15, his report) a card's lock file brings along packages its package.json doesn't
    # name; the ones with a known bug or a malware warning are listed too
    along = sorted((m for (eco, key), m in marks.items() if eco == "npm" and key not in listed),
                   key=lambda m: (*first(m), m["name"]))  # fmt: skip
    if npm or along:
        npm.sort(key=lambda x: (*first(x[2]), x[0]))
        n = len(npm)
        items = [line(name, [str(a["spec"])] if a.get("spec") else [], m)
                 for name, a, m in npm[:PACKAGES_LISTED]]  # fmt: skip
        if n > PACKAGES_LISTED:
            items.append(f"<li>and {n - PACKAGES_LISTED:,} more</li>")
        more = [
            line(m["name"], [", ".join(m["versions"][:6])] * bool(m["versions"])
                 + ["only used to build it" if m["build"] else "comes along through the lock file"],
                 m)
            for m in along[:PACKAGES_LISTED]
        ]  # fmt: skip
        out.append(f'<h3 class="kindh">npm packages it is built from ({n:,})</h3>'
                   f'<p class="sub">Its <code>package.json</code> lists '
                   f"{_count(n, 'npm package', 'npm packages')}, with the versions it accepts. "
                   "The developer builds them into the file you install.</p>"
                   f"{_checked_line(report, 'osv-npm')}"
                   + (f'<div class="libs">{_zone_list(items)}</div>' if items else "")
                   + (f'<p class="sub">Its lock file brings along '
                      f"{_count(len(along), 'more package', 'more packages')} with a known bug or "
                      "a malware warning. The rest of the lock file's packages aren't listed "
                      f'here.</p><div class="libs">{_zone_list(more, 25)}</div>'
                      if more else ""))  # fmt: skip
    return "".join(out)


def _supply_runtime(report: dict[str, Any]) -> str:
    """Code that doesn't come with the release: installed or downloaded while the app
    runs, or a library taken straight from a web address. From the scan's own items."""
    by: dict[str, list[dict[str, Any]]] = {}
    for f in report.get("findings") or []:
        if str(f.get("rule_id")) in RUNTIME_CODE_RULES:
            by.setdefault(str(f["rule_id"]), []).append(f)
    head = '<h3 class="kindh">Code it gets while it runs</h3>'
    if not by:
        kind = str((report.get("target") or {}).get("kind"))
        what = ("that loads code from a website while the card runs" if kind in ("plugin", "card")
                else "that installs packages while the app runs")  # fmt: skip
        who = ("Barkley found" if report.get("complete", True)
               else "In the part Barkley could check, it found")  # fmt: skip
        return f'{head}<p class="sub">{who} nothing {what}.</p>'
    li = []
    for rule in RUNTIME_CODE_RULES:
        fs = by.get(rule) or []
        if fs:
            li.append(f"<b>{e(explain.explain(rule).title)}.</b> "
                      f'<span class="muted">{_where(fs)}</span>')  # fmt: skip
    return (f'{head}<p class="sub">Barkley can only read the code in the release. It '
            'never sees code that arrives later.</p><ul class="plain">'
            + "".join(f"<li>{x}</li>" for x in li) + "</ul>")  # fmt: skip


def supply_html(report: dict[str, Any]) -> str:
    """(0.15, his decision 2026-11-20) "Where its code comes from": the project and this
    release, every Python or npm package, the published libraries copied into it, and
    code it gets while it runs. Facts from the scan; nothing here is scored."""
    parts = [_supply_repo(report), _supply_packages(report),
             libraries_html(report, inner=True), _supply_runtime(report)]  # fmt: skip
    if not any(parts[:3]) and "nothing" in parts[3]:
        return ""  # a report with none of these facts (a local folder scanned offline)
    return ('<section class="box"><h2>Where its code comes from</h2>'
            + "".join(parts) + "</section>")  # fmt: skip


def cache_text(report: dict[str, Any]) -> str:
    """(0.14.1) "124 of 124 files from the cache, about 3 min saved" on its own line under
    the facts, for a scan that used the cache (scancache); nothing otherwise."""
    c = report.get("cache")
    if not isinstance(c, dict):
        return ""
    hits, files, saved = c.get("hits"), c.get("files"), c.get("saved_secs")
    if not (isinstance(hits, int) and isinstance(files, int) and hits > 0):
        return ""
    when = (
        f", which saved {scancache.saved_text(float(saved))}"
        if isinstance(saved, (int, float)) and saved >= 1
        else ""
    )
    return (
        f'<p class="muted small">{icon("check", 12, "ok")} Barkley reused {hits:,} of {files:,} '
        f"files it had already read{when}.</p>"
    )


def rules_label(v: str) -> str:
    """(0.14.1) A stored scan's rules: a scan-logic key (logic.py) as its first 7 hex
    digits, an older scan's tool version as it is."""
    return v.removeprefix("logic-")[:7] if v.startswith("logic-") else v


def history_html(base: str, sid: int, report: dict[str, Any], rows: list[ScanRow]) -> str:
    items = []
    ordered = sorted(rows, key=lambda r: r.id)
    prev: ScanRow | None = None
    for r in ordered:
        what = f'<a href="{base}/scan/{r.id}">{e(r.ref or "?", 40)}</a>'
        score = f"{r.score}" + ("" if r.complete else " (unfinished)")
        if prev is None:
            cause = "first check"
        elif prev.ref == r.ref and prev.tool_version != r.tool_version:
            cause = (
                f"Barkley's rules changed ({e(rules_label(prev.tool_version))} → "
                f"{e(rules_label(r.tool_version))})"
            )
        elif prev.ref == r.ref:
            cause = "checked again"
        else:
            link = f'<a href="{base}/diff?old={prev.id}&amp;new={r.id}">what changed</a>'
            older = False
            try:  # scan order isn't release order: an older release sniffed later
                older = version_key("npm", r.ref or "") < version_key("npm", prev.ref or "")
            except (TypeError, ValueError):
                older = False
            if older:
                cause = f"an older release than {e(prev.ref or '?', 40)} · {link}"
            else:
                cause = f"update {e(prev.ref or '?', 40)} → {e(r.ref or '?', 40)} · {link}"
        here = " <b>(this page)</b>" if r.id == sid else ""
        items.append(
            f"<li><b>{what}</b> · {score} · {cause} · "
            f'<span class="muted">{e(r.scanned_at[:10])}, rules version {e(rules_label(r.tool_version))}'
            f"</span>{here}</li>"
        )
        prev = r
    # (0.14.1, his pick) newest first; each line still compares with the scan before it
    items.reverse()
    p = report.get("provenance") or {}
    pubs = p.get("publishers") if isinstance(p, dict) else None
    pubs = [x for x in pubs if isinstance(x, dict)] if isinstance(pubs, list) else []
    if len(pubs) == 1 and not pubs[0].get("bot"):
        one = pubs[0]
        items.append(
            f"<li>Every one of its {int(one.get('releases', 0))} releases since "
            f"{e(str(one.get('first', ''))[:7])} was published by <code>{e(one.get('login'), 60)}</code>.</li>"
        )
    elif len(pubs) > 1:
        names = ", ".join(f"<code>{e(x.get('login'), 60)}</code>" for x in pubs[:4])
        items.append(
            f"<li>{len(pubs)} people have published releases: {names}"
            f"{' and more' if len(pubs) > 4 else ''}.</li>"
        )
    if isinstance(p, dict) and isinstance(p.get("former_names"), list) and p["former_names"]:
        items.append(
            "<li>The project used to live at "
            + ", ".join(f"<code>{e(n, 100)}</code>" for n in p["former_names"][:3])
            + ".</li>"
        )
    elif p:
        items.append(
            "<li>The project has never changed owner or name, as far as GitHub shows.</li>"
        )
    return '<ul class="plain">' + "".join(items[-12:]) + "</ul>"


# --- (0.14.0) part 3: kinds, the row under each item --------------------------------------

ReviewFn = Callable[[dict[str, Any], list[dict[str, Any]]], str]


_REPO_LINK = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}")


def facts_line(report: dict[str, Any]) -> str:
    """(0.15, his ask) The facts under the title at body size: what kind of app, the
    version, the repository (a link to GitHub, with its mark), stars and downloads. Stars
    and downloads are facts, never scored (popularity isn't safety, and stars can be
    bought). GitHub counts downloads only of files the developer uploads to a release, so
    an app installed from its Source code zip (most integrations) has no count: then
    nothing is said (his call 2026-11-20). Scans from before 0.14.0 have neither."""
    t = report.get("target") or {}
    parts = []
    kind = KIND.get(str(t.get("kind")), str(t.get("kind") or ""))
    if kind:
        parts.append(f"<span>{e(kind)}</span>")
    if t.get("ref"):
        parts.append(f"<span>{icon('tag')} {e(t['ref'], 60)}</span>")
    repo = str(t.get("repo") or "")
    if _REPO_LINK.fullmatch(repo):
        parts.append(f'<a href="https://github.com/{e(repo)}" target="_blank" '
                     f'rel="noopener noreferrer">{icon("github")} {e(repo)}</a>')  # fmt: skip
    elif t.get("input"):
        parts.append(f"<span>{e(t['input'], 120)}</span>")
    pop = report.get("popularity")
    if isinstance(pop, dict):
        stars = pop.get("stars")
        if isinstance(stars, int):
            parts.append(f"<span>{icon('star')} {stars:,} star{'s' * (stars != 1)}</span>")
        dl = pop.get("downloads")
        if isinstance(dl, int):
            parts.append(f"<span>{icon('download')} {dl:,} download{'s' * (dl != 1)}</span>")
    return f'<div class="facts">{"".join(parts)}</div>' if parts else ""


def _it_can(title: str) -> str:
    """ "It can change who can log in …"; a card's "Its dashboard card uses …" is already a
    sentence (it read "It can it dashboard card uses …" before)."""
    return f"{title}." if title.startswith("Its ") else f"It can {_can_phrase(title)}."


def _in_short_plain(report: dict[str, Any]) -> str:
    """(preview) In short, in plain words (his note 2026-11-20): where its code points,
    what it can do, and whether Barkley found your data leaving. Escaped text."""
    out: list[str] = []
    net = internet(hosts(report))
    home = any(h.cls == "local" for h in hosts(report))
    own = sum(1 for h in net if h.cls == "declared")
    n = len(net)
    if not n:
        out.append("Its code mentions no websites.")
    elif own == n:
        out.append(
            f"Its code mentions {n} website{'s' * (n != 1)}, "
            + (
                "the app's own."
                if n == 1
                else "all of them the app's own."
                if n > 2
                else "both the app's own."
            )
        )
    elif own:
        out.append(
            f"Its code mentions {n} websites. {own} of them {'is' if own == 1 else 'are'} "
            "the app's own."
        )
    else:
        out.append(f"Its code mentions {n} website{'s' * (n != 1)}.")
    if home:
        out.append("It also mentions addresses on your home network.")
    if pts := ports(report):
        out.append(ports_sentence(pts))
    titles = [
        explain.explain(g[0]["rule_id"]).title
        for g in scored_findings(report)
        if kinds.kind(str(g[0]["rule_id"])) == kinds.CAPABILITY
        and g[0]["severity"] in ("critical", "high", "medium")
    ][:3]
    # "Its dashboard card uses …" is a sentence already; the rest start with a verb
    whole = [t for t in titles if t.startswith("Its ")]
    can = [_can_phrase(t) for t in titles if not t.startswith("Its ")]
    out.extend(f"{t}." for t in whole)
    if can:
        out.append("It can " + (can[0] if len(can) == 1 else
                                ", ".join(can[:-1]) + " and " + can[-1]) + ".")  # fmt: skip
    fl = flows(report)
    if any(x["evidence"] == "proven" for x in fl):
        out.append("Barkley traced your data being sent off your Home Assistant machine.")
    elif fl:
        out.append("It reads private data and names websites Barkley can't explain. Barkley "
                   "found no direct path between the two.")  # fmt: skip
    else:
        out.append("Barkley found nothing that sends your data off your Home Assistant machine.")
    p = len(privacy.notes(report))
    if p:
        out.append(f"There {'is' if p == 1 else 'are'} {p} privacy note{'s' * (p != 1)} below.")
    if not report.get("complete"):
        out.append("Part of the check didn't finish.")
    return e(" ".join(out), 1200)


def _can_phrase(title: str) -> str:
    """ "Changes who can log in to Home Assistant" → "change who can log in to Home
    Assistant": the rule titles start with a verb in the third person."""
    word, _, rest = title.partition(" ")
    low = word.lower()
    base = {"has": "have", "does": "do", "is": "be"}.get(low)
    if base is None:
        if low.endswith(("ches", "shes", "sses", "xes", "zes")):
            base = low[:-2]
        elif low.endswith("ies") and len(low) > 4:
            base = low[:-3] + "y"
        elif low.endswith("s") and not low.endswith("ss"):
            base = low[:-1]
        else:
            return _lower1(title)
    return f"{base} {rest}".strip()


# The panel's words under each kind's heading (plain-words pass, 2026-11-20). They live
# here, not in kinds.py, so a wording change doesn't change the scan-logic key (kinds.py
# isn't panel-only).
KIND_BLURBS = {
    kinds.THREAT: "Signs of malicious behavior. For example, sending your data or logins out "
    "of your home, hidden or disguised code, or known malware.",
    kinds.CAPABILITY: "Powerful things the app can do. Some apps need them. They are also what "
    "an attacker would get if this app were ever taken over.",
    kinds.VULNERABILITY: "Security bugs that have been published in the code libraries it uses.",
    kinds.PRACTICE: "How the developer works and how the release was built.",
    kinds.COVERAGE: "Barkley couldn't check these parts of the code.",
}


def kinds_html(
    report: dict[str, Any],
    groups: list[tuple[dict[str, Any], list[dict[str, Any]], int]],
    render: Callable[[dict[str, Any], list[dict[str, Any]], int], str],
    skip: frozenset[str] = frozenset(),
    untitled: frozenset[str] = frozenset(),
) -> str:
    """What we found, by kind (Threats first; "No signs of malicious behavior" when there
    are none). `render` draws one finding group. `skip`: kinds shown elsewhere on the
    page (the preview's Threat box)."""
    by: dict[str, list[tuple[dict[str, Any], list[dict[str, Any]], int]]] = defaultdict(list)
    for g in groups:
        by[kinds.kind(str(g[0]["rule_id"]))].append(g)
    out = []
    for k in kinds.ORDER:
        if k in skip:
            continue
        items = by.get(k, [])
        if k == kinds.THREAT and not items:
            out.append(f'<h3 class="kindh">{e(kinds.TITLES[k])} (0)</h3>'
                       f'<p class="ok">{icon("check", 14, "ok")} No signs of malicious '
                       "behavior.</p>")  # fmt: skip
            continue
        if not items:
            continue
        if k in untitled:  # the section's own title already says it
            out.extend(render(*g) for g in items)
            continue
        out.append(f'<h3 class="kindh">{e(kinds.TITLES[k])} ({len(items)})</h3>'
                   f'<p class="sub small">{e(KIND_BLURBS[k])}</p>')  # fmt: skip
        out.extend(render(*g) for g in items)
    return "".join(out)


def minor_line(base: str, sid: int, report: dict[str, Any]) -> str:
    """The minor items left out of the page (Settings: Minor items), or shown. They never
    change the readings."""
    r = report.get("shown") or {}
    minor = r.get("minor") or []
    if not minor:
        return ""
    n = len(minor)
    chips = sorted({explain.explain(x).chip for x in minor})
    what = f"{n} minor thing{'s' * (n != 1)} ({e(', '.join(chips))})"
    if r.get("always"):
        return (f'<p class="muted small mt3">{what} {"is" if n == 1 else "are"} shown above '
                f'(<a href="{base}/settings">Settings</a>: Minor items).</p>')  # fmt: skip
    if r.get("show_minor"):
        return (f'<p class="muted small mt3">{what} {"is" if n == 1 else "are"} shown above. '
                f'<a href="{base}/scan/{sid}">Hide them</a></p>')  # fmt: skip
    return (f'<p class="muted small mt3">{what} {"isn" if n == 1 else "aren"}\'t shown. '
            f'<a href="{base}/scan/{sid}?minor=1">Show them</a></p>')  # fmt: skip


def all_green(h: Any) -> bool:
    """A+ security habits: every habit check green. A dependency-update pull request
    younger than HABITS_GRACE_DAYS doesn't count against it (user decision 2026-11-18)."""
    if not isinstance(h, dict) or h.get("errors"):
        return False
    prs, iss = h.get("update_prs"), h.get("security_issues")
    if not (isinstance(prs, dict) and not prs.get("off")):
        return False
    waiting = int(prs.get("open") or 0)
    oldest = prs.get("oldest_days")
    if waiting and not (isinstance(oldest, int) and oldest < HABITS_GRACE_DAYS):
        return False
    # (0.14.1) a scanner counts when it runs in CI: a workflow, or pre-commit run by one
    ci = [
        x for x in h.get("scanners") or []
        if isinstance(x, dict) and (not x.get("via") or x.get("ci") or x.get("via") == "github")
    ]  # fmt: skip
    return (
        bool(ci)
        and (h.get("dependabot") is not None or bool(h.get("renovate"))
             or bool(h.get("dependabot_updates")))
        and bool(h.get("security_policy"))
        and isinstance(iss, dict)
        and not iss.get("off")
        and not int(iss.get("open") or 0)
        and not h.get("dependabot_but_known_vulns")
    )


HABITS_GRACE_DAYS = 7


# --- (preview) proposed readings ---------------------------------------------------------------

_T_WORD = {"none": "None found", "possible": "Possible", "found": "Found"}
_T_COLOR = {"none": "green", "possible": "yellow", "found": "red"}
_E_WORD = {"low": "Low", "medium": "Medium", "high": "High"}
_E_COLOR = {"low": "green", "medium": "yellow", "high": "orange"}


def readings_band(r: dict[str, Any]) -> str:
    """The card outline with the readings shown: a found threat red, a possible one yellow,
    high exposure orange, else no outline (green, as "no concerns" today)."""
    t, x = r.get("threat_level"), r.get("exposure_level")
    if t == "found":
        return "red"
    if t == "possible":
        return "yellow"
    return "orange" if x == "high" else "green"


_T_VERDICT = {
    "none": "🦴 Good Boy · no signs of malicious behavior",
    "possible": "🐕 Sus · a possible sign of malicious behavior",
    "found": "🚨 BORK BORK BORK · malicious behavior found",
}


def _num(x: Any) -> str:
    v = float(x or 0)
    return f"{v:.0f}" if v == int(v) else f"{v:.2f}".rstrip("0")


def _rdial(label: str, value: Any, word: str, color: str) -> str:
    c = 113.1  # 2πr, r = 18
    v = max(0.0, min(10.0, float(value or 0)))
    arc = (f'<circle cx="24" cy="24" r="18" fill="none" stroke="currentColor" stroke-width="5" '
           f'stroke-dasharray="{v / 10 * c:.1f} {c}" stroke-linecap="round" '
           'transform="rotate(-90 24 24)"/>') if v else ""  # fmt: skip
    return (
        f'<div class="rdial rd-{color}"><svg viewBox="0 0 48 48" role="img" '
        f'aria-label="{e(label)} {_num(value)} of 10">'
        '<circle cx="24" cy="24" r="18" fill="none" stroke="var(--line)" stroke-width="5"/>'
        f'{arc}<text x="24" y="29" text-anchor="middle" fill="currentColor">{_num(value)}</text>'
        f'</svg><div><span class="k">{e(label)}</span><span class="w">{e(word)}</span></div></div>'
    )


def _rmini(label: str, value: Any, word: str, color: str) -> str:
    c = 87.96  # 2πr, r = 14
    v = max(0.0, min(10.0, float(value or 0)))
    tenth = int(v * 10 + 0.5) / 10  # one decimal fits the small ring; half rounds up (1.25: 1.3)
    shown = f"{tenth:.0f}" if tenth == int(tenth) else f"{tenth:.1f}"
    arc = (f'<circle cx="18" cy="18" r="14" fill="none" stroke="currentColor" stroke-width="4" '
           f'stroke-dasharray="{v / 10 * c:.1f} {c}" stroke-linecap="round" '
           'transform="rotate(-90 18 18)"/>') if v else ""  # fmt: skip
    return (
        f'<div class="rdi rd-{color}"><svg viewBox="0 0 36 36" role="img" '
        f'aria-label="{e(label)} {_num(value)} of 10">'
        '<circle cx="18" cy="18" r="14" fill="none" stroke="var(--line)" stroke-width="4"/>'
        f'{arc}<text x="18" y="22" text-anchor="middle" fill="currentColor">{shown}</text>'
        f'</svg><span><span class="k">{e(label)}</span> · <span class="w">{e(word)}</span></span></div>'
    )


def readings_compact(r: dict[str, Any]) -> str:
    """The list's form of the two readings: a card is about 240 px wide."""
    t, x = str(r.get("threat_level")), str(r.get("exposure_level"))
    return ('<div class="rdc">'
            + _rmini("Threat", r.get("threat"), _T_WORD.get(t, t), _T_COLOR.get(t, "yellow"))
            + _rmini("Exposure", r.get("exposure"), _E_WORD.get(x, x), _E_COLOR.get(x, "yellow"))
            + "</div>")  # fmt: skip


def readings_text(r: dict[str, Any] | None, complete: bool = True) -> str:
    """(0.15) The two readings as a short line for tables and lists: "Threat: none found ·
    Exposure 1.3 Low", each in its colour. Nothing when there are none."""
    if not r:
        return '<span class="muted">–</span>'
    t, x = str(r.get("threat_level")), str(r.get("exposure_level"))
    tword = _T_WORD.get(t, t).lower()
    if t == "none" and not complete:
        tword = "none found so far"
    v = float(r.get("exposure") or 0)
    shown = f"{int(v * 10 + 0.5) / 10:g}"
    return (f'<span class="rdt"><span class="rd-{_T_COLOR.get(t, "yellow")}">Threat: '
            f'{e(tword)}</span> · <span class="rd-{_E_COLOR.get(x, "yellow")}">Exposure '
            f"{shown} {e(_E_WORD.get(x, x))}</span></span>"
            + ("" if complete else ' <span class="muted">(unfinished)</span>'))  # fmt: skip


def readings_dials(r: dict[str, Any]) -> str:
    t, x = str(r.get("threat_level")), str(r.get("exposure_level"))
    tword = _T_WORD.get(t, t)
    if t == "none" and not r.get("complete", True):
        tword = "None found so far"
    return ('<div class="rd">'
            + _rdial("Threat", r.get("threat"), tword, _T_COLOR.get(t, "yellow"))
            + _rdial("Exposure", r.get("exposure"), _E_WORD.get(x, x), _E_COLOR.get(x, "yellow"))
            + "</div>")  # fmt: skip


def threat_banner(r: dict[str, Any] | None, many: int = 0) -> str:
    """The one sentence for a found threat. `many`: on the installed list, how many apps."""
    if not r and not many:
        return ""
    if many:
        return (f'<div class="banner threat"><b>🚨 {_plural(many, "app")} '
                f"{'shows' if many == 1 else 'show'} malicious behavior. Remove "
                f"{'it' if many == 1 else 'them'}.</b></div>")  # fmt: skip
    if (r or {}).get("threat_level") != "found":
        return ""
    return (f'<div class="banner threat"><b>🚨 This app {e(r.get("threat_reason"), 200)}. '
            "Don't install it.</b><span class=small>If it's installed, remove it. Then log out "
            "of Home Assistant everywhere and change the passwords it could reach.</span></div>")  # fmt: skip


_SRC = {"scan": "Barkley's scan", "dev": "The developer's words", "ai": "AI"}


def src_tag(kind: str, where: str = "", name: str = "") -> str:
    """(preview) Where a block's sentences come from (his decision 2026-11-20). `where`:
    for the developer's words, the file and lines quoted; `name`: a more specific name for
    the source ("The developer's note"). Escaped here."""
    label = (name or _SRC[kind]) + (f" · {where}" if where else "")
    return f'<span class="src {kind}">{e(label, 200)}</span>'


def with_tag(section: str, kind: str = "scan") -> str:
    """A `<section>…<h2>Title</h2>…` with the source tag after its title."""
    return section.replace("</h2>", f" {src_tag(kind)}</h2>", 1) if section else ""


def devnote_html(n: devnote.Note | None, title: str = "The developer's note") -> str:
    """A docstring quoted as the developer's own words, with its file and lines. Shown as
    context only: it never changes a reading."""
    if n is None:
        return ""
    lines = f"{n.start}" if n.start == n.end else f"{n.start}–{n.end}"
    return (
        f'<div class="devq">{src_tag("dev", f"description in the code, {n.file}:{lines}", title)}'
        f"<q>{e(n.text, 900)}</q>"
        '<span class="cite">It doesn\'t change the readings.</span></div>'
    )


def _lines(cites: Any) -> str:
    """`README.md lines 123-129, api.py line 40` (with a dash) from checked citations."""
    out = []
    for c in cites or []:
        try:
            f, a, b = str(c[0]), int(c[1]), int(c[2])
        except (TypeError, ValueError, IndexError):
            continue
        out.append(f"{f} line {a}" if a == b else f"{f} lines {a}–{b}")
    return ", ".join(out[:4])


def said_html(says: list[dict[str, Any]]) -> str:
    """(0.15) "AI inferred" sentences under one item: what the developer's README or
    docstrings say about it, as the AI summed it up (report/ai_words), each with the
    lines Barkley checked. Text from an AI about untrusted text: escaped."""
    return "".join(
        f'<div class="devq">{src_tag("ai", _lines(x.get("cites")), "AI inferred")}'
        f"<div>{e(x.get('text'), 400)}</div>"
        '<span class="cite">The developer wrote those lines. It doesn\'t change the readings.'
        "</span></div>"
        for x in says
        if isinstance(x, dict) and x.get("text")
    )


def said_box(says: list[dict[str, Any]], failed: str = "") -> str:
    """The sentences that aren't about one listed item, in a box of their own."""
    rows = "".join(
        f'<li>{e(x.get("text"), 400)} <span class="u">{e(_lines(x.get("cites")), 300)}</span></li>'
        for x in says
        if isinstance(x, dict) and x.get("text")
    )
    if not rows and not failed:
        return ""
    body = (f'<div class="libs"><ul>{rows}</ul></div>' if rows else
            f'<p class="muted">The AI didn\'t answer this part: {e(failed, 300)}</p>')  # fmt: skip
    return (
        f'<section class="box"><h2>What the developer says it does {src_tag("ai", "", "AI inferred")}'
        '</h2><p class="sub">Your AI read parts of the app\'s README and the descriptions in '
        "its code, and summed up what they say. The developer wrote those lines. Barkley "
        "checked that each line exists and holds these words, not that they are true. "
        "Nothing here changes the readings.</p>"
        f"{body}</section>"
    )


def notes_allowed(report: dict[str, Any], f: dict[str, Any]) -> bool:
    """(his rule, 2026-11-20) The developer's words never sit next to a found or possible
    threat: none on a page with a found threat, none on a threat item, and with a possible
    threat none on what it reads that could be stolen (the credential reads a possible
    exfil pairs with outside hosts)."""
    rd = report.get("readings") or {}
    if rd.get("threat_level") == "found" or kinds.is_threat(str(f.get("rule_id"))):
        return False
    return not (rd.get("threat_level") == "possible"
                and str(f.get("rule_id")) in CREDENTIAL_SOURCES)  # fmt: skip


def threat_box(r: dict[str, Any], items: str) -> str:
    """The Threat box: the signs found, or what Barkley looked for and didn't find."""
    t = str(r.get("threat_level"))
    if t == "none":
        who = ("Barkley found" if r.get("complete", True)
               else "In the part Barkley could check, it found")  # fmt: skip
        body = (f"<p>{icon('check', 14, 'ok')} {who} nothing that sends your data off your "
                "Home Assistant machine, no hidden code and no known-bad packages.</p>")  # fmt: skip
    else:
        body = items
    return f'<section class="box"><h2>Threat {src_tag("scan")}</h2>{body}</section>'


_VIEW_CLASS = re.compile(r"\s*class\s+([A-Za-z_][A-Za-z0-9_]{0,99})")


def login_free_pages(report: dict[str, Any]) -> str:
    """(0.15, his question) The pages behind "N pages open without logging in": each one's
    view class and where it is, 5 then "N more". The scan keeps the class line, not the
    address the page answers on. Names come from the scanned code: escaped."""
    fs = [f for f in report.get("findings") or [] if f.get("rule_id") == "ha-unauth-view"]
    if not fs:
        return ""
    checked = {str(f.get("file")) for f in report.get("findings") or []
               if f.get("rule_id") == "ha-auth-token-check"}  # fmt: skip
    items = []
    for f in fs:
        m = _VIEW_CLASS.match(str(f.get("evidence") or "")[:300])
        where = f"{f.get('file')}:{f['line']}" if f.get("line") else str(f.get("file") or "")
        check = (" · the same file checks a signed link or token" if str(f.get("file"))
                 in checked else "")  # fmt: skip
        page = f.get("page")  # (0.15) the address, from the scan; absent before 0.15
        if page:
            name = f"<code>{e(page, 200)}</code>"
            where = (f"{m[1]} in " if m else "") + where
        else:
            name = f"<code>{e(m[1])}</code>" if m else "A page"
            if page == "":
                check += " · its address is built while the app runs"
        said = f.get("page_note")  # (0.15) the view class's docstring: the developer's words
        note = (f'<span class="u">{src_tag("dev")} {e(said, 300)}</span>'
                if isinstance(said, str) and said and notes_allowed(report, f) else "")  # fmt: skip
        items.append(f'<li>{name} <span class="u">{e(where, 300)}{e(check)}</span>{note}</li>')
    n = len(fs)
    return (f'<p class="small mt2">The {"page" if n == 1 else f"{n} pages"}:</p>'
            '<div class="libs">'
            f"{_zone_list(items)}</div>")  # fmt: skip


def exposure_box(r: dict[str, Any], pages: str = "", listed: str = "") -> str:
    """The Exposure box: the reasons (Barkley's scan), then the developer's notes on its
    pages, then where Home Assistant runs. `pages`: escaped HTML of those notes."""
    why = [w for w in r.get("exposure_reasons") or []
           if not str(w).startswith("A possible sign of malicious")]  # fmt: skip
    based = {  # one whole sentence per network setting
        "home": "Based on Home Assistant running on a home network (Settings).",
        "shared": "Based on Home Assistant running on a shared or work network (Settings).",
        "internet": "Based on Home Assistant being reachable from the internet (Settings).",
    }.get(str(r.get("network")), "")
    return (
        f'<section class="box"><h2>Exposure {src_tag("scan")}</h2>'
        + ('<ul class="rdwhy">' + "".join(f"<li>{e(w, 400)}</li>" for w in why) + "</ul>"
           if why else "<p>Barkley found nothing that would let someone who isn't an admin "
                       "get in.</p>")
        + listed
        + pages
        + (f'<p class="small muted">{e(based)}</p>' if based else "")
        + "</section>"
    )  # fmt: skip


def render_app(
    base: str,
    sid: int,
    report: dict[str, Any],
    rows: list[ScanRow],
    *,
    name: str | None = None,
    update: str = "",
    ai: dict[str, Any] | None = None,
    ai_form: str = "",
    refresh: int = 0,
    deep: DeepFn | None = None,
    again: str = "",
    refresh_url: str = "",
    trust: TrustFn | None = None,
    review: ReviewFn | None = None,
    open_item: str = "",
) -> bytes:
    """One app's detail page. `report` is the shown report (shown.view). `trust(finding)`
    lists the addresses an item is about; `review(finding, places)` is the row under each
    item (Report a false positive). `update`, `ai_form` and `again` (the "sniff this
    version again" / "other versions" text actions in the head) are server-built HTML."""
    t = report.get("target", {})
    title = name or (t.get("repo") or t.get("input") or "?").rsplit("/", 1)[-1]
    rd = report.get("readings") or readings.compute(report).to_dict()
    b = readings_band(rd)
    ha = (
        f", with dependencies worked out for Home Assistant {e(report['ha_version'])}"
        if report.get("ha_version")
        else ""
    )
    commit = (t.get("commit_sha") or "")[:12]
    ai = ai or {}
    vline = _T_VERDICT.get(str(rd.get("threat_level")), "")
    head = (
        f'<p class="crumb"><a href="{base}/">{icon("back")} All apps</a></p>'
        f'<section class="box dhead rdhead">'
        f'<div style="min-width:0"><h1>{e(title, 80)}</h1>'
        f'<div class="verdict" style="color:var(--{b})">{e(vline)}</div>'
        f"{facts_line(report)}"
        f'<div class="muted small">Checked with Barkley {e(report.get("tool", {}).get("version"))}. It read '
        f"{e(_SOURCE.get(str(t.get('install_source')), t.get('install_source')))}"
        f"{' (commit ' + e(commit) + ')' if commit else ''}{ha}. Scan @{sid}.</div>"
        f"{cache_text(report)}{again}"
        f"{readings_dials(rd)}</div></section>"
    )
    parts = [f'<div class="stack">{head}{update}</div>' if update else head]
    # a found threat's one sentence goes right under "All apps"; the reasons for the
    # readings follow the head (the capability score: the technical report)
    parts[0] = parts[0].replace("</p>", "</p>" + threat_banner(rd), 1)
    parts.append("\0readings\0")  # Threat and Exposure go here, once items can be drawn
    missing = [
        a for a in report.get("analyzers", []) if a.get("state") not in ("ok", "not_applicable")
    ]
    if missing:
        parts.append(
            '<div class="banner warn"><b>Part of the check didn\'t finish</b>, so '
            + "Barkley can't speak for every part of the app. What didn't finish:"
            + "<ul class=plain>"
            + "".join(_missing_html(a) for a in missing)
            + "</ul></div>"
        )
    summary = ai.get("summary", "")
    parts.append(
        f'<section class="box"><h2>In short{" " + src_tag("scan")}</h2>'
        f'<p class="inshort">{in_short(report)}</p>'
        + (
            f'<div class="aibox"><div class="small">{AI_BADGE}<b>AI explanation</b>'
            f"{' ' + src_tag('ai')}</div>"
            f"<p>{e(summary, 1500)}</p></div>"
            if summary
            else ""
        )
        + ai_form
        + "</section>"
    )
    notes = privacy.notes(report)
    parts.append(privacy_html(notes, (lambda i: deep(i, part="inline")) if deep else None))
    # (0.14.0) an unscored usage-reporting trace is shown inside its privacy note
    groups = [g for g in scored_findings(report) if g[0]["rule_id"] != privacy.TRACED]
    expl = ai.get("findings", {})
    items = (report.get("context") or {}).get("items") or {}
    shown: set[str] = set()  # items whose block (with its sheet) is on the page

    def dfn(item_id: str) -> str:
        out = deep(item_id) if deep else ""
        if out:
            shown.add(item_id)
        return out

    def zdeep(item_id: str, part: str = "both") -> str:
        out = deep(item_id, part=part) if deep else ""
        if out and part != "inline":
            shown.add(item_id)
        return out

    tfn = trust or (lambda _f: "")
    rfn = review or (lambda _f, _fs: "")

    quoted: set[tuple[str, int]] = set()  # (preview) each docstring once per page

    def note_for(fs: list[dict[str, Any]], title: str = "The developer's note") -> str:
        for x in fs:
            n = devnote.note(report, x["id"]) if x["id"] in items else None
            if n is not None:
                if (n.file, n.start) in quoted:
                    return ""
                quoted.add((n.file, n.start))
                return devnote_html(n, title)
        return ""

    # (0.15) "AI inferred": never on a page with a found threat; with a possible threat
    # only under an item the developer's words may sit beside (ai_words keeps no other)
    words = ai.get("words") if isinstance(ai.get("words"), dict) else {}
    says = [x for x in words.get("says") or [] if isinstance(x, dict)]
    if rd.get("threat_level") == "found":
        says = []
    placed: set[int] = set()

    def said_for(f: dict[str, Any]) -> str:
        mine = [x for x in says if x.get("about") == f.get("rule_id")]
        placed.update(id(x) for x in mine)
        return said_html(mine)

    def one(f: dict[str, Any], fs: list[dict[str, Any]], p: int) -> str:
        ctx = not kinds.is_threat(str(f["rule_id"]))
        note = note_for(fs) if ctx and notes_allowed(report, f) else ""
        if ctx and notes_allowed(report, f):
            note += said_for(f)
        return finding_html(
            f,
            fs,
            0,  # no points: only the two readings are scored
            next((expl[x["id"]] for x in fs if x["id"] in expl), ""),
            next((dfn(x["id"]) for x in fs if x["id"] in items), "") + "".join(tfn(x) for x in fs),
            next(
                (patch_html(items[x["id"]].get("patch")) for x in fs if x["id"] in items),
                "",
            ),
            next(
                (
                    explain.patch_means(items[x["id"]].get("patch"))
                    for x in fs
                    if x["id"] in items and items[x["id"]].get("patch")
                ),
                None,
            ),
            rfn(f, fs),
            context=ctx,
            note=note,
        )

    # Threat and Exposure first; everything else is context, unscored
    threats = [g for g in groups if kinds.is_threat(str(g[0]["rule_id"]))]
    rest = [g for g in groups if not kinds.is_threat(str(g[0]["rule_id"]))]
    page_notes = "".join(
        note_for([x], "The developer's note on this page")
        for g in rest if g[0]["rule_id"] == "ha-unauth-view" and notes_allowed(report, g[0])
        for x in g[1]
    )  # fmt: skip
    boxes = threat_box(rd, "".join(one(*g) for g in threats)) + exposure_box(
        rd, page_notes, login_free_pages(report) if rd.get("threat_level") != "found" else ""
    )
    parts[parts.index("\0readings\0")] = boxes
    parts.append(
        '<section class="box"><h2>What it can do <span class="muted small">(not scored)'
        f'</span> {src_tag("scan")}</h2>'
        + (kinds_html(report, rest, one, skip=frozenset({kinds.THREAT}),
                      untitled=frozenset({kinds.CAPABILITY})) if rest else
           f'<p class="ok">{icon("check", 16, "ok")} Barkley found nothing notable.</p>')
        + minor_line(base, sid, report)
        + "</section>"
    )  # fmt: skip
    loose = [x for x in says if id(x) not in placed]
    if rd.get("threat_level") == "none":  # beside a possible threat: only the placed ones
        parts.append(said_box(loose, str(words.get("failed") or "")))
    parts.append(
        f'<section class="box"><h2>{"What it touches " + src_tag("scan")}</h2>'
        '<p class="sub">On the left is what it can read. On the right is where it can connect. '
        "A red line means Barkley found a path in the code from your data to that place. No "
        "line means Barkley found no path.</p>"
        f"{flow_svg(report, title)}</section>"
    )
    tag = with_tag
    # an integration whose requests the scan read: proven sites and mentioned ones apart
    split = isinstance(report.get("requests"), dict)
    dev_ok = rd.get("threat_level") != "found"
    parts.append(
        f'<section class="box"><h2>Where it connects{" " + src_tag("scan")}</h2>'
        + (
            '<p class="sub">These are the sites Barkley read a request to in the code, the '
            "ports it uses, and requests whose address the app works out while it runs. Web "
            "addresses are cut off at the <code>?</code>, because what comes after it can hold "
            f"keys.{requests_note(report)}</p>"
            if split else
            '<p class="sub">This lists every site, IP address '
            "and port in the shipped code, grouped by where it is. A site is listed because the "
            "code mentions it. That doesn't mean Barkley saw it connect. Web addresses are cut "
            "off at the <code>?</code>, because what comes after it can hold keys.</p>"
        )
        + zones_html(report, zdeep if deep else None, open_item, dev_ok,
                     "connects" if split else "")
        + "</section>"
    )  # fmt: skip
    other = (
        zones_html(report, zdeep if deep else None, open_item, dev_ok, "mentioned") if split else ""
    )
    if other:
        parts.append(
            f'<section class="box"><h2>Other addresses in its code {src_tag("scan")}</h2>'
            '<p class="sub">The code mentions these, but Barkley saw no request that names '
            "them. Many are only links, such as a help page or a donation page. If the app "
            "sends requests to addresses it works out while it runs, it may still reach one "
            f"of them.</p>{other}</section>"
        )
    parts.append(tag(supply_html(report)))
    parts.append(tag(environment_html(report)))
    parts.append(tag(hygiene_html(report)))
    can = explain.can_do(report)
    inside = "Everything it uses inside Home Assistant " + src_tag("scan")
    tech = (" It includes the capability score, which counts what the code openly uses. "
            "That score isn't a judgment.")  # fmt: skip
    parts.append(
        f'<div class="two"><section class="box"><h2>{inside}</h2>'
        + (
            '<ul class="plain">' + "".join(f"<li>{e(x)}</li>" for x in can) + "</ul>"
            if can
            else '<p class="muted small">Barkley found nothing notable.</p>'
        )
        + f'</section><section class="box"><h2>History{" " + src_tag("scan")}</h2>'
        f"{history_html(base, sid, report, rows)}"
        f'<p class="tech"><a href="{base}/scan/{sid}.json">Technical report (raw JSON)</a>'
        f"{tech}</p></section></div>"
    )
    if deep:  # a note's item with no sheet on the page yet (one zones_html didn't list)
        parts.extend(
            deep(i, part="sheet")
            for i in dict.fromkeys(x for n in notes for x in n.edges)
            if i and i not in shown
        )
    return page(f"Barkley · {title}", "".join(parts), refresh, base, refresh_url)
