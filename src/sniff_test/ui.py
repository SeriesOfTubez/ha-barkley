"""The panel's pages: the card grid and each app's detail page (M8).

Pure functions from stored reports to HTML. No scripts anywhere (the CSP forbids them):
the score ring and the data-flow diagram are inline SVG drawn here, and filters are
links. Every string that came from a scanned repo (names, hosts, URLs, files, evidence)
goes through `e()`. Plain-English text comes from `report.explain` and
`report.privacy`; nothing here computes or changes a score.
"""

from __future__ import annotations

import html
import re
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from sniff_test import __version__
from sniff_test.analyzers.correlate import SENSITIVE_NODES
from sniff_test.analyzers.endpoints import WELL_KNOWN_PORTS
from sniff_test.report import explain, privacy
from sniff_test.report.json_report import sanitize_untrusted

if TYPE_CHECKING:
    from sniff_test.store import ScanRow

DeepFn = Callable[[str], str]  # item id -> "Explain in context" HTML ("" for none)


def e(text: Any, limit: int = 300) -> str:
    """Escape for HTML text and attribute values (untrusted text is also truncated)."""
    return html.escape(sanitize_untrusted(str(text), limit) if text is not None else "")


# --- look --------------------------------------------------------------------------------

CSS = """
:root { --bg:#f7f8f6; --card:#fff; --fg:#1b1f1d; --muted:#66706b; --line:#e2e5e1;
  --accent:#2f6b5a; --soft:#edf3f0;
  --green:#2e7d32; --yellow:#9a7800; --orange:#c2560b; --red:#c62828; --grey:#8a938f;
  --green-bg:#e9f4ea; --yellow-bg:#fbf4dc; --orange-bg:#fdeee2; --red-bg:#fbe7e6;
  --priv:#6a4fb3; --priv-bg:#efeafa; --new:#0b6e99; --new-bg:#e2f1f8;
  --ai:#a3267f; --ai-bg:#fbeaf5; color-scheme:light; }
@media (prefers-color-scheme: dark) { :root { --bg:#121514; --card:#1a1e1c; --fg:#e4e8e6;
  --muted:#95a09b; --line:#2a302d; --accent:#7cc4ad; --soft:#1d2a26;
  --green:#6fcf74; --yellow:#e3c04f; --orange:#ff9f5a; --red:#ff7b72; --grey:#7b8580;
  --green-bg:#18291a; --yellow-bg:#2e2810; --orange-bg:#33210f; --red-bg:#351a19;
  --priv:#b9a4f0; --priv-bg:#251f38; --new:#6cc4ea; --new-bg:#13293a;
  --ai:#f07acb; --ai-bg:#33172b; color-scheme:dark; } }
* { box-sizing:border-box; }
body { background:var(--bg); color:var(--fg); font:14px/1.5 system-ui,-apple-system,
  "Segoe UI",Roboto,sans-serif; margin:0 auto; max-width:1100px; padding:18px 16px 48px; }
a { color:var(--accent); } h1 { font-size:1.35rem; margin:0; } h2 { font-size:1.05rem; margin:0 0 4px; }
p { margin:0; } code { font:0.82rem ui-monospace,"SF Mono",Menlo,monospace; overflow-wrap:anywhere; }
main { display:flex; flex-direction:column; gap:16px; }
.muted { color:var(--muted); } .small { font-size:0.82rem; }
.box { background:var(--card); border:1px solid var(--line); border-radius:10px;
  padding:14px 16px; min-width:0; }
.sub { color:var(--muted); font-size:0.85rem; margin-bottom:10px; }
.head { display:flex; flex-wrap:wrap; gap:6px 18px; align-items:baseline; }
.summary { display:flex; flex-wrap:wrap; gap:8px 22px; font-size:0.9rem; }
.summary b { font-variant-numeric:tabular-nums; }
a.sum { color:var(--fg); text-decoration:none; border-bottom:2px solid transparent; }
a.sum:hover { border-bottom-color:var(--line); }
a.sum.on { border-bottom-color:currentColor; font-weight:600; }
.bar { display:flex; flex-wrap:wrap; gap:8px 16px; align-items:center;
  justify-content:space-between; }
.bar > :last-child { margin-left:auto; }
.tablebox { padding:4px 8px; overflow-x:auto; }
table.apps td { vertical-align:middle; }
table.apps .badge { display:inline-block; white-space:nowrap; overflow-wrap:normal; }
table.apps td.actcell { width:1%; }
.again { display:flex; flex-wrap:wrap; gap:8px 12px; align-items:center; }
.again form { margin:0; }
.status { display:flex; flex-direction:column; gap:4px; border-color:var(--accent); }
.status .row { display:flex; flex-wrap:wrap; gap:4px 12px; align-items:baseline; }
.filters { display:flex; flex-wrap:wrap; gap:6px; }
.pill { font-size:0.8rem; padding:4px 10px; border-radius:999px; border:1px solid var(--line);
  background:var(--card); color:var(--fg); white-space:nowrap; text-decoration:none; }
.pill.on { background:var(--fg); color:var(--card); border-color:var(--fg); }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(236px,1fr)); gap:12px; }
.app { position:relative; background:var(--card); border:2px dashed var(--grey);
  border-radius:12px; padding:12px 14px; display:flex; flex-direction:column; gap:8px; min-width:0; }
.app:hover, .app:focus-within { box-shadow:0 0 0 3px var(--soft); }
.app.green { border:2px solid var(--green); } .app.yellow { border:2px solid var(--yellow); }
.app.orange { border:2px solid var(--orange); } .app.red { border:2px solid var(--red); }
.app-top { display:flex; gap:10px; align-items:flex-start; justify-content:space-between; }
.app-name { font-weight:650; font-size:0.98rem; line-height:1.25; color:var(--fg);
  text-decoration:none; overflow-wrap:anywhere; }
a.app-name::after { content:""; position:absolute; inset:0; border-radius:10px; }
.app-kind { font-size:0.76rem; color:var(--muted); overflow-wrap:anywhere; }
.badge { flex:none; min-width:44px; text-align:center; border-radius:8px; padding:3px 6px 4px;
  font-weight:700; font-size:1.1rem; font-variant-numeric:tabular-nums; line-height:1.1;
  background:var(--soft); color:var(--muted); }
.badge small { display:block; font-size:0.6rem; font-weight:600; letter-spacing:0.03em;
  text-transform:uppercase; }
.badge.green { background:var(--green-bg); color:var(--green); }
.badge.yellow { background:var(--yellow-bg); color:var(--yellow); }
.badge.orange { background:var(--orange-bg); color:var(--orange); }
.badge.red { background:var(--red-bg); color:var(--red); }
.say { font-size:0.86rem; line-height:1.45; }
.chips { display:flex; flex-wrap:wrap; gap:5px; margin-top:auto; }
.chip { font-size:0.72rem; padding:2px 7px; border-radius:5px; background:var(--soft);
  color:var(--fg); white-space:nowrap; }
.chip.priv { background:var(--priv-bg); color:var(--priv); }
.chip.warn { background:var(--yellow-bg); color:var(--yellow); }
.chip.bad { background:var(--red-bg); color:var(--red); }
.chip.new { background:var(--new-bg); color:var(--new); }
.act { position:relative; z-index:1; display:flex; gap:6px; align-items:center; font-size:0.8rem; }
.act form { margin:0; }
button { font:inherit; font-size:0.8rem; padding:4px 10px; border-radius:6px;
  border:1px solid var(--line); background:var(--soft); color:var(--fg); cursor:pointer; }
button.primary { background:var(--accent); color:var(--card); border-color:var(--accent); }
.legend { display:flex; flex-wrap:wrap; gap:6px 16px; font-size:0.78rem; color:var(--muted); }
.sw { display:inline-block; width:12px; height:12px; border-radius:3px; border:2px solid;
  vertical-align:-1px; margin-right:4px; }
.banner { border-radius:8px; padding:10px 12px; border:1px solid var(--line); }
.banner.warn { background:var(--yellow-bg); color:var(--fg); border-color:var(--yellow); }
.banner.bad { background:var(--red-bg); border-color:var(--red); }
.crumb { font-size:0.85rem; }
.dhead { display:grid; grid-template-columns:auto 1fr; gap:6px 18px; align-items:center; }
.ring { width:84px; height:84px; } .ring text { font:700 24px system-ui,sans-serif; }
.verdict { font-weight:600; }
.inshort { font-size:0.97rem; line-height:1.55; max-width:76ch; }
.two { display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:16px;
  align-items:start; }
.finding { border-top:1px solid var(--line); padding:12px 0 4px; display:grid;
  grid-template-columns:6.4em 1fr; gap:4px 14px; }
.finding:first-of-type { border-top:0; padding-top:4px; }
.lvl { font-size:0.72rem; font-weight:700; text-transform:uppercase; letter-spacing:0.05em;
  padding:3px 0; color:var(--muted); }
.lvl.critical { color:var(--red); } .lvl.high { color:var(--orange); }
.lvl.medium { color:var(--yellow); } .lvl.p { color:var(--priv); }
.finding h3 { margin:0; font-size:0.98rem; }
.finding dl { margin:6px 0 0; display:grid; grid-template-columns:9.5em 1fr; gap:4px 12px;
  font-size:0.88rem; }
.finding dt { color:var(--muted); } .finding dd { margin:0; min-width:0; }
.ai dd { border-left:3px solid var(--new); padding-left:8px; }
.aib { display:inline-block; font-size:0.68rem; font-weight:700; letter-spacing:0.04em;
  color:var(--card); background:var(--ai); border-radius:4px; padding:1px 5px; margin-right:6px;
  vertical-align:1px; }
.ai dt { color:var(--ai); font-weight:600; } .ai dd { border-left:3px solid var(--ai); }
.aibox { border-left:3px solid var(--ai); background:var(--ai-bg); border-radius:0 8px 8px 0;
  padding:8px 10px; margin-top:8px; }
button.ai, .deepi button { color:var(--ai); border-color:var(--ai); background:var(--ai-bg);
  font-weight:600; }
.deepi { margin-top:6px; display:flex; flex-wrap:wrap; gap:4px 10px; align-items:center; }
.deepi form { margin:0; }
a.aichip { display:inline-block; font-size:0.8rem; font-weight:600; color:var(--ai);
  background:var(--ai-bg); border:1px solid var(--ai); border-radius:10px; padding:2px 10px;
  text-decoration:none; }
a.aichip.warn { color:var(--orange); border-color:var(--orange); }
div.modal { display:none !important; position:fixed; inset:0; z-index:50; overflow:auto; padding:24px 12px; }
div.modal:target { display:block !important; }
.modal .shade { position:fixed; inset:0; background:rgba(0,0,0,0.55); }
.modal .sheet { position:relative; max-width:880px; margin:0 auto; background:var(--card);
  color:var(--fg); border:1px solid var(--line); border-top:4px solid var(--ai);
  border-radius:12px; padding:14px 18px 18px; font-size:0.9rem; }
.sheet .sh { display:flex; align-items:center; gap:4px; color:var(--ai); }
.sheet .sh .x { margin-left:auto; font-size:0.85rem; }
.sheet .st { color:var(--muted); font-size:0.85rem; margin:2px 0 8px; }
.modal .sheet h3 { font-size:0.9rem; margin:14px 0 4px; }
.modal .sheet ul { list-style:disc; margin:2px 0 6px; padding-left:1.2em; display:flex;
  flex-direction:column; gap:4px; }
.modal .sheet li { display:list-item; }
.sheet .cite { font-size:0.75rem; color:var(--muted); white-space:nowrap; }
.sheet form { margin-top:10px; }
pre.code { margin:4px 0 0; padding:6px 8px; background:var(--soft); border-radius:6px;
  font:0.76rem/1.45 ui-monospace,"SF Mono",Menlo,monospace; white-space:pre-wrap;
  overflow-wrap:anywhere; max-height:420px; overflow:auto; }
pre.code .nc { color:var(--muted); } pre.code .fn { color:var(--new); font-weight:600; }
.tech { font-size:0.8rem; color:var(--muted); margin-top:6px; overflow-wrap:anywhere; }
details summary { cursor:pointer; color:var(--muted); font-size:0.82rem; }
.ev { display:block; white-space:pre-wrap; background:var(--soft); padding:6px 8px;
  border-radius:6px; margin-top:4px; }
@media (max-width:560px) { .finding { grid-template-columns:1fr; }
  .finding dl { grid-template-columns:1fr; } .finding dt { margin-top:4px; } }
.zones { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:10px; }
.zone { border-radius:8px; padding:10px 12px; border:1px solid var(--line); min-width:0; }
.zone h3 { margin:0 0 2px; font-size:0.88rem; }
.zone .zs { font-size:0.76rem; color:var(--muted); margin-bottom:6px; }
.zone ul { list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:6px;
  font-size:0.84rem; }
.zone li > div { display:flex; gap:6px; justify-content:space-between; align-items:baseline; }
.zone .p { font-size:0.74rem; color:var(--muted); white-space:nowrap; }
.zone .u { font-size:0.74rem; color:var(--muted); display:block; overflow-wrap:anywhere; }
.zone.home { background:var(--soft); }
.zone.dev, .zone.ana { border-color:var(--priv); }
.lock { font-size:0.72rem; white-space:nowrap; } .lock.ok { color:var(--green); }
.lock.no { color:var(--orange); }
.flowwrap { overflow-x:auto; }
.flow text { fill:var(--fg); font:12px system-ui,sans-serif; }
.flow .sm { fill:var(--muted); font-size:10.5px; }
.privbox { border:1px solid var(--priv); background:var(--priv-bg); border-radius:10px;
  padding:12px 14px; }
.privbox h2 { color:var(--priv); }
ul.plain { margin:0; padding-left:1.1em; font-size:0.88rem; display:flex;
  flex-direction:column; gap:3px; }
table { border-collapse:collapse; width:100%; font-size:0.86rem; }
td, th { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line);
  vertical-align:top; overflow-wrap:anywhere; }
.tools form { display:flex; gap:8px; flex-wrap:wrap; margin:8px 0; }
.tools input, .tools select { padding:6px; min-width:0; flex:1 1 180px; font:inherit;
  background:var(--card); color:var(--fg); border:1px solid var(--line); border-radius:6px; }
.tools select { flex:0 1 auto; }
form.search { display:flex; gap:8px; flex-wrap:wrap; margin:0; }
.sev-critical { color:var(--red); font-weight:600; } .sev-high { color:var(--orange); font-weight:600; }
.sev-medium { color:var(--yellow); } .ok { color:var(--green); } .bad { color:var(--red); }
"""


def page(title: str, body: str, refresh: int = 0) -> bytes:
    """`refresh`: reload after N seconds (a meta tag, not a script: the CSP allows it)."""
    meta = f'<meta http-equiv="refresh" content="{int(refresh)}">' if refresh else ""
    return (
        f"<!doctype html><html lang=en><head><meta charset=utf-8>{meta}"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{e(title)}</title><style>{CSS}</style></head><body><main>"
        f"{body}</main></body></html>"
    ).encode()


# --- scores in plain words ------------------------------------------------------------------

BANDS = {
    "green": ("Fine", "no concerns found"),
    "yellow": ("Look", "worth a look"),
    "orange": ("Sus", "several concerns"),
    "red": ("Bork", "don't install"),
    "grey": ("?", "not checked or unfinished"),
}
_VERDICT_EMOJI = {"good_boy": "🦴", "kinda_sus": "🐕", "very_sus": "🐕‍🦺", "bork": "🚨"}


def band(score: int | None, complete: bool = True) -> str:
    if score is None or not complete:
        return "grey"
    return (
        "green" if score >= 90 else "yellow" if score >= 70 else "orange" if score >= 40 else "red"
    )


def ring(score: int, b: str) -> str:
    c = 226.2
    dash = f"{score / 100 * c:.1f} {c}"
    color = f"var(--{b})" if b != "grey" else "var(--grey)"
    return (
        f'<svg class="ring" viewBox="0 0 84 84" role="img" aria-label="Score {score} of 100">'
        '<circle cx="42" cy="42" r="36" fill="none" stroke="var(--soft)" stroke-width="8"/>'
        f'<circle cx="42" cy="42" r="36" fill="none" stroke="{color}" stroke-width="8" '
        f'stroke-dasharray="{dash}" stroke-linecap="round" transform="rotate(-90 42 42)"/>'
        f'<text x="42" y="50" text-anchor="middle" fill="{color}">{score}</text></svg>'
    )


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

    @property
    def band(self) -> str:
        return band(self.scan.score, self.scan.complete) if self.scan else "grey"

    def notes(self) -> list[privacy.Note]:
        return privacy.notes(self.report) if self.report else []

    @property
    def worth_a_look(self) -> bool:
        return self.band in ("yellow", "orange", "red") or self.group == "attention"


def card_sentence(c: Card) -> str:
    if c.scan is None:
        return f"Not sniffed yet with Barkley {__version__}."
    if not c.scan.complete:
        return "The last check didn't finish, so we can't vouch for it yet. Sniff it again."
    rep = c.report or {}
    big = [t for t in scored_findings(rep) if t[0]["severity"] in ("critical", "high", "medium")]
    if big:
        first = explain.explain(big[0][0]["rule_id"]).title + "."
        if len(big) > 1:
            first += f" And {len(big) - 1} more thing{'s' * (len(big) > 2)} worth a look."
    else:
        first = "No security concerns found."
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
        return f"Connects to {port_phrase(pts)} on a device or server it's set up with."
    if dirs == {"in"}:
        return f"Listens on {port_phrase(pts)}."
    return f"Its code names {port_phrase(pts)}."


def connection_sentence(rep: dict[str, Any]) -> str:
    hs = hosts(rep)
    net = internet(hs)
    home = [h for h in hs if h.cls == "local"]
    pts = ports(rep)
    if net:
        s = f"Names {len(net)} internet site{'s' * (len(net) != 1)}"
        s += " and addresses on your own network." if home else " in its code."
    elif home:
        s = "Names no internet sites, only addresses on your own network."
    else:
        s = "No internet sites in its code."
    if pts:
        s += " " + ports_sentence(pts)
    return s


def card_chips(c: Card) -> list[tuple[str, str]]:
    chips: list[tuple[str, str]] = []
    if c.available:
        chips.append(("new", f"Update {c.available}"))
    if c.group == "attention" and c.reasons and c.available:
        chips.append(("warn", "Update needs a look"))
    if c.report and c.scan and c.scan.complete:
        for f, _fs, _p in scored_findings(c.report):
            if f["severity"] in ("critical", "high", "medium") and len(chips) < 4:
                cls = "bad" if f["severity"] in ("critical", "high") else "warn"
                chip = explain.explain(f["rule_id"]).chip
                if (cls, chip) not in chips:
                    chips.append((cls, chip))
        for n in c.notes():
            chips.append(("priv", n.label))
        net = internet(hosts(c.report))
        if net:
            chips.append(("", f"{len(net)} internet site{'s' * (len(net) != 1)}"))
        elif any(h.cls == "local" for h in hosts(c.report)):
            chips.append(("", "Own network only"))
        else:
            chips.append(("", "No internet sites"))
    return chips


def card_html(base: str, c: Card) -> str:
    b = c.band
    label = BANDS[b][0]
    score = str(c.scan.score) if c.scan else "–"
    if c.scan and not c.scan.complete:
        label = "Unfinished"
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
    return (
        f'<div class="app {b}"><div class="app-top"><div>{name}'
        f'<div class="app-kind">{e(KIND.get(c.kind, c.kind))} · {e(c.installed, 40)}</div></div>'
        f'<div class="badge {b}">{score}<small>{label}</small></div></div>'
        f'<div class="say">{e(card_sentence(c), 400)}</div>'
        f'<div class="chips">{chips}</div>{actions}</div>'
    )


FILTERS = {
    "all": "All",
    "look": "Worth a look",
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

    @classmethod
    def parse(cls, q: dict[str, list[str]], default_view: str = "cards") -> View:
        f = (q.get("f") or ["all"])[0]
        view = (q.get("view") or [default_view])[0]
        try:
            pg = int((q.get("page") or ["1"])[0])
        except ValueError:
            pg = 1
        return cls(
            f if f in FILTERS else "all",
            view if view in VIEWS else "cards",
            max(1, min(pg, 10_000)),
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
    return (c.band != "grey", not c.worth_a_look, c.scan.score if c.scan else -1, c.name.lower())


def _busy_text(c: Card) -> str:
    return {"running": "checking…", "waiting": "waiting for GitHub…"}.get(c.busy, "queued…")


def card_row(base: str, c: Card) -> str:
    """One app as a table row: the same facts as its card, in less space."""
    b = c.band
    label = "Unfinished" if c.scan and not c.scan.complete else BANDS[b][0]
    score = str(c.scan.score) if c.scan else "–"
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
        f'<tr><td><span class="badge {b}">{score}<small>{label}</small></span></td>'
        f'<td>{name}<div class="app-kind">{e(KIND.get(c.kind, c.kind))} · {e(c.installed, 40)}'
        f'</div><div class="small">{e(card_sentence(c), 400)}</div></td>'
        f'<td><div class="chips">{chips}</div></td>'
        f'<td class="actcell">{act}</td></tr>'
    )


def _pager(base: str, v: View, pages: int) -> str:
    if pages <= 1:
        return ""
    links = []
    if v.pg > 1:
        links.append(f'<a class="pill" href="{base}/?{v.qs(pg=v.pg - 1)}">‹ Previous</a>')
    for n in range(1, pages + 1):
        on = " on" if n == v.pg else ""
        links.append(f'<a class="pill{on}" href="{base}/?{v.qs(pg=n)}">{n}</a>')
    if v.pg < pages:
        links.append(f'<a class="pill" href="{base}/?{v.qs(pg=v.pg + 1)}">Next ›</a>')
    return f'<nav class="filters pager" aria-label="pages">{"".join(links)}</nav>'


def render_grid(base: str, cards: list[Card], v: View | None = None) -> str:
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
        summary.append(item("look", "worth a look", "yellow"))
    summary.append(item("fine", "no concerns found", "green"))
    if counts["privacy"]:
        summary.append(item("privacy", "with privacy notes", "priv"))
    summary.append(item("updates", f"update{'s' * (ups != 1)} waiting"))
    if counts["unchecked"]:
        summary.append(item("unchecked", "not checked"))
    views = "".join(
        f'<a class="pill{" on" if v.view == k else ""}" href="{base}/?{v.qs(view=k, pg=1)}">'
        f"{label}</a>"
        for k, label in (("cards", "▦ Cards"), ("table", "☰ Table"))
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
            '<div class="box tablebox"><table class="apps"><tr><th>Score</th><th>App</th>'
            "<th>Notes</th><th></th></tr>"
            + "".join(card_row(base, c) for c in window)
            + "</table></div>"
        )
    else:
        body = '<div class="grid">' + "".join(card_html(base, c) for c in window) + "</div>"
    legend = (
        '<div class="legend">'
        + "".join(
            f'<span><span class="sw" style="border-color:var(--{b})"></span>{lo}–{hi} {BANDS[b][1]}</span>'
            for b, lo, hi in (
                ("green", 90, 100),
                ("yellow", 70, 89),
                ("orange", 40, 69),
                ("red", 0, 39),
            )
        )
        + '<span><span class="sw" style="border-color:var(--grey);border-style:dashed"></span>'
        "not checked or unfinished</span>"
        '<span><span class="chip priv">purple</span> privacy note (never scored)</span></div>'
    )
    return (
        f'<nav class="box summary" aria-label="filters">{"".join(summary)}</nav>'
        f'<div class="bar">{showing}<span class="filters">{views}</span></div>'
        f"{body}{_pager(base, v, pages)}{legend}"
    )


# --- the detail page ---------------------------------------------------------------------------


def in_short(report: dict[str, Any]) -> str:
    """A deterministic summary built only from the report (escaped HTML)."""
    out: list[str] = []
    hs = hosts(report)
    net = internet(hs)
    home = [h for h in hs if h.cls == "local"]
    own = [h for h in net if h.cls == "declared"]
    if net:
        s = f"Its code names {len(net)} site{'s' * (len(net) != 1)} on the internet"
        if own:
            s += f", {len(own)} of them the app's own"
        s += " and addresses on your own network." if home else "."
        out.append(s)
    elif home:
        out.append("Its code names no internet sites, only addresses on your own network.")
    else:
        out.append("Its code names no internet sites.")
    if pts := ports(report):
        out.append(
            ports_sentence(pts).removesuffix(".")
            + "; the address comes from setup or a cloud service."
        )
    groups = scored_findings(report)
    big = [g for g in groups if g[0]["severity"] in ("critical", "high", "medium")]
    if big:
        titles = [_lower1(explain.explain(g[0]["rule_id"]).title) for g in big[:2]]
        lead = f"We found {len(big)} thing{'s' * (len(big) != 1)} worth a look"
        out.append(
            f"{lead}: {titles[0]}"
            + (f", and {titles[1]}" if len(titles) > 1 else "")
            + (" (and more below)." if len(big) > 2 else ".")
        )
    elif groups:
        out.append("We found only minor things, listed below.")
    else:
        out.append("We found no security concerns.")
    fl = flows(report)
    rd = [r for r in reads(report) if r[2]]
    if any(x["evidence"] == "proven" for x in fl):
        out.append("<b>We traced private data being sent out of your home.</b>")
    elif fl:
        out.append(
            "<b>It reads private data and can talk to sites we can't explain,</b> "
            "though we found no direct path between the two."
        )
    elif rd:
        what = explain.data_label(rd[0][1]).lower().replace("ha ", "HA ")
        out.append(
            f"It reads {e(what)}, but <b>we found no path that sends your data to the internet.</b>"
        )
    else:
        out.append("<b>We found no path that sends your data to the internet.</b>")
    n = len(privacy.notes(report))
    if n:
        out.append(
            f"There {'is' if n == 1 else 'are'} {n} privacy note{'s' * (n != 1)} "
            "below; they don't change the score."
        )
    if not report.get("complete"):
        out.append("Part of the check didn't finish, so the score is capped at 89.")
    return " ".join(x if x.startswith("<b>") or "<b>" in x else e(x, 600) for x in out)


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
    return shown + more + times


def finding_html(
    f: dict[str, Any], fs: list[dict[str, Any]], points: int, ai: str = "", deep: str = ""
) -> str:
    ex = explain.explain(f["rule_id"])
    where = _where(fs)
    tech = [e(f["rule_id"]), e(f["severity"])]
    if points:
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
    return (
        f'<div class="finding"><div class="lvl {e(f["severity"])}">{e(explain.level(f["severity"]))}</div>'
        f"<div><h3>{e(ex.title)}</h3><dl{' class=ai' if ai else ''}>"
        f"<dt>What it means</dt><dd>{e(ex.means, 800)}</dd>"
        f"<dt>Should you worry?</dt><dd>{e(ex.worry, 600)}</dd>"
        + (f"<dt>Where we saw it</dt><dd>{where}</dd>" if where else "")
        + ai_html
        + f'</dl>{deep}<div class="tech">{" · ".join(tech)}</div>{code}</div></div>'
    )


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
                "is one long line; shown reformatted (numbers are of the reformatted text)</span>"
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


AI_BADGE = '<span class="aib">✦ AI</span>'


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
) -> str:
    """One item's "Explain in context": a compact chip or button where the item is, and
    a full-width sheet (`#ai-<id>`, opened with CSS :target, no script) with the answer
    and the code. `form` is the server-built button form with a `{label}` placeholder.
    Everything from the AI or the repo is escaped."""
    from sniff_test.report.context import line_count

    mid = f"ai-{e(item_id, 40)}"
    lines = line_count(snip)
    nseg = len(snip.get("segments", []))
    parts_txt = f", {nseg} parts" if nseg > 1 else ""
    sent = (
        f"<details{'' if answer else ' open'}><summary>The code it reads ({lines} line"
        f"{'s' if lines != 1 else ''}{parts_txt})</summary>{code_html(snip)}</details>"
    )
    if state == "running":
        inline = f'<a class="aichip" href="#{mid}">✦ AI is reading the code… (can take minutes)</a>'
        body = (
            '<p class="small"><b>Reading the code…</b> This can take a few minutes, depending '
            "on your AI. You don't have to wait here: close this and carry on. The answer is "
            "saved, and this item's chip on the page changes to the AI's reading when it's "
            "ready. While it works, this page refreshes by itself.</p>" + sent
        )
    elif error:
        inline = f'<a class="aichip warn" href="#{mid}">✦ The AI didn\'t answer</a>'
        body = (f'<p class="small">{e(error, 400)}</p>{form.replace("{label}", "✦ Try again")}'
                + sent)  # fmt: skip
    elif not answer:
        inline = (
            form.replace("{label}", "✦ Explain in context")
            + f'<a class="small" href="#{mid}">see the {lines} lines it would send</a>'
        )
        body = (
            f'<p class="small">Explain in context sends these {lines} lines of the app\'s own '
            f"code (public on GitHub, no Home Assistant data) to the AI behind "
            f"<code>{e(entity, 120)}</code>. Nothing is sent until you click.</p>"
            + form.replace("{label}", "✦ Explain in context")
            + sent
        )
    else:
        claims = answer.get("claims") or []
        questions = answer.get("questions") or []
        n_c, n_q = len(claims), len(questions)
        summary = f"{n_c} statement{'s' if n_c != 1 else ''}"
        if n_q:
            summary += f", {n_q} question{'s' if n_q != 1 else ''}"
        inline = f'<a class="aichip" href="#{mid}">✦ AI\'s reading of the code: {summary}</a>'
        out = []
        if claims:
            out.append(
                "<ul>"
                + "".join(f"<li>{_ai_text(c['text'], 400)}{_cite(c['cites'])}</li>" for c in claims)
                + "</ul>"
            )
        else:
            out.append('<p class="small">It gave no statement we could check against the code.</p>')
        if questions:
            out.append(
                "<h3>Worth checking</h3><ul>"
                + "".join(
                    f"<li>{_ai_text(q['text'], 300)}{_cite(q['cites'])}</li>" for q in questions
                )
                + "</ul>"
            )
        dropped = answer.get("dropped") or []
        if dropped:
            why = ", ".join(e(w, 60) for w in sorted(set(dropped)))
            n = len(dropped)
            out.append(f'<p class="tech">Left out {n} statement{"s" if n != 1 else ""} that '
                       f"didn't check out ({why}).</p>")  # fmt: skip
        out.append(
            f'<p class="tech">By <code>{e(answer.get("entity_id"), 120)}</code>, '
            f"{e(str(answer.get('created', ''))[:16].replace('T', ' '))} UTC. Each statement "
            "cites lines we sent, which contain the code it names (comments don't count). It "
            "can still be wrong, and it can't change the score or clear a finding.</p>"
        )
        body = "".join(out) + sent + form.replace("{label}", "✦ Ask again")
    sheet = (
        f'<div class="modal" id="{mid}"><a class="shade" href="#item-{e(item_id, 40)}" '
        'aria-label="Close"></a><div class="sheet" role="dialog">'
        f'<div class="sh">{AI_BADGE}<b>The AI\'s reading of the code</b>'
        f'<a class="x" href="#item-{e(item_id, 40)}">Close ✕</a></div>'
        f'<div class="st">{e(title, 200)}</div>{body}</div></div>'
    )
    return f'<div class="deepi" id="item-{e(item_id, 40)}">{inline}</div>{sheet}'


def privacy_html(notes: list[privacy.Note]) -> str:
    if not notes:
        return ""
    parts = [
        f'<section class="privbox"><h2>🔒 Privacy notes ({len(notes)})</h2>'
        '<p class="sub">Things worth knowing about your privacy. They never change the score.</p>'
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
            f"<dt>What we can't tell</dt><dd>{e(n.unknown, 400)}</dd>"
            + (f"<dt>Where we saw it</dt><dd>{where}</dd>" if where else "")
            + "</dl></div></div>"
        )
    parts.append("</section>")
    return "".join(parts)


# --- data-flow diagram -------------------------------------------------------------------------


def _clip(s: str, n: int = 26) -> str:
    s = sanitize_untrusted(s, 200)
    return s if len(s) <= n else s[: n - 1] + "…"


def flow_svg(report: dict[str, Any], name: str) -> str:
    """Left: what it reads. Middle: the app. Right: where it can connect. Lines between
    left and right only for flows the scanner found (proven solid, possible dashed)."""
    rd = reads(report)[:6]
    fl = flows(report)
    hs = hosts(report)
    pts = ports(report)
    g, nodes = _graph(report)
    right: list[tuple[str, str, str, str]] = []  # (key, title, subtitle, style)
    flow_targets = []
    for x in fl:
        if x["target"] not in flow_targets:
            flow_targets.append(x["target"])
    for t in flow_targets[:3]:
        n = nodes.get(t, {})
        if n.get("kind") == "network":
            right.append(
                (t, "Somewhere off your box", "destination not visible in the code", "bad")
            )
        else:
            right.append((t, _clip(n.get("label", t)), "unexplained site", "bad"))
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
        right.append(("dev", title, _clip(dev[0].name, 30), "priv"))
    rest = [h for h in net if h not in dev]
    if rest:
        own = sum(1 for h in rest if h.cls == "declared")
        sub = f"{own} named in the app's docs" if own else "none named in the app's docs"
        label = "Other internet sites" if dev else "Internet sites"
        right.append(("net", f"{label}: {len(rest)}", sub, ""))
    if not rd and not right:
        return '<p class="muted">It reads none of your private data, and its code names no network addresses.</p>'

    row_h, top = 56, 16
    rows = max(len(rd), len(right), 2)
    height = top * 2 + rows * row_h + 22
    cy = top + rows * row_h / 2
    w = 700
    parts = [
        f'<svg class="flow" viewBox="0 0 {w} {height:.0f}" width="100%" style="min-width:560px" '
        f'role="img" aria-label="Data flow for {e(name, 80)}">',
        '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
        'markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" '
        'fill="var(--red)"/></marker>'
        '<marker id="arrg" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" '
        'markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" '
        'fill="var(--muted)"/></marker></defs>',
    ]
    port_dirs = {p.direction for p in pts}
    proven_src = {x["source"] for x in fl if x["evidence"] == "proven"}
    flow_src = {x["source"] for x in fl}

    def ys(n: int) -> list[float]:
        span = n * row_h
        start = cy - span / 2
        return [start + i * row_h + 6 for i in range(n)]

    lpos: dict[str, float] = {}
    for (nid, label, sens), y in zip(rd, ys(len(rd)), strict=False):
        style = (
            ("var(--red-bg)", "var(--red)")
            if nid in flow_src
            else (("var(--yellow-bg)", "var(--yellow)") if sens else ("var(--soft)", "var(--line)"))
        )
        parts.append(
            f'<rect x="6" y="{y:.0f}" width="176" height="44" rx="8" fill="{style[0]}" stroke="{style[1]}"/>'
            f'<text x="18" y="{y + 19:.0f}">{e(_clip(explain.data_label(label)))}</text>'
            f'<text class="sm" x="18" y="{y + 35:.0f}">{e(_clip(label, 30))}</text>'
        )
        parts.append(
            f'<line x1="182" y1="{y + 22:.0f}" x2="258" y2="{cy:.0f}" '
            'stroke="var(--muted)" stroke-dasharray="3 3" marker-end="url(#arrg)"/>'
        )
        lpos[nid] = y + 22
    if not rd:
        parts.append(
            f'<text class="sm" x="6" y="{cy + 4:.0f}">Reads none of your private data</text>'
        )
    # bold system-ui is ~0.62em per character; the box has ~154px for text
    name_px = 12 if len(name) <= 19 else max(9.5, round(154 / (0.62 * min(len(name), 26)), 1))
    center_at = len(parts)
    parts.append(
        f'<rect x="260" y="{cy - 28:.0f}" width="170" height="56" rx="10" fill="var(--card)" '
        'stroke="var(--fg)" stroke-width="1.5"/>'
        f'<text x="345" y="{cy - 3:.0f}" text-anchor="middle" style="font-weight:650;font-size:{name_px}px">{e(_clip(name, 26))}</text>'
        f'<text class="sm" x="345" y="{cy + 13:.0f}" text-anchor="middle">'
        f"{e(KIND.get(str(report.get('target', {}).get('kind')), ''))}</text>"
    )
    rpos: dict[str, float] = {}
    for (key, title, sub, style), y in zip(right, ys(len(right)), strict=False):
        fill, stroke = {
            "bad": ("var(--card)", "var(--red)"),
            "priv": ("var(--priv-bg)", "var(--priv)"),
        }.get(style, ("var(--soft)", "var(--line)"))
        parts.append(
            f'<rect x="{w - 200}" y="{y:.0f}" width="194" height="44" rx="8" fill="{fill}" stroke="{stroke}"/>'
            f'<text x="{w - 188}" y="{y + 19:.0f}">{e(title, 60)}</text>'
            f'<text class="sm" x="{w - 188}" y="{y + 35:.0f}">{e(_clip(sub, 32))}</text>'
        )
        # Arrow = who opens the connection: out to a site or server; into the app for a
        # port it listens on; no arrow when the code doesn't make the direction clear.
        way = (port_dirs.pop() if len(port_dirs) == 1 else None) if key == "ports" else "out"
        if way == "in":
            parts.append(
                f'<line x1="{w - 200}" y1="{y + 22:.0f}" x2="432" y2="{cy:.0f}" '
                'stroke="var(--muted)" marker-end="url(#arrg)"/>'
            )
        else:
            mark = ' marker-end="url(#arrg)"' if way == "out" else ""
            x2 = w - 202 if way == "out" else w - 200
            parts.append(
                f'<line x1="430" y1="{cy:.0f}" x2="{x2}" y2="{y + 22:.0f}" '
                f'stroke="var(--muted)"{mark}/>'
            )
        rpos[key] = y + 22
    lines: list[str] = []
    for x in fl:
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
    if fl:
        cap = "solid: traced in the code · dashed: reads it and can reach an unexplained site, path not proven"
        if extra > 0:
            cap += f" · {extra} more destination{'s' * (extra != 1)} below"
    else:
        cap = "Arrows: which way the connection goes. No path found from your data to the internet."
    parts.append(f'<text class="sm" x="6" y="{height - 8:.0f}">{e(cap)}</text></svg>')
    del proven_src, g
    return '<div class="flowwrap">' + "".join(parts) + "</div>"


# --- where it connects -------------------------------------------------------------------------

ZONES = [
    ("home", "🏠 Your home network", "Addresses on your own network", {"local"}),
    ("own", "☁️ The app's own sites", "Named in its docs, or matching its name", {"declared"}),
    ("dev", "🛠 Servers the developer runs", "On free app-hosting services", {"developer_hosted"}),
    (
        "ana",
        "📊 Analytics and crash reports",
        "Services that collect usage or errors",
        {"analytics"},
    ),
    (
        "other",
        "🌐 Other sites",
        "Not in the app's docs",
        {"undeclared", "public_ip", "exfil_service", "messaging"},
    ),
    (
        "links",
        "🔗 Project and help links",
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


def _host_li(h: Host, deep: str = "") -> str:
    """Scheme, port (the URL's own, else the scheme's default) and encryption per site,
    so a port listed under "address not in the code" is never mistaken for this one."""
    bits = []
    explicit = sorted(set(h.ports))
    for s in sorted(set(h.schemes)):
        nums = explicit or [_DEFAULT_PORT[s]] if s in _DEFAULT_PORT else explicit
        port = f" · port {', '.join(map(str, nums))}" if nums else ""
        lock = _lock(s) if h.cls not in ("link", "infrastructure") else ""
        bits.append(e(s) + port + lock)
    if not h.schemes and explicit:
        bits.append("port " + ", ".join(map(str, explicit)))
    urls = "".join(f'<span class="u">{e(u, 200)}</span>' for u in h.urls[:3])
    flag = ' <span class="chip bad">see findings</span>' if h.flagged else ""
    return (
        f'<li><div><code>{e(h.name, 120)}</code>{flag}<span class="p">{" · ".join(bits)}</span>'
        f"</div>{urls}{deep}</li>"
    )


def zones_html(report: dict[str, Any], deep: DeepFn | None = None) -> str:
    """`deep(edge_id)` adds the "Explain in context" block to an address or port."""
    deep = deep or (lambda _id: "")
    hs = hosts(report)
    pts = ports(report)
    if not hs and not pts:
        return '<p class="muted">Its code names no sites, IP addresses or ports.</p>'
    out = ['<div class="zones">']
    for key, title, sub, classes in ZONES:
        zh = [h for h in hs if h.cls in classes]
        if not zh:
            continue
        shown = zh[:12]
        more = f'<li class="muted">and {len(zh) - 12} more</li>' if len(zh) > 12 else ""
        out.append(
            f'<div class="zone {key}"><h3>{title}</h3><div class="zs">{sub}</div><ul>'
            + "".join(_host_li(h, deep(h.edge_id)) for h in shown)
            + more
            + "</ul></div>"
        )
    if pts:
        items = []
        for p in pts:
            known = WELL_KNOWN_PORTS.get(p.port)
            label = f"{known[0]}, port {p.port}" if known else f"Port {p.port}"
            names = ", ".join(f"<code>{e(n, 60)}</code>" for n in p.names[:2])
            where = e(p.where[0], 160) if p.where else ""
            how = {
                "out": "connects out to it",
                "in": "listens on it (others connect in)",
            }.get(p.direction or "", "direction not clear from the code")
            items.append(
                f'<li><div><span>{e(label)}</span><span class="p">{_lock(p.port).strip()}</span></div>'
                f'<span class="u">{e(how)} · {names} · {where}</span>{deep(p.edge_id)}</li>'
            )
        out.append(
            '<div class="zone"><h3>🔌 Connections whose address isn\'t in the code</h3>'
            '<div class="zs">The code sets these ports, but the server\'s address comes from '
            "setup or from another server while the app runs. So we can't tie them to any "
            "site listed here.</div><ul>" + "".join(items) + "</ul></div>"
        )
    out.append("</div>")
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


def hygiene_html(report: dict[str, Any]) -> str:
    """The repo's own security habits: context, never scored, inferred from public signs."""
    h = report.get("hygiene")
    if not isinstance(h, dict):
        return ""
    repo = str(report.get("target", {}).get("repo") or "")
    yes, no = '<span class="ok">✓</span>', '<span class="muted">–</span>'
    li = []
    sc = h.get("scanners") or []
    if sc:
        names = ", ".join(
            f"{e(x.get('name'))} ({_SCAN_KIND.get(x.get('kind'), 'checks')})" for x in sc
        )
        li.append(f"{yes} Runs security scans in its GitHub workflows: {names}.")
    else:
        li.append(f"{no} No security scanner in its GitHub workflows (CodeQL, Semgrep, Bandit, "
                  "Trivy, OSV-Scanner, pip-audit, Gitleaks…).")  # fmt: skip
    dep = h.get("dependabot")
    if dep is not None:
        what = ", ".join(_ECO.get(x, x) for x in dep) or "its dependencies"
        li.append(f"{yes} Dependabot is set up to propose updates for {e(what)}.")
    if h.get("renovate"):
        li.append(f"{yes} Renovate is set up to propose dependency updates.")
    if dep is None and not h.get("renovate"):
        li.append(f"{no} No Dependabot or Renovate set up for dependency updates.")
    if h.get("security_policy"):
        li.append(f"{yes} Has a security policy (<code>{e(h['security_policy'])}</code>): how to "
                  "report a problem privately.")  # fmt: skip
    else:
        li.append(f"{no} No SECURITY.md telling people how to report a problem privately.")
    prs = h.get("update_prs")
    if isinstance(prs, dict) and prs.get("off"):
        li.append(f"{no} Pull requests are turned off on this repository.")
    elif isinstance(prs, dict):
        n = int(prs.get("open") or 0)
        if n:
            old = _ago(prs.get("oldest_days"))
            li.append(f"Dependency-update pull requests waiting to be merged: <b>{n}</b>"
                      + (f", the oldest {old}" if old else "") + ".")  # fmt: skip
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
            li.append(f"Open issues that look security-related: <b>{n}</b>{among}"
                      f'<ul class="plain">{items}</ul>')  # fmt: skip
        else:
            li.append(f"{yes} No open issue labeled or titled as a security problem "
                      f"({of} open issue{'s' * (of != 1)} checked).")  # fmt: skip
    if h.get("dependabot_but_known_vulns"):
        li.append(
            '<span class="sev-medium">⚠</span> Dependabot watches these dependencies, yet this '
            "release ships some with known vulnerabilities (see What we found). Either an alert "
            "wasn't acted on, or the fix came after this release."
        )
    for err in h.get("errors") or []:
        li.append(f'<span class="muted">Not checked: {e(err, 300)}</span>')
    return (
        '<section class="box"><h2>The developer\'s security habits</h2><p class="sub">What the '
        "app's own repository shows about keeping it safe. This is context and never changes "
        "the score. GitHub keeps scan alerts private, so it's read from public signs.</p>"
        '<ul class="plain">' + "".join(f"<li>{x}</li>" for x in li) + "</ul></section>"
    )


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
            cause = f"our rules changed ({e(prev.tool_version)} → {e(r.tool_version)})"
        elif prev.ref == r.ref:
            cause = "checked again"
        else:
            cause = (
                f"update {e(prev.ref or '?', 40)} → {e(r.ref or '?', 40)} · "
                f'<a href="{base}/diff?old={prev.id}&amp;new={r.id}">what changed</a>'
            )
        here = " <b>(this page)</b>" if r.id == sid else ""
        items.append(
            f"<li><b>{what}</b> · {score} · {cause} · "
            f'<span class="muted">{e(r.scanned_at[:10])}, rules {e(r.tool_version)}</span>{here}</li>'
        )
        prev = r
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
) -> bytes:
    """One app's detail page. `update` and `ai_form` are server-built HTML snippets."""
    t = report.get("target", {})
    title = name or (t.get("repo") or t.get("input") or "?").rsplit("/", 1)[-1]
    complete = bool(report.get("complete"))
    b = band(report.get("score"), complete)
    vkey = report.get("verdict", {}).get("key", "")
    plain = BANDS[b][1] if complete else "the check didn't finish"
    kind = KIND.get(str(t.get("kind")), str(t.get("kind")))
    ha = (
        f", with dependencies resolved for HA {e(report['ha_version'])}"
        if report.get("ha_version")
        else ""
    )
    commit = (t.get("commit_sha") or "")[:12]
    ai = ai or {}
    head = (
        f'<p class="crumb"><a href="{base}/">← All apps</a></p>'
        f'<section class="box dhead">{ring(int(report.get("score", 0)), b)}<div style="min-width:0">'
        f"<h1>{e(title, 80)}</h1>"
        f'<div><span class="verdict" style="color:var(--{b})">{_VERDICT_EMOJI.get(vkey, "")} '
        f"{e(report.get('verdict', {}).get('label', ''))} · {e(plain)}</span> "
        f'<span class="muted">· {e(kind)} · {e(t.get("ref") or "?", 60)} · {e(t.get("repo") or t.get("input"), 120)}</span></div>'
        f'<div class="muted small">Checked with Barkley {e(report.get("tool", {}).get("version"))}: '
        f"{e(_SOURCE.get(str(t.get('install_source')), t.get('install_source')))}"
        f"{' (commit ' + e(commit) + ')' if commit else ''}{ha}. Scan @{sid}.</div>"
        "</div></section>"
    )
    parts = [head, update]
    missing = [
        a for a in report.get("analyzers", []) if a.get("state") not in ("ok", "not_applicable")
    ]
    if missing:
        parts.append(
            '<div class="banner warn"><b>Part of the check didn\'t finish</b>, so the score '
            "is capped at 89 and we can't vouch for everything:<ul class=plain>"
            + "".join(
                f"<li><b>{e(a.get('name'))}</b> {e(a.get('state'))}: {e(a.get('detail'), 300)}</li>"
                for a in missing
            )
            + "</ul></div>"
        )
    summary = ai.get("summary", "")
    parts.append(
        f'<section class="box"><h2>In short</h2><p class="inshort">{in_short(report)}</p>'
        + (
            f'<div class="aibox"><div class="small">{AI_BADGE}<b>AI explanation</b></div>'
            f"<p>{e(summary, 1500)}</p></div>"
            if summary
            else ""
        )
        + ai_form
        + "</section>"
    )
    parts.append(privacy_html(privacy.notes(report)))
    groups = scored_findings(report)
    if groups:
        expl = ai.get("findings", {})
        items = (report.get("context") or {}).get("items") or {}
        dfn = deep or (lambda _id: "")
        parts.append(
            f'<section class="box"><h2>What we found ({len(groups)})</h2>'
            + "".join(
                finding_html(
                    f,
                    fs,
                    p,
                    next((expl[x["id"]] for x in fs if x["id"] in expl), ""),
                    next((dfn(x["id"]) for x in fs if x["id"] in items), ""),
                )
                for f, fs, p in groups
            )
            + "</section>"
        )
    else:
        parts.append(
            '<section class="box"><h2>What we found</h2><p class="ok">Nothing smelled off. 🦴</p></section>'
        )
    parts.append(
        '<section class="box"><h2>Where your data can go</h2><p class="sub">Left: what it can '
        "read. Right: where it can connect. A red line means we found a path from your data "
        "to that place in the code. No line means we found no path.</p>"
        f"{flow_svg(report, title)}</section>"
    )
    parts.append(
        '<section class="box"><h2>Where it connects</h2><p class="sub">Every site, IP address '
        "and port in the shipped code, grouped by where it is. A site being here means the code "
        "mentions it, not that it was seen connecting. Web addresses drop anything after "
        f"<code>?</code>, which can hold keys.</p>{zones_html(report, deep)}</section>"
    )
    parts.append(hygiene_html(report))
    can = explain.can_do(report)
    parts.append(
        '<div class="two"><section class="box"><h2>What it can do inside Home Assistant</h2>'
        + (
            '<ul class="plain">' + "".join(f"<li>{e(x)}</li>" for x in can) + "</ul>"
            if can
            else '<p class="muted small">Nothing notable.</p>'
        )
        + f'</section><section class="box"><h2>History</h2>{history_html(base, sid, report, rows)}'
        f'<p class="tech"><a href="{base}/scan/{sid}.json">Technical report (raw JSON)</a></p></section></div>'
    )
    return page(f"Barkley · {title}", "".join(parts), refresh)
