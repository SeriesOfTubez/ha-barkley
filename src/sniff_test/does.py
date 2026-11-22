"""(0.15, his decision 2026-11-21: mock-up v5) "What it does": the app's page picture.

Inside your Home Assistant, a column of seven fixed rooms (the same for every app, so apps
can be compared at a glance): blue when the app reads (eye) or changes (pencil) something
there, dashed when Barkley saw it do nothing. The app sits to their right, still inside.
Outside your home, the sites it sends requests to. A path Barkley found from your data to
a site that isn't the app's own runs red, from the room through the app to the site; to
the app's own site it runs dotted grey. Exposure is orange and points in: a door for each
way in (a page that opens without logging in, messages from the internet, a link that can
run code), a bug strip on the app for libraries with known security bugs, and a card's
box says it runs in your browser session. The Exposure bar on top shows from medium by
default (Settings → Exposure bar: medium and high, high only, always).

Everything comes from the stored scan (findings, the graph's flows, the requests); nothing
here is scored, and nothing is stored. Names and sites come from the scanned code:
escaped and clipped. Panel-only (logic.PANEL_ONLY). Two layouts: an SVG for wide screens
and plain HTML for phones (the CSS shows one).
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from html import escape
from typing import Any

from sniff_test import kinds, readings

ROOMS = (  # key, label, icon
    ("users", "Users and logins", "user"),
    ("apps", "Other apps' settings", "puzzle"),
    ("devices", "Devices and entities", "bulb"),
    ("files", "Files on the system", "file"),
    ("programs", "Programs and the system", "term"),
    ("network", "Your home network", "wifi"),
    ("browser", "Your browser session", "browser"),
)
READS, CHANGES, OUT = "eye", "pencil", "out"

# rule -> (room, reads or changes, what it does there, in plain words)
RULE_ROOM: dict[str, tuple[str, str, str]] = {
    "ha-auth-change-users": ("users", CHANGES, "changes who can log in"),
    "ha-auth-internals": ("users", READS, "handles login tokens"),
    "ha-auth-list-users": ("users", READS, "reads the list of users"),
    "ha-auth-token-check": ("users", READS, "checks login tokens sent to it"),
    "ha-read-auth-storage": ("users", READS, "opens the login and password storage"),
    "ha-foreign-entry-data": ("apps", READS, "reads other apps' saved passwords and settings"),
    "ha-foreign-entry-options": ("apps", READS, "reads other apps' settings"),
    "ha-bulk-location-read": ("devices", READS, "reads where the people in your home are"),
    "ha-read-secrets": ("files", READS, "reads your secrets file"),
    "ha-raw-storage-access": ("files", READS, "looks inside the private storage folder"),
    "ha-own-storage-path": ("files", CHANGES, "keeps its own file in the storage folder"),
    "py-write-outside-own-dir": ("files", CHANGES, "writes or deletes files outside its folder"),
    "py-shell-exec": ("programs", CHANGES, "runs commands on your system"),
    "py-runtime-pip": ("programs", CHANGES, "installs extra software while running"),
    "py-eval-exec": ("programs", CHANGES, "builds code while running and runs it"),
    "py-dynamic-import": ("programs", READS, "loads code whose name it works out"),
    "ha-monkeypatch": ("programs", CHANGES, "changes how Home Assistant itself works"),
    "ha-supervisor-token": ("programs", READS, "reads the key to your whole system"),
    "ha-supervisor-token-local": ("programs", READS, "asks the Supervisor with that key"),
    "card-read-tokens": ("browser", READS, "reads your saved login"),
    "card-access-token-use": ("browser", READS, "uses your login"),
    "card-eval": ("browser", CHANGES, "builds code while running and runs it"),
    "card-eval-config": ("browser", CHANGES, "runs code from its own settings"),
    "card-eval-address": ("browser", CHANGES, "runs code taken from the page address"),
    "card-remote-script": ("browser", CHANGES, "loads code from the internet"),
    "card-remote-pinned": ("browser", CHANGES, "loads a fixed version of code from the internet"),
    # signs of malicious behavior: red in the room they come from
    "card-token-exfil": ("browser", OUT, "may send your login to another site"),
    "card-eval-remote": ("browser", CHANGES, "runs code it gets from outside"),
    "card-b64-eval": ("browser", CHANGES, "hides code and then runs it"),
    "py-b64-exec": ("programs", CHANGES, "hides code and then runs it"),
    "py-obfuscation": ("programs", CHANGES, "uses tricks that hide what its code does"),
}
# flows_to sources (graph node ids) -> room
FLOW_ROOM = {"auth": "users", "data:secrets.yaml": "files", "data:.storage files": "files",
             "data:auth and credential storage": "users",
             "data:other integrations' credentials": "apps"}  # fmt: skip
# ways in: rule -> (who, what they can do)
DOORS = {
    "ha-unauth-view": ("Anyone on your network", "can open one of its pages without logging in"),
    "ha-webhook-remote": ("Anyone on the internet", "can send it messages"),
    "ha-cors-allowed": ("Other websites", "can call one of its pages from your browser"),
    "card-eval-address": ("Anyone who sends you a link", "can make it run code in your dashboard"),
}
SITES_SHOWN = 6
OFF_BOX = "Off your Home Assistant machine"
WRAP = 40  # characters per room line
BAR = {"medium": readings.LOW, "high": readings.MEDIUM, "always": -1.0}


def e(text: Any, n: int = 200) -> str:
    s = str(text or "")
    s = s if len(s) <= n else s[: n - 1] + "…"
    return escape(s, quote=True)


@dataclass
class Model:
    name: str
    kind: str  # Integration | Dashboard card
    use: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # room -> (glyph, text)
    bad_rooms: set[str] = field(default_factory=set)
    sites: list[tuple[str, list[str], str]] = field(default_factory=list)  # host, lines, how
    more_sites: int = 0
    paths: list[tuple[str, int, str]] = field(default_factory=list)  # room, site index, how
    doors: list[tuple[str, str]] = field(default_factory=list)
    bugs: int = 0
    browser: bool = False
    elsewhere: int = 0  # requests whose address the code works out while it runs


def _site_lines(calls: Any) -> list[str]:
    out: list[str] = []
    for c in calls if isinstance(calls, list) else []:
        if not isinstance(c, dict):
            continue
        what = str(c.get("method") or "Request")
        carry = [str(x) for x in (c.get("body") or [])[:3] if isinstance(x, str)]
        if c.get("auth"):
            what += " · with a login"
        elif carry:
            what += " · " + ", ".join(carry)
        if what not in out:
            out.append(what)
    return out[:2]


def build(report: dict[str, Any], name: str) -> Model:
    """The picture's content from a shown report (shown.view: test scripts left out)."""
    from sniff_test import ui  # the graph helpers live there

    t = report.get("target") or {}
    card = str(t.get("kind")) == "plugin"
    m = Model(name, "Dashboard card" if card else "Integration", browser=card)
    findings = [f for f in report.get("findings") or [] if isinstance(f, dict)]
    seen: set[tuple[str, str]] = set()
    for f in findings:
        rule = str(f.get("rule_id"))
        if rule in RULE_ROOM:
            room, glyph, text = RULE_ROOM[rule]
            if (room, text) not in seen:
                seen.add((room, text))
                m.use.setdefault(room, []).append((glyph, text))
            if kinds.is_threat(rule):
                m.bad_rooms.add(room)
        if rule in DOORS and DOORS[rule] not in m.doors:
            m.doors.append(DOORS[rule])
        if rule == readings.DEP_VULN:
            m.bugs += 1
    hs = ui.hosts(report)
    home = [h for h in hs if h.cls == "local"]
    if home:
        n = len(home)
        m.use.setdefault("network", []).append(
            (READS, f"talks to {n} address{'es' * (n != 1)} on your home network")
        )
    if pts := ui.ports(report):
        m.use.setdefault("network", []).append(
            (READS, f"uses {len(pts)} network port{'s' * (len(pts) != 1)}")
        )
    own = {h.name for h in hs if h.cls == "declared"}
    sites = ui.site_requests(report)
    flows = ui.flows(report)
    _g, nodes = ui._graph(report)
    flow_hosts: dict[str, str] = {}  # host -> room
    for x in flows:
        node = nodes.get(x.get("target"), {})
        # a flow to the network with no address in the code: said plainly
        host = OFF_BOX if node.get("kind") == "network" else str(node.get("label", ""))
        src = str(x.get("source", ""))
        room = FLOW_ROOM.get(src) or FLOW_ROOM.get(src.split(":", 1)[0], "apps")
        if card and room == "users":  # a card's login is the one in your browser
            room = "browser"
        flow_hosts.setdefault(host, room)
    # a site Barkley proved data flows to is drawn even when no request to it was read
    # (a card's code, or an address the request reader couldn't follow)
    names = list(sites) + [h for h in flow_hosts if h and h not in sites]
    order = sorted(names, key=lambda h: (h not in flow_hosts, h not in own, h))
    for host in order[:SITES_SHOWN]:
        how = "bad" if host in flow_hosts and host not in own else "own" if host in own else ""
        lines = _site_lines(sites.get(host))
        if host == OFF_BOX:
            lines = ["the code doesn't show where"]
        elif not lines and host in flow_hosts:
            lines = ["your data goes here"]
        m.sites.append((host, lines, how))
    m.more_sites = max(0, len(order) - SITES_SHOWN)
    for i, (host, _lines, how) in enumerate(m.sites):
        if host in flow_hosts:
            room = flow_hosts[host]
            m.paths.append((room, i, how or "own"))
            text = (
                "goes out of your Home Assistant machine"
                if host == OFF_BOX
                else f"goes out to {host}"
            )
            m.use.setdefault(room, []).append((OUT, text))
            if how == "bad":
                m.bad_rooms.add(room)
    r = report.get("requests")
    m.elsewhere = len(r.get("elsewhere") or []) if isinstance(r, dict) else 0
    return m


# --- the Exposure bar ------------------------------------------------------------------


def bar_html(rd: dict[str, Any], setting: str) -> str:
    """The orange strip with the Exposure reading and its reasons, above the picture: from
    medium by default; never for a found threat (the banner speaks then)."""
    if rd.get("threat_level") == "found":
        return ""
    x = float(rd.get("exposure") or 0)
    if x < BAR.get(setting, readings.LOW):
        return ""
    reasons = [str(w) for w in rd.get("exposure_reasons") or []
               if not str(w).startswith("This may be a sign")]  # fmt: skip
    if not reasons:
        return (
            f'<p class="expo none">{_ic("door")}<span><b>Exposure {x:g} of 10.</b> Barkley '
            "found no way in: no page without a login, no library with known security "
            "bugs.</span></p>"
        )
    level = str(rd.get("exposure_level") or "")
    return (f'<p class="expo">{_ic("door")}<span><b>Exposure {x:g} of 10 ({e(level)}).</b> '
            + " ".join(e(w, 400) for w in reasons) + "</span></p>")  # fmt: skip


def _ic(name: str) -> str:
    from sniff_test import ui

    return ui.icon(name, 14, "dic")


# --- wide: one SVG -----------------------------------------------------------------------

W = 1010
RX, RW = 24, 300
IDLE_H, GAP = 34, 8
APP_X, APP_W, APP_H = 396, 170, 60
WALL = 700
YARD_X, SITE_W = 724, 266


def _icon(name: str, x: float, y: float, size: int = 14) -> str:
    from sniff_test import ui

    return (f'<svg x="{x:.0f}" y="{y:.0f}" width="{size}" height="{size}" viewBox="0 0 24 24">'
            '<g fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" '
            f'stroke-linejoin="round">{ui._ICONS[name]}</g></svg>')  # fmt: skip


def _room_h(u: list[tuple[str, str]] | None) -> int:
    if not u:
        return IDLE_H
    return 34 + 17 * sum(len(textwrap.wrap(t, WRAP)) for _, t in u) + 6


def wide(m: Model, key: str = "d") -> str:
    hs = [_room_h(m.use.get(k)) for k, _, _ in ROOMS]
    top = 60
    height = top + sum(hs) + GAP * (len(hs) - 1) + 24
    cy = top + (height - top - 24) / 2
    p = [f'<svg class="flow does" viewBox="0 0 {W} {height:.0f}" role="img" '
         f'aria-label="What {e(m.name, 80)} does">',
         f'<defs><marker id="g-{key}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
         'markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="mk"/>'
         f'</marker><marker id="r-{key}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
         'markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="mkr"/>'
         f'</marker><marker id="o-{key}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
         'markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" class="mko"/></marker></defs>',
         f'<rect class="inside" x="4" y="8" width="{WALL - 4}" '
         f'height="{height - 16:.0f}" rx="12"/>',
         f'<rect class="outside" x="{WALL + 12}" y="8" width="{W - WALL - 16}" '
         f'height="{height - 16:.0f}" rx="12"/>',
         f'<g class="hdr">{_icon("home", 22, 21, 16)}<text x="44" y="34">Inside your Home '
         "Assistant</text></g>",
         f'<g class="hdr">{_icon("globe", YARD_X + 4, 21, 16)}<text x="{YARD_X + 26}" y="34">'
         "Outside your home</text></g>"]  # fmt: skip
    # doors take the top of the yard; sites go below them
    door_h = [36 + 16 * len(textwrap.wrap(what, 32)) for _who, what in m.doors]
    sites_top = top + sum(h + 12 for h in door_h)
    sh = [28 + 16 * max(1, len(lines)) for _h, lines, _how in m.sites]
    total = sum(sh) + 12 * max(len(sh) - 1, 0)
    sy = max(sites_top, cy - total / 2)
    smid: list[float] = []
    yard: list[str] = []
    for (host, lines, how), h in zip(m.sites, sh, strict=True):
        yard.append(f'<g class="site{" bad" if how == "bad" else ""}"><rect x="{YARD_X}" '
                    f'y="{sy:.0f}" width="{SITE_W}" height="{h}" rx="8"/><text class="nt'
                    f'{"" if host == OFF_BOX else " mono"}" '
                    f'x="{YARD_X + 12}" y="{sy + 21:.0f}">{e(host, 34)}</text>'
                    + "".join(f'<text class="ns" x="{YARD_X + 12}" y="{sy + 39 + 16 * j:.0f}">'
                              f"{e(t, 36)}</text>" for j, t in enumerate(lines))
                    + "</g>")  # fmt: skip
        smid.append(sy + h / 2)
        sy += h + 12
    notes = []
    if m.more_sites:
        notes.append(f"and {m.more_sites} more site{'s' * (m.more_sites != 1)}")
    if m.elsewhere:
        notes.append("and requests to addresses it works out while it runs")
    if not m.sites and not m.elsewhere:
        notes.append("Nothing leaves: no request in its code.")
    wrapped = [part for text in notes for part in textwrap.wrap(text, 38)]
    for j, text in enumerate(wrapped):
        yard.append(f'<text class="ns" x="{YARD_X}" y="{max(sy, cy) + 16 + 17 * j:.0f}">'
                    f"{e(text)}</text>")  # fmt: skip
    path_room = {room: how for room, _i, how in m.paths}
    rooms, lines, y = [], [], float(top)
    for (k, label, ic), h in zip(ROOMS, hs, strict=True):
        u = m.use.get(k)
        cls = "room " + ("bad" if k in m.bad_rooms else "on" if u else "idle")
        r = [f'<g class="{cls}"><rect x="{RX}" y="{y:.0f}" width="{RW}" height="{h}" rx="8"/>',
             f'<g class="ri">{_icon(ic, RX + 10, y + 10)}</g>',
             f'<text class="rt" x="{RX + 32}" y="{y + 22:.0f}">{e(label)}</text>']  # fmt: skip
        yy = y + 41
        for glyph, what in u or []:
            for j, part in enumerate(textwrap.wrap(what, WRAP)):
                if j == 0:
                    r.append(f'<g class="rg">{_icon(glyph, RX + 32, yy - 10, 12)}</g>')
                r.append(f'<text class="rd" x="{RX + 48}" y="{yy:.0f}">{e(part, 60)}</text>')
                yy += 17
        r.append("</g>")
        rooms.append("".join(r))
        if u:
            mid = y + h / 2
            how = path_room.get(k)
            if how:
                cls_l = "path bad" if how == "bad" else "path"
                ends = f' marker-end="url(#{"r" if how == "bad" else "g"}-{key})"'
            else:
                cls_l = "ln"
                ends = f' marker-end="url(#g-{key})"' if any(g == READS for g, _ in u) else ""
                if any(g == CHANGES for g, _ in u):
                    ends += f' marker-start="url(#g-{key})"'
            curve = f"M{RX + RW} {mid:.0f} C {APP_X - 40} {mid:.0f}, {APP_X - 50} {cy:.0f}, "
            lines.append(f'<path class="{cls_l}" d="{curve}{APP_X - 2} {cy:.0f}"{ends}/>')
        y += h + GAP
    for i, mid in enumerate(smid):
        how = next((hw for _r, s, hw in m.paths if s == i), None)
        cls_l = "ln" if how is None else ("path bad" if how == "bad" else "path")
        mk = "r" if how == "bad" else "g"
        lines.append(f'<path class="{cls_l}" d="M{APP_X + APP_W} {cy:.0f} C {WALL - 20} '
                     f'{cy:.0f}, {YARD_X - 40} {mid:.0f}, {YARD_X - 2} {mid:.0f}" '
                     f'marker-end="url(#{mk}-{key})"/>')  # fmt: skip
    if smid:
        bad = any(how == "bad" for *_x, how in m.paths)
        ly = min(smid[0], cy) - 24
        lines.append(f'<text class="cross{" bad" if bad else ""}" x="{WALL - 8}" '
                     f'y="{ly:.0f}" text-anchor="end">leaves your home</text>')  # fmt: skip
    app = [f'<g class="app"><rect x="{APP_X}" y="{cy - APP_H / 2:.0f}" width="{APP_W}" '
           f'height="{APP_H}" rx="8"/><text class="nt" x="{APP_X + APP_W / 2}" '
           f'y="{cy - 4:.0f}" text-anchor="middle">{e(m.name, 22)}</text><text class="ns" '
           f'x="{APP_X + APP_W / 2}" y="{cy + 14:.0f}" text-anchor="middle">{e(m.kind)}</text>'
           "</g>"]  # fmt: skip
    if m.browser:
        app.append(f'<text class="runs" x="{APP_X + APP_W / 2}" y="{cy - APP_H / 2 - 8:.0f}" '
                   'text-anchor="middle">runs in your browser session</text>')  # fmt: skip
    if m.bugs:
        by = cy + APP_H / 2 + 8
        note = textwrap.wrap(_bug_note(m.bugs), 20)
        bh = 12 + 16 * len(note)
        app.append(f'<g class="bugs"><rect x="{APP_X}" y="{by:.0f}" width="{APP_W}" '
                   f'height="{bh}" rx="6"/><g class="bi">{_icon("bug", APP_X + 8, by + 6, 14)}'
                   "</g>" + "".join(f'<text x="{APP_X + 28}" y="{by + 18 + 16 * j:.0f}">'
                                    f"{e(t)}</text>" for j, t in enumerate(note))
                   + "</g>")  # fmt: skip
    for i, (who, what) in enumerate(m.doors):
        dy = top + sum(door_h[:i]) + 12 * i
        body = textwrap.wrap(what, 32)
        app.append(f'<g class="door"><rect x="{YARD_X}" y="{dy:.0f}" width="{SITE_W}" '
                   f'height="{door_h[i]}" rx="8"/><g class="di">'
                   f'{_icon("door", YARD_X + 10, dy + 10, 14)}</g><text class="nt" '
                   f'x="{YARD_X + 32}" y="{dy + 22:.0f}">{e(who)}</text>'
                   + "".join(f'<text class="ns" x="{YARD_X + 32}" y="{dy + 40 + 16 * j:.0f}">'
                             f"{e(t)}</text>" for j, t in enumerate(body)) + "</g>")  # fmt: skip
        y1 = dy + 30
        app.append(f'<path class="inbound" d="M{YARD_X - 2} {y1:.0f} C {WALL - 10} {y1:.0f}, '
                   f'{APP_X + APP_W + 50} {cy - 22:.0f}, {APP_X + APP_W + 2} {cy - 22:.0f}" '
                   f'marker-end="url(#o-{key})"/><text class="cross in" x="{WALL - 8}" '
                   f'y="{y1 + 4:.0f}" text-anchor="end">comes in</text>')  # fmt: skip
    p += lines + rooms + app + yard + ["</svg>"]
    return "".join(p)


def _bug_note(n: int) -> str:
    return f"Uses {n} librar{'ies' if n != 1 else 'y'} with known security bugs"


# --- narrow: plain HTML --------------------------------------------------------------------


def narrow(m: Model) -> str:
    rooms = []
    for k, label, ic in ROOMS:
        u = m.use.get(k)
        cls = "bad" if k in m.bad_rooms else "on" if u else ""
        items = "".join(f'<span class="nd">{_ic(g)}{e(t)}</span>' for g, t in u or [])
        rooms.append(f'<div class="nroom {cls}"><span class="nl">{_ic(ic)}{e(label)}</span>'
                     f"{items}</div>")  # fmt: skip
    extra = ""
    if m.browser:
        extra += '<span class="ns2">runs in your browser session</span>'
    if m.bugs:
        extra += f'<span class="nbug">{_ic("bug")}{e(_bug_note(m.bugs))}</span>'
    app = (f'<div class="napp"><b>{e(m.name, 60)}</b><span class="ns2">{e(m.kind)}</span>'
           f"{extra}</div>")  # fmt: skip
    doors = "".join(
        f'<div class="ndoor">{_ic("door")}<span><b>{e(who)}</b> {e(what)}</span>'
        '<span class="arrow-in">comes in</span></div>'
        for who, what in m.doors
    )
    sites = "".join(
        f'<div class="nsite{" bad" if how == "bad" else ""}">'
        + (f"<b>{e(host)}</b>" if host == OFF_BOX else f"<code>{e(host, 60)}</code>")
        + "".join(f'<span class="ns2">{e(t, 60)}</span>' for t in lines) + "</div>"
        for host, lines, how in m.sites
    )  # fmt: skip
    if m.more_sites:
        sites += f'<p class="ns2">and {m.more_sites} more site{"s" * (m.more_sites != 1)}</p>'
    if not m.sites and not m.elsewhere:
        sites += '<p class="ns2">Nothing leaves: no request in its code.</p>'
    return (
        f'<div class="narrow"><div class="hdr2">{_ic("home")}Inside your Home Assistant</div>'
        f'<div class="nrooms">{"".join(rooms)}{app}</div>'
        f'<div class="hdr2">{_ic("globe")}Outside your home</div>{doors}{sites}</div>'
    )


def legend(m: Model) -> str:
    bits = [
        "Blue rooms: what it reads (eye) or changes (pencil). Dashed rooms: Barkley saw it "
        "do nothing there."
    ]
    if any(how == "own" for *_x, how in m.paths):
        bits.append("Dotted line: your data goes through the app to its own site.")
    if any(how == "bad" for *_x, how in m.paths):
        bits.append("Red line: your data goes through the app to a site that isn't the app's own.")
    if m.doors or m.bugs:
        bits.append("Orange, pointing in: a way in that counts toward Exposure.")
    return f'<p class="sub">{" ".join(bits)}</p>'


def section(report: dict[str, Any], name: str, rd: dict[str, Any], setting: str) -> str:
    m = build(report, name)
    return ('<section class="box"><h2>What it does</h2>' + bar_html(rd, setting)
            + f'<div class="flowwrap"><div class="wide">{wide(m)}</div>{narrow(m)}</div>'
            + legend(m) + "</section>")  # fmt: skip
