"""(0.15, his decision 2026-11-21: mock-up v5) "What it touches" (named "What it does"
until 2026-11-24): the app's page picture.

Inside your Home Assistant, a column of seven fixed rooms (the same for every app, so apps
can be compared at a glance): blue when the app reads (eye) or changes (pencil) something
there, dashed when Barkley saw it do nothing. The app sits to their right, still inside.
Outside your home, the sites it sends requests to. A path Barkley found from your data to
a site that isn't the app's own runs red, from the room through the app to the site; to
the app's own site it runs dotted grey. Exposure is orange and points in: a door for each
way in (a page that opens without logging in, messages from the internet, a link that can
run code), a bug strip on the app for libraries with known vulnerabilities, and a card's
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
from sniff_test.report import logins

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
# (0.15, his ask 2026-11-22) what an app does in its own space: said in grey, with a thin
# dashed line into the room, without lighting it (blue is reach beyond its own job)
OWN_RULES = {
    "ha-own-storage-path": ("files", "keeps its own data in Home Assistant's storage folder"),
}

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
    "ha-read-own-secret": ("files", READS, "reads one named entry of your secrets file"),
    "ha-raw-storage-access": ("files", READS, "looks inside the private storage folder"),
    "py-write-outside-own-dir": ("files", CHANGES, "writes or deletes files outside its folder"),
    "py-shell-exec": ("programs", CHANGES, "runs commands on your system"),
    "py-runtime-pip": ("programs", CHANGES, "installs extra software while running"),
    "py-eval-exec": ("programs", CHANGES, "builds code while running and runs it"),
    "py-lua-download": ("programs", CHANGES, "runs code it downloads"),
    "py-dynamic-import": ("programs", READS, "loads code whose name it works out"),
    "ha-monkeypatch": ("programs", CHANGES, "changes how Home Assistant itself works"),
    "ha-supervisor-token": ("programs", READS, "reads the key to your whole system"),
    "ha-supervisor-token-local": ("programs", READS, "asks the Supervisor with that key"),
    "card-read-tokens": ("browser", READS, "reads your saved login"),
    "card-access-token-use": ("browser", READS, "uses your login"),
    "card-token-settings": ("browser", READS, "sends your login to the address in its settings"),
    "card-eval": ("browser", CHANGES, "builds code while running and runs it"),
    "card-eval-config": ("browser", CHANGES, "runs code from its own settings"),
    "card-eval-address": ("browser", CHANGES, "runs code taken from the page address"),
    "card-remote-script": ("browser", CHANGES, "loads code from the internet"),
    "card-remote-pinned": ("browser", CHANGES, "loads a fixed version of code from the internet"),
    # signs of malicious behavior: red in the room they come from
    "card-token-exfil": ("browser", OUT, "may send your login to another site"),
    "card-eval-remote": ("browser", CHANGES, "runs code it gets from outside"),
    "card-code-loader": ("browser", CHANGES, "can run code from an address it is given"),
    "card-b64-eval": ("browser", CHANGES, "hides code and then runs it"),
    "py-b64-exec": ("programs", CHANGES, "hides code and then runs it"),
    "py-obfuscation": ("programs", CHANGES, "uses tricks that hide what its code does"),
}
# flows_to sources (graph node ids) -> room
FLOW_ROOM = {"auth": "users", "data:secrets.yaml": "files", "data:.storage files": "files",
             "data:auth and credential storage": "users",
             "data:other integrations' credentials": "apps"}  # fmt: skip
# ways in: rule -> what someone can do. Who that someone is, and so whether the door is
# inside your home or outside it, follows where Home Assistant can be reached from
# (Settings → Where Home Assistant runs; his rule 2026-11-22: it has to be accurate).
NETWORK_WHO = {"home": "Anyone on your home network",
               "shared": "Anyone on your shared or work network",
               "internet": "Anyone on the internet"}  # fmt: skip
DOORS = {
    # reachable by whoever can reach Home Assistant
    "ha-unauth-view": (None, "can open one of its pages without logging in"),
    "ha-webhook-remote": (None, "who knows its secret address can send it messages"),
    # always someone outside: a site you visit, a link someone sends you
    "ha-cors-allowed": ("Other websites you visit", "can call one of its pages from your "
                        "browser"),
    "card-eval-address": ("Anyone who sends you a link", "can make it run code in your "
                          "dashboard"),
}  # fmt: skip


def door(rule: str, network: str) -> tuple[str, str, bool]:
    """(who, what they can do, inside your home?) for a way in."""
    who, what = DOORS[rule]
    if who is None:
        where = network if network in NETWORK_WHO else "home"
        return NETWORK_WHO[where], what, where != "internet"
    return who, what, False


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
    doors: list[tuple[str, str, bool]] = field(default_factory=list)  # who, what, inside
    bugs: int = 0
    browser: bool = False
    elsewhere: int = 0  # requests whose address the code works out while it runs
    # (0.15, his ask 2026-11-22) what the app does for itself, drawn without lighting a room:
    # the kinds of entity it adds, and that it holds the login you gave it
    own: dict[str, list[str]] = field(default_factory=dict)  # room -> plain lines
    holds_login: bool = False
    # an address you entered at setup (home network or internet: Barkley can't tell)
    entered: list[str] = field(default_factory=list)  # the setup fields
    entered_login: bool = False  # the login you gave this app goes there
    entered_how: list[str] = field(default_factory=list)  # "by MQTT"… (a library's other ways)
    elsewhere_other: int = 0  # run-time addresses not from what you entered
    # (0.15, his ask 2026-11-23) code from outside that runs here: a dotted orange arrow from
    # where it comes from into the room where it runs. Sites by index -> room; and for code
    # whose address comes from a server's answer, a dashed box (its text, room, the sites
    # whose answer gives the address)
    code_paths: list[tuple[int, str]] = field(default_factory=list)
    code_only: set[int] = field(default_factory=set)  # code sites with no request drawn
    code_boxes: list[tuple[str, str, list[str]]] = field(default_factory=list)


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


_URL_HOST = readings.URL_HOST
CODE_RULES = {"card-remote-script": "sends code that runs here",
              "card-remote-pinned": "sends a fixed version of code"}  # fmt: skip
WHERE_RUNS = {"browser": "in your browser", "programs": "in Home Assistant"}


def code_sources(
    report: dict[str, Any],
) -> tuple[dict[str, tuple[str, str]], list[tuple[str, str, list[str]]]]:
    """(0.15, his ask 2026-11-23) Where code from outside comes from: {site: (room, what
    the site's line says)} for a card's code site and Lua downloaded from a site named in
    the code; and boxes (text, room, answering sites) for Lua whose address comes from a
    server's answer or can't be traced. Only sites Barkley read in the code."""
    sites: dict[str, tuple[str, str]] = {}
    boxes: list[tuple[str, str, list[str]]] = []
    for f in report.get("findings") or []:
        if not isinstance(f, dict) or str(f.get("rule_id")) not in CODE_RULES:
            continue
        m = _URL_HOST.search(str(f.get("evidence") or "")[:2000])
        if m and m[1] not in sites:
            sites[m[1].lower().rstrip(".")] = ("browser", CODE_RULES[str(f["rule_id"])])
    lua = report.get("lua")
    runs = lua.get("runs") if isinstance(lua, dict) else None
    for r in runs if isinstance(runs, list) else []:
        if not isinstance(r, dict) or r.get("source") != "downloaded":
            continue
        for o in [o for o in r.get("from") or [] if isinstance(o, dict)][:2] or [{}]:
            kind, detail = str(o.get("kind") or ""), str(o.get("detail") or "")
            hosts = [h for h in detail.split(",") if _URL_HOST.fullmatch("//" + h)][:3]
            if kind in ("site", "list") and hosts:
                for h in hosts:
                    sites.setdefault(h, ("programs", "sends code that runs here"))
                continue
            if kind == "answer":
                said = [h for h in str(o.get("site") or "").split(",")
                        if _URL_HOST.fullmatch("//" + h)][:3]  # fmt: skip
                text = (f"Code from an address {said[0]} gives it" if len(said) == 1
                        else "Code from an address one of these sites gives it" if said
                        else "Code from an address a server gives it")  # fmt: skip
                box = (text, "programs", said)
            elif kind == "setup":
                box = ("Code from the address you entered", "programs", [])
            else:
                box = ("Code from an address Barkley couldn't trace", "programs", [])
            if box not in boxes:
                boxes.append(box)
    return sites, boxes[:2]


def build(report: dict[str, Any], name: str) -> Model:
    """The picture's content from a shown report (shown.view: test scripts left out)."""
    from sniff_test import ui  # the graph helpers live there

    t = report.get("target") or {}
    card = str(t.get("kind")) == "plugin"
    m = Model(name, "Dashboard card" if card else "Integration", browser=card)
    rd = report.get("readings") if isinstance(report.get("readings"), dict) else {}
    network = str(rd.get("network") or "home")
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
        if rule in OWN_RULES:
            room, text = OWN_RULES[rule]
            if text not in m.own.get(room, []):
                m.own.setdefault(room, []).append(text)
        if rule in DOORS and (d := door(rule, network)) not in m.doors:
            m.doors.append(d)
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
    sites = ui.all_site_requests(report)  # (0.15) with the sites it picks from a list
    named = ui.site_requests(report)
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
    # (0.15) a site that gets your login, and one a library connects to for the app
    marked = logins.marks(report)
    # a site Barkley proved data flows to is drawn even when no request to it was read
    # (a card's code, or an address the request reader couldn't follow)
    names = list(sites) + [h for h in flow_hosts if h and h not in sites]
    names += [h for h, mk in marked.items() if mk.library and h not in names]
    code, m.code_boxes = code_sources(report)
    names += [h for h in code if h not in names]
    order = sorted(
        names,
        key=lambda h: (h not in code, h not in flow_hosts, h not in own,
                       not (h in marked and marked[h].login), h),
    )  # fmt: skip
    for host in order[:SITES_SHOWN]:
        how = "bad" if host in flow_hosts and host not in own else "own" if host in own else ""
        lines = _site_lines(sites.get(host))
        picked = next((len(c.get("picked") or []) for c in sites.get(host) or []
                       if isinstance(c, dict) and c.get("picked")), 0)  # fmt: skip
        if picked > 1 and host not in named:  # (0.15) picked from a list while it runs
            lines = [f"one of {picked} sites it picks from", *lines][:2]
        if host == OFF_BOX:
            lines = ["the code doesn't show where"]
        elif not lines and host in flow_hosts:
            lines = ["your data goes here"]
        mk = marked.get(host)
        if mk and mk.library:
            via = f"the {mk.library} library" if len(mk.library) <= 20 else "a library"
            lines = [f"through {via}", *lines][:2]
        if mk and (mk.login or mk.token):
            said = "gets the login you gave this app" if mk.login else "gets a token from a server"
            lines = [*lines[:2], KEY + said]
        if host in code:  # (0.15) code from here runs in a room: a dotted orange arrow
            room, said = code[host]
            if not lines:
                m.code_only.add(len(m.sites))
            lines = [CODE + said, *lines][:3]
            m.code_paths.append((len(m.sites), room))
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
    entity_kinds = [x for x in report.get("platforms") or [] if isinstance(x, str)]
    g = report.get("graph") if isinstance(report.get("graph"), dict) else {}
    by_kind: dict[str, set[str]] = {}  # node kind -> relations from the app
    gnodes = {n.get("id"): n for n in g.get("nodes") or [] if isinstance(n, dict)}
    for x in g.get("edges") or []:
        if isinstance(x, dict):
            kind = str(gnodes.get(x.get("target"), {}).get("kind") or "")
            by_kind.setdefault(kind, set()).add(str(x.get("relation") or ""))
    actions = "registers" in by_kind.get("service", set()) | by_kind.get("entity_service", set())
    if entity_kinds or actions:
        m.own.setdefault("devices", []).append(own_devices(entity_kinds, actions))
    if card:  # a card works inside your session by design
        m.own.setdefault("browser", []).append("runs here, with your Home Assistant login")
        if m.bugs:
            n = m.bugs
            lib, run = ("library", "runs") if n == 1 else ("libraries", "run")
            m.own["browser"].append(f"{n} {lib} with known vulnerabilities {run} here too")
    else:
        if "injects" in by_kind.get("frontend_js", set()):  # reach: every page you open
            m.use.setdefault("browser", []).append(
                (CHANGES, "adds code to every Home Assistant page in your browser")
            )
        if "registers" in by_kind.get("panel", set()):
            m.own.setdefault("browser", []).append("adds its own page to the sidebar")
        if "registers" in by_kind.get("http_static", set()):
            m.own.setdefault("browser", []).append("serves its own files to your browser")
    m.holds_login = logins.holds_login(report)
    ent = logins.entered(report)
    if ent.discovered:
        m.own.setdefault("network", []).append(
            "connects to devices Home Assistant finds for it on your network"
        )
    m.entered, m.entered_login, m.entered_how = ent.fields, ent.login, ent.how
    m.elsewhere_other = ent.other
    return m


# Home Assistant's entity platforms in plain words (analyzers/platforms.ENTITY_PLATFORMS)
KIND_WORDS = {
    "sensor": "sensors", "binary_sensor": "on/off sensors", "climate": "thermostats",
    "switch": "switches", "light": "lights", "select": "option lists",
    "number": "number settings", "button": "buttons", "cover": "covers", "fan": "fans",
    "lock": "locks", "camera": "cameras", "media_player": "media players",
    "alarm_control_panel": "alarm panels", "vacuum": "vacuums", "water_heater": "water heaters",
    "humidifier": "humidifiers", "device_tracker": "device trackers", "weather": "weather",
    "update": "update notices", "event": "events", "image": "images", "text": "text fields",
    "time": "time settings", "date": "date settings", "datetime": "date settings",
    "siren": "sirens", "valve": "valves", "lawn_mower": "lawn mowers", "notify": "notifiers",
    "tts": "text-to-speech", "stt": "speech-to-text", "scene": "scenes",
    "calendar": "calendars", "todo": "to-do lists", "conversation": "conversation agents",
    "remote": "remotes", "air_quality": "air quality", "geo_location": "map locations",
    "assist_satellite": "voice satellites", "ai_task": "AI tasks", "wake_word": "wake words",
    "image_processing": "image processing",
}  # fmt: skip
_KIND_ORDER = ("climate", "light", "switch", "cover", "lock", "sensor", "binary_sensor")


def own_devices(kinds: list[str], actions: bool = False) -> str:
    """ "adds its own thermostats, sensors and option lists" (the first four kinds), and
    "…, and its own actions" when it registers actions."""
    if not kinds:
        return "adds its own actions"
    ordered = sorted(kinds, key=lambda k: (_KIND_ORDER.index(k) if k in _KIND_ORDER else 99, k))
    words = list(dict.fromkeys(KIND_WORDS.get(k, k.replace("_", " ")) for k in ordered))
    shown, more = words[:4], len(words) - 4
    text = ", ".join(shown[:-1]) + (" and " if len(shown) > 1 else "") + shown[-1]
    out = f"adds its own {text}" + (f" and {more} more kinds" if more > 0 else "")
    return out + (", and its own actions" if actions else "")


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
               if not str(w).startswith(readings.POSSIBLE_REASON)]  # fmt: skip
    if not reasons:
        return (
            f'<p class="expo none">{_ic("door")}<span><b>Exposure {x:g} of 10.</b> Barkley '
            "found no way in: no page without a login, no library with known "
            "vulnerabilities.</span></p>"
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


KEY = "\x00key:"  # a site line that says your login (or a token) goes there
CODE = "\x00code:"  # a site line that says code from there runs here (orange)


def _site_line(t: str, x: float, y: float) -> str:
    if t.startswith(CODE):
        return f'<text class="co" x="{x}" y="{y:.0f}">{e(t[len(CODE) :], 36)}</text>'
    if t.startswith(KEY):
        text = e(t[len(KEY) :], 34)
        return (f'<g class="pk">{_icon("key", x, y - 10, 12)}</g>'
                f'<text class="pv" x="{x + 16}" y="{y:.0f}">{text}</text>')  # fmt: skip
    return f'<text class="ns" x="{x}" y="{y:.0f}">{e(t, 36)}</text>'


def _room_h(u: list[tuple[str, str]] | None, own: list[str] | None = None) -> int:
    if not u and not own:
        return IDLE_H
    texts = [t for _, t in u or []] + list(own or [])
    return 34 + 17 * sum(len(textwrap.wrap(t, WRAP)) for t in texts) + 6


def wide(m: Model, key: str = "d") -> str:
    hs = [_room_h(m.use.get(k), m.own.get(k)) for k, _, _ in ROOMS]
    top = 60
    height = top + sum(hs) + GAP * (len(hs) - 1) + 24
    cy = top + (height - top - 24) / 2
    inside = [d for d in m.doors if d[2]]
    outside = [d for d in m.doors if not d[2]]
    in_h = [36 + 16 * len(textwrap.wrap(what, IN_WRAP)) for _w, what, _i in inside]
    if inside:  # the app moves down far enough for its doors and their arrow above it
        need = top + sum(in_h) + 12 * (len(in_h) - 1) + 44 + APP_H / 2 + 20 * m.browser
        cy = max(cy, need)
    bug_h = (12 + 16 * len(textwrap.wrap(_bug_note(m.bugs), 20)) + 8) if m.bugs else 0
    height = max(height, cy + APP_H / 2 + bug_h + 40 + (20 if m.holds_login else 0))
    p = [f'<svg class="flow does" viewBox="0 0 {W} {height:.0f}" role="img" '
         f'aria-label="What {e(m.name, 80)} does">',
         f'<defs><marker id="g-{key}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
         'markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="mk"/>'
         f'</marker><marker id="r-{key}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
         'markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="mkr"/>'
         f'</marker><marker id="o-{key}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
         'markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" class="mko"/></marker>'
         f'<marker id="k-{key}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
         'markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" class="mkk"/></marker></defs>',
         f'<rect class="inside" x="4" y="8" width="{WALL - 4}" '
         f'height="{height - 16:.0f}" rx="12"/>',
         f'<rect class="outside" x="{WALL + 12}" y="8" width="{W - WALL - 16}" '
         f'height="{height - 16:.0f}" rx="12"/>',
         f'<g class="hdr">{_icon("home", 22, 21, 16)}<text x="44" y="34">Inside your Home '
         "Assistant</text></g>",
         f'<g class="hdr">{_icon("globe", YARD_X + 4, 21, 16)}<text x="{YARD_X + 26}" y="34">'
         "Outside your home</text></g>"]  # fmt: skip
    # doors take the top of the yard; sites go below them
    door_h = [36 + 16 * len(textwrap.wrap(what, 32)) for _who, what, _i in outside]
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
                    + "".join(_site_line(t, YARD_X + 12, sy + 39 + 16 * j)
                              for j, t in enumerate(lines))
                    + "</g>")  # fmt: skip
        smid.append(sy + h / 2)
        sy += h + 12
    notes = []
    if m.more_sites:
        notes.append(f"and {m.more_sites} more site{'s' * (m.more_sites != 1)}")
    if m.elsewhere_other or (m.elsewhere and not m.entered and "network" not in m.own):
        notes.append("and requests to addresses it works out while it runs")
    if not m.sites and not m.elsewhere and not m.entered:
        notes.append("Nothing leaves: no request in its code.")
    wrapped = [part for text in notes for part in textwrap.wrap(text, 38)]
    for j, text in enumerate(wrapped):
        yard.append(f'<text class="ns" x="{YARD_X}" y="{max(sy, cy) + 16 + 17 * j:.0f}">'
                    f"{e(text)}</text>")  # fmt: skip
    notes_end = max(sy, cy) + 16 + 17 * len(wrapped)
    entered_box = _entered_box(m, cy, notes_end, bug_h, key)
    path_room = {room: how for room, _i, how in m.paths}
    rooms, lines, y = [], [], float(top)
    room_mid: dict[str, float] = {}
    for (k, label, ic), h in zip(ROOMS, hs, strict=True):
        room_mid[k] = y + h / 2
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
        for what in m.own.get(k) or []:  # its own devices: said, the room not lit
            for part in textwrap.wrap(what, WRAP):
                r.append(f'<text class="ro" x="{RX + 48}" y="{yy:.0f}">{e(part, 60)}</text>')
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
        elif m.own.get(k):  # its own space: a thin dashed line from the app into the room
            mid = y + h / 2
            curve = f"M{RX + RW + 2} {mid:.0f} C {APP_X - 40} {mid:.0f}, {APP_X - 50} {cy:.0f}, "
            lines.append(f'<path class="own" d="{curve}{APP_X} {cy:.0f}" '
                         f'marker-start="url(#g-{key})"/>')  # fmt: skip
        y += h + GAP
    for i, room in m.code_paths:  # (0.15) code from this site runs in that room
        if i < len(smid):
            lines.append(_code_arrow(YARD_X - 2, smid[i], room_mid[room], key))
    for i, mid in enumerate(smid):
        if i in m.code_only:
            continue  # only code comes from it: the orange arrow is its line
        how = next((hw for _r, s, hw in m.paths if s == i), None)
        cls_l = "ln" if how is None else ("path bad" if how == "bad" else "path")
        mk = "r" if how == "bad" else "g"
        if how != "bad" and any(t.startswith(KEY + "gets the login") for t in m.sites[i][1]):
            cls_l, mk = "kp", "k"  # the login you gave this app goes along this line
        lines.append(f'<path class="{cls_l}" d="M{APP_X + APP_W} {cy:.0f} C {WALL - 20} '
                     f'{cy:.0f}, {YARD_X - 40} {mid:.0f}, {YARD_X - 2} {mid:.0f}" '
                     f'marker-end="url(#{mk}-{key})"/>')  # fmt: skip
    # (2026-11-23, his report) over the grey lines only: a site that only sends code has
    # an orange arrow instead, and the label sat on it
    grey = [mid for i, mid in enumerate(smid) if i not in m.code_only]
    if grey:
        bad = any(how == "bad" for *_x, how in m.paths)
        ly = min(_curve_y(cy, mid, WALL - 60) for mid in grey) - 8
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
    if m.holds_login:  # (his ask) the app holds the login you gave it
        ky = cy + APP_H / 2 + 20
        app.append(f'<g class="pk">{_icon("key", APP_X + 4, ky - 10, 12)}</g>'
                   f'<text class="pv" x="{APP_X + 20}" y="{ky:.0f}">holds the login you gave it'
                   "</text>")  # fmt: skip
    if m.bugs:
        by = cy + APP_H / 2 + 8 + (20 if m.holds_login else 0)
        note = textwrap.wrap(_bug_note(m.bugs), 20)
        bh = 12 + 16 * len(note)
        app.append(f'<g class="bugs"><rect x="{APP_X}" y="{by:.0f}" width="{APP_W}" '
                   f'height="{bh}" rx="6"/><g class="bi">{_icon("bug", APP_X + 8, by + 6, 14)}'
                   "</g>" + "".join(f'<text x="{APP_X + 28}" y="{by + 18 + 16 * j:.0f}">'
                                    f"{e(t)}</text>" for j, t in enumerate(note))
                   + "</g>")  # fmt: skip
    for i, (who, what, _in) in enumerate(outside):  # outside: crosses the wall, from above
        dy = top + sum(door_h[:i]) + 12 * i
        app.append(_door_box(YARD_X, dy, SITE_W, door_h[i], who, what, 32))
        y1 = dy + 30
        ax = APP_X + APP_W - 16
        app.append(f'<path class="inbound" d="M{YARD_X - 2} {y1:.0f} C {WALL - 30} {y1:.0f}, '
                   f'{ax} {y1:.0f}, {ax} {cy - APP_H / 2 - 2:.0f}" marker-end="url(#o-{key})"/>'
                   f'<text class="cross in" x="{WALL - 8}" y="{y1 - 6:.0f}" '
                   'text-anchor="end">comes in</text>')  # fmt: skip
    dy = float(top)
    for i, (who, what, _in) in enumerate(inside):  # inside your home: no wall to cross
        app.append(_door_box(IN_X, dy, IN_W, in_h[i], who, what, IN_WRAP))
        dy += in_h[i] + 12
    if inside:
        mx = APP_X + 24
        end = cy - APP_H / 2 - 2 - (20 if m.browser else 0)
        app.append(f'<path class="inbound" d="M{mx} {dy - 10:.0f} L {mx} {end:.0f}" '
                   f'marker-end="url(#o-{key})"/><text class="cross in" x="{mx + 8}" '
                   f'y="{(dy - 10 + end) / 2 + 4:.0f}">comes in</text>')  # fmt: skip
    below = notes_end
    if entered_box:
        below = entered_box[1]
    for text, room, said in m.code_boxes:  # code from an address worked out while it runs
        to = [smid[i] for i, (h, _l, _w) in enumerate(m.sites) if h in said and i < len(smid)]
        box, bottom = _code_box(text, room_mid[room], to, below, cy, bug_h, m, key)
        yard.append(box)
        below = bottom
        entered_box = (entered_box[0] if entered_box else "", bottom)
    if entered_box:
        box, bottom = entered_box
        yard.append(box)
        if bottom + 24 > height:  # the box sits below the rest: the picture grows
            old_h, height = height, bottom + 24
            p = [x.replace(f'viewBox="0 0 {W} {old_h:.0f}"', f'viewBox="0 0 {W} {height:.0f}"')
                 .replace(f'height="{old_h - 16:.0f}"', f'height="{height - 16:.0f}"')
                 for x in p]  # fmt: skip
    p += lines + rooms + app + yard + ["</svg>"]
    return "".join(p)


EBOX_X, EBOX_W = WALL - 60, 220  # straddles the wall: home network or internet


def _entered_box(m: Model, cy: float, notes_end: float, bug_h: float, key: str):
    """The dashed box for an address you entered at setup, below the app and the sites,
    with the line from the app (purple when the login you gave this app goes there)."""
    if not m.entered:
        return None
    rows = [("nt", "The address you entered"),
            ("ns", f"when you set it up ({', '.join(m.entered)})"),
            ("ns", "Home network or internet:"), ("ns", "Barkley can't tell")]  # fmt: skip
    if m.entered_how:
        rows.append(("ns", "by " + " and ".join(m.entered_how[:2])))
    if m.entered_login:
        rows.append(("pv", KEY + "gets the login you gave this app"))
    app_bottom = cy + APP_H / 2 + (20 if m.holds_login else 0) + bug_h
    y0 = max(notes_end, app_bottom) + 24
    h = 20 + 17 * len(rows)
    out = [f'<g class="maybe"><rect x="{EBOX_X}" y="{y0:.0f}" width="{EBOX_W}" height="{h}" '
           'rx="8"/>']  # fmt: skip
    for j, (cls, text) in enumerate(rows):
        ty = y0 + 22 + 17 * j
        if text.startswith(KEY):
            out.append(_site_line(text, EBOX_X + 12, ty))
        else:
            out.append(f'<text class="{cls}" x="{EBOX_X + 12}" y="{ty:.0f}">{e(text, 34)}</text>')
    out.append("</g>")
    mid = y0 + h / 2
    cls_l, mk = ("kp", "k") if m.entered_login else ("ln", "g")
    # from the app's right edge, then down to the right of the notes under the app
    sx, sy0 = APP_X + APP_W, cy + 10
    out.append(f'<path class="{cls_l}" d="M{sx} {sy0:.0f} C {EBOX_X - 14} {sy0:.0f}, '
               f'{EBOX_X - 24} {mid:.0f}, {EBOX_X - 2} {mid:.0f}" '
               f'marker-end="url(#{mk}-{key})"/>')  # fmt: skip
    return "".join(out), y0 + h


def _code_arrow(x0: float, y0: float, room_y: float, key: str) -> str:
    """A dotted orange arrow from where code comes from (a site's or a box's left edge)
    into the right edge of the room where it runs; it passes behind the app."""
    x1 = RX + RW + 2
    return (
        f'<path class="codein" d="M{x0:.0f} {y0:.0f} C {WALL - 60} {y0:.0f}, '
        f'{x1 + 50} {room_y:.0f}, {x1} {room_y:.0f}" marker-end="url(#o-{key})"/>'
    )


def _code_box(
    text: str,
    room_y: float,
    sites: list[float],
    below: float,
    cy: float,
    bug_h: float,
    m: Model,
    key: str,
) -> tuple[str, float]:
    """(0.15) A dashed box for code whose address comes from a server's answer (or can't be
    traced): below the app and the notes, straddling the wall like the address you entered.
    A thin grey line from the box to each answering site on the picture; a dotted orange
    arrow from the box into the room where the code runs."""
    rows = [*textwrap.wrap(text, 30), f"runs {WHERE_RUNS.get('programs')}"]
    app_bottom = cy + APP_H / 2 + (20 if m.holds_login else 0) + bug_h
    y0 = max(below, app_bottom) + 24
    h = 20 + 17 * len(rows)
    out = [f'<g class="maybe"><rect x="{EBOX_X}" y="{y0:.0f}" width="{EBOX_W}" height="{h}" '
           'rx="8"/>']  # fmt: skip
    for j, t in enumerate(rows):
        cls = "nt" if j < len(rows) - 1 else "co"
        out.append(f'<text class="{cls}" x="{EBOX_X + 12}" y="{y0 + 22 + 17 * j:.0f}">'
                   f"{e(t, 34)}</text>")  # fmt: skip
    out.append("</g>")
    mid = y0 + h / 2
    bx = EBOX_X + 30
    for sy in sites:  # up from the box's top to the site whose answer gives the address
        out.append(f'<path class="own" d="M{bx} {y0 - 2:.0f} C {bx} {sy:.0f}, {bx} {sy:.0f}, '
                   f'{YARD_X - 2} {sy:.0f}"/>')  # fmt: skip
    out.append(_code_arrow(EBOX_X - 2, mid, room_y, key))
    return "".join(out), y0 + h


IN_X, IN_W, IN_WRAP = APP_X - 16, WALL - 16 - (APP_X - 16), 34  # a door inside your home


def _door_box(x: float, y: float, w: float, h: float, who: str, what: str, wrap: int) -> str:
    body = textwrap.wrap(what, wrap)
    return (f'<g class="door"><rect x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{h}" '
            f'rx="8"/><g class="di">{_icon("door", x + 10, y + 10, 14)}</g><text class="nt" '
            f'x="{x + 32:.0f}" y="{y + 22:.0f}">{e(who)}</text>'
            + "".join(f'<text class="ns" x="{x + 32:.0f}" y="{y + 40 + 16 * j:.0f}">{e(t)}</text>'
                      for j, t in enumerate(body)) + "</g>")  # fmt: skip


def _curve_y(cy: float, mid: float, x: float) -> float:
    """Where an outgoing line (the app's right edge at cy to a site's middle) is at `x`."""
    x0, x1, x2, x3 = APP_X + APP_W, WALL - 20, YARD_X - 40, YARD_X - 2
    lo, hi, t = 0.0, 1.0, 0.5
    for _ in range(30):  # bisection on the curve's x
        t = (lo + hi) / 2
        xt = (1 - t) ** 3 * x0 + 3 * (1 - t) ** 2 * t * x1 + 3 * (1 - t) * t**2 * x2 + t**3 * x3
        lo, hi = (t, hi) if xt < x else (lo, t)
    return (1 - t) ** 3 * cy + 3 * (1 - t) ** 2 * t * cy + 3 * (1 - t) * t**2 * mid + t**3 * mid


def _bug_note(n: int) -> str:
    return f"Uses {n} librar{'ies' if n != 1 else 'y'} with known vulnerabilities"


# --- narrow: plain HTML --------------------------------------------------------------------


def narrow(m: Model) -> str:
    rooms = []
    for k, label, ic in ROOMS:
        u = m.use.get(k)
        cls = "bad" if k in m.bad_rooms else "on" if u else ""
        items = "".join(f'<span class="nd">{_ic(g)}{e(t)}</span>' for g, t in u or [])
        items += "".join(f'<span class="ns2">{e(t)}</span>' for t in m.own.get(k) or [])
        rooms.append(f'<div class="nroom {cls}"><span class="nl">{_ic(ic)}{e(label)}</span>'
                     f"{items}</div>")  # fmt: skip
    extra = ""
    if m.browser:
        extra += '<span class="ns2">runs in your browser session</span>'
    if m.holds_login:
        extra += f'<span class="ns2 pv2">{_ic("key")}holds the login you gave it</span>'
    if m.bugs:
        extra += f'<span class="nbug">{_ic("bug")}{e(_bug_note(m.bugs))}</span>'
    app = (f'<div class="napp"><b>{e(m.name, 60)}</b><span class="ns2">{e(m.kind)}</span>'
           f"{extra}</div>")  # fmt: skip

    def ndoor(who: str, what: str) -> str:
        return (f'<div class="ndoor">{_ic("door")}<span><b>{e(who)}</b> {e(what)}</span>'
                '<span class="arrow-in">comes in</span></div>')  # fmt: skip

    in_doors = "".join(ndoor(w, t) for w, t, inside in m.doors if inside)
    doors = "".join(ndoor(w, t) for w, t, inside in m.doors if not inside)
    sites = "".join(
        f'<div class="nsite{" bad" if how == "bad" else ""}">'
        + (f"<b>{e(host)}</b>" if host == OFF_BOX else f"<code>{e(host, 60)}</code>")
        + "".join(f'<span class="ns2 pv2">{_ic("key")}{e(t[len(KEY):], 60)}</span>'
                  if t.startswith(KEY) else
                  f'<span class="ns2 co2">{e(_runs_where(m, i, t[len(CODE):]), 80)}</span>'
                  if t.startswith(CODE) else f'<span class="ns2">{e(t, 60)}</span>'
                  for t in lines) + "</div>"
        for i, (host, lines, how) in enumerate(m.sites)
    )  # fmt: skip
    if m.more_sites:
        sites += f'<p class="ns2">and {m.more_sites} more site{"s" * (m.more_sites != 1)}</p>'
    if m.entered:
        sites += (f'<div class="nsite maybe"><b>The address you entered</b><span class="ns2">'
                  f'when you set it up ({e(", ".join(m.entered), 80)}). Home network or '
                  "internet: Barkley can't tell.</span>"
                  + (f'<span class="ns2">by {e(" and ".join(m.entered_how[:2]))}</span>'
                     if m.entered_how else "")
                  + (f'<span class="ns2 pv2">{_ic("key")}gets the login you gave this app</span>'
                     if m.entered_login else "") + "</div>")  # fmt: skip
    for text, room, _said in m.code_boxes:
        sites += (f'<div class="nsite maybe"><b>{e(text, 80)}</b><span class="ns2 co2">'
                  f"runs {e(WHERE_RUNS.get(room, ''))}</span></div>")  # fmt: skip
    if not m.sites and not m.elsewhere and not m.entered:
        sites += '<p class="ns2">Nothing leaves: no request in its code.</p>'
    return (
        f'<div class="narrow"><div class="hdr2">{_ic("home")}Inside your Home Assistant</div>'
        f'<div class="nrooms">{"".join(rooms)}{in_doors}{app}</div>'
        f'<div class="hdr2">{_ic("globe")}Outside your home</div>{doors}{sites}</div>'
    )


def _runs_where(m: Model, i: int, said: str) -> str:
    """A code site's line on a phone: where that code runs ("… runs in your browser")."""
    room = next((r for j, r in m.code_paths if j == i), "")
    where = WHERE_RUNS.get(room, "")
    return said.replace("that runs here", f"that runs {where}") if where else said


def legend(m: Model) -> str:
    bits = [
        "Blue rooms: what it reads (eye) or changes (pencil) beyond its own devices. Dashed "
        "rooms: Barkley saw nothing more there."
    ]
    if m.holds_login:
        bits.append("Purple: the login you gave this app, and where Barkley saw it go.")
    if m.own:
        bits.append(
            "Thin dashed line: what it does in its own space, such as adding its own "
            "devices, or for a card, running in your browser session."
        )
    if m.entered:
        bits.append(
            "Dashed box: an address you entered when you set it up. Barkley can't "
            "tell if it's on your home network or the internet."
        )
    if any(how == "own" for *_x, how in m.paths):
        bits.append("Dotted line: your data goes through the app to its own site.")
    if any(how == "bad" for *_x, how in m.paths):
        bits.append("Red line: your data goes through the app to a site that isn't the app's own.")
    if m.code_paths or m.code_boxes:
        bits.append("Dotted orange arrow: code from outside that runs here.")
    if m.doors or m.bugs:
        bits.append("Orange, pointing in: a way in that counts toward Exposure.")
    return f'<p class="sub">{" ".join(bits)}</p>'


def section(report: dict[str, Any], name: str, rd: dict[str, Any], setting: str) -> str:
    m = build(report, name)
    return ('<section class="box"><h2>What it touches</h2>' + bar_html(rd, setting)
            + f'<div class="flowwrap"><div class="wide">{wide(m)}</div>{narrow(m)}</div>'
            + legend(m) + "</section>")  # fmt: skip
