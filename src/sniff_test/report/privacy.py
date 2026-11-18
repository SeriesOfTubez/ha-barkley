"""Privacy notes: data we surface, never scored (user decision, 2026-11-09).

Worked out from a stored report when a page renders, so they work on every stored scan
(0.4.0 reports have no URL samples or port facts; their notes are just thinner).

Notes:
- `telemetry` / `developer`: a server the developer runs (serverless hosting such as
  workers.dev), titled telemetry when the host or URL path says so;
- `analytics`: analytics, tag-manager or crash-report services;
- `unencrypted`: a site on the internet the code only ever addresses with `http://` or
  `ws://`. A host that also appears with `https://` is left out: on 25 real repos those
  were documentation links inside error messages (moment.js's "See http://momentjs.com/
  guides/…", a bundled library's "http://github.com/…"), never connections;
- `mqtt`: MQTT on port 1883 in the code, which is normally unencrypted.

Sending tokens, secrets or other integrations' data off the box is not a privacy note:
the exfil rules score it.

(0.14.0) The telemetry analyzer traces a usage-reporting send in the code. One address
gets one entry: a scored `telemetry-shadow` / `telemetry-opt-out` finding replaces the
note for its address, and an unscored `telemetry-usage` finding is folded into the note
(its trace becomes "What we can't tell"; the app page doesn't list it again). The user's
report: the same send showed twice, as a privacy note and as an FYI.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_TELEMETRY = re.compile(
    r"(?i)telemetry|analytic|metric|(?:^|[./_-])(?:ping|stats?|track|beacon)(?:$|[./_-])"
)
# Classes where http:// says nothing about your data: your own network, links shown in a
# UI, identifiers, and the HA ecosystem / package registries (docs links, mostly).
_NO_TRANSPORT_NOTE = {"local", "link", "namespace", "resolver", "infrastructure"}


@dataclass
class Note:
    kind: str  # telemetry | developer | analytics | unencrypted | mqtt
    label: str  # short purple chip / level text
    title: str
    means: str
    unknown: str  # what we can't tell from the code
    hosts: list[str] = field(default_factory=list)  # untrusted: from the scanned code
    where: list[str] = field(default_factory=list)  # "file:line", untrusted
    # (0.13.0) graph edge ids behind the note, in the order shown: an edge with an
    # "Explain in context" item (report.context) opens that same reading from the note
    edges: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)  # each edge's host class ("" for a port)


def _ids(edges: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Edge ids and host classes, one per edge, so they line up with `hosts`."""
    return (
        [str(e.get("id") or "") for e in edges],
        [str(e.get("attrs", {}).get("class") or "") for e in edges],
    )


def _where(edges: list[dict[str, Any]], limit: int = 4) -> list[str]:
    out: list[str] = []
    for e in edges:
        for s in e.get("samples", []):
            loc = f"{s['file']}:{s['line']}" if s.get("line") else str(s.get("file"))
            if loc not in out:
                out.append(loc)
    return out[:limit]


def _host_edges(report: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    g = report.get("graph") or {}
    nodes = {n["id"]: n for n in g.get("nodes", [])}
    return [
        (e, nodes[e["target"]])
        for e in g.get("edges", [])
        if e["relation"] == "connects_to"
        and e["source"] == g.get("subject")
        and e["target"] in nodes
    ]


def _port_edges(report: dict[str, Any], port: int) -> list[dict[str, Any]]:
    g = report.get("graph") or {}
    return [
        e
        for e in g.get("edges", [])
        if e["relation"] == "uses_port" and e["target"] == f"port:{port}"
    ]


TRACED = "telemetry-usage"  # folded into a privacy note, not listed under What we found
_SCORED_TRACE = {"telemetry-shadow", "telemetry-opt-out"}
_LEAD = "Sends what looks like usage reporting to "


def _traces(report: dict[str, Any]) -> tuple[set[str], dict[str, dict[str, Any]]]:
    """Hosts of scored telemetry findings, and host -> the unscored telemetry finding."""
    scored: set[str] = set()
    usage: dict[str, dict[str, Any]] = {}
    for f in report.get("findings", []):
        rule = f.get("rule_id")
        host = str(f.get("evidence") or "").split(" from ", 1)[0]
        if not host or rule not in _SCORED_TRACE | {TRACED}:
            continue
        if rule == TRACED:
            usage.setdefault(host, f)
        else:
            scored.add(host)
    return scored, usage


def _trace_text(f: dict[str, Any]) -> str:
    msg = str(f.get("message") or "")
    head, _, rest = msg.partition(". ")
    return rest if head.startswith(_LEAD) and rest else msg


def _loc(f: dict[str, Any]) -> str:
    return f"{f['file']}:{f['line']}" if f.get("line") else str(f.get("file") or "")


def _fold(note: Note, usage: dict[str, dict[str, Any]]) -> Note:
    """The code trace answers part of "what we can't tell" for the hosts it covers."""
    found = [(h, usage[h]) for h in note.hosts if h in usage]
    if not found:
        return note
    if len(found) == 1 and len(note.hosts) == 1:
        told = _trace_text(found[0][1])
    else:
        told = " ".join(f"{h}: {_trace_text(f)}" for h, f in found)
    rest = "" if len(found) == len(note.hosts) else " For the other addresses: " + note.unknown
    note.unknown = (told + " Barkley can't tell what it sends." + rest).strip()
    locs = [_loc(f) for _, f in found]
    note.where = [*dict.fromkeys([*locs, *note.where])][:4]
    return note


def notes(report: dict[str, Any]) -> list[Note]:
    out = _notes(report)
    scored, usage = _traces(report)
    if not scored and not usage:
        return out
    kept: list[Note] = []
    for n in out:
        if n.hosts and n.kind in ("telemetry", "developer", "analytics"):
            keep = [i for i, h in enumerate(n.hosts) if h not in scored]
            if not keep:
                continue
            if len(keep) < len(n.hosts):
                n.hosts = [n.hosts[i] for i in keep]
                n.edges = [n.edges[i] for i in keep if i < len(n.edges)]
                n.classes = [n.classes[i] for i in keep if i < len(n.classes)]
            n = _fold(n, usage)
        kept.append(n)
    covered = {h for n in kept for h in n.hosts}
    loose = [h for h in usage if h not in covered and h not in scored]
    if loose:
        edges = {n["label"]: e for e, n in _host_edges(report)}
        note = Note(
            "telemetry",
            "Telemetry",
            "Can send usage statistics to the developer",
            "The code has what looks like usage reporting. Any server it contacts sees your "
            "home's internet address.",
            "",
            loose,
            [],
            [str(edges[h].get("id") or "") if h in edges else "" for h in loose],
            [str(edges[h]["attrs"].get("class") or "") if h in edges else "" for h in loose],
        )
        note.unknown = "Whether it's switched on."
        kept.insert(0, _fold(note, usage))
    return kept


def _notes(report: dict[str, Any]) -> list[Note]:
    out: list[Note] = []
    dev_tel: list[tuple[dict, dict]] = []
    dev_other: list[tuple[dict, dict]] = []
    analytics: list[tuple[dict, dict]] = []
    plain: list[tuple[dict, dict]] = []
    for e, n in _host_edges(report):
        cls = e["attrs"].get("class")
        if cls == "developer_hosted":
            text = " ".join([n["label"], *e["attrs"].get("urls", [])])
            (dev_tel if _TELEMETRY.search(text) else dev_other).append((e, n))
        elif cls == "analytics":
            analytics.append((e, n))
        schemes = set(e["attrs"].get("schemes", []))
        if (
            schemes & {"http", "ws"}
            and not schemes & {"https", "wss"}
            and cls not in _NO_TRANSPORT_NOTE
        ):
            plain.append((e, n))

    if dev_tel:
        out.append(
            Note(
                "telemetry",
                "Telemetry",
                "Can send usage statistics to the developer",
                "The app can contact a server the developer runs (not the device maker), "
                "and its address says it collects statistics. Any server it contacts sees "
                "your home's internet address.",
                "Whether it's switched on, or exactly what it sends. Check the app's "
                "options in Settings > Devices & services.",
                [n["label"] for _, n in dev_tel],
                _where([e for e, _ in dev_tel]),
                *_ids([e for e, _ in dev_tel]),
            )
        )
    if dev_other:
        out.append(
            Note(
                "developer",
                "Developer server",
                "Talks to a server the developer runs",
                "The app can contact a server hosted on a free app-hosting service, which "
                "usually means the developer runs it rather than the device maker. Any "
                "server it contacts sees your home's internet address.",
                "What it sends there, or when. It may be a harmless helper, such as a login relay.",
                [n["label"] for _, n in dev_other],
                _where([e for e, _ in dev_other]),
                *_ids([e for e, _ in dev_other]),
            )
        )
    if analytics:
        out.append(
            Note(
                "analytics",
                "Analytics",
                "Uses an analytics or crash-report service",
                "The code mentions a service that collects usage statistics or error "
                "reports. Error reports can include details about your setup.",
                "Whether it's switched on, or what it sends.",
                [n["label"] for _, n in analytics],
                _where([e for e, _ in analytics]),
                *_ids([e for e, _ in analytics]),
            )
        )
    if plain:
        out.append(
            Note(
                "unencrypted",
                "Unencrypted",
                "Uses unencrypted web addresses on the internet",
                "The code only ever reaches these sites with http:// or ws://, never the "
                "encrypted https:// or wss://. Anything sent that way can be read or "
                "changed on the way.",
                "Whether the app sends anything private over them, or whether the site "
                "redirects to an encrypted address.",
                [n["label"] for _, n in plain],
                _where([e for e, _ in plain]),
                *_ids([e for e, _ in plain]),
            )
        )
    mqtt = _port_edges(report, 1883)
    if mqtt:
        out.append(
            Note(
                "mqtt",
                "May be unencrypted",
                "May use unencrypted MQTT",
                "The code uses port 1883, the usual port for MQTT without encryption. "
                "Device status and commands sent that way can be read on the way.",
                "Which server it connects to (it may be on your home network, where this "
                "matters less) and whether encryption is switched on elsewhere.",
                [],
                _where(mqtt),
                *_ids(mqtt),
            )
        )
    return out
