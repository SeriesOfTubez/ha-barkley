"""(0.15, his decision 2026-11-26) The developer's disclosure.yaml beside the scan.

Worked out from a stored scan when the page is shown (logic.PANEL_ONLY), so it never
changes a finding, a score or a reading. His scoring rule: Barkley scores only what it
can prove; a statement in the file changes nothing. Where the scan shows something
different, both are shown and Barkley says they don't match, in neutral words ("doesn't
match", never "false"): often the developer didn't know, and that's what it's for.

Compared with the scan: connections (with links and telemetry, against the sites the
code names), pages that open without a login (against the open routes and webhooks the
scan found) and telemetry (against the usage reporting the scan traced). Every other
section is shown as the developer's words only. A missing section means "not stated"
and is never compared; an empty list means "none".

Everything from the file is the developer's words from a scanned repository: hostile
text, escaped where it's shown, and never sent to the AI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SPEC = "https://ha-barkley.github.io/disclosure/"
TELEMETRY_RULES = ("telemetry-shadow", "telemetry-opt-out", "telemetry-usage")
WEBHOOK_RULES = ("inv-webhook", "ha-webhook-remote")
_OFF_BY_DEFAULT = "only after you switch on an option that is off by default"


@dataclass
class Line:
    """One comparison line. `scan`: Barkley's words (from the scan); `said`: the
    developer's words from the file; `mismatch`: they don't match."""

    subject: str  # a host or a path (hostile, escaped when shown)
    scan: str = ""
    said: str = ""
    mismatch: bool = False


@dataclass
class HostNote:
    said: str = ""  # the purpose (and who runs it) from the file
    listed: bool = False
    mismatch: str = ""  # Barkley's words on what doesn't match


@dataclass
class Comparison:
    state: str  # read | ignored
    problems: list[str] = field(default_factory=list)
    stated: list[str] = field(default_factory=list)  # sections the file has
    hosts: dict[str, HostNote] = field(default_factory=dict)  # sites with a request read
    unseen: list[Line] = field(default_factory=list)  # in the file, not in the code
    set_by: list[Line] = field(default_factory=list)  # addresses the code doesn't hold
    telemetry: list[Line] = field(default_factory=list)
    pages: list[Line] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def mismatches(self) -> int:
        lines = [*self.telemetry, *self.pages]
        return sum(1 for x in lines if x.mismatch) + sum(
            1 for h in self.hosts.values() if h.mismatch or not h.listed
        )


def covers(dest: str, host: str) -> bool:
    """`*.example.com` covers its subdomains (not example.com itself), as the spec says."""
    dest, host = dest.lower(), host.lower()
    if dest.startswith("*."):
        return host.endswith(dest[1:]) and host != dest[2:]
    return host == dest


def _dests(entry: dict[str, Any]) -> list[str]:
    d = entry.get("destination")
    return [x for x in (d if isinstance(d, list) else [d]) if isinstance(x, str)]


def _link_host(entry: dict[str, Any]) -> str:
    if isinstance(entry.get("host"), str):
        return entry["host"]
    url = str(entry.get("url") or "")
    return url.split("//", 1)[-1].split("/", 1)[0].split("?", 1)[0].split(":", 1)[0]


def _who(entry: dict[str, Any]) -> str:
    name = entry.get("run_by_name")
    words = {"developer": "the developer", "vendor": "the company the app is for",
             "third_party": "another company", "user": "you"}  # fmt: skip
    who = name if isinstance(name, str) else words.get(str(entry.get("run_by")), "")
    return f"Run by {who}." if who else ""


def _said(entry: dict[str, Any]) -> str:
    return " ".join(x for x in (str(entry.get("purpose") or ""), _who(entry)) if x)


def _telemetry_host(f: dict[str, Any]) -> str:
    return str(f.get("evidence") or "").split(" from ", 1)[0].strip()


def compare(
    report: dict[str, Any],
    hosts: dict[str, set[str]],
    requested: set[str],
) -> Comparison | None:
    """`hosts`: every internet site the code names, with the schemes it's reached by;
    `requested`: the ones Barkley read a request to (the only ones compared one by one:
    a site the code only mentions, such as a help link, isn't a connection)."""
    disc = report.get("disclosure")
    if not isinstance(disc, dict) or disc.get("state") not in ("read", "ignored"):
        return None
    if disc["state"] == "ignored":
        return Comparison("ignored", [str(p) for p in disc.get("problems") or []][:5])
    data = disc.get("data") if isinstance(disc.get("data"), dict) else {}
    out = Comparison("read", stated=[k for k in data if not k.startswith("_")], data=data)
    conns = data.get("connections")
    tele = data.get("telemetry")
    links = data.get("links")
    findings = report.get("findings") or []

    # connections: each site Barkley read a request to
    if isinstance(conns, list):
        listed = [(e, d) for e in conns for d in _dests(e)]
        listed += [(e, d) for e in tele or [] for d in _dests(e)]
        linked = [_link_host(e) for e in links or []]
        for host in sorted(requested):
            match = next((e for e, d in listed if covers(d, host)), None)
            note = HostNote()
            if match is not None:
                note.listed, note.said = True, _said(match)
                schemes = hosts.get(host, set())
                plain = bool(schemes) and schemes <= {"http", "ws"}
                secure = bool(schemes) and schemes <= {"https", "wss"}
                if match.get("encrypted") == "always" and plain:
                    note.mismatch = ("The file says the connection is always encrypted. The "
                                     "code reaches this site only without encryption.")  # fmt: skip
                elif match.get("encrypted") == "never" and secure:
                    note.mismatch = ("The file says the connection isn't encrypted. The code "
                                     "reaches this site only with encryption.")  # fmt: skip
            elif any(covers(d, host) for d in linked if d):
                note.listed = True
                note.mismatch = ("The file lists this site only as a link. Barkley read a "
                                 "request to it in the code.")  # fmt: skip
            out.hosts[host] = note
        for e in conns:
            if not _dests(e):
                where = {"setup": "An address you enter at setup.",
                         "setting": f"An address from the setting “{e.get('setting', '')}”.",
                         "server_reply": "An address a server's answer gives."}.get(
                    str(e.get("destination_set_by")), "")  # fmt: skip
                out.set_by.append(Line("", said=f"{where} {_said(e)}".strip()))
                continue
            for d in _dests(e):
                if not any(covers(d, h) for h in hosts):
                    out.unseen.append(Line(d, said=_said(e)))

    # telemetry: against the usage reporting the scan traced
    if isinstance(tele, list):
        sent = [f for f in findings if f.get("rule_id") in TELEMETRY_RULES]
        for f in sent:
            host = _telemetry_host(f)
            found = str(f.get("message") or "")
            entry = next((e for e in tele if any(covers(d, host) for d in _dests(e))), None)
            auto = f.get("rule_id") in ("telemetry-shadow", "telemetry-opt-out")
            off = f.get("rule_id") == "telemetry-usage" and _OFF_BY_DEFAULT in found
            if entry is None:
                said = ("The file says the app sends no usage statistics, analytics or crash "
                        "reports." if not tele else "The file's telemetry list doesn't have "
                        "this site.")  # fmt: skip
                out.telemetry.append(Line(host, found, said, mismatch=True))
                continue
            setting = entry.get("setting")
            if entry.get("on_by_default") is False and auto:
                said = (
                    f"The file says it's off until you turn on “{setting}”."
                    if isinstance(setting, str)
                    else "The file says it's off out of the box."
                )
                what = f"What it sends: {entry.get('contents', '')}"
                out.telemetry.append(Line(host, found, f"{said} {what}", mismatch=True))
            elif entry.get("on_by_default") is True and off:
                out.telemetry.append(
                    Line(
                        host,
                        found,
                        "The file says it's on out of the box. " + str(entry.get("contents", "")),
                        mismatch=True,
                    )
                )
            else:
                out.telemetry.append(Line(host, found, str(entry.get("contents") or "")))
        seen = {_telemetry_host(f) for f in sent}
        for e in tele:
            if not any(covers(d, h) for d in _dests(e) for h in seen):
                for d in _dests(e):
                    out.telemetry.append(
                        Line(d, "Barkley found no usage reporting to this site.",
                             str(e.get("contents") or ""))
                    )  # fmt: skip

    # pages that open without a login
    pages = data.get("pages")
    if isinstance(pages, list):
        open_pages = sorted(
            {
                str(f["page"])
                for f in findings
                if f.get("rule_id") == "ha-unauth-view" and f.get("page")
            }
        )
        hooks = any(f.get("rule_id") in WEBHOOK_RULES for f in findings) or any(
            n.get("kind") == "webhook" for n in (report.get("graph") or {}).get("nodes", [])
        )

        def has(path: str, p: dict[str, Any]) -> bool:
            q = str(p.get("path") or "")
            return path == q or (q.endswith("/") and path.startswith(q))

        for path in open_pages:
            entry = next((p for p in pages if has(path, p)), None)
            if entry is None:
                said = (
                    "The file says the app adds no page that opens without a login."
                    if not pages
                    else "The file's list of pages doesn't have this one."
                )
                out.pages.append(Line(path, "Barkley found a page here that opens without "
                                      "logging in.", said, mismatch=True))  # fmt: skip
            else:
                out.pages.append(Line(path, "Barkley found a page here that opens without "
                                      "logging in.", _page_said(entry)))  # fmt: skip
        for p in pages:
            path = str(p.get("path") or "")
            if any(has(x, p) for x in open_pages):
                continue
            if p.get("protection") == "webhook" and hooks:
                out.pages.append(Line(path, "Barkley found a webhook in the code.", _page_said(p)))
            else:
                out.pages.append(Line(path, "Barkley didn't find this page in the code.",
                                      _page_said(p)))  # fmt: skip
    return out


_PROTECTION = {
    "none": "Nothing stands in for the login.",
    "own_token": "The app checks a token of its own.",
    "signed_link": "It needs a link Home Assistant signed.",
    "webhook": "It needs a Home Assistant webhook id.",
}


def _page_said(p: dict[str, Any]) -> str:
    how = _PROTECTION.get(str(p.get("protection")), "")
    local = "It only answers on the local network." if p.get("local_only") is True else ""
    return " ".join(x for x in (str(p.get("purpose") or ""), how, local,
                                str(p.get("checks") or "")) if x)  # fmt: skip
