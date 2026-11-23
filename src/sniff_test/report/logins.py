"""(0.15, his yes 2026-11-22) Where the app's own logins go, and where its run-time
addresses come from, in plain words for the app's page (the mock-up he approved, round 2).

Everything here reads the report's `requests` section (py_requests.summary, py_flow,
py_library): never the code. It is context, never scored, and says only what the scan
found: a login Barkley followed to a request, a token from a server's answer, a library the
app hands the login to and what Barkley read inside it. Names and addresses come from the
scanned code: escaped where they are shown.

- `groups`: one group per thing that is sent (your login for this app, a token from a
  server's answer), each read left to right: what is sent, who sends it (the app's own code
  or a named library), where it goes. "Where your logins go" draws them (`html`).
- `marks`: per site, what the picture and "Where it connects" add to it: that your login or
  a token goes there, and the library that makes the requests.
- `origins_html`: where the addresses it works out while it runs come from, counted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html import escape
from typing import Any

DESTS_SHOWN = 6
_FIELDS_SHOWN = 6
_ORDER = ("setup", "site", "list", "answer", "discovery", "ha", "unknown")
_ORDER_SHOWN = {"site": 0, "list": 1, "setup": 2, "answer": 3, "discovery": 4, "ha": 5}


def _e(text: Any, n: int = 200) -> str:
    return escape(str(text)[:n])


def _code(names: list[str]) -> str:
    shown = ", ".join(f"<code>{_e(n, 60)}</code>" for n in names[:_FIELDS_SHOWN])
    more = len(names) - _FIELDS_SHOWN
    return shown + (f" and {more} more" if more > 0 else "")


def _list(x: Any) -> list[Any]:
    return x if isinstance(x, list) else []


def _strs(x: Any) -> list[str]:
    return [v for v in _list(x) if isinstance(v, str) and v]


def origin_words(o: dict[str, Any]) -> tuple[str, bool]:
    """(plain words for where an address comes from, whether it is one fixed site)."""
    kind, detail = str(o.get("kind") or ""), str(o.get("detail") or "")
    if kind == "site" and detail:
        return f"<code>{_e(detail, 120)}</code>", True
    if kind == "setup":
        what = f" (<code>{_e(detail, 60)}</code>)" if detail else ""
        return f"The address you entered when you set it up{what}", False
    if kind == "list":
        sites = [s for s in detail.split(",") if s]
        shown = ", ".join(f"<code>{_e(s, 80)}</code>" for s in sites[:3])
        more = f" and {len(sites) - 3} more" if len(sites) > 3 else ""
        return f"One of {len(sites)} sites in its code ({shown}{more})", False
    if kind == "answer":
        site = str(o.get("site") or "")
        if site and site != "?":
            return f"An address from <code>{_e(site, 120)}</code>'s answer", False
        return "An address from a server's answer", False
    if kind == "discovery":
        return "A device it found on your network", False
    if kind == "ha":
        return "Your Home Assistant's own address", False
    return "An address Barkley couldn't trace", False


@dataclass
class Dest:
    name: str  # html: a site as code, or where the address comes from
    note: str  # html
    fixed: bool = True  # one site named in the code (else: worked out while it runs)
    at: list[str] = field(default_factory=list)  # where in a library's code


@dataclass
class Group:
    what: str  # html: "The login you gave this app (…)", "The token from …'s answer"
    via: str  # "" = the app's own code, else the library's name
    via_note: str  # html
    dests: list[Dest] = field(default_factory=list)
    note: str = ""  # html: said instead of destinations (a library Barkley couldn't follow)


def _how(shape: dict[str, Any]) -> str:
    method = str(shape.get("method") or "")
    n = shape.get("count") if isinstance(shape.get("count"), int) else 1
    count = f"{n} requests" if n != 1 else ""
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        return count  # the method is picked while it runs
    return f"{method} · {count}" if count else method


def _shapes(report: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """(site or "", shape) for every request shape in the report."""
    r = report.get("requests")
    if not isinstance(r, dict):
        return []
    out = []
    sites = r.get("sites") if isinstance(r.get("sites"), dict) else {}
    for host, shapes in sites.items():
        out += [(str(host), s) for s in _list(shapes) if isinstance(s, dict)]
    out += [("", s) for s in _list(r.get("elsewhere")) if isinstance(s, dict)]
    return out


def _handoffs(report: dict[str, Any]) -> list[dict[str, Any]]:
    r = report.get("requests")
    return [h for h in _list(r.get("handoffs") if isinstance(r, dict) else None)
            if isinstance(h, dict)]  # fmt: skip


def _dest_of(host: str, shape: dict[str, Any], note: str) -> Dest:
    if host:
        return Dest(f"<code>{_e(host, 120)}</code>", note)
    origins = [o for o in _list(shape.get("from")) if isinstance(o, dict)]
    # a site in the code first, then a list of sites, then what you entered and the rest:
    # "monitor.x, or the address you entered when you set it up (base_url)" (his pick,
    # 2026-11-22: the usual case before the exception)
    origins.sort(key=lambda o: _ORDER_SHOWN.get(str(o.get("kind")), 9))
    words = [origin_words(o) for o in origins] or [origin_words({})]
    fixed = all(f for _w, f in words)
    shown = [w for w, _f in words[:3]]
    text = shown[0] + "".join(f", or {w[0].lower()}{w[1:]}" for w in shown[1:])
    return Dest(text, note, fixed)


def _add(dests: list[Dest], d: Dest) -> None:
    """One entry per place: a second way to the same place adds to its note."""
    for x in dests:
        if x.name == d.name:
            if d.note and d.note not in x.note and len(x.note) < 300:
                x.note = f"{x.note}; {d.note}" if x.note else d.note
            return
    dests.append(d)


def _library_note(h: dict[str, Any]) -> tuple[str, str]:
    """(what is said about the library, said instead of destinations or "")."""
    inside = h.get("inside") if isinstance(h.get("inside"), dict) else None
    lib = f"<code>{_e(h.get('library'), 60)}</code>"
    if inside is None:  # a scan from before 0.15's library reading
        return "The library makes the requests. Barkley doesn't read inside libraries.", (
            "Where it goes from there isn't in the app's code.")  # fmt: skip
    state = inside.get("state")
    ver = f" {_e(inside.get('version'), 40)}" if inside.get("version") else ""
    if state == "followed":
        return f"Barkley read inside the library (version{ver}).", ""
    if state == "requests":
        sites = _strs(inside.get("sites"))
        to = f" to {_code(sites)}" if sites else ""
        return (f"Barkley read inside the library (version{ver}).",
                f"It makes web requests{to}, but Barkley couldn't tell which of them gets "
                "the login.")  # fmt: skip
    if state == "no_requests":
        other = _strs(inside.get("other"))
        how = f" It connects by {_e(' and '.join(other[:3]))}." if other else ""
        return (f"Barkley read inside the library (version{ver}).",
                f"There are no web requests in it.{how}")  # fmt: skip
    why = {
        "offline": "Barkley was offline",
        "not one of its requirements": f"{lib} isn't one of the app's own requirements (it "
        "comes with Home Assistant or with another package)",
        "no wheel": "it has no ready-made package to read",
        "too big": "its package is too big to read",
        "too many libraries": "the app hands logins to more libraries than Barkley reads",
        "download failed": "Barkley couldn't download it",
    }.get(str(inside.get("why") or ""), "Barkley couldn't read it")
    return (f"Barkley didn't read inside the library: {why}.",
            "Where it goes from there isn't in the app's code.")  # fmt: skip


def groups(report: dict[str, Any], app: str) -> list[Group]:
    """What the box draws: your login through the app's own code, each token, then each
    library the login is handed to."""
    own = Group("", "", "its own code")
    fields: list[str] = []
    tokens: dict[str, Group] = {}
    for host, s in _shapes(report):
        logins = _strs(s.get("logins"))
        if logins:
            fields += [f for f in logins if f not in fields]
            _add(own.dests, _dest_of(host, s, _how(s)))
        for t in _strs(s.get("tokens")):
            g = tokens.get(t)
            if g is None:
                who = (f"<code>{_e(t, 120)}</code>'s answer" if t != "?"
                       else "a server's answer")  # fmt: skip
                g = tokens[t] = Group(f"The token from {who}", "", "its own code")
            _add(g.dests, _dest_of(host, s, _how(s)))
    out = []
    if own.dests:
        own.what = f"The login you gave this app ({_code(fields)})"
        out.append(own)
    out += list(tokens.values())
    for h in _handoffs(report):
        logins = _strs(h.get("logins"))
        if not logins:
            continue  # an address alone: "Where it connects" lists it
        lib = str(h.get("library") or "")
        say, instead = _library_note(h)
        g = Group(f"The login you gave this app ({_code(logins)})", lib, say, note=instead)
        inside = h.get("inside") if isinstance(h.get("inside"), dict) else {}
        for s in _list(inside.get("sends")):
            if isinstance(s, dict) and _strs(s.get("logins")):
                d = _dest_of(str(s.get("site") or ""), s, "")
                _add(g.dests, d)
                if s.get("at"):
                    x = next(x for x in g.dests if x.name == d.name)
                    x.at = [*x.at, str(s["at"])][:4]
        for d in g.dests:
            if d.at:
                d.note = f"inside the library at {_e(', '.join(d.at), 200)}"
        if inside.get("state") == "followed" and not g.dests:
            g.note = ("Barkley followed the address the app gives the library, but not your "
                      "login, inside it.")  # fmt: skip
        out.append(g)
    for g in out:
        g.via_note = g.via_note if g.via else f"{_e(app, 60)}'s own code"
    return out


def html(report: dict[str, Any], app: str, tag: str = "") -> str:
    """The "Where your logins go" box, or "" when Barkley followed no login."""
    gs = groups(report, app)
    if not gs:
        return ""
    rows = []
    for g in gs:
        if g.via:
            via = (f'<div class="lg-via lib"><b><code>{_e(g.via, 60)}</code> library</b>'
                   f'<span class="muted small">{g.via_note}</span></div>')  # fmt: skip
        else:
            via = (f'<div class="lg-via"><b>{_e(app, 60)}</b>'
                   '<span class="muted small">its own code</span></div>')  # fmt: skip
        if g.dests:
            items = [
                f'<div class="lg-dest{"" if d.fixed else " maybe"}"><span class="h">{d.name}</span>'
                + (f'<span class="muted small">{d.note}</span>' if d.note else "") + "</div>"
                for d in g.dests
            ]  # fmt: skip
            dests = "".join(items[:DESTS_SHOWN])
            if len(items) > DESTS_SHOWN:
                rest = len(items) - DESTS_SHOWN
                dests += (f'<details class="more"><summary>and {rest} more '
                          f'place{"s" * (rest != 1)}</summary><div class="in">'
                          f'{"".join(items[DESTS_SHOWN:])}</div></details>')  # fmt: skip
        else:
            dests = f'<div class="lg-dest maybe"><span class="muted small">{g.note}</span></div>'
        rows.append(
            f'<div class="lg-grp"><div class="lg-pill"><b>{g.what}</b></div>'
            '<div class="lg-arr" aria-hidden="true">→</div>'
            f'{via}<div class="lg-arr" aria-hidden="true">→</div>'
            f'<div class="lg-dests">{dests}</div></div>'
        )
    return (
        f'<section class="box"><h2>Where the login you gave this app goes'
        f"{' ' + tag if tag else ''}</h2>"
        '<p class="sub">The login you entered when you set up this app (not your Home '
        "Assistant login), and any token it gets back, from what is sent to where it goes. A "
        "dashed box is an address the app works out while it runs.</p>"
        f'<div class="lg">{"".join(rows)}</div></section>'
    )


# --- per site: the picture and "Where it connects" --------------------------------------------


@dataclass
class Mark:
    login: bool = False  # your login for this app goes here
    token: bool = False  # a token from a server's answer goes here
    library: str = ""  # the library that makes the requests
    lines: list[str] = field(default_factory=list)  # html, for the site's fold
    # library -> (the logins it sends here, where in its code): one line each
    sent: dict[str, tuple[list[str], list[str]]] = field(default_factory=dict)


def marks(report: dict[str, Any]) -> dict[str, Mark]:
    """host -> what the picture and the site's fold add to it."""
    out: dict[str, Mark] = {}

    def at(host: str) -> Mark:
        return out.setdefault(host, Mark())

    for host, s in _shapes(report):
        if host and _strs(s.get("logins")):
            at(host).login = True
        if host and _strs(s.get("tokens")):
            at(host).token = True
    for h in _handoffs(report):
        lib = str(h.get("library") or "")
        logins = _strs(h.get("logins"))
        for a in _list(h.get("addresses")):  # a site handed to the library as its address
            arg = str(a.get("arg") or "") if isinstance(a, dict) else ""
            for o in _list(a.get("from") if isinstance(a, dict) else None):
                if isinstance(o, dict) and o.get("kind") == "site" and o.get("detail"):
                    m = at(str(o["detail"]))
                    m.library = m.library or lib
                    name = f"<code>{_e(lib, 60)}</code> library"
                    as_ = (
                        f" as its address (<code>{_e(arg, 40)}</code>)"
                        if arg
                        else " as its address"
                    )
                    m.lines.append(
                        (f"The login you gave this app ({_code(logins)}) is handed to the {name}, "
                         f"with this site{as_}." if logins else
                         f"The app hands this site to the {name}{as_}.")
                        + " The library makes the requests.")  # fmt: skip
                    if logins:
                        m.login = True
        inside = h.get("inside") if isinstance(h.get("inside"), dict) else {}
        for s in _list(inside.get("sends")):
            site = str(s.get("site") or "") if isinstance(s, dict) else ""
            if not site:
                continue
            m = at(site)
            m.library = m.library or lib
            sent = _strs(s.get("logins"))
            m.login = m.login or bool(sent)
            got = m.sent.setdefault(lib, ([], []))
            got[0].extend(x for x in sent if x not in got[0])
            if s.get("at") and len(got[1]) < 4:
                got[1].append(str(s["at"]))
    for m in out.values():
        for lib, (sent, where) in m.sent.items():
            places = f" (at {_e(', '.join(where), 200)})" if where else ""
            m.lines.append(
                (f"The <code>{_e(lib, 60)}</code> library sends the login you gave this app "
                 f"({_code(sent)}) here" if sent else
                 f"The <code>{_e(lib, 60)}</code> library sends requests here with what the "
                 "app passes it")
                + f"{places}. Barkley read this inside the library.")  # fmt: skip
    return out


def chips(m: Mark | None) -> str:
    if m is None:
        return ""
    out = ""
    if m.library:
        out += '<span class="chip">through a library</span>'
    if m.login:
        out += '<span class="chip priv">the login you gave this app</span>'
    elif m.token:
        out += '<span class="chip priv">a token</span>'
    return out


def fold_lines(m: Mark | None) -> str:
    if m is None:
        return ""
    return "".join(f'<span class="u">{x}</span>' for x in dict.fromkeys(m.lines))


# --- where the run-time addresses come from ---------------------------------------------------


def origins_html(shapes: list[dict[str, Any]]) -> str:
    """One line per place the addresses come from, with how many requests and the logins
    that go there (requests whose address isn't in the code)."""
    by: dict[tuple[str, str, str], list[int | set[str]]] = {}
    for s in shapes:
        n = s.get("count") if isinstance(s.get("count"), int) else 1
        origins = [o for o in _list(s.get("from")) if isinstance(o, dict)] or [{"kind": "unknown"}]
        for o in origins:
            k = (
                str(o.get("kind") or "unknown"),
                str(o.get("detail") or ""),
                str(o.get("site") or ""),
            )
            got = by.setdefault(k, [0, set()])
            got[0] += n  # type: ignore[operator]
            got[1] |= set(_strs(s.get("logins")))  # type: ignore[operator]
    if not by or set(k[0] for k in by) == {"unknown"}:
        return ""
    items = []
    for (kind, detail, site), (n, logins) in sorted(
        by.items(), key=lambda kv: (_ORDER.index(kv[0][0]) if kv[0][0] in _ORDER else 9, kv[0])
    ):
        words, _fixed = origin_words({"kind": kind, "detail": detail, "site": site})
        if kind == "unknown":
            words = "Barkley couldn't trace where the address comes from"
        also = (
            f" The login you gave this app ({_code(sorted(logins))}) goes there too."
            if logins
            else ""
        )  # type: ignore[arg-type]
        items.append(f"<li>{words}: {n} request{'s' * (n != 1)}.{also}</li>")
    return f'<ul class="from">{"".join(items)}</ul>'


def holds_login(report: dict[str, Any]) -> bool:
    """Whether Barkley followed a login you gave the app (a setup field) anywhere."""
    if any(_strs(s.get("logins")) for _h, s in _shapes(report)):
        return True
    return any(_strs(h.get("logins")) for h in _handoffs(report))


# --- an address you entered at setup (the picture's dashed box) -----------------------------


@dataclass
class Entered:
    fields: list[str] = field(default_factory=list)  # setup fields that are the address
    login: bool = False  # the login you gave this app goes there (followed)
    how: list[str] = field(default_factory=list)  # a library's other ways ("MQTT"…)
    discovered: bool = False  # it connects to a device Home Assistant found for it
    other: int = 0  # run-time request shapes whose address comes from somewhere else


def _setup_only(origins: list[Any]) -> list[str]:
    """The setup fields when an address comes only from what you entered (a default site
    in the code is drawn as that site instead)."""
    os_ = [o for o in origins if isinstance(o, dict)]
    if not os_ or any(o.get("kind") != "setup" for o in os_):
        return []
    return [str(o.get("detail") or "") for o in os_]


def entered(report: dict[str, Any]) -> Entered:
    """What the picture's dashed "address you entered" box says, from the app's own
    requests and what Barkley read inside a library it hands the address to."""
    out = Entered()

    def add(names: list[str]) -> None:
        for n in names:
            if n and n not in out.fields and len(out.fields) < 3:
                out.fields.append(n)

    for host, s in _shapes(report):
        if host:
            continue
        origins = _list(s.get("from"))
        if any(isinstance(o, dict) and o.get("kind") == "discovery" for o in origins):
            out.discovered = True
            continue
        names = _setup_only(origins)
        if not names:
            out.other += 1
            continue
        add(names)
        out.login = out.login or bool(_strs(s.get("logins")))
    for h in _handoffs(report):
        inside = h.get("inside") if isinstance(h.get("inside"), dict) else {}
        for a in _list(h.get("addresses")):
            names = _setup_only(_list(a.get("from") if isinstance(a, dict) else None))
            if names:
                add(names)
                if inside.get("state") == "no_requests":
                    out.how += [w for w in _strs(inside.get("other")) if w not in out.how]
        for s in _list(inside.get("sends")):
            if isinstance(s, dict) and not s.get("site"):
                names = _setup_only(_list(s.get("from")))
                if names:
                    add(names)
                    out.login = out.login or bool(_strs(s.get("logins")))
    return out
