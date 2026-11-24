"""Human-readable summary. The dog lives here and only here."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.text import Text

from sniff_test.diff import HEADLINE_MAX
from sniff_test.fetch import retry
from sniff_test.models import AnalyzerState, Finding, Severity, Tag
from sniff_test.report.json_report import ScanResult, ordered, sanitize_untrusted
from sniff_test.scoring import VERDICTS

if TYPE_CHECKING:
    from sniff_test.releases import Timeline
    from sniff_test.store import ScanRow

_INDENT = (0, 0, 0, 11)
_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_VERDICT_STYLE = {
    "good_boy": "green",
    "kinda_sus": "yellow",
    "very_sus": "dark_orange",
    "bork": "red",
}

# One-liners keyed by rule; shown at most a few per report. Flavor, never substance.
_QUIPS = {
    "ha-exfil-taint": "🐕 Grrr. Caught it carrying your secrets out the door.",
    "card-token-exfil": "🐕 This card is trying to walk off with your house keys.",
    "py-b64-exec": "🐕 Something's buried in the yard, and it's not a bone.",
    "card-b64-eval": "🐕 Something's buried in the yard, and it's not a bone.",
    "card-hidden-name": "🐕 Spelling it out in pieces doesn't fool the nose.",
    "card-read-tokens": "🐕 It reads your login tokens.",
    "ha-read-secrets": "🐕 Sniffing around secrets.yaml. Bad.",
    "ha-auth-internals": "🐕 Pawing at the auth system.",
    "ha-monkeypatch": "🐕 It replaces parts of Home Assistant's own code.",
    "py-runtime-pip": "🐕 It installs packages while it runs, and Barkley can't check which.",
    "repo-no-releases": "🐕 No releases.",
    "ha-unauth-view": "🐕 It opens a web page anyone can reach without logging in.",
    "possible-exfil": (
        "🐕 It reads secrets and can reach a site Barkley can't explain. "
        "Barkley can't prove they're sent."
    ),
    "endpoint-exfil-host": "🐕 Its code names a site that collects data.",
    "repo-transferred": "🐕 This repository changed owners.",
}
_VERDICT_QUIP = {
    "good_boy": "🦴 Tail wagging. Nothing smelled off.",
    "kinda_sus": "🐕 A few things to check.",
    "very_sus": "🐕‍🦺 Several concerns.",
    "bork": "🚨 BORK BORK BORK. Do not let this in the house.",
}


def sniffing(console: Console, source: str) -> None:
    console.print(f"🐕 sniff sniff... [bold]{escape(source)}[/]")


def _location(f: Finding) -> str:
    if not f.file:
        return ""
    loc = sanitize_untrusted(f.file, 200)
    return f"{loc}:{f.line}" if f.line else loc


def _finding_block(console: Console, f: Finding) -> None:
    sev = Text(f" {str(f.severity).upper():8} ", style=_SEV_STYLE[f.severity])
    head = Text.assemble(sev, " ", (f.title, "bold"))
    if Tag.POSSIBLE in f.tags:
        head.append("  (possible)", style="italic")
    if f.base_severity is not None:
        moved = "raised" if f.severity > f.base_severity else "lowered"
        head.append(
            f"  [{moved} from {f.base_severity} because of how Home Assistant is exposed]",
            style="dim",
        )
    console.print(head)
    loc = _location(f)
    console.print(Padding(Text(f.rule_id + (f"  {loc}" if loc else ""), style="dim"), _INDENT))
    console.print(Padding(Text(f.message), _INDENT))
    if f.evidence:
        ev = sanitize_untrusted(f.evidence, 200).replace("\n", " ⏎ ")
        console.print(Padding(Text(f"│ {ev}", style="dim italic"), _INDENT))
    console.print()


def hooks_line(graph: dict | None) -> str:
    """One plain line summarizing the graph (the dog stays out of it)."""
    if not graph:
        return ""
    subject = graph["subject"]
    out = [e for e in graph["edges"] if e["source"] == subject]
    nodes = {n["id"]: n for n in graph["nodes"]}

    def n(rel: str, kinds: tuple[str, ...]) -> int:
        return sum(1 for e in out if e["relation"] == rel and nodes[e["target"]]["kind"] in kinds)

    parts = []
    reg = n(
        "registers", ("service", "entity_service", "http_view", "webhook", "panel", "ws_command")
    )
    if reg:
        parts.append(f"registers {reg} group(s) of actions or web endpoints")
    hosts = [e for e in out if e["relation"] == "connects_to"]
    undeclared = sum(
        1
        for e in hosts
        if e["attrs"].get("class") in ("undeclared", "developer_hosted", "analytics", "public_ip")
    )
    if hosts:
        parts.append(
            f"mentions {len(hosts)} site(s)"
            + (f", {undeclared} Barkley can't explain" if undeclared else "")
        )
    sensitive = sorted(
        nodes[e["target"]]["label"] for e in out if e["relation"] == "reads" and e["finding_ids"]
    )
    if sensitive:
        parts.append("reads " + ", ".join(sensitive))
    pkgs = n("depends_on", ("package",)) + n("bundles", ("package",))
    if pkgs:
        parts.append(f"uses {pkgs} package(s)")
    return "What it touches: " + "; ".join(parts) if parts else ""


def render(
    scan: ScanResult,
    console: Console,
    verbose: bool = False,
    readings_of: dict | None = None,
) -> None:
    from sniff_test.ui import _SOURCE  # the panel's plain words for where the code came from

    t, s = scan.target, scan.score
    where = t.repo or t.source
    ref = f"@{t.ref}" if t.ref else ""
    sha = f" ({t.commit_sha[:12]})" if t.commit_sha else ""
    console.print(
        f"[dim]{escape(str(t.kind))} · {escape(where)}{escape(ref)}{sha}"
        f" · installed from: {escape(_SOURCE.get(t.install_source, t.install_source))}"
        f" · exposure: {scan.exposure}[/]"
    )
    console.print()

    findings = ordered(scan.findings)
    shown = [f for f in findings if verbose or f.severity >= Severity.MEDIUM]
    hidden = [f for f in findings if f.severity < Severity.MEDIUM] if not verbose else []

    quips: list[str] = []
    for f in shown:
        q = _QUIPS.get(f.rule_id)
        if q and q not in quips:
            quips.append(q)
    for q in quips[:3]:
        console.print(q)
    if quips:
        console.print()

    for f in shown:
        _finding_block(console, f)

    if hidden:
        lows = sum(1 for f in hidden if f.severity == Severity.LOW)
        infos = sum(1 for f in hidden if f.severity == Severity.INFO)
        parts = [p for p in (f"{lows} low" if lows else "", f"{infos} info" if infos else "") if p]
        console.print(f"[dim]+ {', '.join(parts)} not shown (use --verbose)[/]")
        console.print()

    if line := hooks_line(scan.graph):
        console.print(Text(sanitize_untrusted(line, 400), style="dim"))
        console.print()

    for a in scan.analyzers:
        if a.state in (AnalyzerState.SKIPPED, AnalyzerState.ERROR):
            console.print(f"[yellow]⚠ {a.name} {a.state}: {escape(a.detail)}[/]")
            for problem in a.problems[:5]:  # (0.14.0) files it couldn't fetch, in plain words
                console.print(Text("  " + retry.plain(problem), style="yellow"))

    # (0.15) the two readings first; the capability score after them, without dog words
    # (his decision 2026-11-20: what the code openly uses, not a judgment)
    from sniff_test.ui import readings_band, verdict_line

    rd = readings_of or {}
    level = str(rd.get("threat_level") or "none")
    style = readings_band(rd) if rd else "green"
    style = {"orange": "dark_orange"}.get(style, style)  # a Rich colour name
    body = Text.assemble((verdict_line(rd), f"bold {style}"))
    if rd:
        body.append(
            f"\nThreat: {level} ({rd.get('threat', 0):g} of 10) · Exposure: "
            f"{rd.get('exposure_level')} ({rd.get('exposure', 0):g} of 10)",
            "bold",
        )
        if rd.get("threat_reason") and level != "none":
            body.append(f"\nIt {rd['threat_reason']}.", style)
    body.append(
        f"\nCapability score: {s.score}/100 (what the code openly uses, not a judgment)",
        "dim",
    )
    if not s.complete:
        body.append("\nThe scan didn't finish. Some checks did not run.", style="yellow")
    console.print(Panel(body, expand=False, border_style=style))


# --- history -------------------------------------------------------------------------


def render_history(rows: list[ScanRow], console: Console) -> None:
    """Stored scans, newest first. Repo names and refs come from the scanned repos."""
    if not rows:
        console.print("🐕 No stored scans yet.")
        return
    emoji = {v.key: v.emoji for _, v in VERDICTS}
    for r in rows:
        style = _VERDICT_STYLE.get(r.verdict, "")
        name = sanitize_untrusted(r.repo or r.source, 80)
        ref = sanitize_untrusted(r.ref or "?", 60)
        extra = [r.kind, r.scanned_at[:16].replace("T", " ")]
        if r.ha_version:
            extra.append(f"HA {r.ha_version}")
        if not r.complete:
            extra.append("incomplete")
        console.print(
            f"[bold]@{r.id}[/]  [{style}]{r.score:>3} {emoji.get(r.verdict, '')}[/]  "
            f"{escape(name)}@{escape(ref)}  [dim]{escape(' · '.join(extra))}[/]",
            soft_wrap=True,
        )


# --- releases ------------------------------------------------------------------------


def render_releases(t: Timeline, console: Console, limit: int | None = 20) -> None:
    """Newest `limit` releases, plus the HACS picks and every handover wherever they are."""
    console.print(f"🐕 sniffing the release history of [bold]{escape(t.repo)}[/]")
    if t.renamed:
        console.print(
            f"[yellow]You asked for {escape(t.requested_as or '')}, but GitHub redirected, so "
            "this repository was moved or renamed[/]"
        )
    created = (t.created_at or "")[:10]
    humans = [p for p in t.publishers if not p["bot"]]
    console.print(
        f"[dim]created {created} · {len(t.releases)} releases · {len(humans)} human publisher(s)[/]"
    )
    if len(t.handovers) > 3:
        console.print(f"[dim]{len(t.handovers) - 3} earlier change(s) of publisher not shown[/]")
    for h in t.handovers[-3:]:
        when = next((r.published_at or "" for r in t.releases if r.tag == h.tag), "")[:10]
        console.print(
            f"[yellow]★ {escape(h.publisher)} started publishing at "
            f"{escape(sanitize_untrusted(h.tag, 60))} ({when}), after {h.prior_releases} "
            f"release(s) by {escape(', '.join(h.previous))}[/]",
            soft_wrap=True,
        )
    console.print()
    if not t.releases:
        console.print(
            "This repository has no releases, so HACS installs the latest code on "
            f"'{escape(t.default_branch or 'main')}'."
        )
        return
    firsts = {h.tag: h for h in t.handovers}
    keep = {t.hacs_default, t.hacs_beta, *firsts}
    shown = [i for i, r in enumerate(t.releases) if limit is None or i < limit or r.tag in keep]
    width = min(max(len(sanitize_untrusted(r.tag, 30)) for r in t.releases), 30)
    pwidth = min(max(len(r.publisher or "?") for r in t.releases), 24)
    last = -1
    for i in shown:
        if i != last + 1:
            console.print(f"[dim]  ⋮ {i - last - 1} release(s)[/]")
        last = i
        r = t.releases[i]
        row = Text("  ")
        row.append((r.published_at or "")[:10].ljust(12), style="dim")
        row.append(sanitize_untrusted(r.tag, 30).ljust(width + 2), style="bold")
        row.append((r.publisher or "?").ljust(pwidth + 1))
        row.append("bot " if r.bot else "    ", style="dim")
        row.append("beta " if r.prerelease else "     ", style="cyan")
        notes = []
        if r.tag == t.hacs_default:
            notes.append(("◀ HACS installs this by default", "bold green"))
        if r.tag == t.hacs_beta:
            notes.append(('◀ offered with "show beta"', "cyan"))
        if r.tag in firsts:
            h = firsts[r.tag]
            prev = ", ".join(h.previous[:2]) + (" and others" if len(h.previous) > 2 else "")
            notes.append(
                (
                    f"★ first release by {h.publisher} ({h.prior_releases} earlier by {prev})",
                    "yellow",
                )
            )
        others = [u for u in r.asset_uploaders if u != r.publisher and not u.endswith("[bot]")]
        if others:
            notes.append((f"assets uploaded by {', '.join(others)}", "yellow"))
        for j, (note, style) in enumerate(notes):
            row.append(("  " if j else "") + note, style=style)
        console.print(row, soft_wrap=True)
    if last < len(t.releases) - 1:
        console.print(f"[dim]  ⋮ {len(t.releases) - 1 - last} older release(s) (--all)[/]")
    console.print()
    if t.hacs_default is None:
        console.print(
            "There is no stable release among the 30 newest, so HACS installs the latest code on "
            f"'{escape(t.default_branch or 'main')}'."
        )
    for p in t.publishers:
        span = f"{(p['first'] or '')[:10]} → {(p['last'] or '')[:10]}"
        bot = " (bot)" if p["bot"] else ""
        console.print(f"[dim]{escape(p['login'])}{bot}: {p['releases']} release(s), {span}[/]")


# --- diff ----------------------------------------------------------------------------

_DIFF_LABEL = {
    "new_finding": "finding",
    "resolved_finding": "resolved",
    "severity_up": "severity",
    "severity_down": "severity",
    "new_flow": "flow",
    "new_read": "reads",
    "new_host": "host",
    "host_class": "host",
    "new_package": "package",
    "package_version": "package",
    "new_inbound": "inbound",
    "new_hook": "hook",
    "evidence_up": "evidence",
    "evidence_down": "evidence",
    "new_publisher": "publisher",
    "publisher_changed": "publisher",
    "repo_moved": "repo",
    "coverage_lost": "coverage",
    "install_source": "coverage",
    "removed_flow": "flow",
    "removed_data": "reads",
    "removed_host": "host",
    "removed_package": "package",
    "removed_hook": "hook",
}
_SIGN_STYLE = {"+": "bold red", "-": "green", "~": "yellow"}
_GROUP_NAME = {
    "findings": "finding",
    "flows": "flow",
    "data": "data access",
    "hosts": "host",
    "packages": "package",
    "hooks": "Home Assistant hook",
    "repo": "repo",
    "coverage": "coverage",
}


def _side_label(side: dict) -> str:
    ref = f"@{side['ref']}" if side.get("ref") else ""
    return f"{side.get('repo') or '?'}{ref}"


def render_diff(d: dict, console: Console, verbose: bool = False) -> None:
    a, b = d["from"], d["to"]
    same_repo = (a.get("repo") or "").lower() == (b.get("repo") or "").lower()
    title = (
        f"{a.get('repo')}  {a.get('ref') or '(local)'} → {b.get('ref') or '(local)'}"
        if same_repo
        else f"{_side_label(a)} → {_side_label(b)}"
    )
    console.print(Text.assemble("🐕 sniff diff · ", (sanitize_untrusted(title, 200), "bold")))
    delta = d["score"]["delta"]
    style = "red" if delta < 0 else "green" if delta > 0 else "dim"
    console.print(
        Text.assemble(
            f"Score {a['score']} → {b['score']} ",
            (f"({delta:+d})" if delta else "(=)", style),
            f"   {a['verdict']['label']} → {b['verdict']['label']}",
        )
    )
    for w in d["warnings"]:
        console.print(f"[yellow]⚠ {escape(w)}[/]")
    if not b["complete"] or not a["complete"]:
        console.print("[yellow]⚠ at least one scan was incomplete, so changes may be missing[/]")
    console.print()
    changes = d["changes"]
    if not changes:
        console.print("Nothing changed that Barkley can see. 🦴")
        return
    head = [c for c in changes if c["rank"] >= d["headline_rank"]]
    rest = changes if verbose else [c for c in changes if c["rank"] < d["headline_rank"]]
    if verbose:
        head, rest = changes, []
    elif len(head) > HEADLINE_MAX:
        head, rest = head[:HEADLINE_MAX], head[HEADLINE_MAX:] + rest
    if head:
        console.print("[bold]What changed, most important first[/]")
        for c in head:
            row = Text("  ")
            row.append(c["sign"] + " ", style=_SIGN_STYLE[c["sign"]])
            row.append(_DIFF_LABEL.get(c["kind"], c["kind"]).ljust(10), style="bold")
            if c["severity"] and c["sign"] != "-":
                row.append(
                    f"{c['severity'].upper():8} ", style=_SEV_STYLE[Severity.parse(c["severity"])]
                )
            row.append(sanitize_untrusted(c["text"], 300))
            console.print(row, soft_wrap=True)
    else:
        console.print("Nothing important changed.")
    if rest:
        counts: dict[str, int] = {}
        for c in rest:
            counts[c["group"]] = counts.get(c["group"], 0) + 1
        parts = [
            f"{n} change{'s' if n > 1 else ''} in what was checked"
            if g == "coverage"
            else f"{n} {_GROUP_NAME.get(g, g)} change{'s' if n > 1 else ''}"
            for g, n in sorted(counts.items(), key=lambda x: -x[1])
        ]
        console.print(f"[dim]Also changed: {', '.join(parts)} (--verbose to list)[/]")
