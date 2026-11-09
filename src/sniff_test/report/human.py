"""Human-readable summary. The dog lives here and only here."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.text import Text

from sniff_test.models import AnalyzerState, Finding, Severity, Tag
from sniff_test.report.json_report import ScanResult, ordered, sanitize_untrusted

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
    "card-read-tokens": "🐕 Nose is in the token drawer. Why is the nose in the token drawer?",
    "ha-read-secrets": "🐕 Sniffing around secrets.yaml. Bad.",
    "ha-auth-internals": "🐕 Pawing at the auth system.",
    "ha-monkeypatch": "🐕 Rearranging the furniture in HA core while nobody's looking.",
    "py-runtime-pip": "🐕 Brings its own snacks at runtime. Nobody checked the snacks.",
    "repo-no-releases": "🐕 No releases, just vibes.",
    "ha-unauth-view": "🐕 Left a doggy door open with no lock on it.",
    "possible-exfil": "🐕 Sniffed secrets near an open window. Can't prove it jumped out.",
    "endpoint-exfil-host": "🐕 Knows a guy who knows a guy. The guy collects data.",
    "repo-transferred": "🐕 This house changed owners. Checking the new collar.",
}
_VERDICT_QUIP = {
    "good_boy": "🦴 Tail wagging. Nothing smelled off.",
    "kinda_sus": "🐕 Head tilt. A few things worth a sniff.",
    "very_sus": "🐕‍🦺 The dog won't stop staring at it.",
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
        head.append(f"  [raised from {f.base_severity} by public exposure]", style="dim")
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
        parts.append(f"registers {reg} service/endpoint group(s)")
    hosts = [e for e in out if e["relation"] == "connects_to"]
    undeclared = sum(
        1
        for e in hosts
        if e["attrs"].get("class") in ("undeclared", "developer_hosted", "public_ip")
    )
    if hosts:
        parts.append(
            f"mentions {len(hosts)} host(s)" + (f", {undeclared} undeclared" if undeclared else "")
        )
    sensitive = sorted(
        nodes[e["target"]]["label"] for e in out if e["relation"] == "reads" and e["finding_ids"]
    )
    if sensitive:
        parts.append("reads " + ", ".join(sensitive))
    pkgs = n("depends_on", ("package",)) + n("bundles", ("package",))
    if pkgs:
        parts.append(f"{pkgs} package(s)")
    return "Hooks: " + "; ".join(parts) if parts else ""


def render(scan: ScanResult, console: Console, verbose: bool = False) -> None:
    t, s = scan.target, scan.score
    where = t.repo or t.source
    ref = f"@{t.ref}" if t.ref else ""
    sha = f" ({t.commit_sha[:12]})" if t.commit_sha else ""
    console.print(
        f"[dim]{escape(str(t.kind))} · {escape(where)}{escape(ref)}{sha}"
        f" · installed from: {escape(t.install_source)} · exposure: {scan.exposure}[/]"
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

    style = _VERDICT_STYLE[s.verdict.key]
    body = Text.assemble(
        (f"{s.verdict.emoji}  {s.verdict.label}", f"bold {style}"),
        (f"  ({s.verdict.blurb})", style),
        "\n",
        (f"Score: {s.score}/100", "bold"),
    )
    if s.caps:
        body.append("\n" + "; ".join(s.caps), style="dim")
    if not s.complete:
        body.append("\nScan incomplete: some analyzers did not run.", style="yellow")
    console.print(Panel(body, expand=False, border_style=style))
    console.print(_VERDICT_QUIP[s.verdict.key])
