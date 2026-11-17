"""Cross-file "possible exfil" correlation.

Free Semgrep follows taint only inside one function, so `read secrets in helper A, send
in helper B` is invisible to `ha-exfil-taint`. This joins what the per-file analyzers
saw, at the level of the whole item:

  a high sensitive-access finding that reads a credential (secrets, auth tokens, other
  integrations' credentials, the Supervisor token, stored tokens: CREDENTIAL_SOURCES)
  that no proven taint path already explains
  + code that can send data out (inventory: HTTP client, sockets, websockets, fetch)
  + somewhere unexplained to send it (an undeclared or developer-hosted host, a public
    IP, a known drop/tunnel host or a credential-bearing webhook)
  = `possible-exfil`: high, tagged `possible` (decided 2026-11-08). Proven paths stay
    critical; heuristics never reach critical.

A source counts as explained when a taint finding sits in the same Python function
(found with `ast.parse`, which parses and never runs code) or, for cards, the same file.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from sniff_test.analyzers.endpoints import UNEXPLAINED
from sniff_test.models import Category, Fact, Finding, Severity, Tag

NAME = "correlate"
PROVEN_RULES = frozenset({"ha-exfil-taint", "card-token-exfil"})
_DESTINATION_RULES = frozenset({"endpoint-exfil-host", "endpoint-public-ip-literal"})
_MAX_LISTED = 5

# Sensitive-access rule -> (graph node kind, node key). Shared with report.graph.
SENSITIVE_NODES: dict[str, tuple[str, str]] = {
    "ha-read-secrets": ("data", "secrets.yaml"),
    "ha-read-auth-storage": ("data", "auth and credential storage"),
    "ha-raw-storage-access": ("data", ".storage files"),
    "ha-auth-internals": ("auth", "login tokens"),
    "ha-auth-change-users": ("auth", "user accounts"),
    "ha-auth-list-users": ("auth", "the user list"),
    "ha-foreign-entry-data": ("data", "other integrations' credentials"),
    "ha-foreign-entry-options": ("data", "other integrations' settings"),
    "ha-own-storage-path": ("data", ".storage files"),
    "ha-bulk-location-read": ("data", "household locations"),
    "ha-supervisor-token": ("auth", "Supervisor token"),
    "card-read-tokens": ("auth", "stored HA tokens"),
    "card-access-token-use": ("auth", "user's access token"),
}

# (0.14.0) Only these sources pair with an outside host into `possible-exfil`: what they
# read is a credential, a token or a secret. Listing or changing users, other apps'
# settings, locations and .storage paths are what an app can do, not something to steal
# (a real integration lists users for its panel's picker and also talks to its cloud).
CREDENTIAL_SOURCES = frozenset(
    {
        "ha-read-secrets",
        "ha-read-auth-storage",
        "ha-auth-internals",
        "ha-foreign-entry-data",
        "ha-supervisor-token",
        "card-read-tokens",
        "card-access-token-use",
    }
)


def function_spans(path: Path) -> list[tuple[int, int]] | None:
    """(start, end) line spans of every function in a Python file; None if unparseable."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, ValueError, RecursionError, MemoryError, OSError):
        return None
    return [
        (n.lineno, n.end_lineno or n.lineno)
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda)
    ]


def _innermost(spans: list[tuple[int, int]], line: int) -> tuple[int, int] | None:
    inside = [s for s in spans if s[0] <= line <= s[1]]
    return min(inside, key=lambda s: s[1] - s[0]) if inside else None


@dataclass
class _Scopes:
    root: Path
    cache: dict[str, list[tuple[int, int]] | None]

    def scope(self, file: str, line: int) -> tuple[str, tuple[int, int] | None]:
        if not file.endswith(".py"):
            return file, None  # JS: whole file
        if file not in self.cache:
            self.cache[file] = function_spans(self.root / file)
        spans = self.cache[file]
        return file, (_innermost(spans, line) if spans else None)


def explained_by_taint(findings: list[Finding], root: Path) -> dict[str, Finding]:
    """Source finding id -> the proven taint finding sharing its function (or JS file)."""
    scopes = _Scopes(root, {})
    proven = [f for f in findings if f.rule_id in PROVEN_RULES and f.file and f.line]
    out: dict[str, Finding] = {}
    for src in findings:
        if src.rule_id not in SENSITIVE_NODES or not (src.file and src.line):
            continue
        s_file, s_scope = scopes.scope(src.file, src.line)
        for p in proven:
            p_file, p_scope = scopes.scope(p.file, p.line)  # type: ignore[arg-type]
            if p_file == s_file and (
                p_scope == s_scope and (s_scope or not s_file.endswith(".py"))
            ):
                out[src.id] = p
                break
    return out


def _and(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def correlate(findings: list[Finding], facts: list[Fact], root: Path) -> list[Finding]:
    explained = explained_by_taint(findings, root)
    sources = [
        f
        for f in findings
        if f.category is Category.SENSITIVE_ACCESS
        and f.severity >= Severity.HIGH
        and f.rule_id in CREDENTIAL_SOURCES
        and f.id not in explained
    ]
    outbound = [f for f in facts if f.attrs.get("outbound")]
    dest_hosts = sorted(
        {f.key for f in facts if f.kind in ("host", "ip") and f.attrs.get("class") in UNEXPLAINED}
    )
    dest_findings = [f for f in findings if f.rule_id in _DESTINATION_RULES]
    if not (sources and outbound and (dest_hosts or dest_findings)):
        return []

    sources.sort(key=lambda f: (f.file or "", f.line or 0))
    source_files = {f.file for f in sources}
    same_file = sorted({o.file for o in outbound if o.file in source_files} - {None})
    what = sorted({SENSITIVE_NODES[f.rule_id][1] for f in sources})
    where = ", ".join(f"{f.file}:{f.line}" for f in sources[:_MAX_LISTED])
    to = dest_hosts[:_MAX_LISTED] or sorted({f.evidence or "" for f in dest_findings})[:2]
    link = (
        f"The same file also sends data out ({', '.join(same_file[:3])})."
        if same_file
        else "The read and the outbound call are in different files."
    )
    first = sources[0]
    return [
        Finding(
            rule_id="possible-exfil",
            title="Possible exfiltration: sensitive data and an undeclared destination",
            severity=Severity.HIGH,
            category=Category.EXFIL,
            message=(
                f"Reads {_and(what)}, and can send data to hosts it doesn't declare "
                f"({', '.join(to)}). No single function shows the data going out, so "
                f"this is a correlation, not a proven path. {link}"
            ),
            file=first.file,
            line=first.line,
            evidence=f"sources: {where}; destinations: {', '.join(to)}",
            tags=frozenset({Tag.EXFIL, Tag.POSSIBLE}),
            analyzer=NAME,
        )
    ]
