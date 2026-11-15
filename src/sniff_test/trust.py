"""Addresses the user marked trusted (host reputation, user decisions 2026-11-12).

Some findings are purely about where an address points: a hardcoded public IP, or
GuardDog's address heuristics on a dependency (a dependency that names
`https://api.together.xyz/`, which is Together AI's API). Barkley can't know every host a
Home Assistant app legitimately talks to, so the user decides: "Trust api.together.xyz?",
for this app or for every app.

What a trust mark does, and doesn't:

- It only ever applies to findings that carry `addresses` (the scanner sets them when
  every address behind the finding was read with certainty), and only when **every** one
  of those addresses is trusted, exactly (no subdomains, no wildcards). An update that
  names a new address is flagged again.
- It never touches a finding about what is sent: proven data flows, possible exfil,
  paste sites, tunnels and chat webhooks carry no `addresses`, so no list entry can
  reach them.
- The stored scan is never changed. `view()` returns a copy for showing: the trusted
  findings move to `trusted_findings` (still shown, costing nothing), the score is
  computed again from the rest with the scanner's own `scoring.score`, and `trust`
  records Barkley's own score next to it. Removing a mark undoes it at once.
- The AI plays no part: marks come only from the user's own form posts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, NamedTuple

from sniff_test import scoring
from sniff_test.models import Severity

SETTING = "trusted_addresses"
_ADDRESS = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?|[0-9a-f:]{3,45}")
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}")
_MAX = 500  # entries per list; a bound, not a feature


def valid_address(value: str) -> bool:
    """A lowercase hostname or IP literal, nothing else (no scheme, port, path, space)."""
    return bool(_ADDRESS.fullmatch(value))


@dataclass
class Trusted:
    """`everywhere`: trusted for every app. `apps`: per app, keyed by lowercase owner/repo."""

    everywhere: set[str] = field(default_factory=set)
    apps: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def loads(cls, text: str | None) -> Trusted:
        """Tolerant of anything in the settings table: bad shapes become an empty list."""
        try:
            raw = json.loads(text or "{}")
        except ValueError:
            return cls()
        if not isinstance(raw, dict):
            return cls()

        def clean(xs: Any) -> set[str]:
            return (
                {x for x in xs if isinstance(x, str) and valid_address(x)}
                if isinstance(xs, list)
                else set()
            )

        apps_raw = raw.get("apps") if isinstance(raw.get("apps"), dict) else {}
        apps = {
            k.lower(): clean(v)
            for k, v in apps_raw.items()
            if isinstance(k, str) and _REPO.fullmatch(k)
        }
        return cls(clean(raw.get("all")), {k: v for k, v in apps.items() if v})

    def dumps(self) -> str:
        return json.dumps(
            {
                "all": sorted(self.everywhere),
                "apps": {k: sorted(v) for k, v in sorted(self.apps.items()) if v},
            },
            separators=(",", ":"),
        )

    def scope(self, repo: str | None, address: str) -> str:
        """ "app", "all" or "" (not trusted) for one address as seen from `repo`."""
        if repo and address in self.apps.get(repo.lower(), ()):
            return "app"
        return "all" if address in self.everywhere else ""

    def covers(self, repo: str | None, addresses: list[str] | tuple[str, ...]) -> bool:
        return bool(addresses) and all(self.scope(repo, a) for a in addresses)

    def add(self, address: str, repo: str | None) -> bool:
        """Trust `address` for `repo`, or for every app when `repo` is None."""
        if not valid_address(address) or (repo is not None and not _REPO.fullmatch(repo)):
            return False
        target = self.everywhere if repo is None else self.apps.setdefault(repo.lower(), set())
        if len(target) >= _MAX or (repo is not None and len(self.apps) > _MAX):
            return False
        target.add(address)
        return True

    def remove(self, address: str, repo: str | None) -> None:
        if repo is None:
            self.everywhere.discard(address)
        else:
            self.apps.get(repo.lower(), set()).discard(address)

    def __bool__(self) -> bool:
        return bool(self.everywhere or any(self.apps.values()))


class _F(NamedTuple):
    """What `scoring.score` reads of a finding."""

    id: str
    rule_id: str
    severity: Severity


@dataclass(frozen=True)
class Rescored:
    score: int
    verdict_key: str
    verdict_label: str
    raw_score: int
    caps: list[str]
    breakdown: list[dict[str, Any]]


def rescore(findings: list[tuple[str, str, str]], complete: bool) -> Rescored:
    """The scanner's own score for (id, rule_id, severity) triples."""
    s = scoring.score([_F(i, r, Severity.parse(sev)) for i, r, sev in findings], complete)  # type: ignore[list-item]
    return Rescored(
        s.score,
        s.verdict.key,
        s.verdict.label,
        s.raw_score,
        s.caps,
        [
            {
                "finding_id": d.finding_id,
                "rule_id": d.rule_id,
                "severity": str(d.severity),
                "points": d.points,
            }
            for d in s.deductions
            if d.points
        ],
    )


def trusted_ids(report: dict[str, Any], trusted: Trusted) -> dict[str, str]:
    """finding id → "app" | "all" for the findings whose every address is trusted."""
    repo = (report.get("target") or {}).get("repo")
    out: dict[str, str] = {}
    for f in report.get("findings", []):
        addrs = [a for a in f.get("addresses") or [] if isinstance(a, str)]
        if len(addrs) != len(f.get("addresses") or []) or not trusted.covers(repo, addrs):
            continue
        scopes = {trusted.scope(repo, a) for a in addrs}
        out[str(f["id"])] = "app" if scopes == {"app"} else "all" if scopes == {"all"} else "mixed"
    return out


def view(report: dict[str, Any], trusted: Trusted) -> dict[str, Any]:
    """The report as the panel shows it: the same dict when nothing in it is trusted,
    else a shallow copy with the trusted findings set aside and the score computed from
    the rest. Never stored, never sent to the AI, never diffed."""
    ids = trusted_ids(report, trusted) if trusted else {}
    if not ids:
        return report
    keep = [f for f in report["findings"] if str(f["id"]) not in ids]
    aside = [{**f, "trusted": ids[str(f["id"])]} for f in report["findings"] if str(f["id"]) in ids]
    r = rescore(
        [(str(f["id"]), str(f["rule_id"]), str(f["severity"])) for f in keep],
        bool(report.get("complete")),
    )
    counts: dict[str, int] = {}
    for f in keep:
        counts[str(f["severity"])] = counts.get(str(f["severity"]), 0) + 1
    addresses = sorted({a for f in aside for a in f["addresses"]})
    repo = (report.get("target") or {}).get("repo")
    return {
        **report,
        "findings": keep,
        "trusted_findings": aside,
        "score": r.score,
        "raw_score": r.raw_score,
        "verdict": {"key": r.verdict_key, "label": r.verdict_label},
        "caps_applied": r.caps,
        "score_breakdown": r.breakdown,
        "counts": counts,
        "trust": {
            "own_score": report.get("score"),
            "own_verdict": report.get("verdict"),
            "addresses": addresses,
            "scopes": {a: trusted.scope(repo, a) for a in addresses},
            "findings": len(aside),
        },
    }
