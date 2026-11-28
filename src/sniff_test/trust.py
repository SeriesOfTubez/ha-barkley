"""What is left of the 0.9.0 "addresses you trust" module after reviews went in 0.15:

- `valid_address`: the shape of a host or IP the scanner may record on a finding that is
  only about where an address points (`Finding.addresses`, shown on the app's page).
- `rescore`: the scanner's own `scoring.score` for stored (id, rule, severity) triples,
  which an advisory re-check uses to build its new report (recheck.apply).

Nothing a user does changes a reading or a stored scan any more; someone who disagrees
with what Barkley shows reports a false positive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, NamedTuple

from sniff_test import scoring
from sniff_test.models import Severity

_ADDRESS = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?|[0-9a-f:]{3,45}")


def valid_address(value: str) -> bool:
    """A lowercase hostname or IP literal, nothing else (no scheme, port, path, space)."""
    return bool(_ADDRESS.fullmatch(value))


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


def rescore(
    findings: list[tuple[str, str, str]], complete: bool, policy: scoring.Policy | None = None
) -> Rescored:
    """The scanner's own score for (id, rule_id, severity) triples."""
    s = scoring.score(
        [_F(i, r, Severity.parse(sev)) for i, r, sev in findings],  # type: ignore[misc]
        complete,
        policy,
    )
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
