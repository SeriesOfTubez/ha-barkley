"""Deterministic scoring. No AI, no network, no randomness: same findings -> same score."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum

from sniff_test.models import RULE_FILE_NOT_CHECKED, Finding, Severity, Tag

BASE_POINTS: dict[Severity, float] = {
    Severity.CRITICAL: 60,
    Severity.HIGH: 25,
    Severity.MEDIUM: 8,
    Severity.LOW: 2,
    Severity.INFO: 0,
}
REPEAT_FACTOR = 0.25  # each repeat of the same rule costs a quarter of the first hit
PER_RULE_CAP = 2.0  # one rule can never cost more than 2x its base points

CAP_CRITICAL = 39  # any critical finding -> BORK BORK BORK
CAP_HIGH = 89  # any high finding -> at best Kinda Sus
CAP_INCOMPLETE = 89  # a partial scan can never be a Good Boy
# A file no code rule could read (models.RULE_FILE_NOT_CHECKED). Unlike an incomplete scan
# this repeats on every sniff, so the scan stays complete (stored, reused, re-checked) and
# the cap comes from the finding itself: anything that rescores stored findings keeps it.
CAP_UNCHECKED = 89


class Exposure(StrEnum):
    LOCAL = "local"
    PUBLIC = "public"


@dataclass(frozen=True)
class Verdict:
    key: str
    emoji: str
    label: str
    blurb: str


VERDICTS = (
    (90, Verdict("good_boy", "🦴", "Good Boy", "passed the sniff test")),
    (70, Verdict("kinda_sus", "🐕", "Kinda Sus", "a few things worth a look")),
    (40, Verdict("very_sus", "🐕‍🦺", "Very Sus", "the dog won't stop staring at it")),
    (0, Verdict("bork", "🚨", "BORK BORK BORK", "do not install")),
)


def verdict_for(score: int) -> Verdict:
    for floor, v in VERDICTS:
        if score >= floor:
            return v
    return VERDICTS[-1][1]


@dataclass
class Deduction:
    finding_id: str
    rule_id: str
    severity: Severity
    points: float


@dataclass
class ScoreResult:
    score: int
    verdict: Verdict
    raw_score: int
    complete: bool
    deductions: list[Deduction] = field(default_factory=list)
    caps: list[str] = field(default_factory=list)


def apply_exposure(findings: list[Finding], exposure: Exposure) -> list[Finding]:
    """Public exposure raises inbound-surface findings by one level.

    It only ever raises. Exfil findings are untouched (they're already top severity);
    nothing is ever lowered.
    """
    if exposure is not Exposure.PUBLIC:
        return list(findings)
    out = []
    for f in findings:
        if Tag.INBOUND in f.tags and Tag.EXFIL not in f.tags:
            f = f.with_severity(f.severity.bumped())
        out.append(f)
    return out


def score(findings: list[Finding], complete: bool) -> ScoreResult:
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in sorted(findings, key=lambda f: (-f.severity, f.id)):
        by_rule[f.rule_id].append(f)

    deductions: list[Deduction] = []
    for rule_id, group in sorted(by_rule.items()):
        spent = 0.0
        base_top = BASE_POINTS[group[0].severity]
        cap = base_top * PER_RULE_CAP
        for i, f in enumerate(group):
            pts = BASE_POINTS[f.severity] * (1.0 if i == 0 else REPEAT_FACTOR)
            pts = max(0.0, min(pts, cap - spent))
            spent += pts
            deductions.append(Deduction(f.id, rule_id, f.severity, round(pts, 2)))

    raw = max(0, round(100 - sum(d.points for d in deductions)))
    severities = {f.severity for f in findings}
    rules = (
        (Severity.CRITICAL in severities, CAP_CRITICAL, "critical finding present"),
        (Severity.HIGH in severities, CAP_HIGH, "high finding present"),
        (not complete, CAP_INCOMPLETE, "scan incomplete"),
        (
            any(f.rule_id == RULE_FILE_NOT_CHECKED for f in findings),
            CAP_UNCHECKED,
            "a file no code rule could read",
        ),
    )
    final = raw
    caps: list[str] = []
    for applies, cap, reason in rules:
        if applies and final > cap:
            final = cap
            caps.append(f"{reason}: capped at {cap}")
    return ScoreResult(
        score=final,
        verdict=verdict_for(final),
        raw_score=raw,
        complete=complete,
        deductions=deductions,
        caps=caps,
    )
