"""Deterministic scoring. No AI, no network, no randomness: same findings -> same score."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, replace
from enum import StrEnum

from sniff_test import kinds
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


FLOOR_NO_THREAT = 40  # Very Sus: what an app can do, alone, can't push it lower


@dataclass(frozen=True)
class Policy:
    """(0.14.0 part 3) The scoring choices a user can change on the Settings page. The
    defaults are Barkley's own score: the scanner stores it, and the panel computes it
    again (never stored) only when a setting differs.

    - `paranoid`: score the minor findings (kinds.MINOR). Off: they're not counted (the
      panel leaves them out unless asked).
    - `floor`: with no Threat finding (and no critical one), the score can't go below
      Very Sus. Only for a complete scan: an unfinished one may have missed a Threat.
    - `unauth_views`: count a page without a login (ha-unauth-view) under local
      exposure. Public exposure always counts it, raised a level.
    - `shadow_telemetry`: count usage reporting sent with no option and no mention.
    """

    paranoid: bool = False
    floor: bool = True
    unauth_views: bool = False
    shadow_telemetry: bool = True
    exposure: str = Exposure.LOCAL

    def counts(self, rule_id: str) -> bool:
        if rule_id in kinds.MINOR:
            return self.paranoid
        if rule_id == "ha-unauth-view":
            return self.unauth_views or self.exposure == Exposure.PUBLIC
        if rule_id == "telemetry-shadow":
            return self.shadow_telemetry
        return True


DEFAULT = Policy()


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


DEP_VULN = "dep-vuln"


def apply_exposure(findings: list[Finding], exposure: Exposure) -> list[Finding]:
    """Public exposure raises inbound-surface findings by one level. Exfiltration and
    malware are never touched (already top severity).

    (0.14.1, user decision 2026-11-18) A known vulnerability in a dependency depends on
    whether an attacker can reach Home Assistant: on a box that isn't exposed to the
    internet it is at most medium, and the finding says so; when exposed it keeps its
    rating (at most high), and one that CISA says is exploited in the wild (SSVC active
    or listed in KEV), automatable and of total impact is critical. This is the one case
    where exposure lowers a severity.
    """
    out = []
    for f in findings:
        if f.rule_id == DEP_VULN:
            f = _dependency_by_exposure(f, exposure)
        elif exposure is Exposure.PUBLIC and Tag.INBOUND in f.tags and Tag.EXFIL not in f.tags:
            f = f.with_severity(f.severity.bumped())
        out.append(f)
    return out


def _dependency_by_exposure(f: Finding, exposure: Exposure) -> Finding:
    advisories = f.dependency.advisories if f.dependency else ()
    worst = next((a for a in advisories if a.worst_case), None)
    if exposure is Exposure.PUBLIC:
        if worst is not None:
            return replace(
                f.with_severity(Severity.CRITICAL),
                message=f.message + " CISA lists it as exploited in the wild, automatable and "
                "of total impact, and your Home Assistant is exposed to the internet, so "
                "it's critical.",
            )
        if Tag.INBOUND in f.tags:
            return f.with_severity(f.severity.bumped())
        return f
    if f.severity <= Severity.MEDIUM and worst is None:
        return f
    rated = str(f.severity)
    why = (
        "CISA lists it as exploited in the wild, automatable and of total impact, which "
        "would make it critical if your Home Assistant were exposed to the internet"
        if worst is not None
        else f"It is rated {rated}"
    )
    if f.severity <= Severity.MEDIUM:  # the worst case, rated low or medium: say so only
        return replace(f, message=f.message + f" {why}; your Home Assistant isn't exposed.")
    return replace(
        f.with_severity(Severity.MEDIUM),
        message=f.message + f" {why}; Barkley counts it as medium because your Home "
        "Assistant isn't exposed to the internet (Settings: Exposure).",
    )


def score(findings: list[Finding], complete: bool, policy: Policy | None = None) -> ScoreResult:
    """`policy` None is Barkley's own: the defaults, local exposure."""
    policy = policy or DEFAULT
    every = findings
    findings = [f for f in findings if policy.counts(f.rule_id)]
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
    if (
        policy.floor
        and complete
        and final < FLOOR_NO_THREAT
        and Severity.CRITICAL not in severities
        and not any(kinds.is_threat(f.rule_id) for f in every)
    ):
        final = FLOOR_NO_THREAT
        caps.append(f"no Threat finding: what it can do alone stops at {FLOOR_NO_THREAT}")
    return ScoreResult(
        score=final,
        verdict=verdict_for(final),
        raw_score=raw,
        complete=complete,
        deductions=deductions,
        caps=caps,
    )
