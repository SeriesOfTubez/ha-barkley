"""(0.14.0 part 3) The user's review: findings marked reviewed ("accepted"), the reviewed
score beside Barkley's own, Paranoid mode and Malware check only. Decided with the user
2026-11-17/18 (vault: Feedback Plan, part 3 and the mock-up review).

What a review does, and doesn't:

- Barkley's own score never changes. The stored report is never edited; `view()` returns
  a copy for showing. Barkley's score there is `scoring.score` with the user's scoring
  settings (the stored one when they're the defaults); the reviewed score is the same
  formula without the findings the user accepted or whose addresses they trust.
- An acceptance is kept per app by the finding's fingerprint (report/fingerprint.py): the
  same code in the next version stays accepted; changed code reopens (and, with the
  setting on, notifies). Re-confirm (a setting) reopens acceptances older than 6 or 12
  months.
- Known malware (kinds.NEVER_ACCEPT) can never be accepted, and an app that has any never
  gets a reviewed score.
- The AI plays no part: acceptances come only from the user's own form posts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sniff_test import kinds, scoring, trust

NOTE_MAX = 300
WHO_MAX = 60
_WHO = re.compile(r"[^\x00-\x1f\x7f<>]{1,60}")


def clean_note(text: str) -> str:
    """A note is the user's own text; kept short, one line, control characters dropped."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", text or "").strip()[:NOTE_MAX]


def clean_who(name: str | None) -> str:
    """Who accepted: the HA user's display name from ingress or the standalone login."""
    name = re.sub(r"\s+", " ", (name or "").strip())[:WHO_MAX]
    return name if name and _WHO.fullmatch(name) else ""


@dataclass(frozen=True)
class Accept:
    repo: str  # lowercase owner/name
    fingerprint: str
    rule_id: str
    note: str
    who: str
    at: str  # ISO 8601, UTC
    scan_id: int  # where it was accepted (for "What changed?")
    finding_id: str
    ref: str
    file: str = ""

    def age_days(self, now: datetime) -> float:
        try:
            return (now - datetime.fromisoformat(self.at)).total_seconds() / 86400
        except ValueError:
            return 0.0


@dataclass(frozen=True)
class Settings:
    """The scoring and review settings `view()` reads (settings.Settings carries more)."""

    paranoid: bool = False
    floor: bool = True
    unauth_views: bool = False
    shadow_telemetry: bool = True
    reconfirm_months: int = 0  # 0: never

    def policy(self, exposure: str) -> scoring.Policy:
        return scoring.Policy(
            paranoid=self.paranoid,
            floor=self.floor,
            unauth_views=self.unauth_views,
            shadow_telemetry=self.shadow_telemetry,
            exposure=exposure,
        )


@dataclass
class State:
    """Per finding id: `accepted` (an Accept), `reopened` (the old Accept its changed code
    replaced), `reconfirm` (an Accept older than the re-confirm period)."""

    accepted: dict[str, Accept] = field(default_factory=dict)
    reopened: dict[str, Accept] = field(default_factory=dict)
    reconfirm: dict[str, Accept] = field(default_factory=dict)


def can_accept(f: dict[str, Any]) -> bool:
    return str(f.get("rule_id")) not in kinds.NEVER_ACCEPT and bool(f.get("fingerprint"))


def states(
    report: dict[str, Any],
    accepts: list[Accept],
    reconfirm_months: int = 0,
    now: datetime | None = None,
) -> State:
    """Match the app's acceptances to this scan's findings by fingerprint. A finding with
    no matching fingerprint is `reopened` when an acceptance of the same rule in the same
    file no longer matches anything here: that code changed since it was accepted."""
    now = now or datetime.now(UTC)
    by_fp: dict[str, Accept] = {}
    for a in accepts:
        by_fp.setdefault(a.fingerprint, a)
    out = State()
    findings = [f for f in report.get("findings", []) if can_accept(f)]
    present = {str(f["fingerprint"]) for f in findings}
    stale = [a for a in accepts if a.fingerprint not in present]
    for f in findings:
        fid, fp = str(f["id"]), str(f["fingerprint"])
        a = by_fp.get(fp)
        if a is None:
            continue
        if reconfirm_months and a.age_days(now) > reconfirm_months * 30.4:
            out.reconfirm[fid] = a
        else:
            out.accepted[fid] = a
    for f in findings:
        fid = str(f["id"])
        if fid in out.accepted or fid in out.reconfirm:
            continue
        rule, file = str(f["rule_id"]), str(f.get("file") or "")
        match = next((a for a in stale if a.rule_id == rule and a.file == file), None)
        if match is not None:
            out.reopened[fid] = match
            stale.remove(match)  # one old acceptance reopens one finding
    return out


def _score(
    findings: list[dict[str, Any]], complete: bool, policy: scoring.Policy
) -> trust.Rescored:
    return trust.rescore(
        [(str(f["id"]), str(f["rule_id"]), str(f["severity"])) for f in findings],
        complete,
        policy,
    )


def malware(report: dict[str, Any]) -> bool:
    return any(str(f.get("rule_id")) in kinds.NEVER_ACCEPT for f in report.get("findings", []))


def view(
    report: dict[str, Any],
    *,
    trusted: trust.Trusted | None = None,
    settings: Settings | None = None,
    accepts: list[Accept] | None = None,
    malware_only: bool = False,
    show_minor: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The report as the panel shows it. Never stored, never sent to the AI, never diffed.

    Keys added: `review` (Barkley's score and verdict, the reviewed score if there is
    one, counts, the hidden minor findings), `trusted_findings` (as trust.view), and on
    each finding a `review` dict when it's accepted, reopened or due again. `score` and
    `verdict` are what the circle shows: the reviewed score once there is one."""
    settings = settings or Settings()
    trusted = trusted or trust.Trusted()
    exposure = str(report.get("exposure") or "local")
    policy = settings.policy(exposure)
    complete = bool(report.get("complete"))
    every = list(report.get("findings", []))

    if policy == scoring.Policy(exposure=exposure) and "score" in report:
        own_score = int(report["score"])
        own_verdict = report.get("verdict") or {}
        breakdown = report.get("score_breakdown", [])
        caps = report.get("caps_applied", [])
    else:  # the user changed a scoring setting: Barkley's score under their settings
        r = _score(every, complete, policy)
        own_score, own_verdict = r.score, {"key": r.verdict_key, "label": r.verdict_label}
        breakdown, caps = r.breakdown, r.caps

    minor = [] if settings.paranoid else [f for f in every if f["rule_id"] in kinds.MINOR]
    minor_ids = {str(f["id"]) for f in minor}
    st = states(report, accepts or [], settings.reconfirm_months, now)
    trusted_map = trust.trusted_ids(report, trusted) if trusted else {}
    has_malware = malware(report)
    reviewed_ids = (set(st.accepted) | set(trusted_map)) - minor_ids

    def tagged(f: dict[str, Any]) -> dict[str, Any]:
        fid = str(f["id"])
        for key, src in (("accepted", st.accepted), ("reopened", st.reopened),
                         ("reconfirm", st.reconfirm)):  # fmt: skip
            a = src.get(fid)
            if a is not None:
                return {**f, "review": {"state": key, "note": a.note, "who": a.who,
                                        "at": a.at, "scan_id": a.scan_id,
                                        "finding_id": a.finding_id, "ref": a.ref}}  # fmt: skip
        return f

    shown = [tagged(f) for f in every if str(f["id"]) not in trusted_map]
    if not show_minor:
        shown = [f for f in shown if str(f["id"]) not in minor_ids]
    aside = [{**tagged(f), "trusted": trusted_map[str(f["id"])]} for f in every
             if str(f["id"]) in trusted_map]  # fmt: skip

    counted = [f for f in every if policy.counts(str(f["rule_id"]))]
    reviewed: trust.Rescored | None = None
    if reviewed_ids & {str(f["id"]) for f in counted} and not has_malware:
        reviewed = _score([f for f in every if str(f["id"]) not in reviewed_ids], complete, policy)
    open_left = [f for f in counted if str(f["id"]) not in reviewed_ids]
    all_accepted = bool(counted) and not open_left and reviewed is not None

    if malware_only:  # only Threats and known malware are shown, and they alone score
        threats = [f for f in every if kinds.is_threat(str(f["rule_id"]))]
        r = _score(threats, complete, policy)
        score, verdict = r.score, {"key": r.verdict_key, "label": r.verdict_label}
        shown = [tagged(f) for f in threats]
        aside = []
    elif reviewed is not None:
        score, verdict = reviewed.score, {"key": reviewed.verdict_key,
                                          "label": reviewed.verdict_label}  # fmt: skip
    else:
        score, verdict = own_score, own_verdict

    counts: dict[str, int] = {}
    for f in shown:
        counts[str(f["severity"])] = counts.get(str(f["severity"]), 0) + 1
    out = {
        **report,
        "findings": shown,
        "trusted_findings": aside,
        "score": score,
        "verdict": verdict,
        "score_breakdown": breakdown,
        "caps_applied": caps,
        "counts": counts,
        "review": {
            "own_score": own_score,
            "own_verdict": own_verdict,
            "stored_score": report.get("score"),
            "reviewed": reviewed is not None and not malware_only,
            "delta": (reviewed.score - own_score) if reviewed is not None else 0,
            "accepted": len(st.accepted),
            "reopened": sorted(st.reopened),
            "reconfirm": sorted(st.reconfirm),
            "all_accepted": all_accepted,
            "malware": has_malware,
            "malware_only": malware_only,
            "minor": [str(f["rule_id"]) for f in minor],
            "show_minor": show_minor,
        },
    }
    if trusted_map:  # what the trust section and the card sentence read (trust.view's key)
        addresses = sorted({a for f in aside for a in f.get("addresses") or []})
        repo = (report.get("target") or {}).get("repo")
        out["trust"] = {
            "own_score": own_score,
            "own_verdict": own_verdict,
            "addresses": addresses,
            "scopes": {a: trusted.scope(repo, a) for a in addresses},
            "findings": len(aside),
        }
    return out


def due(report_view: dict[str, Any]) -> int:
    """Findings the user should look at again: reopened or due for re-confirming."""
    r = report_view.get("review") or {}
    return len(r.get("reopened") or []) + len(r.get("reconfirm") or [])
