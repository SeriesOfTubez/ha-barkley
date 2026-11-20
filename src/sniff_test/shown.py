"""The report as the panel shows it: Barkley's score with the user's scoring settings, and
the minor items left out unless asked for. Never stored, never sent to the AI, never
diffed: the stored report is never edited, `view()` returns a copy.

(0.15) Reviews (Accept, Mark reviewed, Accept all), Malware check only and addresses the
user trusts were removed (his decision 2026-11-20): with the Threat and Exposure readings,
a review changed nothing, and a user can never change Barkley's own readings. Someone who
disagrees with what Barkley shows uses Report a false positive. The stored reviews and
lists are deleted once when 0.15 first starts (store.Store).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sniff_test import kinds, scoring, trust


@dataclass(frozen=True)
class Settings:
    """The scoring settings `view()` reads (settings.Settings carries more)."""

    paranoid: bool = False
    floor: bool = True
    unauth_views: bool = False
    shadow_telemetry: bool = True

    def policy(self, exposure: str) -> scoring.Policy:
        return scoring.Policy(
            paranoid=self.paranoid,
            floor=self.floor,
            unauth_views=self.unauth_views,
            shadow_telemetry=self.shadow_telemetry,
            exposure=exposure,
        )


def view(
    report: dict[str, Any],
    *,
    settings: Settings | None = None,
    show_minor: bool = False,
) -> dict[str, Any]:
    """Keys added: `shown` (the minor items left out, whether they're shown). `score` and
    `verdict` are Barkley's own: the stored ones when the scoring settings are the
    defaults, else the same formula under the user's settings."""
    settings = settings or Settings()
    exposure = str(report.get("exposure") or "local")
    policy = settings.policy(exposure)
    every = list(report.get("findings", []))

    if policy == scoring.Policy(exposure=exposure) and "score" in report:
        score = int(report["score"])
        verdict = report.get("verdict") or {}
        breakdown = report.get("score_breakdown", [])
        caps = report.get("caps_applied", [])
    else:  # the user changed a scoring setting: Barkley's score under their settings
        r = trust.rescore(
            [(str(f["id"]), str(f["rule_id"]), str(f["severity"])) for f in every],
            bool(report.get("complete")),
            policy,
        )
        score, verdict = r.score, {"key": r.verdict_key, "label": r.verdict_label}
        breakdown, caps = r.breakdown, r.caps

    minor = [] if settings.paranoid else [f for f in every if f["rule_id"] in kinds.MINOR]
    minor_ids = {str(f["id"]) for f in minor}
    shown = every if show_minor else [f for f in every if str(f["id"]) not in minor_ids]
    counts: dict[str, int] = {}
    for f in shown:
        counts[str(f["severity"])] = counts.get(str(f["severity"]), 0) + 1
    return {
        **report,
        "findings": shown,
        "score": score,
        "verdict": verdict,
        "score_breakdown": breakdown,
        "caps_applied": caps,
        "counts": counts,
        "shown": {
            "minor": [str(f["rule_id"]) for f in minor],
            "show_minor": show_minor,
        },
    }
