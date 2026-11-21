"""The report as the panel shows it: the Threat and Exposure readings added, and the minor
items left out unless asked for. Never stored, never sent to the AI, never diffed: the
stored report is never edited, `view()` returns a copy.

(0.15) The panel shows only the two readings (readings.py); the 0-100 capability score
stays in the stored report, the raw JSON and the CLI (his decision 2026-11-20). With it
went the settings that only changed the score (Paranoid mode, Powerful no threat, Pages
without a login, Hidden usage reporting). Reviews, Malware check only and addresses the
user trusts were removed too: a user can never change Barkley's own readings. Someone who
disagrees with what Barkley shows uses Report a false positive. The stored reviews and
lists are deleted once when 0.15 first starts (store.Store).
"""

from __future__ import annotations

from typing import Any

from sniff_test import kinds, readings


def view(
    report: dict[str, Any],
    *,
    network: str = "home",
    show_minor: bool = False,
    always: bool = False,
    quiet_months: int = 12,
) -> dict[str, Any]:
    """Keys added: `readings` (readings.compute on the stored findings, all of them) and
    `shown` (the minor items, whether they're shown: for this page, or `always` by the
    Minor items setting)."""
    show_minor = show_minor or always
    every = list(report.get("findings", []))
    minor = [f for f in every if f["rule_id"] in kinds.MINOR]
    minor_ids = {str(f["id"]) for f in minor}
    shown = every if show_minor else [f for f in every if str(f["id"]) not in minor_ids]
    counts: dict[str, int] = {}
    for f in shown:
        counts[str(f["severity"])] = counts.get(str(f["severity"]), 0) + 1
    return {
        **report,
        "findings": shown,
        "counts": counts,
        "readings": readings.compute(report, network).to_dict(),
        "shown": {
            "minor": [str(f["rule_id"]) for f in minor],
            "show_minor": show_minor,
            "always": always,
            "quiet_months": quiet_months,
        },
    }
