"""Accept AI explanations without letting the AI change anything that matters.

Whatever comes back from the model is filtered to {known_finding_id: short_text}.
Scores, verdicts, severities, and the finding list are never read from AI output.
"""

from __future__ import annotations

import json
from typing import Any

MAX_EXPLANATION = 1200


def accept_explanations(report: dict[str, Any], ai_output: str | dict[str, Any]) -> dict[str, str]:
    if isinstance(ai_output, str):
        try:
            ai_output = json.loads(ai_output)
        except ValueError:
            return {}
    if not isinstance(ai_output, dict):
        return {}
    known = {f["id"] for f in report.get("findings", [])}
    accepted: dict[str, str] = {}
    for key, value in ai_output.items():
        if key in known and isinstance(value, str) and value.strip():
            accepted[key] = value.strip()[:MAX_EXPLANATION]
    return accepted
