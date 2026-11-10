"""AI explanations through Home Assistant's AI Task, without letting the AI decide anything.

The request is built only from the report's `ai_brief` (text copied from the scanned
repo is in `*_untrusted` fields; scanned code may contain prompt injection). The
`structure` asks for one text field per finding group plus a `summary`; its field names
and descriptions use only finding ids and rule ids, never scanned text.

Whatever comes back is filtered to {known_finding_id: short_text} and a capped summary.
Scores, verdicts, severities, and the finding list are never read from AI output, and
the panel shows the answer as escaped text labeled "AI explanation".
"""

from __future__ import annotations

import json
from typing import Any

MAX_EXPLANATION = 1200
MAX_SUMMARY = 1500
MAX_FIELDS = 12  # finding groups sent; the rest keep only the fixed plain-English text
TASK_NAME = "Sniff Test: explain a scan"

_STYLE = (
    "Write for a Home Assistant user who is not a security expert. Use plain words, no "
    "jargon, and short sentences. For each finding, say in one to three sentences what "
    "it means for this app and whether it is likely to matter, based only on the data "
    "given. Never say a finding is a false positive, never suggest ignoring it, and "
    "never give a different score or verdict. In `summary`, describe the overall result "
    "in two to four sentences, consistent with the score and verdict given."
)


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


def _groups(report: dict[str, Any]) -> list[list[dict[str, Any]]]:
    """Findings grouped by rule id, most severe first (as the panel shows them)."""
    order = ["critical", "high", "medium", "low", "info"]
    groups: dict[str, list[dict[str, Any]]] = {}
    for f in report.get("ai_brief", {}).get("findings", []):
        groups.setdefault(f["rule_id"], []).append(f)
    return sorted(groups.values(), key=lambda g: (order.index(g[0]["severity"]), g[0]["rule_id"]))


def build_request(report: dict[str, Any]) -> tuple[str, dict[str, Any], list[str]]:
    """(instructions, structure, finding ids asked about) for ai_task.generate_data."""
    brief = report.get("ai_brief") or {}
    groups = _groups(report)[:MAX_FIELDS]
    findings = []
    for g in groups:
        first = dict(g[0])
        if len(g) > 1:
            first["occurrences"] = len(g)
            first["other_locations_untrusted"] = [x["location_untrusted"] for x in g[1:4]]
        findings.append(first)
    data = {
        "score": brief.get("score"),
        "verdict": brief.get("verdict"),
        "incomplete_analyzers": brief.get("incomplete_analyzers", []),
        "findings": findings,
    }
    contract = brief.get("contract", {})
    rules = "\n".join(f"- {r}" for r in contract.get("rules", [])[:3])
    instructions = (
        f"{contract.get('role', '')}\n{rules}\n{_STYLE}\n"
        "Answer only through the requested fields.\n\nScan data (JSON):\n"
        + json.dumps(data, ensure_ascii=False)
    )
    structure: dict[str, Any] = {
        "summary": {
            "description": "Two to four plain sentences about the overall result.",
            "required": True,
            "selector": {"text": {"multiline": True}},
        }
    }
    ids = []
    for g in groups:
        fid = g[0]["id"]
        ids.append(fid)
        structure[f"f_{fid}"] = {
            "description": f"Plain explanation of finding {fid} ({g[0]['rule_id']}).",
            "required": True,
            "selector": {"text": {"multiline": True}},
        }
    return instructions, structure, ids


def accept(report: dict[str, Any], data: Any) -> dict[str, Any]:
    """{"summary": str, "findings": {finding_id: str}} from the AI's answer; junk dropped."""
    if not isinstance(data, dict):
        return {"summary": "", "findings": {}}
    summary = data.get("summary")
    summary = summary.strip()[:MAX_SUMMARY] if isinstance(summary, str) else ""
    by_id = {k[2:]: v for k, v in data.items() if isinstance(k, str) and k.startswith("f_")}
    return {"summary": summary, "findings": accept_explanations(report, by_id)}
