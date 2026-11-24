"""(0.14.0 part 3) What kind of finding each rule makes, and the two fixed lists the user
agreed on (2026-11-18): the minor findings Paranoid mode decides about, and the Home
Assistant actions counted as high-privilege.

Kinds (decided 2026-11-17):
- Threat: signs of malicious behavior. Proven or possible exfil, exfil hosts, known
  malware, decode-and-run, obfuscation and hidden code. No real app had one after the
  part 2 precision fixes; both malicious fixtures keep theirs.
- Capability: powerful things the app is able to do. Normal for some apps; what an
  attacker would get if the app were ever compromised.
- Practice: how the app is made and released.
- Vulnerability: published vulnerabilities in the libraries it uses.
- Coverage: parts of the code the scan couldn't read.

Kinds never change a severity. Scoring reads them only for the "no Threat" floor
(scoring.Policy) and Accept all reads them for the per-Threat tick.
"""

from __future__ import annotations

THREAT = "threat"
CAPABILITY = "capability"
PRACTICE = "practice"
VULNERABILITY = "vulnerability"
COVERAGE = "coverage"

ORDER = (THREAT, CAPABILITY, VULNERABILITY, PRACTICE, COVERAGE)

THREAT_RULES = frozenset(
    {
        "ha-exfil-taint",
        "possible-exfil",
        "card-token-exfil",
        "endpoint-exfil-host",
        "dep-malicious",
        "dep-malicious-build",
        "py-b64-exec",
        "card-b64-eval",
        "card-eval-remote",
        "py-obfuscation",
        "card-hidden-name",
        "py-bytecode-runs-instead-of-source",
        "py-native-module-shadows-source",
        "py-native-module-without-source",
        "card-html-comment-token",
    }
)
VULNERABILITY_RULES = frozenset({"dep-vuln", "dep-build-tool-vuln"})
COVERAGE_RULES = frozenset({"scan-parse-error", "scan-file-not-checked"})
PRACTICE_RULES = frozenset(
    {
        "dep-npm-no-lockfile",
        "dep-vcs-or-url-requirement",
        "dep-invalid-requirement",
        "dep-unresolvable",
        "dep-sdist-only",
        "dep-very-new-package",
        "dep-typosquat",
        "dep-lookalike-own",
        "py-runtime-pip-listed",
        "py-pickle-stored",
        "telemetry-shadow",
        "telemetry-opt-out",
        "telemetry-usage",
    }
)

# Paranoid mode (default off, user decision 2026-11-17/18): while it's off these are left
# out of the page and the score. The test for each: it touches no password or login,
# changes nothing, and usually has a plain reason. Changing users, other apps' passwords,
# the Supervisor token, location history and running code are never on it.
MINOR = frozenset(
    {
        "ha-auth-list-users",  # names only, no credentials
        "ha-foreign-entry-options",  # filters and device choices; credentials are in .data
        "ha-own-storage-path",  # its own files only
        "dep-build-tool-vuln",  # the tool never ships in the card
        "py-runtime-pip-listed",  # the same libraries Barkley already checked
        "telemetry-usage",  # disclosed or optional; hidden reporting stays counted
    }
)


def kind(rule_id: str) -> str:
    if rule_id in THREAT_RULES:
        return THREAT
    if rule_id in VULNERABILITY_RULES:
        return VULNERABILITY
    if rule_id in COVERAGE_RULES:
        return COVERAGE
    if rule_id in PRACTICE_RULES or rule_id.startswith("repo-"):
        return PRACTICE
    return CAPABILITY  # every other HA, Python and card rule, and GuardDog's heuristics


def is_threat(rule_id: str) -> bool:
    return rule_id in THREAT_RULES


# "Runs N kinds of Home Assistant actions, n of them high-privilege" (user yes 2026-11-18,
# "good starts"; refine from the research run). An action whose domain is worked out
# while running (`*.turn_on`) can't be judged, so it isn't counted. Notify and covers are
# left off: notify is everyday, covers are mostly blinds.
HIGH_PRIVILEGE_DOMAINS = frozenset({"hassio", "shell_command", "python_script", "backup"})
HIGH_PRIVILEGE_ACTIONS = frozenset(
    {
        "homeassistant.restart",
        "homeassistant.stop",
        "update.install",
        "recorder.purge",
        "recorder.purge_entities",
        "recorder.disable",
        "lock.unlock",
        "lock.open",
        "alarm_control_panel.alarm_disarm",
    }
)
# Home Assistant's own constant names for the two core actions, as the graph keeps them
# when the code passes the constant rather than the string.
_CONST_ACTIONS = {
    "SERVICE_HOMEASSISTANT_RESTART": "homeassistant.restart",
    "SERVICE_HOMEASSISTANT_STOP": "homeassistant.stop",
}


def high_privilege(label: str) -> bool:
    """`label` is a graph node's "domain.action" (either part may be a constant name)."""
    dom, _, act = label.partition(".")
    if dom in HIGH_PRIVILEGE_DOMAINS:
        return True
    if f"{dom}.{act.lower()}" in HIGH_PRIVILEGE_ACTIONS:
        return True
    # The constant names only exist for Home Assistant's own restart and stop, whatever
    # name the code imported the domain under (`DOMAIN`, `HA_DOMAIN`, ...).
    return act in _CONST_ACTIONS
