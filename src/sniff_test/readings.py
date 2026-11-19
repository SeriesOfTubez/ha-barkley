"""(preview, 2026-11-19) The proposed Threat and Exposure readings, shown beside Barkley's
score when the user turns on Settings → "Proposed readings (preview)". Nothing here is
stored, scored or notified: the readings are worked out from a stored scan's findings each
time a page is shown, so the user can compare them with today's score on real apps without
a re-sniff. Barkley's own score is untouched.

Decided with the user 2026-11-19 (vault: Roadmap "Scoring rethink", rounds 1-3 of the
mock-ups and his yes to items 1-4 of round 4):

- **Threat, 0-10**: signs of malicious behavior only (kinds.THREAT_RULES and a lookalike
  package name). Critical 6, high 2.5, medium 0.8, low 0.2; each repeat of a rule a
  quarter; capped at 10; any critical sign is at least 7. 0 none found, under 7 possible,
  7 and up found.
- **Exposure, 0-10**: only what lets someone other than an administrator in, measured for
  Home Assistant (an administrator can already do everything, so admin-only adds 0):
  a page that skips Home Assistant's login (0.25 when the same file checks a signed link or
  token, else 0.75: a check of its own Barkley can't confirm); a login token the app may
  hand out (non-admin 1, administrator 3, times a lifetime factor); a library bug (medium
  1, high 3, critical 5). Times 1.25 on a shared or work network, 1.5 when Home Assistant
  is reachable from the internet. Under 2 low, under 5 medium, 5 and up high. A found
  threat is exposure 10: the app itself sends your data out.

Preview limits, said on the page: the stored finding for token code keeps one line per
function, so Barkley can't yet tell whether a token leaves Home Assistant, whose it is or
how long it lasts. A `ha-auth-internals` finding counts as one non-administrator token
lasting over a year (1 x 1.25). Listening ports aren't told apart from outgoing ones yet,
so they aren't counted.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any

from sniff_test import kinds

THREAT_POINTS = {"critical": 6.0, "high": 2.5, "medium": 0.8, "low": 0.2, "info": 0.0}
REPEAT = 0.25
THREAT_MAX = 10.0
CRITICAL_FLOOR = 7.0
FOUND = 7.0

# Signs of malicious behavior beyond the Threat kind: a package named one typo from a
# popular one is the attacker's move, not the developer's habit.
EXTRA_THREAT_RULES = frozenset({"dep-typosquat"})

PAGE_RECOGNISED = 0.25  # the same file checks a signed link or a login token
PAGE_OWN_CHECK = 0.75  # a check of its own that Barkley can't confirm
TOKEN_NON_ADMIN = 1.0
TOKEN_ADMIN = 3.0
# How long a handed-out token lasts (the user's buckets, as multipliers: decided 2026-11-19)
LIFETIME = ((1, 0.0), (30, 0.5), (180, 0.75), (366, 1.0))  # (under N days, factor)
LIFETIME_LONG = 1.25  # over a year, or not known
LIB_BUG = {"critical": 5.0, "high": 3.0, "medium": 1.0}
NETWORK = {"home": 1.0, "shared": 1.25}
PUBLIC = 1.5
EXPOSURE_MAX = 10.0
LOW, MEDIUM = 2.0, 5.0

UNAUTH_VIEW = "ha-unauth-view"
TOKEN_CHECK = "ha-auth-token-check"  # noqa: S105 - a rule id
AUTH_INTERNALS = "ha-auth-internals"
DEP_VULN = "dep-vuln"

# Fixed phrases for the banner and the reason line, by rule (no text from the scanned app)
_THREAT_PHRASE = {
    "ha-exfil-taint": "sends your Home Assistant data off the box",
    "card-token-exfil": "sends your login token off the box",
    "possible-exfil": "may send other apps' passwords or your secrets to sites it doesn't declare",
    "endpoint-exfil-host": "sends data to a channel its developer controls",
    "dep-malicious": "includes a package known to be malware",
    "py-b64-exec": "decodes hidden code and runs it",
    "card-b64-eval": "decodes hidden code and runs it",
    "card-eval-remote": "runs code it downloads or receives",
    "py-obfuscation": "hides what its code does",
    "card-hidden-name": "hides the names its code uses",
    "py-bytecode-runs-instead-of-source": "runs compiled code instead of the source you can read",
    "py-native-module-shadows-source": "runs a compiled module in place of its source",
    "py-native-module-without-source": "ships a compiled module without its source",
    "card-html-comment-token": "hides a login token in its page",
    "dep-typosquat": "depends on a package named like a popular one",
}
# Most serious first, for the one sentence a banner says
_THREAT_ORDER = tuple(_THREAT_PHRASE)


def lifetime_factor(days: float | None) -> float:
    if days is None:
        return LIFETIME_LONG
    for under, factor in LIFETIME:
        if days < under:
            return factor
    return LIFETIME_LONG


def level(exposure: float) -> str:
    return "low" if exposure < LOW else "medium" if exposure < MEDIUM else "high"


@dataclass
class Readings:
    threat: float
    threat_level: str  # none | possible | found
    exposure: float
    exposure_level: str  # low | medium | high
    threat_reason: str = ""  # a fixed phrase ("sends your login token off the box")
    exposure_reasons: list[str] = field(default_factory=list)
    complete: bool = True
    network: str = "home"  # home | shared | internet

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _is_threat(rule_id: str) -> bool:
    return kinds.is_threat(rule_id) or rule_id in EXTRA_THREAT_RULES


def _threat(findings: list[dict[str, Any]]) -> tuple[float, str]:
    by_rule: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        if _is_threat(str(f.get("rule_id"))):
            by_rule[str(f["rule_id"])].append(str(f.get("severity") or "info"))
    total = 0.0
    critical = False
    for sevs in by_rule.values():
        pts = sorted((THREAT_POINTS.get(s, 0.0) for s in sevs), reverse=True)
        total += pts[0] + REPEAT * sum(pts[1:])
        critical = critical or "critical" in sevs
    score = min(THREAT_MAX, total)
    if critical:
        score = max(score, CRITICAL_FLOOR)
    first = next((r for r in _THREAT_ORDER if r in by_rule), "")
    return round(score, 2), _THREAT_PHRASE.get(first, "")


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def compute(report: dict[str, Any], network: str = "home") -> Readings:
    """`report`: a stored scan (or the panel's view of one). `network`: the preview's
    setting (home | shared); a scan made with exposure "public" counts as on the internet."""
    findings = list(report.get("findings") or [])
    complete = bool(report.get("complete", True))
    public = str(report.get("exposure") or "local") == "public"
    where = "internet" if public else (network if network in NETWORK else "home")
    threat, phrase = _threat(findings)
    t_level = "none" if threat == 0 else "found" if threat >= FOUND else "possible"
    if t_level == "found":
        return Readings(threat, t_level, EXPOSURE_MAX, "high", phrase,
                        [f"It {phrase}."], complete, where)  # fmt: skip

    reasons: list[str] = []
    pts = 0.0
    checked_files = {str(f.get("file")) for f in findings if f.get("rule_id") == TOKEN_CHECK}
    views = [f for f in findings if f.get("rule_id") == UNAUTH_VIEW]
    recognised = [f for f in views if str(f.get("file")) in checked_files]
    own = [f for f in views if str(f.get("file")) not in checked_files]
    if recognised:
        pts += PAGE_RECOGNISED * len(recognised)
        reasons.append(_plural(len(recognised), "page skips", "pages skip") + " Home "
                       "Assistant's login and checks a signed link or token instead.")  # fmt: skip
    if own:
        pts += PAGE_OWN_CHECK * len(own)
        reasons.append(_plural(len(own), "page skips", "pages skip") + " Home Assistant's "
                       "login. Barkley can't confirm what checks the caller.")  # fmt: skip
    if any(f.get("rule_id") == AUTH_INTERNALS for f in findings):
        pts += TOKEN_NON_ADMIN * lifetime_factor(None)
        reasons.append("It handles Home Assistant login tokens. A token handed to another "
                       "machine is only as safe as that machine. Barkley can't yet tell "
                       "whether one leaves Home Assistant, whose it is or how long it "
                       "lasts, so it counts one non-administrator token lasting over a "
                       "year.")  # fmt: skip
    bugs = [f for f in findings if f.get("rule_id") == DEP_VULN]
    bug_pts = sum(LIB_BUG.get(str(f.get("severity")), 0.0) for f in bugs)
    if bug_pts:
        pts += bug_pts
        reasons.append(_plural(len(bugs), "library has", "libraries have")
                       + " published security bugs.")  # fmt: skip
    factor = PUBLIC if public else NETWORK.get(where, 1.0)
    if pts and factor != 1.0:
        reasons.append("Raised because your Home Assistant is "
                       + ("reachable from the internet." if public
                          else "on a shared or work network."))  # fmt: skip
    exposure = round(min(EXPOSURE_MAX, pts * factor), 2)
    if t_level == "possible" and phrase:
        reasons.insert(0, f"A possible sign of malicious behavior: it {phrase}.")
    return Readings(threat, t_level, exposure, level(exposure), phrase, reasons, complete,
                    where)  # fmt: skip
