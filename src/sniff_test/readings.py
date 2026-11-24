"""(preview, 2026-11-19) The proposed Threat and Exposure readings, shown in place of
Barkley's score when the user turns on Settings → "Proposed readings (preview)", and in
update notifications while it's on (2026-11-20). Nothing here is stored: the readings are
worked out from a stored scan's findings each time a page or notification needs them, so
no re-sniff is needed. Barkley's own score is untouched and stays in the technical report.

Decided with the user 2026-11-19 (vault: Roadmap "Scoring rethink", rounds 1-3 of the
mock-ups and his yes to items 1-4 of round 4):

- **Threat, 0-10** (shown as none / possible / found): signs of malicious behavior only
  (kinds.THREAT_RULES and a lookalike
  package name). Critical 6, high 2.5, medium 0.8, low 0.2; each repeat of a rule a
  quarter; capped at 10; any critical sign is at least 7. 0 none found, under 7 possible,
  7 and up found.
- **Exposure, 0-10**: only what lets someone other than an administrator in, measured for
  Home Assistant (an administrator can already do everything, so admin-only adds 0):
  a page that skips Home Assistant's login (0.25 when the same file checks a signed link or
  token, else 0.75: a check of its own Barkley can't confirm; the strongest page counts in
  full, each further page a quarter); a login token the app may
  hand out (non-admin 1, administrator 3, times a lifetime factor); a library bug (medium
  1, high 3, critical 5). Times 1.25 on a shared or work network, 1.5 when Home Assistant
  is reachable from the internet. (0.15) Plus code a card loads from another site while it
  runs (5 when the version is decided then, 2 for a fixed one; not raised by the network),
  and Lua an integration downloads and runs where it can reach Python (5).
  Under 2 low, under 5 medium, 5 and up high. A found threat is exposure 10: the app
  itself sends your data out.

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
# (0.15, his decision 2026-11-21) Code a card loads from another site while it runs:
# 5 when which version it gets is only decided then, 2 for one fixed version. The
# strongest counts in full, each further one a quarter. Not raised by the network setting:
# who can reach Home Assistant doesn't change who publishes that code.
REMOTE_CODE = {"card-remote-script": 5.0, "card-remote-pinned": 2.0,
               # (0.15, his decision 2026-11-23) an integration that downloads Lua and runs
               # it where it can reach Python: the same principle, on the server ("I might
               # even argue this is worse")
               "py-lua-download": 5.0}  # fmt: skip
# (0.15, his decision 2026-11-21) Code taken from the page address: anyone who gets you to
# open a link decides what runs. Counted with the remote code (same principle: someone
# else picks the code), so the strongest of them counts in full, each further a quarter.
LINK_CODE = {"card-eval-address": 5.0}
NETWORK = {"home": 1.0, "shared": 1.25}
PUBLIC = 1.5
EXPOSURE_MAX = 10.0
# the possible-threat sentence that leads the reasons; the Exposure box and the picture
# leave it out (it is about Threat)
POSSIBLE_REASON = "This may be a sign of malicious behavior."
LOW, MEDIUM = 2.0, 5.0

# (0.15, his decision 2026-11-22) A build tool known to be malware: Threat 2.5 by default
# ("possible"), 2 or 3 in Settings (settings.build_tool_points)
BUILD_RULE = "dep-malicious-build"
BUILD_TOOL = 2.5

UNAUTH_VIEW = "ha-unauth-view"
TOKEN_CHECK = "ha-auth-token-check"  # noqa: S105 - a rule id
AUTH_INTERNALS = "ha-auth-internals"
DEP_VULN = "dep-vuln"
TEST_CODE = "test-code"  # models.Tag.TEST_CODE (the readings read stored JSON)


def in_test_script(f: dict[str, Any]) -> bool:
    """(0.15, his decision 2026-11-21) A finding in a test script no part of the app that
    Home Assistant loads imports (scanner.loadable_tests): it never runs in your home, so
    it doesn't count toward either reading."""
    return TEST_CODE in (f.get("tags") or ())


# Fixed phrases for the banner and the reason line, by rule (no text from the scanned app)
_THREAT_PHRASE = {
    "ha-exfil-taint": "sends your Home Assistant data out of your home",
    "card-token-exfil": "may send your login token to another site",
    "possible-exfil": (
        "may send other apps' passwords or your secrets to sites that aren't the app's own"
    ),
    "endpoint-exfil-host": "sends data to a site used for collecting data",
    "dep-malicious": "includes a package known to be malware",
    "dep-malicious-build": "is built with a tool known to be malware",
    "py-b64-exec": "decodes hidden code and runs it",
    "card-b64-eval": "decodes hidden code and runs it",
    "card-eval-remote": "runs code it downloads or receives",
    "py-obfuscation": "hides what its code does",
    "card-hidden-name": "hides the names its code uses",
    "py-bytecode-runs-instead-of-source": (
        "runs compiled code instead of the readable code it ships with"
    ),
    "py-native-module-shadows-source": "runs a compiled file in place of its readable code",
    "py-native-module-without-source": "ships a compiled file with no readable version",
    "card-html-comment-token": "hides code from scanners with an HTML comment marker (<!--)",
    "dep-typosquat": "uses a library whose name is one typo away from a popular one",
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
    threat_reason: str = ""  # a fixed phrase ("may send your login token to another site")
    exposure_reasons: list[str] = field(default_factory=list)
    complete: bool = True
    network: str = "home"  # home | shared | internet

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _is_threat(rule_id: str) -> bool:
    return kinds.is_threat(rule_id) or rule_id in EXTRA_THREAT_RULES


def _threat(findings: list[dict[str, Any]], build_tool: float = BUILD_TOOL) -> tuple[float, str]:
    by_rule: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        if _is_threat(str(f.get("rule_id"))):
            by_rule[str(f["rule_id"])].append(str(f.get("severity") or "info"))
    total = 0.0
    critical = False
    for rule, sevs in by_rule.items():
        if rule == BUILD_RULE:  # the user's setting, whatever the stored severity
            pts = [build_tool] * len(sevs)
            total += pts[0] + REPEAT * sum(pts[1:])
            continue
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


def counts_in_exposure(f: dict[str, Any]) -> bool:
    """Whether a finding adds to the Exposure reading in compute() (the panel marks it)."""
    rule = str(f.get("rule_id"))
    if in_test_script(f):
        return False
    if rule == DEP_VULN:
        return str(f.get("severity")) in LIB_BUG
    return rule in (UNAUTH_VIEW, AUTH_INTERNALS) or rule in REMOTE_CODE or rule in LINK_CODE


def compute(
    report: dict[str, Any], network: str = "home", build_tool: float = BUILD_TOOL
) -> Readings:
    """`report`: a stored scan (or the panel's view of one). `network`: the preview's
    setting (home | shared); a scan made with exposure "public" counts as on the internet.
    `build_tool`: Threat points for a build tool known to be malware (Settings)."""
    findings = [f for f in report.get("findings") or [] if not in_test_script(f)]
    complete = bool(report.get("complete", True))
    public = str(report.get("exposure") or "local") == "public"
    where = "internet" if public else (network if network in NETWORK else "home")
    threat, phrase = _threat(findings, build_tool)
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
    # Pages: the strongest counts in full, each further page a quarter, as Threat repeats
    # (his decision 2026-11-20: an OAuth integration's 12 login-free pages summed to 9).
    page_pts = sorted([PAGE_OWN_CHECK] * len(own) + [PAGE_RECOGNISED] * len(recognised),
                      reverse=True)  # fmt: skip
    if page_pts:
        pts += page_pts[0] + REPEAT * sum(page_pts[1:])
    if recognised:
        n = len(recognised)
        reasons.append(_plural(n, "page opens", "pages open") + " without logging in to Home "
                       "Assistant. " + ("It checks" if n == 1 else "They check")
                       + " a signed link or token instead.")  # fmt: skip
    if own:
        reasons.append(_plural(len(own), "page opens", "pages open") + " without logging "
                       "in to Home Assistant. Barkley can't see whether anything checks "
                       "who's asking.")  # fmt: skip
    if any(f.get("rule_id") == AUTH_INTERNALS for f in findings):
        pts += TOKEN_NON_ADMIN * lifetime_factor(None)
        reasons.append("It works with Home Assistant login tokens. A token handed to another "
                       "machine is only as safe as that machine. Barkley can't tell yet who "
                       "gets a token or how long it lasts. So it counts one token for a user "
                       "who isn't an administrator, lasting over a year.")  # fmt: skip
    bugs = [f for f in findings if f.get("rule_id") == DEP_VULN]
    bug_pts = sum(LIB_BUG.get(str(f.get("severity")), 0.0) for f in bugs)
    if bug_pts:
        pts += bug_pts
        reasons.append(_plural(len(bugs), "library it uses has", "libraries it uses have")
                       + " published vulnerabilities.")  # fmt: skip
    others = REMOTE_CODE | LINK_CODE
    remote = sorted((others[str(f.get("rule_id"))] for f in findings
                     if str(f.get("rule_id")) in others), reverse=True)  # fmt: skip
    links = sum(1 for f in findings if str(f.get("rule_id")) in LINK_CODE)
    remote_pts = remote[0] + REPEAT * sum(remote[1:]) if remote else 0.0
    loose = sum(1 for f in findings if str(f.get("rule_id")) == "card-remote-script")
    fixed = sum(1 for f in findings if str(f.get("rule_id")) == "card-remote-pinned")
    lua = sum(1 for f in findings if str(f.get("rule_id")) == "py-lua-download")
    if links:
        reasons.append("A link can make it run code: it runs code taken from the page "
                       "address. Anyone who gets you to open a link to your dashboard can "
                       "run code there, with your login.")  # fmt: skip
    if loose:
        reasons.append(("It loads code from another site while it runs" if loose == 1 else
                        f"It loads code from {loose} other sites or packages while it runs")
                       + ". Which version it gets is only decided then, so whoever publishes "
                       "that code decides what runs in your dashboard, with your login. "
                       "Barkley never read it.")  # fmt: skip
    if lua:
        reasons.append("It downloads Lua code while it runs and runs it where that code can "
                       "reach Python. Whoever controls where that code comes from decides "
                       "what runs in Home Assistant. Barkley never read it.")  # fmt: skip
    if fixed:
        reasons.append(("It loads one fixed version of code from another site" if fixed == 1
                        else f"It loads fixed versions of code from {fixed} other sites or "
                        "packages") + " while it runs. Barkley never read that code.")  # fmt: skip
    factor = PUBLIC if public else NETWORK.get(where, 1.0)
    if pts and factor != 1.0:
        reasons.append("Barkley counts this higher because Home Assistant is "
                       + ("reachable from the internet." if public
                          else "on a shared or work network."))  # fmt: skip
    exposure = round(min(EXPOSURE_MAX, pts * factor + remote_pts), 2)
    if t_level == "possible" and phrase:
        reasons.insert(0, f"{POSSIBLE_REASON} It {phrase}.")
    return Readings(threat, t_level, exposure, level(exposure), phrase, reasons, complete,
                    where)  # fmt: skip
