"""Core data model. Everything downstream of the analyzers speaks in Findings."""

from __future__ import annotations

import datetime
import hashlib
import re
from dataclasses import dataclass, field, replace
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        return cls[value.strip().upper()]

    def bumped(self) -> Severity:
        return Severity(min(self + 1, Severity.CRITICAL))

    def __str__(self) -> str:
        return self.name.lower()


class Category(StrEnum):
    EXFIL = "exfil"  # sensitive data -> outbound channel
    SENSITIVE_ACCESS = "sensitive_access"  # reads secrets/tokens/other domains' data
    CODE_EXEC = "code_exec"  # eval/exec, runtime installs, obfuscation
    TAMPER = "tamper"  # monkeypatching core, writes outside own dir
    INBOUND = "inbound"  # unauthenticated views, remote webhooks
    ENDPOINT = "endpoint"  # undeclared / suspicious hosts
    DEPENDENCY = "dependency"  # SCA findings
    REPO = "repo"  # repo-level trust signals


class Tag(StrEnum):
    EXFIL = "exfil"  # never downgraded, regardless of exposure
    INBOUND = "inbound"  # weighted up under --exposure public
    POSSIBLE = "possible"  # heuristic correlation, not a proven path
    MALWARE = "malware"  # known-malicious package / payload pattern
    # (0.14.0) in a test file no runtime module imports: HA never loads it. The finding
    # stays in the stored report and the capability score. (0.15, his decision 2026-11-21)
    # It doesn't count toward Threat or Exposure and isn't listed under "What it can do":
    # the panel lists it apart, as a test script Home Assistant never loads. Not set when
    # a computed import could load the file (scanner.loadable_tests).
    TEST_CODE = "test-code"


# A shipped code file no Semgrep rule could read at all. Scoring caps the score while one
# is present (scoring.CAP_UNCHECKED): the scan is complete, but it can't be a Good Boy.
RULE_FILE_NOT_CHECKED = "scan-file-not-checked"


class AnalyzerState(StrEnum):
    OK = "ok"
    SKIPPED = "skipped"  # tool missing or not applicable-but-should-have-run
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"  # e.g. npm analyzer on a pure-Python integration


@dataclass(frozen=True, slots=True)
class Advisory:
    """One known vulnerability of a dependency, from the OSV record (third-party text)."""

    id: str
    summary: str = ""
    details: str = ""
    fixed: str | None = None  # first fixed version above ours; "" = OSV lists none; None = unknown
    aliases: tuple[str, ...] = ()  # e.g. the CVE id of a GHSA advisory
    # (0.14.1) CISA's SSVC decision points from the CVE record (osv.ssvc), "" when unknown:
    # exploitation none | poc | active; automatable yes | no; impact partial | total;
    # kev: the CVE is in CISA's Known Exploited Vulnerabilities catalog
    exploitation: str = ""
    automatable: str = ""
    impact: str = ""
    kev: bool = False

    @property
    def worst_case(self) -> bool:
        """Exploited in the wild (SSVC active, or listed in KEV: SSVC's exploitation
        field lags), automatable, total technical impact."""
        exploited = self.exploitation == "active" or self.kev
        return exploited and self.automatable == "yes" and self.impact == "total"


@dataclass(frozen=True, slots=True)
class DepFacts:
    """Checked facts about a vulnerable dependency (0.7.4): no AI involved."""

    package: str
    ecosystem: str  # "PyPI" | "npm"
    version: str
    advisories: tuple[Advisory, ...] = ()
    direct: bool | None = None  # listed by the app itself (manifest / package.json)
    latest: str | None = None  # newest final release on the registry
    latest_date: str | None = None  # YYYY-MM-DD
    behind: int | None = None  # final releases newer than ours, up to latest
    lookup_error: str = ""  # why latest/behind are missing

    @property
    def fixed_in(self) -> str | None:
        """The version that fixes every advisory; "" if one has no fix; None if unknown."""
        fixes = [a.fixed for a in self.advisories]
        if not fixes or any(f is None for f in fixes):
            return None
        if any(f == "" for f in fixes):
            return ""
        return max(fixes, key=lambda v: version_key(self.ecosystem, v or ""))


def fix_phrase(ecosystem: str, fixes: list[tuple[str, str | None]]) -> str:
    """'fixed in 4.3.2', 'fixed in 3.4.0 for 2 of 3; no fix listed for X', 'no fixed version
    yet' or "the advisory doesn't say which version fixes it", from (advisory id, fixed)."""
    fixed = [(i, f) for i, f in fixes if f]
    none = [i for i, f in fixes if f == ""]
    if fixed:
        top = max((f for _i, f in fixed), key=lambda v: version_key(ecosystem, v))
        if len(fixed) == len(fixes):
            return f"fixed in {top}"
        out = f"fixed in {top} for {len(fixed)} of {len(fixes)}"
        return out + (f"; no fix listed for {', '.join(none[:3])}" if none else "")
    if none:
        return "no fixed version yet"
    return "the advisory doesn't say which version fixes it"


STALE_YEARS = 2  # no release for this long: likely unmaintained


def years_since(date: str | None, today: datetime.date | None = None) -> int | None:
    """Whole years since an ISO date (YYYY-MM-DD…), or None if unreadable."""
    try:
        then = datetime.date.fromisoformat(str(date)[:10])
    except ValueError:
        return None
    today = today or datetime.datetime.now(datetime.UTC).date()
    years = today.year - then.year - ((today.month, today.day) < (then.month, then.day))
    return max(0, years)


def version_key(ecosystem: str, version: str) -> tuple:
    """Sortable key for PyPI or npm versions; pre-releases sort before their release."""
    v = version.strip().lstrip("vV").split("+", 1)[0]
    m = re.match(r"(?:\d+!)?(\d+(?:\.\d+)*)(.*)", v)
    if not m:
        return ((), False)
    nums = [int(x) for x in m[1].split(".")[:6]]
    while nums and nums[-1] == 0:
        nums.pop()
    rest = m[2].lower()
    pre = (
        rest.startswith("-")
        if ecosystem == "npm"
        else bool(re.match(r"[.-]?(a|b|c|rc|alpha|beta|pre|preview|dev)", rest))
    )
    return (tuple(nums), not pre)


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    message: str
    file: str | None = None  # path relative to the scanned root
    line: int | None = None
    evidence: str | None = None  # untrusted: comes from the scanned code
    tags: frozenset[Tag] = frozenset()
    analyzer: str = ""
    base_severity: Severity | None = None  # set when exposure weighting changed severity
    # Rule ids this finding replaces when both hit the same line (a more specific,
    # better-explained match wins, even if it is less severe).
    supersedes: frozenset[str] = frozenset()
    # Install platforms a dependency finding applies to (e.g. {"x86_64", "aarch64"});
    # empty when the finding isn't platform-specific.
    platforms: frozenset[str] = frozenset()
    dependency: DepFacts | None = None  # dep-vuln only: fix, newest release, advisories
    # Host reputation (0.9.0): set only on findings that are purely about where an address
    # points (a hardcoded public IP, GuardDog's address heuristics), and only when every
    # address behind the finding could be read with certainty. The panel lets the user
    # mark these addresses trusted; a finding without them can never be switched off.
    addresses: tuple[str, ...] = ()
    # (0.14.0) report/fingerprint.py: stays the same while the flagged code does
    fingerprint: str | None = None
    # (0.15) ha-unauth-view: the address the page answers on, as the code writes it ("" when
    # it's built while the app runs; None when not looked up). Untrusted text (py_pages.py)
    page: str | None = None
    # (0.15) ha-unauth-view: the first lines of the view class's docstring, the developer's
    # own description of the page. Untrusted text; shown as theirs, never beside a threat.
    page_note: str | None = None

    @property
    def id(self) -> str:
        """Stable id: same rule + location + evidence -> same id across runs."""
        h = hashlib.sha256()
        for part in (self.rule_id, self.file or "", str(self.line or ""), self.evidence or ""):
            h.update(part.encode("utf-8", "replace"))
            h.update(b"\0")
        return h.hexdigest()[:16]

    def with_severity(self, severity: Severity) -> Finding:
        if severity == self.severity:
            return self
        return replace(self, severity=severity, base_severity=self.base_severity or self.severity)


class Evidence(IntEnum):
    """How sure we are that an inventory edge is real. Ordered: higher wins on merge."""

    DECLARED = 1  # stated by the item itself (manifest, package.json, release metadata)
    POSSIBLE = 2  # the capability is present in the code
    PROVEN = 3  # a taint path or an API response shows it
    OBSERVED = 4  # seen at runtime (future: egress logging)

    def __str__(self) -> str:
        return self.name.lower()


class Ring(StrEnum):
    """Rings of the hooks graph around the scanned item."""

    HA = "ha"  # HA internals: services, views, webhooks, events, registries
    DATA = "data"  # the user's data: secrets, auth, locations, env, other entries
    NETWORK = "network"  # hosts and IPs
    PACKAGES = "packages"  # resolved dependencies
    REPO = "repo"  # provenance: publishers, former names


@dataclass(frozen=True, slots=True)
class Fact:
    """A neutral observation for the inventory / hooks graph. Never scored.

    `kind` + `key` name the node (e.g. host / api.vendor.com); `relation` is the edge
    from the scanned item to it. `key` and `attrs` values can come from the scanned
    code and are untrusted.
    """

    ring: Ring
    kind: str
    key: str
    relation: str
    evidence: Evidence
    file: str | None = None
    line: int | None = None
    attrs: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)
    analyzer: str = ""


@dataclass(slots=True)
class AnalyzerResult:
    name: str
    state: AnalyzerState
    findings: list[Finding] = field(default_factory=list)
    detail: str = ""
    tool_version: str | None = None
    facts: list[Fact] = field(default_factory=list)
    # (0.14.0) files that couldn't be fetched: fetch.retry.Failure.as_dict() each, shown
    # in plain English (retry.plain) instead of a bare "incomplete"
    problems: list[dict[str, Any]] = field(default_factory=list)


class TargetKind(StrEnum):
    INTEGRATION = "integration"
    PLUGIN = "plugin"  # HACS's name for frontend cards


@dataclass(slots=True)
class Target:
    """What we scanned: the exact bytes HACS would install, plus provenance."""

    source: str  # original CLI input
    kind: TargetKind
    root: Path  # extracted installable content (e.g. custom_components/<domain>/)
    source_root: Path | None = None  # full repo tree at the ref (for lockfiles, repo checks)
    repo: str | None = None  # owner/name
    ref: str | None = None
    commit_sha: str | None = None
    install_source: str = "local"  # release_asset | tag_source | default_branch | local
    artifact_sha256: str | None = None
    domain: str | None = None
    notes: list[Finding] = field(default_factory=list)  # findings produced while fetching
    requested_repo: str | None = None  # owner/name as given (may redirect to `repo`)
    repo_meta: dict[str, Any] = field(default_factory=dict)  # GitHub repo API response
    # root-relative path -> sha256 of the bytes as installed, for files our analyzers
    # rewrote in place (semgrep.normalize_js). Byte comparisons must use these.
    pristine_sha256: dict[str, str] = field(default_factory=dict)
    # (0.14.0) requirements the code installs itself from a fixed list (a literal
    # `async_process_requirements(hass, DOMAIN, ["x==1"])`): resolved and checked with
    # the manifest's (analyzers/py_precision.pip_listed)
    runtime_requirements: list[str] = field(default_factory=list)
    # (0.14.0) facts for the app's page, never scored: the repo's stars, and the download
    # count of the release file HACS installs (None: installed from the source)
    stars: int | None = None
    downloads: int | None = None
    # (0.15) GitHub's verdict on the scanned commit's signature (fetch/github.signature_state):
    # {"state": github | developer | unsigned | unverified, "reason"?}; None for local scans
    signature: dict[str, str] | None = None
