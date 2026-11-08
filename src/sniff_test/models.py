"""Core data model. Everything downstream of the analyzers speaks in Findings."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from enum import IntEnum, StrEnum
from pathlib import Path


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


class AnalyzerState(StrEnum):
    OK = "ok"
    SKIPPED = "skipped"  # tool missing or not applicable-but-should-have-run
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"  # e.g. npm analyzer on a pure-Python integration


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


@dataclass(slots=True)
class AnalyzerResult:
    name: str
    state: AnalyzerState
    findings: list[Finding] = field(default_factory=list)
    detail: str = ""
    tool_version: str | None = None


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
