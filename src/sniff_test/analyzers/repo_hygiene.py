"""Repo security habits: does the maintainer run security scans, and do updates get merged?

Context only. Nothing here is a finding or changes a score: "the maintainer runs CodeQL"
must never offset something we found (decided with the user, 2026-11-10).

Two sources:
- Files in the downloaded source tree at the release (read as plain text, never run):
  workflows that run a security scanner, Dependabot or Renovate config, SECURITY.md.
- Two GitHub requests: open pull requests (to count Dependabot/Renovate ones and their
  age), and open issues (to count ones labeled or titled as security issues).

GitHub keeps Dependabot and code-scanning *alerts* private (repo admins only), so
whether findings get fixed is inferred from public signals, and labeled as inferred.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sniff_test.fetch.github import GitHub, GitHubError, RateLimitError
from sniff_test.models import Target

_MAX_FILE = 256 * 1024
_MAX_WORKFLOWS = 60

# Security scanners in workflows: (pattern on a `uses:` action or a `run:` command, name, kind)
SCANNERS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(p, re.I), name, kind)
    for p, name, kind in (
        (r"github/codeql-action", "CodeQL", "code"),
        (r"semgrep/semgrep|returntocorp/semgrep|\bsemgrep\s+(ci|scan)\b", "Semgrep", "code"),
        (r"\bbandit\b", "Bandit", "code"),
        (r"aquasecurity/trivy-action|\btrivy\s+(fs|repo|image)\b", "Trivy", "deps"),
        (r"anchore/scan-action|\bgrype\b", "Grype", "deps"),
        (r"google/osv-scanner|\bosv-scanner\b", "OSV-Scanner", "deps"),
        (r"pypa/gh-action-pip-audit|\bpip-audit\b", "pip-audit", "deps"),
        (r"actions/dependency-review-action", "Dependency review", "deps"),
        (r"snyk/actions|\bsnyk\s+test\b", "Snyk", "deps"),
        (r"\bsafety\s+(check|scan)\b", "Safety", "deps"),
        (r"gitleaks/gitleaks-action|\bgitleaks\b", "Gitleaks", "secrets"),
        (r"trufflesecurity/trufflehog|\btrufflehog\b", "TruffleHog", "secrets"),
        (r"ossf/scorecard-action", "OpenSSF Scorecard", "practices"),
    )
]
# (0.14.1, #21) Security hooks run through pre-commit (`id:` in .pre-commit-config.yaml)
PRE_COMMIT_HOOKS: dict[str, tuple[str, str]] = {
    "gitleaks": ("Gitleaks", "secrets"),
    "detect-private-key": ("detect-private-key", "secrets"),
    "detect-secrets": ("detect-secrets", "secrets"),
    "trufflehog": ("TruffleHog", "secrets"),
    "bandit": ("Bandit", "code"),
    "semgrep": ("Semgrep", "code"),
    "pip-audit": ("pip-audit", "deps"),
    "osv-scanner": ("OSV-Scanner", "deps"),
}
_PRE_COMMIT = (".pre-commit-config.yaml", ".pre-commit-config.yml")
# Linear on hostile files: no \\s (it would run across newlines from every line start).
_HOOK_ID = re.compile(r"^[ \t]*+(?:-[ \t]*+)?id[ \t]*+:[ \t]*+[\"']?([A-Za-z0-9_.-]{1,60})", re.M)
_RUFF_IDS = frozenset({"ruff", "ruff-check"})
_SELECT_OPEN = re.compile(r"select[ \t]*+=[ \t]*+$")
_S_RULE = re.compile(r"[\"']S\d{0,3}[\"']")
# a workflow runs pre-commit: `pre-commit run`, pre-commit/action, `tox -e precommit`
_RUNS_PRE_COMMIT = re.compile(r"pre-commit/action|\bpre-?commit\b", re.I)
_DEPENDABOT = (".github/dependabot.yml", ".github/dependabot.yaml")
_RENOVATE = (
    "renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json",
    ".github/renovate.json", ".github/renovate.json5", ".gitlab/renovate.json",
)  # fmt: skip
_SECURITY_MD = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
_ECOSYSTEM = re.compile(r"package-ecosystem\s*:\s*[\"']?([A-Za-z0-9_-]{1,40})")
_BOTS = {"dependabot[bot]": "Dependabot", "renovate[bot]": "Renovate"}
_SECURITY_TITLE = re.compile(
    r"\b(security|vulnerab\w*|CVE-\d{4}-\d{3,}|exploit\w*|XSS|RCE|injection)\b", re.I
)
_SECURITY_LABEL = re.compile(r"security|vulnerab|cve", re.I)
ISSUES_SHOWN = 5


@dataclass
class Hygiene:
    scanners: list[dict[str, str]] = field(default_factory=list)  # name, kind, workflow
    dependabot: list[str] | None = None  # ecosystems, when configured
    renovate: bool = False
    security_policy: str | None = None  # path of SECURITY.md
    update_prs: dict[str, Any] | None = None  # open, oldest_days, by bot; None: not checked
    security_issues: dict[str, Any] | None = None  # open, of, items
    errors: list[str] = field(default_factory=list)


def _read(root: Path, rel: str) -> str | None:
    p = root / rel
    try:
        if p.is_symlink() or not p.is_file() or p.stat().st_size > _MAX_FILE:
            return None
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def scan_files(root: Path) -> Hygiene:
    """What the repo's own files say. Text only: nothing is parsed as code or run."""
    h = Hygiene()
    wf = root / ".github" / "workflows"
    seen: set[str] = set()
    if wf.is_dir() and not wf.is_symlink():
        files = sorted(p for p in wf.iterdir() if p.suffix in (".yml", ".yaml"))
        for p in files[:_MAX_WORKFLOWS]:
            text = _read(root, f".github/workflows/{p.name}")
            if text is None:
                continue
            lines = "\n".join(  # comments don't count as running a scanner
                ln for ln in text.splitlines() if not ln.lstrip().startswith("#")
            )
            for pat, name, kind in SCANNERS:
                if name not in seen and pat.search(lines):
                    seen.add(name)
                    h.scanners.append({"name": name, "kind": kind, "workflow": p.name[:100]})
    ci_pre_commit = False
    if wf.is_dir() and not wf.is_symlink():
        for p in sorted(p for p in wf.iterdir() if p.suffix in (".yml", ".yaml"))[:_MAX_WORKFLOWS]:
            text = _read(root, f".github/workflows/{p.name}") or ""
            # what runs, not what a step is called or a comment
            commands = "\n".join(
                ln
                for ln in text.splitlines()
                if not ln.lstrip().startswith("#")
                and not ln.lstrip().lstrip("- ").startswith("name:")
            )
            if _RUNS_PRE_COMMIT.search(commands):
                ci_pre_commit = True
                break
    pc = next((t for rel in _PRE_COMMIT if (t := _read(root, rel)) is not None), None)
    if pc is not None:
        lines = "\n".join(ln for ln in pc.splitlines() if not ln.lstrip().startswith("#"))
        found = [PRE_COMMIT_HOOKS[i] for i in _HOOK_ID.findall(lines) if i in PRE_COMMIT_HOOKS]
        if _RUFF_IDS & set(_HOOK_ID.findall(lines)) and ruff_security_rules(
            _read(root, "pyproject.toml") or ""
        ):
            found.append(("Ruff security rules", "code"))
        for name, kind in found:
            if name not in seen:
                seen.add(name)
                h.scanners.append(
                    {
                        "name": name,
                        "kind": kind,
                        "workflow": ".pre-commit-config.yaml",
                        "via": "pre-commit",
                        "ci": ci_pre_commit,
                    }
                )
    for rel in _DEPENDABOT:
        if (text := _read(root, rel)) is not None:
            h.dependabot = sorted({m.lower() for m in _ECOSYSTEM.findall(text)})
            break
    h.renovate = any(_read(root, rel) is not None for rel in _RENOVATE)
    h.security_policy = next((rel for rel in _SECURITY_MD if _read(root, rel) is not None), None)
    return h


def ruff_security_rules(pyproject: str) -> bool:
    """Ruff's flake8-bandit rules ("S", "S102", …) in a `select`/`extend-select` list.
    One pass over the text: each list is the piece before a "]", and only the last 200
    characters before its "[" are looked at."""
    for piece in pyproject.split("]"):
        i = piece.rfind("[")
        if i < 0 or not _SELECT_OPEN.search(
            piece[max(0, i - 200) : i].rstrip("\n").split("\n")[-1]
        ):
            continue
        if _S_RULE.search(piece[i + 1 :]):
            return True
    return False


def _days(ts: str | None, now: datetime) -> int | None:
    try:
        return (now - datetime.fromisoformat(str(ts).replace("Z", "+00:00"))).days
    except ValueError:
        return None


def update_prs(pulls: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    by: dict[str, int] = {}
    ages = []
    for pr in pulls:
        bot = _BOTS.get(str((pr.get("user") or {}).get("login", "")))
        if bot:
            by[bot] = by.get(bot, 0) + 1
            if (d := _days(pr.get("created_at"), now)) is not None:
                ages.append(d)
    return {"open": sum(by.values()), "by": by, "oldest_days": max(ages) if ages else None,
            "of": len(pulls)}  # fmt: skip


def security_issues(issues: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    """Open issues labeled or titled as security ones. `issues` also lists pull requests
    (GitHub's issues endpoint does), which are skipped. Titles are untrusted text."""
    real = [i for i in issues if "pull_request" not in i]
    hits = []
    for i in real:
        labels = [str(lb.get("name", "")) for lb in i.get("labels") or [] if isinstance(lb, dict)]
        title = str(i.get("title") or "")
        if any(_SECURITY_LABEL.search(lb) for lb in labels) or _SECURITY_TITLE.search(title):
            hits.append(
                {
                    "number": i.get("number"),
                    "title": title[:200],
                    "age_days": _days(i.get("created_at"), now),
                }
            )
    return {"open": len(hits), "of": len(real), "items": hits[:ISSUES_SHOWN]}


def run(
    target: Target, gh: GitHub | None = None, now: datetime | None = None, offline: bool = False
) -> Hygiene | None:
    if not target.repo:
        return None
    h = scan_files(target.source_root) if target.source_root else Hygiene()
    if offline:
        h.errors.append("offline: open pull requests and issues not checked")
        return h
    gh = gh or GitHub.from_env()
    now = now or datetime.now(UTC)
    meta = target.repo_meta
    full = str(meta.get("full_name") or target.repo)
    # A repo can turn pull requests or issues off; GitHub then answers 404 (pulls) or [].
    if meta.get("has_pull_requests") is False:
        h.update_prs = {"off": True}
    if meta.get("has_issues") is False:
        h.security_issues = {"off": True}
    try:
        if h.update_prs is None:
            pulls = gh.get_json(f"/repos/{full}/pulls?state=open&per_page=100")
            h.update_prs = update_prs(pulls if isinstance(pulls, list) else [], now)
        if h.security_issues is None:
            issues = gh.get_json(f"/repos/{full}/issues?state=open&per_page=100")
            h.security_issues = security_issues(issues if isinstance(issues, list) else [], now)
    except RateLimitError:
        raise  # the job waits for the reset and runs again; never stored as a result
    except GitHubError as ex:
        h.errors.append(f"GitHub didn't answer ({ex})"[:300])
    return h


def to_dict(h: Hygiene | None, findings_rules: set[str], kind: str) -> dict[str, Any] | None:
    """For the report. Adds the cross-check: Dependabot is set up for this kind of app's
    dependencies, yet this release has dependencies with known vulnerabilities."""
    if h is None:
        return None
    eco = "pip" if kind == "integration" else "npm"
    unacted = bool(h.dependabot and eco in h.dependabot and "dep-vuln" in findings_rules)
    return {
        "inferred": True,
        "scored": False,
        "scanners": h.scanners,
        "dependabot": h.dependabot,
        "renovate": h.renovate,
        "security_policy": h.security_policy,
        "update_prs": h.update_prs,
        "security_issues": h.security_issues,
        "dependabot_but_known_vulns": unacted,
        "errors": h.errors,
    }
