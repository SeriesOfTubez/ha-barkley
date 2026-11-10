"""Repo-level trust signals: who publishes this, did it change hands, and does the
release you install match the source people can read?

Facts checked against the real GitHub API (2026-11-08):
- A transferred repo answers `GET /repos/{old}/{name}` with `301 → /repositories/{id}`
  and then the repo under its new `full_name`. There is no timestamp and no public
  transfer history (REST or GraphQL), so a transfer can be proven but not dated.
- Under its new name the repo looks untouched. Old links in the repo's own files
  (alexa_media_player's CHANGELOG links custom-components/alexa_media_player 1,392
  times) still prove it: those URLs resolve to the same repository id.
- Release objects carry `author` (who published it; `type: "Bot"` for workflows) and
  per-asset `uploader`. These are the maintainer signal.

Severity of `repo-transferred` follows maintainer continuity (decided with the user,
2026-11-08): low when the installed release's publisher was already publishing here
180+ days earlier; high when the publisher is new; medium when only bots publish.
"""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sniff_test.fetch.github import GitHub, GitHubError, NotFoundError, RateLimitError
from sniff_test.models import (
    AnalyzerResult,
    AnalyzerState,
    Category,
    Evidence,
    Fact,
    Finding,
    Ring,
    Severity,
    Target,
    TargetKind,
)

NAME = "repo-signals"
CONTINUITY_DAYS = 180
YOUNG_DAYS = 90
MIN_OTHER_RELEASES = 2  # a new publisher only matters if someone else published before
_MAX_FORMER_LOOKUPS = 3
_TIMELINE_MAX = 100
_TEXT_SUFFIXES = {".md", ".rst", ".txt", ".json", ".py", ".yaml", ".yml", ".toml", ".js", ""}
_TEXT_MAX = 2 * 1024 * 1024
_GH_URL = re.compile(r"(?i)github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9_.-]{1,100})")
_VERSIONISH = re.compile(r"""(["'])v?\d+(?:\.\d+){1,3}(?:[-+.][0-9A-Za-z.]+)?\1""")


@dataclass
class Release:
    tag: str
    published_at: str | None
    publisher: str | None
    bot: bool
    prerelease: bool
    asset_uploaders: list[str] = field(default_factory=list)

    @property
    def when(self) -> datetime | None:
        return _parse_time(self.published_at)


@dataclass
class Provenance:
    """Repo identity and history, for the report and a future release-timeline view."""

    repo_id: int | None
    full_name: str
    requested_as: str | None
    created_at: str | None
    owner_type: str | None
    former_names: list[dict[str, Any]] = field(default_factory=list)
    releases: list[Release] = field(default_factory=list)  # newest first
    installed_tag: str | None = None
    publishers: list[dict[str, Any]] = field(default_factory=list)


def _parse_time(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_bot(user: dict[str, Any] | None) -> bool:
    if not user:
        return False
    return user.get("type") == "Bot" or str(user.get("login", "")).endswith("[bot]")


def to_release(raw: dict[str, Any]) -> Release:
    author = raw.get("author") or {}
    return Release(
        tag=str(raw.get("tag_name", "")),
        published_at=raw.get("published_at") or raw.get("created_at"),
        publisher=author.get("login"),
        bot=_is_bot(author),
        prerelease=bool(raw.get("prerelease")),
        asset_uploaders=sorted(
            {
                str((a.get("uploader") or {}).get("login"))
                for a in raw.get("assets", [])
                if (a.get("uploader") or {}).get("login")
            }
        ),
    )


def _finding(rule: str, title: str, sev: Severity, msg: str, evidence: str = "") -> Finding:
    return Finding(
        rule_id=rule,
        title=title,
        severity=sev,
        category=Category.REPO,
        message=msg,
        evidence=evidence or None,
        analyzer=NAME,
    )


# --- transfers -------------------------------------------------------------------------


def former_owner_candidates(source_root: Path | None, owner: str, name: str) -> list[str]:
    """`github.com/<other>/<same name>` links in the repo's own files, most cited first."""
    if source_root is None:
        return []
    counts: Counter[str] = Counter()
    for p in source_root.rglob("*"):
        if p.suffix.lower() not in _TEXT_SUFFIXES or not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > _TEXT_MAX:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _GH_URL.finditer(text):
            o, n = m[1], m[2].removesuffix(".git")
            if n.lower() == name.lower() and o.lower() != owner.lower():
                counts[f"{o}/{n}"] += 1
    return [k for k, _ in counts.most_common(_MAX_FORMER_LOOKUPS)]


def find_former_names(target: Target, gh: GitHub) -> list[dict[str, Any]]:
    meta = target.repo_meta
    full = str(meta.get("full_name") or target.repo or "")
    if "/" not in full:
        return []
    owner, name = full.split("/", 1)
    out: list[dict[str, Any]] = []
    req = target.requested_repo
    if req and req.lower() != full.lower():
        out.append({"name": req, "how": "redirect"})  # GitHub redirected the request
    seen = {req.lower()} if req else set()
    for cand in former_owner_candidates(target.source_root, owner, name):
        if cand.lower() in seen:
            continue
        try:
            other = gh.get_json(f"/repos/{cand}")
        except NotFoundError:
            continue
        except RateLimitError:
            raise  # never a partial result: the caller waits and scans again
        except GitHubError:
            break
        if isinstance(other, dict) and other.get("id") == meta.get("id"):
            out.append({"name": cand, "how": "same_repo_id"})  # an old URL still points here
            seen.add(cand.lower())
    return out


def _transferred(former: list[dict[str, Any]], full_name: str) -> list[dict[str, Any]]:
    owner = full_name.split("/", 1)[0].lower()
    return [f for f in former if f["name"].split("/", 1)[0].lower() != owner]


# --- publishers ------------------------------------------------------------------------


def publisher_summary(releases: list[Release], installed: str | None) -> list[dict[str, Any]]:
    by: dict[str, list[Release]] = {}
    for r in releases:
        if r.publisher:
            by.setdefault(r.publisher, []).append(r)
    out = []
    for login, rs in by.items():
        times = sorted(t for r in rs if (t := r.when))
        out.append(
            {
                "login": login,
                "bot": rs[0].bot,
                "releases": len(rs),
                "first": times[0].isoformat() if times else None,
                "last": times[-1].isoformat() if times else None,
                "published_installed": any(r.tag == installed for r in rs),
            }
        )
    return sorted(out, key=lambda p: (-p["releases"], p["login"]))


@dataclass
class Continuity:
    publisher: str | None
    bot: bool
    prior_own: int  # earlier releases by the same publisher
    prior_others: int  # earlier releases by other human publishers
    since_days: int | None  # days between their first release and the installed one


def continuity(releases: list[Release], installed: Release | None) -> Continuity | None:
    if installed is None:
        return None
    when = installed.when
    earlier = [r for r in releases if r is not installed and r.when and when and r.when < when]
    own = [r for r in earlier if r.publisher == installed.publisher]
    others = [r for r in earlier if r.publisher != installed.publisher and not r.bot]
    since = None
    if own and when:
        since = (when - min(r.when for r in own if r.when)).days
    return Continuity(installed.publisher, installed.bot, len(own), len(others), since)


def transfer_severity(c: Continuity | None) -> tuple[Severity, str]:
    if c is None:
        return Severity.MEDIUM, "There is no release to tell whether the publisher changed."
    if c.bot or not c.publisher:
        return (
            Severity.MEDIUM,
            "Releases are published by a bot, so GitHub doesn't show whether the people "
            "behind them changed.",
        )
    if c.prior_own == 0:
        return (
            Severity.HIGH,
            f"The release you'd install is the first one published by {c.publisher}. A "
            "transfer plus a new publisher is how sold or hijacked repos look.",
        )
    if c.since_days is not None and c.since_days >= CONTINUITY_DAYS:
        return (
            Severity.LOW,
            f"{c.publisher} has been publishing releases here for {c.since_days} days "
            f"({c.prior_own} earlier releases), so the maintainer looks continuous.",
        )
    return (
        Severity.MEDIUM,
        f"{c.publisher} has published here for only {c.since_days} days "
        f"({c.prior_own} earlier releases).",
    )


# --- release asset vs tag source -------------------------------------------------------


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _normalized(p: Path) -> str:
    """Text with version strings blanked: release workflows stamp versions in."""
    return _VERSIONISH.sub('"<v>"', p.read_text(encoding="utf-8", errors="replace"))


def _manifest_sans_version(p: Path) -> Any:
    import json

    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if isinstance(data, dict):
        data.pop("version", None)
    return data


def _files(root: Path) -> dict[str, Path]:
    return {
        p.relative_to(root).as_posix(): p
        for p in root.rglob("*")
        if p.is_file() and not p.is_symlink() and p.name != ".semgrepignore"
    }


def _integration_tree(target: Target) -> Path | None:
    src = target.source_root
    if src is None:
        return None
    if (src / "manifest.json").is_file() and not (src / "custom_components").is_dir():
        return src  # content_in_root
    if target.domain and (src / "custom_components" / target.domain).is_dir():
        return src / "custom_components" / target.domain
    return None


def compare_integration_asset(asset: Path, tree: Path) -> list[Finding]:
    a, b = _files(asset), _files(tree)
    changed = []
    for rel in sorted(set(a) & set(b)):
        if rel.endswith(".py") and _sha(a[rel]) != _sha(b[rel]):
            if _normalized(a[rel]) != _normalized(b[rel]):
                changed.append(rel)
        elif rel == "manifest.json" and _manifest_sans_version(a[rel]) != _manifest_sans_version(
            b[rel]
        ):
            changed.append(rel)
    code = (".py", ".pyc", ".pyo", ".so", ".pyd")
    extra = sorted(rel for rel in set(a) - set(b) if rel.endswith(code))
    out = []
    if changed:
        out.append(
            _finding(
                "repo-release-source-mismatch",
                "Release zip differs from the tagged source",
                Severity.HIGH,
                f"{len(changed)} file(s) in the release zip HACS installs differ from the "
                "same files at the release tag (beyond version stamping). The code people "
                "can review on GitHub is not the code you get. Scanned: the release zip.",
                ", ".join(changed[:10]),
            )
        )
    if extra:
        out.append(
            _finding(
                "repo-release-extra-code",
                "Release zip contains code that isn't in the repository",
                Severity.LOW,
                f"{len(extra)} Python/compiled file(s) exist only in the release zip, e.g. "
                "generated or vendored packages. They were scanned, but nobody can review "
                "them on GitHub. Compiled files (.pyc/.so) can't be checked by our rules.",
                ", ".join(extra[:10]),
            )
        )
    return out


def compare_card_asset(
    asset: Path, source_root: Path, pristine: dict[str, str] | None = None
) -> list[Finding]:
    """Release bundle vs the committed copy, on the bytes as installed.

    `pristine` holds the original sha256 of asset files we rewrote in place before this
    runs (Target.pristine_sha256, from semgrep.normalize_js).
    """
    pristine = pristine or {}
    out = []
    for rel, p in _files(asset).items():
        for loc in (source_root / "dist" / rel, source_root / rel):
            if loc.is_file():
                if _sha(loc) != pristine.get(rel, _sha(p)):
                    out.append(
                        _finding(
                            "repo-release-source-mismatch",
                            "Release bundle differs from the committed bundle",
                            Severity.MEDIUM,
                            f"The released {rel} differs from the copy committed at the "
                            "release tag, so reviewing the repository doesn't review what "
                            "you install. Scanned: the release asset.",
                            rel,
                        )
                    )
                break
    return out


# --- tag vs default branch -------------------------------------------------------------


def tag_off_default_branch(target: Target, gh: GitHub, owner: str, name: str) -> Finding | None:
    """The installed tag's commit isn't in the default branch's history.

    GitHub's compare (default...commit) says `ahead`/`diverged` when the commit has
    changes the default branch doesn't contain: code that reached users by tag without
    landing where the repo's history and reviews are. Maintenance branches (a 1.x patch
    release) do this legitimately, hence medium. 0 of 25 real installed tags (2026-11-09).
    Default-branch installs are pinned to that branch's head and never apply. An API
    failure is no finding, never a guess.
    """
    if target.install_source not in ("tag_source", "release_asset") or not target.ref:
        return None
    default = target.repo_meta.get("default_branch")
    if not default:
        return None
    head = target.commit_sha or target.ref
    try:
        cmp = gh.get_json(
            f"/repos/{owner}/{name}/compare/{urllib.parse.quote(str(default), safe='')}..."
            f"{urllib.parse.quote(head, safe='')}"
        )
    except RateLimitError:
        raise  # "no finding" would be a guess; the caller waits and scans again
    except GitHubError:
        return None
    if not isinstance(cmp, dict) or cmp.get("status") not in ("ahead", "diverged"):
        return None
    ahead = int(cmp.get("ahead_by") or 0)
    return _finding(
        "repo-tag-off-default-branch",
        "Release tag isn't on the default branch",
        Severity.MEDIUM,
        f"The commit behind {target.ref} has {ahead} commit(s) that {default} doesn't "
        "contain, so what you install never landed on the branch people review. Release "
        "branches for older versions do this legitimately; otherwise it's how code gets "
        "shipped around review.",
        f"{target.ref}: {ahead} commit(s) not on {default}",
    )


# --- entry point -----------------------------------------------------------------------


def run(target: Target, gh: GitHub | None = None) -> tuple[AnalyzerResult, Provenance | None]:
    if not target.repo:
        return AnalyzerResult(NAME, AnalyzerState.NOT_APPLICABLE, detail="local scan"), None
    gh = gh or GitHub.from_env()
    meta = target.repo_meta
    full = str(meta.get("full_name") or target.repo)
    owner, name = full.split("/", 1)
    findings: list[Finding] = []
    facts: list[Fact] = []
    try:
        releases = [to_release(r) for r in gh.releases(owner, name)]
        former = find_former_names(target, gh)
    except RateLimitError:
        raise  # an incomplete scan would be stored and reused; the caller waits instead
    except GitHubError as e:
        return AnalyzerResult(NAME, AnalyzerState.ERROR, detail=str(e)), None

    installed = next((r for r in releases if r.tag == target.ref), None)
    prov = Provenance(
        repo_id=meta.get("id"),
        full_name=full,
        requested_as=target.requested_repo,
        created_at=meta.get("created_at"),
        owner_type=(meta.get("owner") or {}).get("type"),
        former_names=former,
        releases=releases[:_TIMELINE_MAX],
        installed_tag=installed.tag if installed else None,
        publishers=publisher_summary(releases, installed.tag if installed else None),
    )
    cont = continuity(releases, installed)

    # Transfer
    moved = _transferred(former, full)
    if moved:
        sev, why = transfer_severity(cont)
        names = ", ".join(f"{f['name']} ({f['how'].replace('_', ' ')})" for f in moved)
        findings.append(
            _finding(
                "repo-transferred",
                "Repository changed owners",
                sev,
                f"This repository used to live at {moved[0]['name']} and now belongs to "
                f"{owner}. GitHub doesn't record when. {why}",
                names,
            )
        )

    # New publisher without a transfer
    if (
        not moved
        and cont
        and cont.publisher
        and not cont.bot
        and cont.prior_own == 0
        and cont.prior_others >= MIN_OTHER_RELEASES
    ):
        findings.append(
            _finding(
                "repo-new-maintainer-release",
                "Release published by someone new",
                Severity.MEDIUM,
                f"{installed.tag} is the first release published by {cont.publisher}; "
                f"{cont.prior_others} earlier releases came from others. Handovers are "
                "usually fine, but this is also how a compromised or sold project looks.",
                f"{installed.tag} by {cont.publisher}",
            )
        )

    # Repo age
    created = _parse_time(meta.get("created_at"))
    if created is not None:
        age = (datetime.now(UTC) - created).days
        if age < YOUNG_DAYS:
            findings.append(
                _finding(
                    "repo-young",
                    "Very new repository",
                    Severity.LOW,
                    f"The repository was created {age} days ago, so there's little history "
                    "or community review yet.",
                    str(meta.get("created_at")),
                )
            )

    # Tag off the default branch
    off = tag_off_default_branch(target, gh, owner, name)
    if off is not None:
        findings.append(off)

    # Release asset vs tag source
    if target.install_source == "release_asset" and target.source_root is not None:
        if target.kind is TargetKind.INTEGRATION:
            if (tree := _integration_tree(target)) is not None:
                findings += compare_integration_asset(target.root, tree)
        else:
            findings += compare_card_asset(target.root, target.source_root, target.pristine_sha256)

    facts += _facts(prov)
    detail = f"{len(releases)} releases, {len(prov.publishers)} publishers"
    if moved:
        detail += f", formerly {moved[0]['name']}"
    return AnalyzerResult(
        NAME, AnalyzerState.OK, findings=findings, facts=facts, detail=detail
    ), prov


def _facts(prov: Provenance) -> list[Fact]:
    out = []
    for p in prov.publishers:
        out.append(
            Fact(
                ring=Ring.REPO,
                kind="account",
                key=f"github/{p['login']}",
                relation="published_by",
                evidence=Evidence.PROVEN,
                attrs={
                    k: p[k] for k in ("bot", "releases", "first", "last", "published_installed")
                },
                analyzer=NAME,
            )
        )
    for f in prov.former_names:
        out.append(
            Fact(
                ring=Ring.REPO,
                kind="repo",
                key=f"github/{f['name']}",
                relation="formerly_at",
                evidence=Evidence.PROVEN,
                attrs={"how": f["how"]},
                analyzer=NAME,
            )
        )
    return out
