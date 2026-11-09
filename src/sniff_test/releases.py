"""`sniff-test releases`: a repo's release history as a timeline, from GitHub's API.

Marks what HACS installs by default (and offers with "show beta"), who published each
release, and the points where a new person started publishing (handovers). Read-only:
nothing is downloaded or scanned, and nothing here affects any score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sniff_test.analyzers.repo_signals import Release, publisher_summary, to_release
from sniff_test.fetch.github import GitHub, parse_repo
from sniff_test.fetch.hacs import hacs_choice
from sniff_test.report.json_report import sanitize_untrusted


class ReleasesError(Exception):
    pass


@dataclass
class Handover:
    """`publisher` published their first release here, after others had published."""

    tag: str
    publisher: str
    previous: list[str]  # human publishers before them, most releases first
    prior_releases: int


@dataclass
class Timeline:
    repo: str
    requested_as: str | None
    repo_id: int | None
    created_at: str | None
    default_branch: str | None
    releases: list[Release]  # newest first, as GitHub lists them
    hacs_default: str | None
    hacs_beta: str | None
    publishers: list[dict[str, Any]] = field(default_factory=list)
    handovers: list[Handover] = field(default_factory=list)

    @property
    def renamed(self) -> bool:
        return bool(self.requested_as) and self.requested_as.lower() != self.repo.lower()


def handovers(releases: list[Release]) -> list[Handover]:
    """First releases by a human publisher after someone else had published.

    Walks oldest to newest by publish time. Bots are neither handovers nor "previous"
    publishers: a workflow account says nothing about who is behind it.
    """
    ordered = sorted((r for r in releases if r.when), key=lambda r: r.when)
    seen: dict[str, int] = {}
    out = []
    for r in ordered:
        if r.publisher and not r.bot and r.publisher not in seen and seen:
            prev = sorted(seen, key=lambda p: -seen[p])
            out.append(Handover(r.tag, r.publisher, prev, sum(seen.values())))
        if r.publisher and not r.bot:
            seen[r.publisher] = seen.get(r.publisher, 0) + 1
    return out


def build(source: str, gh: GitHub | None = None) -> Timeline:
    parsed = parse_repo(source)
    if not parsed:
        raise ReleasesError(f"not a GitHub repository: {source}")
    gh = gh or GitHub.from_env()
    meta = gh.repo(*parsed)
    full = str(meta.get("full_name") or "/".join(parsed))
    owner, name = full.split("/", 1)
    raw = gh.releases(owner, name)
    default, beta = hacs_choice(raw)
    releases = [to_release(r) for r in raw]
    default_tag = default.get("tag_name") if default else None
    return Timeline(
        repo=full,
        requested_as="/".join(parsed),
        repo_id=meta.get("id"),
        created_at=meta.get("created_at"),
        default_branch=meta.get("default_branch"),
        releases=releases,
        hacs_default=default_tag,
        hacs_beta=beta.get("tag_name") if beta else None,
        publishers=publisher_summary(releases, default_tag),
        handovers=handovers(releases),
    )


def to_dict(t: Timeline) -> dict[str, Any]:
    first_by = {h.tag: h for h in t.handovers}
    return {
        "repo": t.repo,
        "requested_as": t.requested_as,
        "renamed_or_transferred": t.renamed,
        "repo_id": t.repo_id,
        "created_at": t.created_at,
        "default_branch": t.default_branch,
        "hacs_default": t.hacs_default,
        "hacs_beta": t.hacs_beta,
        "untrusted_fields": ["releases[].tag"],
        "publishers": t.publishers,
        "handovers": [
            {
                "tag": sanitize_untrusted(h.tag, 100),
                "publisher": h.publisher,
                "previous_publishers": h.previous,
                "prior_releases": h.prior_releases,
            }
            for h in t.handovers
        ],
        "releases": [
            {
                "tag": sanitize_untrusted(r.tag, 100),
                "published_at": r.published_at,
                "publisher": r.publisher,
                "bot": r.bot,
                "prerelease": r.prerelease,
                "asset_uploaders": r.asset_uploaders,
                "hacs_default": r.tag == t.hacs_default,
                "hacs_beta": r.tag == t.hacs_beta,
                "first_by_publisher": r.tag in first_by,
            }
            for r in t.releases
        ],
    }
