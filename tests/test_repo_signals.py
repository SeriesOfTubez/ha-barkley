"""Repo signals against a fake GitHub (offline), plus opt-in checks on real repos."""

import json
import tempfile
from pathlib import Path

import pytest

from sniff_test.analyzers import repo_signals
from sniff_test.analyzers.semgrep import normalize_js
from sniff_test.fetch.github import NotFoundError
from sniff_test.models import Severity, Target, TargetKind


def _rel(tag, when, who, bot=False, pre=False):
    return {
        "tag_name": tag,
        "published_at": when,
        "author": {"login": who, "type": "Bot" if bot else "User"},
        "prerelease": pre,
        "assets": [],
    }


class FakeGitHub:
    def __init__(self, releases, repos=None):
        self._releases, self._repos = releases, repos or {}

    def releases(self, owner, name):
        return self._releases

    def get_json(self, path):
        key = path.removeprefix("/repos/")
        if key not in self._repos:
            raise NotFoundError(path)
        return self._repos[key]


def _target(tmp_path, ref="v2.0", requested="newowner/widget", files=None, **kw) -> Target:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    for name, text in (files or {}).items():
        (src / name).parent.mkdir(parents=True, exist_ok=True)
        (src / name).write_text(text)
    defaults = dict(
        source=requested,
        kind=TargetKind.INTEGRATION,
        root=tmp_path,
        source_root=src,
        repo="newowner/widget",
        ref=ref,
        requested_repo=requested,
        repo_meta={"id": 42, "full_name": "newowner/widget", "created_at": "2019-01-01T00:00:00Z"},
        install_source="tag_source",
    )
    defaults.update(kw)
    return Target(**defaults)


def _by_rule(result):
    return {f.rule_id: f for f in result.findings}


LONG_HISTORY = [
    _rel("v2.0", "2026-11-01T00:00:00Z", "alice"),
    _rel("v1.0", "2020-01-01T00:00:00Z", "alice"),
]


def test_transfer_by_redirect_with_continuous_maintainer_is_low(tmp_path):
    t = _target(tmp_path, requested="oldorg/widget")
    r, prov = repo_signals.run(t, FakeGitHub(LONG_HISTORY))
    f = _by_rule(r)["repo-transferred"]
    assert f.severity is Severity.LOW
    assert "oldorg/widget (redirect)" in f.evidence
    assert prov.former_names == [{"name": "oldorg/widget", "how": "redirect"}]


def test_transfer_found_from_old_links_resolving_to_same_repo_id(tmp_path):
    files = {
        "CHANGELOG.md": "see https://github.com/oldorg/widget/pull/1 and github.com/fork/widget"
    }
    gh = FakeGitHub(LONG_HISTORY, repos={"oldorg/widget": {"id": 42}, "fork/widget": {"id": 7}})
    r, _ = repo_signals.run(_target(tmp_path, files=files), gh)
    assert _by_rule(r)["repo-transferred"].evidence == "oldorg/widget (same repo id)"


def test_rename_by_same_owner_is_not_a_transfer(tmp_path):
    r, prov = repo_signals.run(
        _target(tmp_path, requested="newowner/old-name"), FakeGitHub(LONG_HISTORY)
    )
    assert "repo-transferred" not in _by_rule(r)
    assert prov.former_names[0]["name"] == "newowner/old-name"


def test_transfer_with_new_publisher_is_high(tmp_path):
    releases = [
        _rel("v2.0", "2026-11-01T00:00:00Z", "mallory"),
        _rel("v1.0", "2020-01-01T00:00:00Z", "alice"),
    ]
    r, _ = repo_signals.run(_target(tmp_path, requested="oldorg/widget"), FakeGitHub(releases))
    assert _by_rule(r)["repo-transferred"].severity is Severity.HIGH


def test_transfer_with_bot_publisher_is_medium(tmp_path):
    releases = [_rel("v2.0", "2026-11-01T00:00:00Z", "github-actions[bot]", bot=True)]
    r, _ = repo_signals.run(_target(tmp_path, requested="oldorg/widget"), FakeGitHub(releases))
    assert _by_rule(r)["repo-transferred"].severity is Severity.MEDIUM


def test_new_maintainer_release_without_transfer(tmp_path):
    releases = [
        _rel("v3.0", "2026-11-01T00:00:00Z", "dave"),
        _rel("v2.0", "2025-01-01T00:00:00Z", "alice"),
        _rel("v1.0", "2024-01-01T00:00:00Z", "alice"),
    ]
    r, _ = repo_signals.run(_target(tmp_path, ref="v3.0"), FakeGitHub(releases))
    assert _by_rule(r)["repo-new-maintainer-release"].severity is Severity.MEDIUM
    # dave's second release is no longer "new"
    releases.insert(0, _rel("v3.1", "2026-11-05T00:00:00Z", "dave"))
    r, _ = repo_signals.run(_target(tmp_path, ref="v3.1"), FakeGitHub(releases))
    assert "repo-new-maintainer-release" not in _by_rule(r)


def test_young_repo(tmp_path):
    from datetime import UTC, datetime, timedelta

    created = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    t = _target(
        tmp_path, repo_meta={"id": 42, "full_name": "newowner/widget", "created_at": created}
    )
    r, _ = repo_signals.run(t, FakeGitHub(LONG_HISTORY))
    assert _by_rule(r)["repo-young"].severity is Severity.LOW


def _asset_case(tmp_path, asset_files, tree_files):
    asset = tmp_path / "install"
    for name, text in asset_files.items():
        (asset / name).parent.mkdir(parents=True, exist_ok=True)
        (asset / name).write_text(text)
    tree = {f"custom_components/widget/{k}": v for k, v in tree_files.items()}
    t = _target(tmp_path, files=tree, root=asset, install_source="release_asset", domain="widget")
    r, _ = repo_signals.run(t, FakeGitHub(LONG_HISTORY))
    return _by_rule(r)


MANIFEST = {"domain": "widget", "requirements": ["widgetlib==1.0"], "version": "0.0.0"}


def test_version_stamping_is_not_a_mismatch(tmp_path):
    stamped = dict(MANIFEST, version="2.0.5")
    rules = _asset_case(
        tmp_path,
        {"const.py": 'VERSION = "2.0.5"\n', "manifest.json": json.dumps(stamped)},
        {"const.py": 'VERSION = "0.0.0"\n', "manifest.json": json.dumps(MANIFEST)},
    )
    assert rules == {}


def test_changed_code_and_requirements_in_zip_are_high(tmp_path):
    evil = dict(MANIFEST, requirements=["widgetlib==1.0", "reqeusts"])
    rules = _asset_case(
        tmp_path,
        {"api.py": "send(token)\n", "manifest.json": json.dumps(evil), "extra.py": "x = 1\n"},
        {"api.py": "send(data)\n", "manifest.json": json.dumps(MANIFEST)},
    )
    f = rules["repo-release-source-mismatch"]
    assert f.severity is Severity.HIGH and "api.py" in f.evidence and "manifest.json" in f.evidence
    assert rules["repo-release-extra-code"].severity is Severity.LOW


def test_card_bundle_compared_only_when_committed(tmp_path):
    asset = tmp_path / "install"
    asset.mkdir()
    (asset / "card.js").write_text("fetch(evil)")
    t = _target(
        tmp_path,
        files={"dist/card.js": "fetch(ok)"},
        root=asset,
        kind=TargetKind.PLUGIN,
        install_source="release_asset",
    )
    r, _ = repo_signals.run(t, FakeGitHub(LONG_HISTORY))
    assert _by_rule(r)["repo-release-source-mismatch"].severity is Severity.MEDIUM


def _card_pair(tmp_path, released: str, committed: str):
    asset, src = tmp_path / "install", tmp_path / "src" / "dist"
    asset.mkdir(parents=True)
    src.mkdir(parents=True)
    (asset / "card.js").write_text(released)
    (src / "card.js").write_text(committed)
    pristine: dict[str, str] = {}
    assert normalize_js(asset, pristine) == (1 if "-->" in released else 0)
    return repo_signals.compare_card_asset(asset, tmp_path / "src", pristine)


def test_our_html_comment_rewrite_is_not_a_release_mismatch(tmp_path):
    """power-flow-card-plus v0.4.0 and Helios 2026.9.6 ship the committed bundle byte
    for byte, but semgrep rewrites `-->` in our copy before repo signals ran."""
    js = "for(;n-->0;)x();const t=/-->/g;"
    assert _card_pair(tmp_path, js, js) == []


def test_a_real_bundle_change_is_still_a_mismatch_after_the_rewrite(tmp_path):
    js = "for(;n-->0;)x();"
    found = _card_pair(tmp_path, js + "fetch('https://e.invalid')", js)
    assert [f.rule_id for f in found] == ["repo-release-source-mismatch"]
    # The release ships exactly what our rewrite would produce from the committed copy.
    found = _card_pair(tmp_path / "b", "for(;n-- >0;)x();", js)
    assert [f.rule_id for f in found] == ["repo-release-source-mismatch"]


def test_local_scan_is_not_applicable(tmp_path):
    t = Target(source=".", kind=TargetKind.INTEGRATION, root=tmp_path)
    r, prov = repo_signals.run(t, FakeGitHub([]))
    assert r.state == "not_applicable" and prov is None


@pytest.mark.network
@pytest.mark.parametrize(
    ("source", "how"),
    [
        ("custom-components/alexa_media_player", "redirect"),
        ("alandtse/alexa_media_player", "same repo id"),
    ],
)
def test_alexa_media_player_is_flagged_as_transferred(source, how):
    from sniff_test.fetch.hacs import fetch_remote

    with tempfile.TemporaryDirectory() as d:
        t = fetch_remote(source, Path(d))
        r, _ = repo_signals.run(t)
    f = _by_rule(r)["repo-transferred"]
    assert f"custom-components/alexa_media_player ({how})" in f.evidence
    assert f.severity is Severity.LOW  # alandtse has published every release since 2019


def _tag_check(tmp_path, status, **kw):
    meta = {"id": 42, "full_name": "newowner/widget", "created_at": "2019-01-01T00:00:00Z",
            "default_branch": "main"}  # fmt: skip
    t = _target(tmp_path, repo_meta=meta, commit_sha="abc123", **kw)
    repos = {}
    if status:
        repos["newowner/widget/compare/main...abc123"] = {"status": status, "ahead_by": 3}
    r, _ = repo_signals.run(t, FakeGitHub(LONG_HISTORY, repos))
    return _by_rule(r).get("repo-tag-off-default-branch")


@pytest.mark.parametrize("status", ["ahead", "diverged"])
def test_tag_off_the_default_branch_is_medium(tmp_path, status):
    f = _tag_check(tmp_path, status)
    assert f.severity is Severity.MEDIUM
    assert f.evidence == "v2.0: 3 commit(s) not on main"


@pytest.mark.parametrize("status", ["behind", "identical", None])  # None: API error
def test_tag_on_the_default_branch_or_unknown_is_quiet(tmp_path, status):
    assert _tag_check(tmp_path, status) is None


def test_default_branch_installs_are_never_off_it(tmp_path):
    assert _tag_check(tmp_path, "ahead", install_source="default_branch") is None
