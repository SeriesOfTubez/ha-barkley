"""HACS install-target selection, against a fake GitHub (no network)."""

import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from sniff_test.fetch import hacs
from sniff_test.models import TargetKind


def _tarball(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(f"owner-repo-abc123/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    return buf.getvalue()


class FakeGitHub:
    def __init__(self, tree, releases=None, assets=None, default_branch="main"):
        self.tree, self.releases = tree, releases or {}
        self.assets, self.default_branch = assets or {}, default_branch
        self.tarball_sha = None

    def repo(self, owner, name):
        return {"full_name": f"{owner}/{name}", "default_branch": self.default_branch}

    def hacs_releases(self, owner, name):
        return list(self.releases.values())

    def release_by_tag(self, owner, name, tag):
        return self.releases.get(tag)

    def commit_sha(self, owner, name, ref):
        return f"sha-of-{ref}".ljust(40, "0")

    def commit(self, owner, name, ref):
        return self.commit_sha(owner, name, ref), {"state": "unsigned"}

    def tarball(self, owner, name, sha, dest: Path):
        self.tarball_sha = sha
        dest.write_bytes(_tarball(self.tree))
        return "x"

    def download(self, url, dest: Path, accept=None):
        dest.write_bytes(self.assets[url])
        return "assetsha"


INTEGRATION_TREE = {
    "hacs.json": "{}",
    "custom_components/foo/manifest.json": json.dumps({"domain": "foo"}),
    "custom_components/foo/__init__.py": "x = 1\n",
}


def test_latest_release_tag_source(tmp_path):
    gh = FakeGitHub(INTEGRATION_TREE, releases={"v1.2": {"tag_name": "v1.2", "assets": []}})
    t = hacs.fetch_remote("https://github.com/owner/repo", tmp_path, gh=gh)
    assert t.kind is TargetKind.INTEGRATION
    assert t.ref == "v1.2"
    assert t.install_source == "tag_source"
    assert t.domain == "foo"
    assert (t.root / "__init__.py").exists()
    assert gh.tarball_sha.startswith("sha-of-v1.2")


def test_no_releases_pins_default_branch_and_flags(tmp_path):
    gh = FakeGitHub(INTEGRATION_TREE, default_branch="dev")
    t = hacs.fetch_remote("owner/repo", tmp_path, gh=gh)
    assert t.install_source == "default_branch"
    assert t.ref == "dev"
    assert t.commit_sha.startswith("sha-of-dev")
    assert [n.rule_id for n in t.notes] == ["repo-no-releases"]


def test_zip_release_uses_asset_not_source(tmp_path):
    tree = dict(INTEGRATION_TREE)
    tree["hacs.json"] = json.dumps({"zip_release": True, "filename": "foo.zip"})
    asset = _zip({"manifest.json": json.dumps({"domain": "foo"}), "evil_only_in_zip.py": "x"})
    gh = FakeGitHub(
        tree,
        releases={"v2": {"tag_name": "v2", "assets": [{"name": "foo.zip", "url": "u1"}]}},
        assets={"u1": asset},
    )
    t = hacs.fetch_remote("owner/repo", tmp_path, ref="v2", gh=gh)
    assert t.install_source == "release_asset"
    assert (t.root / "evil_only_in_zip.py").exists()
    assert t.artifact_sha256 == "assetsha"


def test_plugin_prefers_release_asset_then_dist(tmp_path):
    tree = {"hacs.json": json.dumps({"filename": "my-card.js"}), "dist/my-card.js": "src()"}
    gh = FakeGitHub(
        tree,
        releases={"v1": {"tag_name": "v1", "assets": [{"name": "my-card.js", "url": "u"}]}},
        assets={"u": b"asset()"},
    )
    t = hacs.fetch_remote("owner/lovelace-my-card", tmp_path, gh=gh)
    assert t.kind is TargetKind.PLUGIN
    assert t.install_source == "release_asset"
    assert (t.root / "my-card.js").read_bytes() == b"asset()"

    gh2 = FakeGitHub(tree, releases={"v1": {"tag_name": "v1", "assets": []}})
    (tmp_path / "b").mkdir()
    t2 = hacs.fetch_remote("owner/lovelace-my-card", tmp_path / "b", gh=gh2)
    assert t2.install_source == "tag_source"
    assert (t2.root / "my-card.js").read_text() == "src()"


def test_rejects_non_github(tmp_path):
    with pytest.raises(hacs.FetchError):
        hacs.fetch_remote("https://gitlab.com/a/b", tmp_path, gh=FakeGitHub({}))


def test_hacs_choice_follows_list_order_not_latest_flag():
    rels = [
        {"tag_name": "v3.0.0-beta.2", "prerelease": True},
        {"tag_name": "v9-draft", "draft": True},
        {"tag_name": "v2.1.1"},  # e.g. a backport published after v2.2.0
        {"tag_name": "v2.2.0"},
    ]
    default, beta = hacs.hacs_choice(rels)
    assert (default["tag_name"], beta["tag_name"]) == ("v2.1.1", "v3.0.0-beta.2")
    assert hacs.hacs_choice([{"tag_name": "b", "prerelease": True}]) == (
        None,
        {"tag_name": "b", "prerelease": True},
    )
    # Only the first page HACS reads counts: a stable release beyond it doesn't.
    many = [{"tag_name": f"b{i}", "prerelease": True} for i in range(30)] + [{"tag_name": "v1"}]
    assert hacs.hacs_choice(many)[0] is None


def test_only_prereleases_installs_default_branch(tmp_path):
    gh = FakeGitHub(INTEGRATION_TREE, releases={"b1": {"tag_name": "b1", "prerelease": True}})
    t = hacs.fetch_remote("owner/repo", tmp_path, gh=gh)
    assert t.install_source == "default_branch"


# (0.14.0) HACS installs every asset of a card's release; so does Barkley, within limits.
def _plugin_gh(assets):
    tree = {"hacs.json": json.dumps({"filename": "my-card.js"}), "dist/my-card.js": "src()"}
    return FakeGitHub(
        tree,
        releases={"v1": {"tag_name": "v1", "assets": assets}},
        assets={a["url"]: f"// {a['name']}\n".encode() for a in assets},
    )


def test_plugin_fetches_every_release_asset(tmp_path):
    names = ["my-card.js", "card-Ab12.js", "chunk-Cd34.js", "my-card.js.gz", "de.json"]
    gh = _plugin_gh([{"name": n, "url": f"u{i}", "size": 10} for i, n in enumerate(names)])
    t = hacs.fetch_remote("owner/lovelace-my-card", tmp_path, gh=gh)
    assert t.install_source == "release_asset"
    assert sorted(p.name for p in t.root.iterdir()) == sorted(names)
    assert (t.root / "chunk-Cd34.js").read_text() == "// chunk-Cd34.js\n"
    assert t.artifact_sha256 == "assetsha"  # the card's own file, as before


def test_plugin_release_asset_limits(tmp_path):
    many = [
        {"name": f"c{i}.js", "url": f"u{i}", "size": 1} for i in range(hacs.MAX_RELEASE_ASSETS + 1)
    ]
    with pytest.raises(hacs.FetchError, match="at most 300"):
        hacs.fetch_remote("owner/lovelace-my-card", tmp_path, gh=_plugin_gh(many))
    big = [{"name": "my-card.js", "url": "u0", "size": hacs.MAX_RELEASE_BYTES + 1}]
    (tmp_path / "b").mkdir()
    with pytest.raises(hacs.FetchError, match="MB"):
        hacs.fetch_remote("owner/lovelace-my-card", tmp_path / "b", gh=_plugin_gh(big))
    for bad in ("../evil.js", "a/b.js", "..", "a\\b.js"):
        d = tmp_path / f"n{abs(hash(bad))}"
        d.mkdir()
        gh = _plugin_gh(
            [{"name": "my-card.js", "url": "u0", "size": 1}, {"name": bad, "url": "u1", "size": 1}]
        )
        with pytest.raises(hacs.FetchError, match="name"):
            hacs.fetch_remote("owner/lovelace-my-card", d, gh=gh)


def test_card_file_names_are_the_ones_the_marketplace_accepts():
    """(0.15) Core's `_valid_filenames`: hacs.json's filename alone, else the name without
    "lovelace-", the full name, and the full name .umd.js / -bundle.js. A real card whose
    file carried its whole repository name failed to scan before."""
    from sniff_test.fetch.hacs import plugin_filenames

    assert plugin_filenames("lovelace-acme-row", {}) == [
        "acme-row.js",
        "lovelace-acme-row.js",
        "lovelace-acme-row.umd.js",
        "lovelace-acme-row-bundle.js",
    ]
    assert plugin_filenames("acme-card", {"filename": "dist/acme.js"}) == ["dist/acme.js"]
