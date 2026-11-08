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

    def latest_release(self, owner, name):
        return next(iter(self.releases.values()), None)

    def release_by_tag(self, owner, name, tag):
        return self.releases.get(tag)

    def commit_sha(self, owner, name, ref):
        return f"sha-of-{ref}".ljust(40, "0")

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
