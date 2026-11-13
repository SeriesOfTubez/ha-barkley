"""What publishing needs to stay true: the repository manifest, the image name, the
workflows' pins and permissions, and what must never be committed.

Facts checked 2026-11-12 against contributors.home-assistant.io/apps (publishing,
repository, configuration) and the Supervisor 2026.11.0 source: `repository.yaml` at
the root; every `config.*` outside dot folders and `rootfs` is read as an app; with
`image:` the Supervisor pulls `<image>:<version>` and never builds; the generic
multi-arch name is preferred over `{arch}-`; registries refuse capitals.
"""

import re
import subprocess
import sys
from pathlib import Path

import yaml
from conftest import requires_semgrep

from sniff_test import __version__

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import stage_addon

ROOT = Path(__file__).parent.parent
ADDON = ROOT / "addon" / "sniff_test"
WORKFLOWS = ROOT / ".github" / "workflows"
REPO = "SeriesOfTubez/ha-barkley"


def _yaml(path):
    return yaml.safe_load(path.read_text())


def _tracked():
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.split("\n")


def test_repository_manifest():
    repo = _yaml(ROOT / "repository.yaml")
    assert repo["name"] == "Barkley"
    assert repo["url"] == f"https://github.com/{REPO}"
    assert "@" not in repo["maintainer"]  # a handle, no address to harvest


def test_the_store_sees_exactly_one_app():
    # The Supervisor's rule (store/data.py): any config.* whose path has no dot folder
    # and no `rootfs` part. A stray config.json in a fixture would be offered as an app.
    seen = [
        p
        for p in _tracked()
        if Path(p).stem == "config"
        and Path(p).suffix in (".yaml", ".yml", ".json")
        and not any(part.startswith(".") or part == "rootfs" for part in Path(p).parts)
    ]
    assert seen == ["addon/sniff_test/config.yaml"]


def test_image_name_is_lowercase_and_under_the_repo_owner():
    m = _yaml(ADDON / "config.yaml")
    owner = REPO.split("/")[0].lower()
    assert m["image"] == f"ghcr.io/{owner}/barkley"
    assert m["image"] == m["image"].lower()
    assert "{arch}" not in m["image"]  # the multi-arch manifest, not per-arch names
    assert m["url"] == f"https://github.com/{REPO}"
    assert m["version"] == __version__  # the Supervisor pulls <image>:<version>


def test_staged_copy_builds_locally(tmp_path):
    dest = stage_addon.stage(tmp_path)
    staged = _yaml(dest / "config.yaml")
    repo = _yaml(ADDON / "config.yaml")
    assert "image" not in staged  # with it the Supervisor pulls and ignores the source
    repo.pop("image")
    assert staged == repo  # nothing else differs
    assert (dest / "scanner/src/sniff_test/cli.py").exists()


def test_workflows_pin_every_action_to_a_commit():
    uses = []
    for wf in sorted(WORKFLOWS.glob("*.y*ml")):
        uses += re.findall(r"^\s*(?:- )?uses:\s*(\S+)(.*)$", wf.read_text(), re.M)
    assert len(uses) >= 7
    for ref, rest in uses:
        assert re.search(r"@[0-9a-f]{40}$", ref), ref
        assert rest.strip().startswith("#"), ref  # the tag the commit belongs to


def test_workflows_ask_for_the_least():
    for wf in sorted(WORKFLOWS.glob("*.y*ml")):
        doc = _yaml(wf)
        assert doc["permissions"] == {"contents": "read"}, wf.name
        text = wf.read_text()
        assert "pull_request_target" not in text
        assert text.count("actions/checkout@") == text.count("persist-credentials: false")
    ci = _yaml(WORKFLOWS / "ci.yaml")
    assert all("permissions" not in job for job in ci["jobs"].values())
    assert "secrets." not in (WORKFLOWS / "ci.yaml").read_text()
    build = _yaml(WORKFLOWS / "build.yaml")
    wider = {name: job.get("permissions") for name, job in build["jobs"].items()}
    assert wider == {
        "init": None,
        "build": {"contents": "read", "id-token": "write", "packages": "write"},
        "manifest": {"id-token": "write", "packages": "write"},
    }


def test_build_workflow_matches_the_app():
    text = (WORKFLOWS / "build.yaml").read_text()
    build = _yaml(WORKFLOWS / "build.yaml")
    m = _yaml(ADDON / "config.yaml")
    assert build["env"]["IMAGE_NAME"] == m["image"].rsplit("/", 1)[1]
    arches = yaml.safe_load(build["env"]["ARCHITECTURES"])
    assert sorted(arches) == sorted(m["arch"])
    df = (ADDON / "Dockerfile").read_text()
    assert f"FROM {build['env']['BASE_IMAGE']}" in df  # the image whose signature is checked
    assert "context: dist/addon/sniff_test" in text  # the staged folder
    assert "python3 scripts/stage_addon.py" in text
    # A published version is never overwritten, in the per-arch images or the manifest.
    assert text.count("skip-existing: ${{ needs.init.outputs.version }}") == 2
    # Nothing a release author types reaches a shell line directly.
    for line in text.splitlines():
        if "${{" in line and "github.event" in line:
            assert re.match(r"\s+[A-Z_]+: \$\{\{", line), line


def test_ci_runs_the_semgrep_the_image_ships():
    ci = _yaml(WORKFLOWS / "ci.yaml")
    pinned = ci["jobs"]["test"]["env"]["SEMGREP_VERSION"]
    assert f"ARG SEMGREP_VERSION={pinned}" in (ADDON / "Dockerfile").read_text()


@requires_semgrep
def test_the_semgrep_on_this_machine_is_the_one_the_image_ships():
    """The parse gaps and the noise set are verified per Semgrep version (1.185.0 on
    2026-11-13). A different local Semgrep would test rules against another parser.
    Note that `semgrep` runs the `pysemgrep` it finds on PATH: both must be the pin's."""
    pinned = _yaml(WORKFLOWS / "ci.yaml")["jobs"]["test"]["env"]["SEMGREP_VERSION"]
    out = subprocess.run(
        ["semgrep", "--version"], capture_output=True, text=True, check=False
    ).stdout.split()
    assert out[-1:] == [pinned], f"install it: uv tool install --no-build semgrep=={pinned}"


def test_license_and_security_policy():
    assert (ROOT / "LICENSE").read_text().startswith("MIT License")
    assert 'license = "MIT"' in (ROOT / "pyproject.toml").read_text()
    assert "Report a\nvulnerability" in (ROOT / "SECURITY.md").read_text()


def test_the_handoff_and_debris_are_never_committed():
    tracked = _tracked()
    assert "HANDOFF.md" not in tracked
    assert not any(Path(p).name == ".DS_Store" for p in tracked)
    ignore = (ROOT / ".gitignore").read_text().split("\n")
    assert "/HANDOFF.md" in ignore and ".DS_Store" in ignore


def test_no_personal_paths_in_tracked_text():
    bad = re.compile(r"/Users/[a-z]|OneDrive|mobile_app_[a-z]+s_iphone")
    hits = []
    for rel in _tracked():
        path = ROOT / rel
        if not rel or rel == "tests/test_publish.py" or not path.is_file():
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        if bad.search(text):
            hits.append(rel)
    assert hits == []


def test_sample_owner_cannot_be_a_real_github_account():
    # GitHub logins are letters, digits and hyphens. The hostile fixture's "owner" has
    # an underscore, so no real account can ever be the one it names.
    manifest = (
        ROOT / "tests/fixtures/evil_integration/custom_components"
        "/totally_legit_weather/manifest.json"
    ).read_text()
    assert "@not_a_hacker" in manifest
    assert "github.com/not_a_hacker/" in manifest
