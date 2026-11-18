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
    # The security workflow: each scanning job may upload results to code scanning,
    # nothing more. No job there signs, pushes or reads a secret.
    sec = _yaml(WORKFLOWS / "security.yaml")
    scanning = {"contents": "read", "security-events": "write"}
    assert {name: job.get("permissions") for name, job in sec["jobs"].items()} == {
        "visibility": None,
        "scan": scanning,
        "codeql": scanning,
        "image": scanning,
    }
    assert "secrets." not in (WORKFLOWS / "security.yaml").read_text()


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


def test_security_workflow_runs_the_four_kinds_of_check():
    """Secrets, SAST, SCA and container scanning (the owner's standard set, 2026-11-13),
    each failing the job on a finding, none of them reading the hostile samples as if
    they were Barkley's own code."""
    text = (WORKFLOWS / "security.yaml").read_text()
    sec = _yaml(WORKFLOWS / "security.yaml")
    triggers = sec[True]  # YAML reads the key `on` as a boolean
    assert {"push", "pull_request", "schedule"} <= set(triggers)
    steps = {name: job["steps"] for name, job in sec["jobs"].items()}
    runs = {name: "\n".join(s.get("run", "") for s in ss) for name, ss in steps.items()}
    # Secrets: every commit, the repository's own rules.
    assert "gitleaks detect --source ." in runs["scan"]
    assert "--config .gitleaks.toml" in runs["scan"]
    checkout = next(s for s in steps["scan"] if "actions/checkout" in s.get("uses", ""))
    assert checkout["with"]["fetch-depth"] == 0
    # SAST: registry rules, failing on a finding, metrics off.
    for flag in ("--config p/security-audit", "--config p/owasp-top-ten", "--error"):
        assert flag in runs["scan"], flag
    assert "--metrics off" in runs["scan"]
    for sample in ("tests/fixtures", "tests/rules", "demo"):
        assert f"--exclude {sample}" in runs["scan"]
        assert f"- {sample}" in text  # CodeQL's paths-ignore
    # SCA and the image: Trivy fails on high and critical findings that have a fix.
    trivy = [s for ss in steps.values() for s in ss if "trivy-action" in s.get("uses", "")]
    gates = [s["with"] for s in trivy if s["with"].get("exit-code") == "1"]
    assert sorted(w["scan-type"] for w in gates) == ["fs", "image", "image"]
    assert all(w["severity"] == "HIGH,CRITICAL" for w in gates)
    # In SARIF mode trivy-action reports every severity, and fails on any, unless told
    # to keep to the gate's (the first run on GitHub failed on medium findings).
    assert all(w["limit-severities-for-sarif"] is True for w in gates)
    assert all(s["with"]["version"] == "${{ env.TRIVY_VERSION }}" for s in trivy)
    assert re.fullmatch(r"v\d+\.\d+\.\d+", sec["env"]["TRIVY_VERSION"])
    assert {w.get("scanners") for w in gates if w["scan-type"] == "image"} == {
        "vuln",
        "misconfig",
    }
    fs = next(w for w in gates if w["scan-type"] == "fs")
    assert fs["skip-dirs"] == "tests/fixtures,demo"
    # The image scanned is the one a release builds: the staged folder.
    assert "python3 scripts/stage_addon.py" in runs["image"]
    assert "dist/addon/sniff_test" in runs["image"]
    # A step that may fail softly (so its results can be uploaded) has a hard gate after.
    for name, ss in steps.items():
        soft = [s["id"] for s in ss if s.get("continue-on-error")]
        for step_id in soft:
            assert f"steps.{step_id}.outcome == 'failure'" in text, (name, step_id)


def test_security_workflow_tools_are_pinned():
    sec = _yaml(WORKFLOWS / "security.yaml")
    env = sec["env"]
    ci = _yaml(WORKFLOWS / "ci.yaml")
    assert env["SEMGREP_VERSION"] == ci["jobs"]["test"]["env"]["SEMGREP_VERSION"]
    for tool in ("GITLEAKS", "HADOLINT"):
        assert re.fullmatch(r"\d+\.\d+\.\d+", env[f"{tool}_VERSION"])
        assert re.fullmatch(r"[0-9a-f]{64}", env[f"{tool}_SHA256"])
    assert re.fullmatch(r"\d+\.\d+\.\d+", env["CHECKOV_VERSION"])
    text = (WORKFLOWS / "security.yaml").read_text()
    assert text.count("| sha256sum -c -") == 2  # both downloaded binaries are checked
    assert "pip install" not in text
    assert text.count("uv tool install --no-build") == 2  # wheels only


def test_accepted_findings_carry_a_reason_and_dates():
    """.trivyignore: one line per accepted CVE with why, when, and a review date at
    most 90 days later. Checkov's skips are explained in .checkov.yaml."""
    from datetime import date

    for line in (ROOT / ".trivyignore").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        m = re.fullmatch(
            r"(CVE-\d{4}-\d+|GHSA(-[0-9a-z]{4}){3})  # (.{20,})\. "
            r"Accepted: (\d{4}-\d\d-\d\d)  Review: (\d{4}-\d\d-\d\d)",
            line,
        )
        assert m, line
        accepted, review = date.fromisoformat(m[4]), date.fromisoformat(m[5])
        assert 0 < (review - accepted).days <= 90, line
    checkov = (ROOT / ".checkov.yaml").read_text()
    skipped = _yaml(ROOT / ".checkov.yaml")["skip-check"]
    for check in skipped:
        before = checkov.split(f"  - {check}")[0].rstrip().splitlines()[-1]
        assert before.strip().startswith("#"), check  # the reason sits above the id
    assert _yaml(ROOT / ".hadolint.yaml") == {"ignored": ["DL3008"]}


def test_dependabot_waits_a_week():
    bot = _yaml(ROOT / ".github" / "dependabot.yml")
    assert [u["cooldown"] for u in bot["updates"]] == [{"default-days": 7}] * 2


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


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in text.split("."))


def test_barkleys_python_is_not_older_than_home_assistants():
    """(0.14.0) Barkley parses apps written for HA's Python: on an older one, newer syntax
    (3.14's t-strings) doesn't parse, so the ast checks skip that file. HA's version is
    the one recorded with the domain list (scripts/ha_domains.py)."""
    data = (ROOT / "src/sniff_test/data/ha_domains.txt").read_text()
    ha = re.search(r"^# python: (\d+\.\d+\.\d+)", data, re.M).group(1)
    image = re.search(
        r"^ARG BARKLEY_PYTHON=(\S+)$", (ROOT / "addon/sniff_test/Dockerfile").read_text(), re.M
    )
    assert image and _version(image.group(1)) >= _version(ha), (image, ha)
    dev = (ROOT / ".python-version").read_text().strip()
    assert _version(dev) >= _version(ha)[:2]
    need = re.search(r'^requires-python = ">=(\S+)"', (ROOT / "pyproject.toml").read_text(), re.M)
    assert _version(need.group(1)) >= _version(ha)[:2]
    assert sys.version_info[:2] >= _version(ha)[:2]  # what runs this test
