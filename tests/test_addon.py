"""The add-on manifest and image recipe stay within what the Supervisor accepts today.

Facts checked against contributors.home-assistant.io/apps (2026-11-08): required keys,
aarch64/amd64 only (armhf/armv7/i386 deprecated), `init: false` for s6-overlay v3
images, ingress requests only from 172.30.32.2, no per-app memory limit keys.
"""

import sys
from pathlib import Path

import yaml

from sniff_test import __version__, server

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import stage_addon

ADDON = Path(__file__).parent.parent / "addon" / "sniff_test"


def manifest():
    return yaml.safe_load((ADDON / "config.yaml").read_text())


def test_required_keys_and_architectures():
    m = manifest()
    for key in ("name", "version", "slug", "description", "arch"):
        assert m[key], key
    assert m["version"] == __version__
    assert sorted(m["arch"]) == ["aarch64", "amd64"]
    assert m["init"] is False


def test_least_privilege():
    m = manifest()
    assert m["ingress"] is True
    assert m["ingress_port"] == 8099
    assert "ports" not in m  # ingress only
    for key in ("host_network", "full_access", "docker_api", "host_pid", "privileged"):
        assert not m.get(key), key
    assert m.get("hassio_role", "default") == "default"
    assert not m.get("hassio_api")
    assert "map" not in m  # no folders until scanning installed items exists
    assert m["homeassistant_api"] is True  # the installed HA version


def test_options_match_the_run_script():
    m = manifest()
    run = (ADDON / "rootfs/etc/s6-overlay/s6-rc.d/sniff-test/run").read_text()
    assert set(m["options"]) == set(m["schema"])
    for opt in m["options"]:
        assert f"bashio::config '{opt}'" in run
    assert "--store /data/sniff-test.db" in run
    assert f"--port {m['ingress_port']}" in run
    assert run.startswith("#!/command/with-contenv bashio")
    assert m["backup_exclude"] == ["cache/*"]
    assert "SNIFF_TEST_CACHE=/data/cache" in run
    assert "export HOME=/data/cache/home" in run  # tools' home files stay under /data


def test_apparmor_profile_is_what_the_supervisor_loads():
    """supervisor/utils/apparmor.py (2026-11-11): exactly one `profile <name>` line, whose
    name is rewritten to the app's id on install/update; the app folder's apparmor.txt is
    loaded instead of docker-default (contributors.home-assistant.io/apps/reference/files)."""
    text = (ADDON / "apparmor.txt").read_text()
    heads = [ln for ln in text.splitlines() if ln.startswith("profile ")]
    assert len(heads) == 1 and heads[0].split()[1] == manifest()["slug"]
    assert "flags=(attach_disconnected,mediate_deleted)" in heads[0]
    assert "#include <tunables/global>" in text and "#include <abstractions/base>" in text
    # HA's s6/bashio paths. HA's example grants `file,` on top, so its `ix` lines never
    # needed `r`; without `file,` the box's logging-only run (0.7.7) showed s6 reading its
    # own scripts, so the exec lines carry `r` here.
    for rule in (
        "/init rix,",
        "/package/{,**} rix,",
        "/command/{,**} rix,",
        "/usr/lib/bashio/** ix,",
        "/etc/s6-overlay/{,**} rwix,",
    ):
        assert rule in text
    # The other two groups the box showed: bundled libraries named `.so.N` (semgrep-core,
    # pygit2, yara-python), and uv listing PATH then reading the shell and Python it finds
    # (plus osv-scanner reading its own binary).
    for rule in (
        "/opt/tools/**.so{,.*} mr,",
        "/opt/sniff-test/**.so{,.*} mr,",
        "/{usr/,}{s,}bin/ r,",
        "/usr/local/{s,}bin/ r,",
        "/usr/bin/** rix,",
        "/usr/local/bin/* rix,",
    ):
        assert rule in text
    # Writes only under /data and /tmp; nothing downloaded is executable; no capabilities.
    lines = [ln.strip() for ln in text.splitlines()]
    rules = [ln for ln in lines if ln and not ln.startswith("#")]
    assert "/data/{,**} rwk," in rules and "/tmp/{,**} rwk," in rules
    for forbidden in ("capability", "mount", "ptrace", "/tmp/** ix", "/data/** ix", "file,"):
        assert not any(r.startswith(forbidden) or f" {forbidden}" in r for r in rules), forbidden
    assert not any(r.startswith(("/tmp/", "/data/")) and "x" in r.split()[-1] for r in rules)
    assert "complain" not in heads[0]  # enforce (complain was only for the first on-box run)
    # osv-scanner 2.7.1 opens `/` itself before it walks down to a lockfile; 0.10.3 lacked
    # the rule and every advisory check failed on a real box (exit 127). Only the folder
    # may be listed: a rule such as `/** r,` would open the whole image.
    assert "/ r," in rules
    assert not any(r.startswith(("/** ", "/{,**} ")) for r in rules)


def test_panel_only_trusts_the_supervisor_by_default():
    assert server.SUPERVISOR_IP == "172.30.32.2"


def test_image_installs_tools_from_wheels_and_pinned_binaries():
    df = (ADDON / "Dockerfile").read_text()
    assert "FROM ghcr.io/home-assistant/base-debian:trixie" in df
    assert df.count("--no-build") >= 3  # semgrep, guarddog, the scanner's deps
    # uv and osv-scanner both go through get(), which always checks the sha256 pin,
    # whichever URL (release download, or the API asset fallback) served the bytes.
    assert df.count("sha256sum -c") == 1
    assert "get /tmp/uv.tgz" in df and "get /usr/local/bin/osv-scanner" in df
    assert '"${uv_sha}";' in df and '"${osv_sha}";' in df
    assert "Accept: application/octet-stream" in df
    assert "--require-hashes" in df
    assert "COPY scanner /src" in df
    assert "BUILD_ARCH" in df  # the Supervisor's builder may not set TARGETARCH


def test_staged_folder_is_self_contained_and_has_no_tests(tmp_path):
    dest = stage_addon.stage(tmp_path)
    for rel in (
        "config.yaml",
        "Dockerfile",
        "rootfs/etc/s6-overlay/s6-rc.d/sniff-test/run",
        "scanner/pyproject.toml",
        "scanner/uv.lock",
        "scanner/README.md",
        "scanner/src/sniff_test/cli.py",
        "scanner/rules/python",
    ):
        assert (dest / rel).exists(), rel
    staged = {p.relative_to(dest).as_posix() for p in dest.rglob("*")}
    assert not any("tests" in p.split("/") or "fixtures" in p.split("/") for p in staged)
    assert not any(p.endswith(".pyc") or "__pycache__" in p for p in staged)
    assert stage_addon.stage(tmp_path) == dest  # re-staging replaces the folder


def test_archive_has_no_pax_headers_or_xattrs(tmp_path):
    import tarfile

    dest = stage_addon.stage(tmp_path)
    out = stage_addon.archive(dest)
    raw = out.read_bytes()
    for marker in (b"SCHILY.xattr", b"LIBARCHIVE.xattr", b"com.apple."):  # attribute records
        assert marker not in raw
    with tarfile.open(out) as tar:
        names = tar.getnames()
        assert all(m.isfile() or m.isdir() for m in tar.getmembers())
    assert "sniff_test/config.yaml" in names
    assert "sniff_test/scanner/rules/python/inventory.yaml" in names
    assert not any("/._" in n or "PaxHeader" in n for n in names)


def test_dockerignore_drops_copy_debris():
    ignore = (ADDON / ".dockerignore").read_text()
    for pat in ("**/PaxHeader", "**/._*", "**/.DS_Store"):
        assert pat in ignore
