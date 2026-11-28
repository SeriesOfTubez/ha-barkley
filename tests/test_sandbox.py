"""The Landlock sandbox around the scanner tools.

The policy tests run anywhere. The escape tests need Linux with Landlock (they skip
elsewhere): a child started exactly as a tool would be tries to get out.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sniff_test import sandbox
from sniff_test.analyzers import _proc

needs_landlock = pytest.mark.skipif(not sandbox.enabled(), reason="no Landlock here")


@pytest.fixture
def ws():
    with tempfile.TemporaryDirectory(prefix="sniff-test-") as d:
        run = Path(d) / "run"
        run.mkdir()
        yield Path(d).resolve(), run


def test_each_tool_writes_only_its_workspace_and_semgrep_gets_no_network(ws):
    root, run = ws
    sg = sandbox.policy_for("semgrep", run)
    cache = root.parent / f"{root.name}-cache"  # outside the workspace, like /data/cache
    try:
        uv = sandbox.policy_for("uv", run, write=(cache / "uv",), read=(cache / "ha/c.txt",))
        # Landlock can only grant a folder that exists: a fresh install has no uv cache yet
        assert (cache / "uv").is_dir()
    finally:
        shutil.rmtree(cache, ignore_errors=True)
    osv = sandbox.policy_for("osv-scanner", run)
    assert sg.connect == () and uv.connect == (443,) and osv.connect == (443,)
    assert str(root) in sg.write and str(cache / "uv") in uv.write
    assert str(cache / "ha/c.txt") in uv.read
    for p in (sg, uv, osv):
        assert not any(w in ("/", "/data", "/tmp", tempfile.gettempdir()) for w in p.write)
        assert "/" not in p.rx + p.read + p.write
        assert p.env == {"HOME": str(root / ".tool-home"), "TMPDIR": str(root / ".tool-tmp")}
    assert osv.list == ("/",) and sg.list == () and uv.list == ()


def test_the_workspace_is_the_folder_under_the_temp_folder(ws):
    root, run = ws
    assert sandbox.workspace_of(run / "deeper") == root
    assert sandbox.workspace_of(Path("/opt")) == Path("/opt")


def test_rights_follow_the_kernels_abi():
    assert sandbox.handled_fs(1) == (1 << 13) - 1
    assert sandbox.handled_fs(2) & sandbox.REFER and not sandbox.handled_fs(2) & sandbox.TRUNCATE
    assert sandbox.handled_fs(5) & sandbox.IOCTL_DEV


def test_the_wrapper_refuses_bad_input_and_never_runs_the_tool_unsandboxed(monkeypatch, capsys):
    assert sandbox.main(["--policy"]) == 2
    monkeypatch.setattr(sandbox, "abi", lambda: 0)
    assert sandbox.main(["--policy", "{}", "--", "/bin/true"]) == sandbox.EXIT_SANDBOX_FAILED
    assert "not running /bin/true" in capsys.readouterr().err


def _no_landlock(monkeypatch, label, nnp=False, child=True):
    monkeypatch.setattr(sandbox, "abi", lambda: 0)
    monkeypatch.setattr(sandbox, "apparmor_label", lambda: label)
    monkeypatch.setattr(sandbox, "no_new_privs", lambda: nnp)
    monkeypatch.setattr(sandbox, "apparmor_child_works", lambda: child)


def test_without_any_sandbox_tools_run_as_before(monkeypatch, ws):
    _no_landlock(monkeypatch, None)
    cmd, env = _proc.sandboxed(["/bin/true"], ws[1], {"PATH": "/usr/bin"}, "semgrep")
    assert cmd == ["/bin/true"] and env == {"PATH": "/usr/bin"}
    assert sandbox.mode() == "none" and not sandbox.enabled()
    assert "NOT sandboxed" in sandbox.status()[1]


def test_without_landlock_the_app_runs_tools_in_its_apparmor_child(monkeypatch, ws):
    """HA OS has no Landlock: each tool starts through the launcher, which the app's
    profile moves into `tools`."""
    _no_landlock(monkeypatch, "local_sniff_test")
    assert sandbox.mode() == "apparmor"
    cmd, env = _proc.sandboxed(["/bin/true", "x"], ws[1], {"PATH": "/usr/bin"}, "uv")
    assert cmd == [sandbox.APPARMOR_LAUNCHER, "/bin/true", "x"]
    assert env["HOME"].endswith(".tool-home") and env["TMPDIR"].endswith(".tool-tmp")
    assert "AppArmor" in sandbox.status()[1] and "NOT" not in sandbox.status()[1]
    # Barkley's own commands never go through it
    assert _proc.sandboxed(["/bin/true"], ws[1], {}, None)[0] == ["/bin/true"]


@pytest.mark.parametrize(
    ("label", "nnp", "child"),
    [
        ("docker-default", False, True),  # standalone on an AppArmor host: not our profile
        ("local_sniff_test", True, True),  # no-new-privileges: the move would be refused
        ("local_sniff_test", False, False),  # the profile didn't load (a Rebuild)
        ("local_sniff_test//tools", False, True),  # already inside
    ],
)
def test_no_apparmor_child_means_no_sandbox(monkeypatch, label, nnp, child):
    _no_landlock(monkeypatch, label, nnp, child)
    assert sandbox.mode() == "none"


def test_no_new_privileges_is_named_as_the_cause(monkeypatch):
    _no_landlock(monkeypatch, "local_sniff_test", nnp=True)
    monkeypatch.setattr(sandbox.platform, "system", lambda: "Linux")
    assert "no-new-privileges" in sandbox.status()[1]


def test_landlock_wins_over_apparmor(monkeypatch):
    monkeypatch.setattr(sandbox, "abi", lambda: 6)
    monkeypatch.setattr(sandbox, "apparmor_label", lambda: "local_sniff_test")
    assert sandbox.mode() == "landlock"


def test_landlock_policies_grant_no_credential(monkeypatch, tmp_path):
    """The same files the AppArmor child denies, for each tool's
    policy as its call site builds it: s6's copy of the container environment, the
    add-on's options, the GitHub token file, the scan store; and no writes under /etc."""
    from sniff_test import doctor

    data = tmp_path / "data"
    monkeypatch.setenv("SNIFF_TEST_CACHE", str(data / "cache"))
    secrets = [data / "options.json", data / "github-token", data / "sniff-test.db",
               Path("/run/s6/container_environment/SUPERVISOR_TOKEN")]  # fmt: skip
    work = Path(tempfile.mkdtemp(prefix="sniff-test-")) / "run"
    work.mkdir()
    try:
        for tool, (write, read) in doctor._TOOLS.items():
            extra_w = (data / "cache" / "uv",) if tool == "uv" else ()
            pol = sandbox.policy_for(tool, work, "/usr/bin/true", (*write(), *extra_w), read())
            granted = [Path(x) for x in (*pol.rx, *pol.read, *pol.write)]
            for secret in secrets:
                assert not any(secret == g or secret.is_relative_to(g) for g in granted), (
                    tool,
                    secret,
                )
            assert not any(g == Path("/run") or g.is_relative_to("/run") for g in granted)
            assert not any(Path(w).is_relative_to("/etc") for w in pol.write)
            assert "/" not in (*pol.rx, *pol.read, *pol.write)
            assert pol.list in ((), ("/",))  # folder names only (osv-scanner)
    finally:
        shutil.rmtree(work.parent, ignore_errors=True)


def test_with_landlock_the_tool_goes_through_the_wrapper(monkeypatch, ws):
    monkeypatch.setattr(sandbox, "abi", lambda: 6)
    cmd, env = _proc.sandboxed(["/bin/true", "x"], ws[1], {"PATH": "/usr/bin"}, "uv")
    assert cmd[:5] == [sys.executable, "-I", "-m", "sniff_test.sandbox", "--policy"]
    assert cmd[-3:] == ["--", "/bin/true", "x"] and json.loads(cmd[5])["connect"] == [443]
    assert env["HOME"].endswith(".tool-home") and env["TMPDIR"].endswith(".tool-tmp")


# --- Linux with Landlock: a tool that tries to get out ------------------------------------

_ESCAPE = r"""
import json, os, socket, sys
res = {}
def t(name, fn):
    try:
        fn(); res[name] = "allowed"
    except OSError:
        res[name] = "blocked"
outside, ws, ppid = sys.argv[1], sys.argv[2], int(sys.argv[3])
t("read outside", lambda: open(outside).read())
t("write outside", lambda: open(outside + ".new", "w").write("x"))
t("write workspace", lambda: open(ws + "/ok", "w").write("x"))
t("parent environ", lambda: open(f"/proc/{ppid}/environ", "rb").read())
def ex():
    p = ws + "/run.sh"; open(p, "w").write("#!/bin/sh\n"); os.chmod(p, 0o755); os.execv(p, [p])
t("exec from workspace", ex)
print(json.dumps(res))
"""


@needs_landlock
def test_a_sandboxed_tool_cannot_get_out(ws, tmp_path_factory):
    root, run = ws
    outside = tmp_path_factory.mktemp("outside-") / "secret.txt"
    outside.write_text("not for tools")
    script = root / "escape.py"  # inside the workspace: readable for the child
    script.write_text(_ESCAPE)
    cmd, env = _proc.sandboxed(
        [sys.executable, "-I", str(script), str(outside), str(root), str(os.getpid())],
        run, _proc.tool_env(), "semgrep",
    )  # fmt: skip
    p = subprocess.run(cmd, cwd=run, env=env, capture_output=True, text=True, check=False)
    assert json.loads(p.stdout) == {
        "read outside": "blocked", "write outside": "blocked", "write workspace": "allowed",
        "parent environ": "blocked", "exec from workspace": "blocked",
    }  # fmt: skip


def test_landlock_structs_match_the_kernel_layout():
    """struct landlock_path_beneath_attr is packed (12 bytes, parent_fd at 8);
    struct landlock_net_port_attr is two u64 (16 bytes). Python 3.14 changed how ctypes
    picks a layout for _pack_, so the sizes are pinned here."""
    import ctypes

    from sniff_test import sandbox

    assert ctypes.sizeof(sandbox._PathBeneath) == 12
    assert sandbox._PathBeneath.parent_fd.offset == 8
    assert ctypes.sizeof(sandbox._NetPort) == 16
    assert sandbox._NetPort.port.offset == 8


def test_the_tools_path_leaves_out_s6s_command_folder(monkeypatch):
    """uv lists every PATH folder for Pythons; s6's /command isn't one a tool needs (the
    box's first run of the tools profile logged it as a denial)."""
    from sniff_test.analyzers import semgrep

    monkeypatch.setenv("PATH", "/command:/usr/local/bin:/usr/bin:/bin")
    for env in (_proc.tool_env(), semgrep._tool_env()):
        assert env["PATH"] == "/usr/local/bin:/usr/bin:/bin"
