"""The Landlock sandbox around the scanner tools.

The policy tests run anywhere. The escape tests need Linux with Landlock (they skip
elsewhere): a child started exactly as a tool would be tries to get out.
"""

import json
import os
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
    uv = sandbox.policy_for("uv", run, write=(Path("/cache/uv"),), read=(Path("/cache/ha/c.txt"),))
    osv = sandbox.policy_for("osv-scanner", run)
    assert sg.connect == () and uv.connect == (443,) and osv.connect == (443,)
    assert str(root) in sg.write and "/cache/uv" in uv.write and "/cache/ha/c.txt" in uv.read
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


def test_without_landlock_tools_run_as_before(monkeypatch, ws):
    monkeypatch.setattr(sandbox, "abi", lambda: 0)
    cmd, env = _proc.sandboxed(["/bin/true"], ws[1], {"PATH": "/usr/bin"}, "semgrep")
    assert cmd == ["/bin/true"] and env == {"PATH": "/usr/bin"}
    assert "NOT sandboxed" in sandbox.status()[1]


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
