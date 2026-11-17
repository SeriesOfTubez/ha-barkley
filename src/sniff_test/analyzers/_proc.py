"""Running external scanner tools safely.

- minimal environment: no inherited UV_*/PIP_*/proxy-auth variables that could change
  what a tool resolves or where it sends data;
- always run from an empty directory we own, never from inside a scanned tree;
- with `tool=`, inside the Landlock sandbox (sandbox.py) wherever the kernel has it:
  the tool can write only its scan's workspace (and the caches named here), run only
  what the image ships, and connect only where its policy says.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from sniff_test import sandbox

_KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR")


def tool_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in _KEEP}
    env.update(extra)
    return env


def empty_dir(work: Path, name: str) -> Path:
    d = work / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def sandboxed(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str],
    tool: str | None,
    write: tuple[Path, ...] = (),
    read: tuple[Path, ...] = (),
) -> tuple[list[str], dict[str, str]]:
    """`cmd` and `env` as they should run: through the sandbox when `tool` is named and
    the kernel has Landlock, unchanged otherwise."""
    if tool is None or not sandbox.enabled():
        return cmd, env
    exe = cmd[0] if Path(cmd[0]).is_absolute() else (shutil.which(cmd[0]) or cmd[0])
    policy = sandbox.policy_for(tool, cwd, exe, write, read)
    return sandbox.wrap([exe, *cmd[1:]], policy), {**env, **policy.env}


def run(
    cmd: list[str],
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None = None,
    *,
    tool: str | None = None,
    write: tuple[Path, ...] = (),
    read: tuple[Path, ...] = (),
) -> subprocess.CompletedProcess[str]:
    cmd, env = sandboxed(cmd, cwd, env if env is not None else tool_env(), tool, write, read)
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


def version(
    cmd: list[str], env: dict[str, str] | None = None, tool: str | None = None
) -> str | None:
    """The first line a tool prints for `cmd` (its --version), sandboxed like a scan in a
    throwaway workspace. None when it can't run."""
    with tempfile.TemporaryDirectory(prefix="sniff-test-version-") as d:
        try:
            out = run(cmd, Path(d), 60, env, tool=tool)
        except (OSError, subprocess.TimeoutExpired):
            return None
    lines = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
    return lines[0] if lines else None
