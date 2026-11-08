"""Running external scanner tools safely.

- minimal environment: no inherited UV_*/PIP_*/proxy-auth variables that could change
  what a tool resolves or where it sends data;
- always run from an empty directory we own, never from inside a scanned tree.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

_KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR")


def tool_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in _KEEP}
    env.update(extra)
    return env


def empty_dir(work: Path, name: str) -> Path:
    d = work / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def run(
    cmd: list[str], cwd: Path, timeout: int, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env if env is not None else tool_env(),
        check=False,
    )


def version(cmd: list[str], env: dict[str, str] | None = None) -> str | None:
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            env=env if env is not None else tool_env(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
    return lines[0] if lines else None
