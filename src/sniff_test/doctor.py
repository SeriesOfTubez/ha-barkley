"""`sniff-test doctor`: can each tool run here? For troubleshooting on a real box.

Runs every external tool on a one-line sample we write ourselves (never scanned code)
and reports exit codes and output tails, plus the facts that differ between machines:
user, HOME, temp dir, free memory, and the AppArmor profile the process runs under.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sniff_test.analyzers import _proc
from sniff_test.analyzers.semgrep import _tool_env as semgrep_env
from sniff_test.analyzers.semgrep import rules_dir

_TAIL = 1500


@dataclass
class Check:
    name: str
    ok: bool
    summary: str
    command: str = ""
    returncode: int | None = None
    seconds: float | None = None
    stdout: str = ""
    stderr: str = ""
    full_stdout: str = field(default="", repr=False)


def _tail(text: str) -> str:
    text = text.strip()
    return ("…" + text[-_TAIL:]) if len(text) > _TAIL else text


def _run(name: str, cmd: list[str], cwd: Path, env: dict[str, str], timeout: int = 300) -> Check:
    exe = shutil.which(cmd[0])
    if not exe:
        return Check(name, False, f"{cmd[0]} not on PATH")
    start = time.monotonic()
    try:
        p = subprocess.run(
            [exe, *cmd[1:]], cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env
        )
    except subprocess.TimeoutExpired:
        return Check(name, False, f"timed out after {timeout}s", " ".join(cmd))
    except OSError as e:
        return Check(name, False, f"could not start: {e}", " ".join(cmd))
    took = round(time.monotonic() - start, 2)
    rc = p.returncode
    summary = f"exit {rc}" if rc >= 0 else f"killed by signal {-rc}"
    return Check(
        name, rc == 0, summary, " ".join(cmd), rc, took, _tail(p.stdout), _tail(p.stderr), p.stdout
    )


def _facts() -> Check:
    lines = [
        f"uid={os.getuid()} gid={os.getgid()}",
        f"HOME={os.environ.get('HOME', '(unset)')}",
        f"TMPDIR={os.environ.get('TMPDIR', '(unset)')} tempdir={tempfile.gettempdir()}",
        f"cpus={os.cpu_count()}",
    ]
    try:
        attr = Path("/proc/self/attr/current").read_text().strip("\x00\n ")
        lines.append(f"apparmor={attr or '(none)'}")
    except OSError:
        lines.append("apparmor=(unavailable)")
    try:
        mem = {
            k: v.strip()
            for k, v in (ln.split(":", 1) for ln in Path("/proc/meminfo").read_text().splitlines())
            if k in ("MemTotal", "MemAvailable")
        }
        lines.append(" ".join(f"{k}={v}" for k, v in mem.items()))
    except (OSError, ValueError):
        pass
    home = Path(os.environ.get("HOME") or Path.home())
    lines.append(f"HOME writable={os.access(home, os.W_OK)}")
    return Check("environment", True, "; ".join(lines))


def run_checks() -> list[Check]:
    checks = [_facts()]
    with tempfile.TemporaryDirectory(prefix="sniff-doctor-") as tmp:
        work = Path(tmp)
        sample = work / "sample"
        sample.mkdir()
        (sample / "mod.py").write_text("x = 1\n", encoding="utf-8")
        (sample / ".semgrepignore").write_text("", encoding="utf-8")
        run_dir = work / "run"
        run_dir.mkdir()
        checks.append(_run("semgrep --version", ["semgrep", "--version"], run_dir, semgrep_env()))
        sg = _run(
            "semgrep scan (our rules, one-line sample)",
            ["semgrep", "scan", "--config", str(rules_dir()), "--json", "--metrics=off",
             "--disable-version-check", "--no-git-ignore", "--jobs", "1", str(sample)],
            run_dir,
            semgrep_env(),
        )  # fmt: skip
        try:
            data = json.loads(sg.full_stdout)
            errs = [e.get("message", e.get("type")) for e in data.get("errors", [])]
            sg.summary += f"; {len(data.get('paths', {}).get('scanned', []))} file(s) scanned"
            if errs:
                sg.summary += f"; errors: {errs[:3]}"
        except ValueError:
            sg.summary += "; output is not JSON"
        checks.append(sg)
        env = _proc.tool_env()
        checks.append(_run("osv-scanner --version", ["osv-scanner", "--version"], run_dir, env))
        checks.append(_run("guarddog --version", ["guarddog", "--version"], run_dir, env))
        checks.append(
            _run(
                "guarddog scan (one-line sample)",
                ["guarddog", "pypi", "scan", str(sample), "--output-format", "json"],
                run_dir,
                env,
            )
        )
        checks.append(_run("uv --version", ["uv", "--version"], run_dir, env))
    return checks


def to_dicts(checks: list[Check]) -> list[dict]:
    return [{k: v for k, v in asdict(c).items() if k != "full_stdout"} for c in checks]
