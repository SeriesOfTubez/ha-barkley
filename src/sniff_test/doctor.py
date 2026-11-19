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
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sniff_test import memory, supervisor
from sniff_test.analyzers import _proc, guarddog
from sniff_test.analyzers.semgrep import _tool_env as semgrep_env
from sniff_test.analyzers.semgrep import rules_const_dir, rules_dir
from sniff_test.fetch.github import GitHub, RateLimit

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


_TOOLS: dict[str, tuple[Callable[[], tuple[Path, ...]], Callable[[], tuple[Path, ...]]]] = {
    "semgrep": (lambda: (), lambda: (rules_dir(), rules_const_dir())),
    "osv-scanner": (lambda: (), lambda: ()),
    "guarddog": (lambda: guarddog._cache_dirs(), lambda: ()),
    "uv": (lambda: (), lambda: ()),
}


def sandbox_check() -> Check:
    from sniff_test import sandbox

    v, line = sandbox.status()
    return Check("Tool sandbox (Landlock)", v > 0 or not _sandbox_required(), line)


def _sandbox_required() -> bool:
    """Standalone has no AppArmor profile of Barkley's, so the sandbox is required there
    (serve refuses to start without it unless BARKLEY_UNSANDBOXED=1)."""
    conn = supervisor.connection()
    return conn is not None and conn.mode == "direct"


def _run(name: str, cmd: list[str], cwd: Path, env: dict[str, str], timeout: int = 300) -> Check:
    exe = shutil.which(cmd[0])
    if not exe:
        return Check(name, False, f"{cmd[0]} not on PATH")
    start = time.monotonic()
    # The same sandbox a scan uses (`_TOOLS`), so Diagnostics shows whether it works here.
    tool = cmd[0] if cmd[0] in _TOOLS else None
    write, read = _TOOLS.get(cmd[0], ((), ()))
    run_cmd, env = _proc.sandboxed([exe, *cmd[1:]], cwd, env, tool, write(), read())
    try:
        p = subprocess.run(
            run_cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env
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


def _free() -> str:
    """(#22) Free space in the temp folder: a scan of an integration with big libraries
    keeps a few of their archives there at a time (about 0.5 GB is plenty)."""
    from sniff_test.workspace import free_mb

    mb = free_mb()
    return "unknown" if mb is None else f"{mb:,} MB"


def _facts() -> Check:
    lines = [
        f"uid={os.getuid()} gid={os.getgid()}",
        f"HOME={os.environ.get('HOME', '(unset)')}",
        f"TMPDIR={os.environ.get('TMPDIR', '(unset)')} tempdir={tempfile.gettempdir()}"
        f" free={_free()}",
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


def python_check() -> Check:
    """(0.14.0) Barkley parses apps written for HA's Python; an older one can't read newer
    syntax. HA's version is the one shipped with the built-in domain list."""
    import re
    import sys
    from importlib import resources

    mine = ".".join(str(x) for x in sys.version_info[:3])
    text = (resources.files("sniff_test") / "data" / "ha_domains.txt").read_text("utf-8")
    m = re.search(r"^# python: (\d+)\.(\d+)\.(\d+)", text, re.M)
    src = re.search(r"^# Source: home-assistant/core at (\S+)", text, re.M)
    if not m:
        return Check("Barkley's Python", True, f"{mine} (HA's not recorded)")
    ha = tuple(int(x) for x in m.groups())
    ok = sys.version_info[:3] >= ha
    where = f"HA {src.group(1)} runs {'.'.join(m.groups())}" if src else "HA's"
    return Check(
        "Barkley's Python",
        ok,
        f"{mine}; {where}" + ("" if ok else ": older, so files using newer syntax are "
                              "skipped by the parse-only checks"),
    )  # fmt: skip


def memory_check(mem: memory.Memory | None = None) -> Check:
    """The scan guard: warn under ~2 GB available, refuse under ~1 GB."""
    mem = mem or memory.check()
    label = {"ok": "ok", "warn": "LOW", "refuse": "TOO LOW", "unknown": "unknown"}[mem.level]
    return Check(f"memory guard ({label})", not mem.refuse, mem.message())


def github_check(budget: RateLimit | None = None, fetch: bool = True) -> Check:
    """GitHub's API budget (this request isn't counted) and whether a token is set."""
    if budget is None and fetch:
        budget = GitHub.from_env().rate_limit()
    if budget is None:
        return Check("GitHub API", True, "budget unknown (GitHub unreachable?)")
    when = time.strftime("%H:%M UTC", time.gmtime(budget.reset_at))
    token = "with a token" if budget.authenticated else "no token: 60/hour, about 5 scans"
    return Check(
        "GitHub API",
        budget.remaining > 0,
        f"{budget.remaining} of {budget.limit} requests left ({token}); resets {when}",
    )


def supervisor_checks(
    ha_fn=supervisor.ha_version,
    installed_fn=supervisor.installed_hacs,
) -> list[Check]:
    """What Barkley reads from HA: the HA version (and where it came from) and HACS."""
    if problem := supervisor.config_problem():
        return [Check("Home Assistant", False, problem)]
    conn = supervisor.connection()
    if conn is None:
        return [Check("Home Assistant", True,
                      "not running as an add-on (no SUPERVISOR_TOKEN), and no HA_URL")]  # fmt: skip
    out = []
    if conn.mode == "direct":
        how = ("https" if conn.tls else
               "plain http: the token crosses the network unencrypted; use https if "
               "Home Assistant offers it")  # fmt: skip
        out.append(Check("Home Assistant connection", True,
                         f"standalone, {conn.base} ({how})"))  # fmt: skip
    t0 = time.monotonic()
    ha = ha_fn()
    if ha:
        out.append(Check("Home Assistant version", True, f"{ha} (from {conn.where})"))
    else:
        out.append(Check("Home Assistant version", False,
                         f"{conn.where} didn't answer /api/config; scans fall back to "
                         "the latest stable HA release"))  # fmt: skip
    try:
        items, other = installed_fn()
        updates = sum(1 for i in items if i.update)
        skipped = sum(other.values())
        out.append(Check(
            "Marketplace (HACS) installed list", True,
            f"{len(items)} integration(s)/card(s) installed, {updates} with an update"
            + (f"; {skipped} other installed item(s) not scanned" if skipped else ""),
            command="websocket " + " | ".join(supervisor.LIST_COMMANDS),
            seconds=round(time.monotonic() - t0, 1),
        ))  # fmt: skip
    except supervisor.SupervisorError as ex:
        out.append(Check("Marketplace (HACS) installed list", False, str(ex),
                         command="websocket " + " | ".join(supervisor.LIST_COMMANDS)))  # fmt: skip
    return out


def _semgrep_scan(sample: Path, run_dir: Path) -> Check:
    sg = _run(
        "semgrep scan (our rules, one-line sample)",
        # (0.14.0) Both rule folders, so a missing or broken second pass shows here.
        ["semgrep", "scan", "--config", str(rules_dir()), "--config", str(rules_const_dir()),
         "--json", "--metrics=off",
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
    return sg


def _guarddog_env() -> dict[str, str]:
    gd_exe = shutil.which("guarddog")
    return guarddog.tool_env(gd_exe) if gd_exe else _proc.tool_env()  # lists cached under /data


def _guarddog_scan(sample: Path, run_dir: Path) -> Check:
    gd_env = _guarddog_env()
    gd_cmd = ["guarddog", "pypi", "scan", str(sample), "--output-format", "json"]
    gd = _run("guarddog scan (one-line sample)", gd_cmd, run_dir, gd_env)
    if not gd.ok and "sandbox" in gd.stderr.lower():
        # What the analyzer does too: GuardDog only parses; the container is the
        # outer sandbox. Reported, not hidden.
        retry = _run("guarddog scan (one-line sample)", [*gd_cmd, "--no-sandbox"], run_dir,
                     gd_env)  # fmt: skip
        retry.summary += "; kernel sandbox unavailable here, ran with --no-sandbox"
        gd = retry
    return gd


_OSV_SAMPLE = "osv-scanner scan (empty sample lockfile)"


def _osv_scan(sample: Path, run_dir: Path) -> Check:
    """osv-scanner on a lockfile that names no package, called the way a scan calls it.
    It has to find and read the file, and asks OSV nothing. `--version` alone passed on
    a box where every scan's advisory check failed: 2.7.1 opens `/` before it reaches
    the lockfile, and the AppArmor profile of 0.10.3 didn't let it."""
    # Inside the run folder's workspace, as in a scan: the tool sandbox lets osv-scanner
    # read only its own scan's folder.
    with tempfile.TemporaryDirectory(prefix="osv-sample-", dir=run_dir) as tmp:
        lock = Path(tmp) / "pylock.toml"
        lock.write_text('lock-version = "1.0"\ncreated-by = "barkley-doctor"\n')
        config = Path(tmp) / "osv-empty-config.toml"
        config.write_text("")
        check = _run(
            _OSV_SAMPLE,
            ["osv-scanner", "scan", "source", "--config", str(config), "--lockfile", str(lock),
             "--format", "json", "--no-resolve", "--verbosity", "error"],
            run_dir,
            _proc.tool_env(),
        )  # fmt: skip
    if check.returncode == 128:  # "No package sources found": it read the file
        check.ok = True
        check.summary = "exit 128: read the lockfile, which names no package (as expected)"
    elif check.returncode is not None and check.returncode != 0:
        check.summary += "; osv-scanner could not read a lockfile, so scans can't check advisories"
    return check


Step = tuple[str, Callable[[Path, Path], "Check | list[Check]"]]


def steps(addon: bool = False) -> list[Step]:
    """The checks in order, each with the name shown while it is still running. A step
    gets the sample folder and an empty folder to run in. The first ones answer at once;
    the tool runs take seconds each."""
    out: list[Step] = [
        ("environment", lambda s, r: _facts()),
        ("Barkley's Python", lambda s, r: python_check()),
        ("memory guard", lambda s, r: memory_check()),
        ("tool sandbox", lambda s, r: sandbox_check()),
        ("GitHub API", lambda s, r: github_check()),
    ]
    if addon or supervisor.token() or supervisor.config_problem():
        out.append(("Home Assistant and the Marketplace list", lambda s, r: supervisor_checks()))
    out += [
        ("semgrep --version",
         lambda s, r: _run("semgrep --version", ["semgrep", "--version"], r, semgrep_env())),
        ("semgrep scan (our rules, one-line sample)", _semgrep_scan),
        ("osv-scanner --version",
         lambda s, r: _run("osv-scanner --version", ["osv-scanner", "--version"], r,
                           _proc.tool_env())),
        (_OSV_SAMPLE, _osv_scan),
        ("guarddog --version",
         lambda s, r: _run("guarddog --version", ["guarddog", "--version"], r, _guarddog_env())),
        ("guarddog scan (one-line sample)", _guarddog_scan),
        ("uv --version", lambda s, r: _run("uv --version", ["uv", "--version"], r,
                                           _proc.tool_env())),
    ]  # fmt: skip
    return out


def run_checks(
    addon: bool = False, on_step: Callable[[str, list[Check]], None] | None = None
) -> list[Check]:
    """`addon`: also ask HA (through the Supervisor) for its version and HACS's list.
    `on_step(name, checks)` is called as each step ends, so a page can show progress."""
    checks: list[Check] = []
    with tempfile.TemporaryDirectory(prefix="sniff-doctor-") as tmp:
        work = Path(tmp)
        sample = work / "sample"
        sample.mkdir()
        (sample / "mod.py").write_text("x = 1\n", encoding="utf-8")
        (sample / ".semgrepignore").write_text("", encoding="utf-8")
        run_dir = work / "run"
        run_dir.mkdir()
        for name, fn in steps(addon):
            got = fn(sample, run_dir)
            got = got if isinstance(got, list) else [got]
            checks += got
            if on_step:
                on_step(name, got)
    return checks


def to_dicts(checks: list[Check]) -> list[dict]:
    return [{k: v for k, v in asdict(c).items() if k != "full_stdout"} for c in checks]
