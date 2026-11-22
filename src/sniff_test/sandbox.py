"""Landlock: every scanner tool runs in a sandbox Barkley sets up itself.

Semgrep, osv-scanner and uv parse hostile files. If one of them is exploited,
it must not be able to read Home Assistant's token or the scan store, change other
scans, run what it downloaded, or call home on any port. In the add-on the AppArmor
profile does part of this; standalone (plain Docker, maybe no AppArmor at all) nothing
would. Landlock is a Linux security module (kernel 5.13+) that an unprivileged process
applies to itself, so it works the same in the add-on, in Docker on any host, and on
Docker Desktop, with nothing to install on the host.

How: a tool doesn't start directly. `python -I -m sniff_test.sandbox --policy JSON --
TOOL ARGS` sets no_new_privs, builds a Landlock ruleset from the policy, restricts
itself, and execs the tool; the restriction holds for the tool and everything it starts,
and can't be undone. (Not `preexec_fn`: the panel runs scans in threads, and Python
code between fork and exec isn't safe there.) If the wrapper can't restrict itself it
exits 125 and the tool never runs.

What a tool gets (`policy_for`):
- read and execute: the system and the image (/usr, /bin, /lib, /opt, ...);
- read only: /etc, /proc, /sys, /dev; read and write /dev/null and /dev/shm;
- read and write, nothing executable: its own scan's workspace (HOME and TMPDIR are
  moved inside it), plus per tool: uv its package cache (read-only HA constraints);
- osv-scanner only: folder listings from / down (it opens / first), no file contents;
- TCP (Landlock ABI 4+): connect to port 443 only (uv, osv-scanner), nothing
  at all for Semgrep; no listening. DNS is UDP, which Landlock doesn't cover;
- signals and abstract unix sockets scoped (ABI 6+): it can't signal or connect to
  anything outside its own sandbox;
- Landlock also stops ptrace-level access to processes outside the sandbox, so
  /proc/<Barkley's pid>/environ (where an add-on's SUPERVISOR_TOKEN lives) can't be read.

Not covered: hosts (only ports), UDP, reading the image's own files.

Without Landlock (HA OS has none), the app's AppArmor profile does the same job: each
tool starts through `APPARMOR_LAUNCHER`, a two-line script that the profile sends into
its child profile `tools` (apparmor.txt), which grants what scanning needs and nothing
that holds a credential: no /run (s6 keeps SUPERVISOR_TOKEN there), no options.json or
token file, no scan store, no writes under /etc. The two never stack: with Landlock the
wrapper sets no_new_privs, and the kernel refuses a move into another AppArmor profile
after that. Neither one (`mode()` "none"): serve refuses to start unless
BARKLEY_UNSANDBOXED=1.
"""

from __future__ import annotations

import ctypes
import functools
import json
import os
import platform
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Syscall numbers: the same on every architecture (added after the syscall table merge).
_SYS_CREATE, _SYS_ADD, _SYS_RESTRICT = 444, 445, 446
_PR_SET_NO_NEW_PRIVS = 38
_CREATE_VERSION = 1  # LANDLOCK_CREATE_RULESET_VERSION
_RULE_PATH, _RULE_PORT = 1, 2

EXECUTE, WRITE_FILE, READ_FILE, READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
REFER, TRUNCATE, IOCTL_DEV = 1 << 13, 1 << 14, 1 << 15
_FILE_RIGHTS = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV
NET_BIND, NET_CONNECT = 1 << 0, 1 << 1
SCOPE_ABSTRACT_UNIX, SCOPE_SIGNAL = 1 << 0, 1 << 1

READ = READ_FILE | READ_DIR
RX = READ | EXECUTE

UNSANDBOXED_ENV = "BARKLEY_UNSANDBOXED"
EXIT_SANDBOX_FAILED = 125

_SYSTEM_RX = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt")
_SYSTEM_READ = ("/etc", "/proc", "/sys", "/dev")
_DEV_RW = ("/dev/null", "/dev/shm")  # noqa: S108 - shared memory for multiprocessing
HTTPS = 443


class SandboxError(Exception):
    pass


@dataclass(frozen=True)
class Policy:
    rx: tuple[str, ...] = ()
    read: tuple[str, ...] = ()
    write: tuple[str, ...] = ()
    list: tuple[str, ...] = ()  # folder names only, no file contents
    connect: tuple[int, ...] = ()
    env: dict[str, str] = field(default_factory=dict)  # HOME/TMPDIR inside the workspace


# --- the kernel side ----------------------------------------------------------------------


class _PathBeneath(ctypes.Structure):
    # The kernel's struct landlock_path_beneath_attr is __attribute__((packed)): 12 bytes,
    # parent_fd at offset 8. ctypes packs only with the "ms" layout (gcc-sysv refuses
    # _pack_), which gives exactly that here; Python 3.14 wants it named.
    # tests/test_sandbox.py checks the size and offsets.
    _layout_ = "ms"
    _pack_ = 1
    _fields_ = (("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32))


class _NetPort(ctypes.Structure):
    _layout_ = "gcc-sysv"
    _fields_ = (("allowed_access", ctypes.c_uint64), ("port", ctypes.c_uint64))


class _RulesetAttr(ctypes.Structure):
    _fields_ = (
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    )


def _libc() -> ctypes.CDLL | None:
    if platform.system() != "Linux":
        return None
    try:
        return ctypes.CDLL(None, use_errno=True)
    except OSError:
        return None


def abi() -> int:
    """The kernel's Landlock ABI version; 0 when there is none (not Linux, an older
    kernel, Landlock not enabled, or the syscall filtered by seccomp)."""
    libc = _libc()
    if libc is None:
        return 0
    v = libc.syscall(ctypes.c_long(_SYS_CREATE), None, ctypes.c_size_t(0),
                     ctypes.c_uint32(_CREATE_VERSION))  # fmt: skip
    return v if v > 0 else 0


def handled_fs(version: int) -> int:
    rights = (1 << 13) - 1  # ABI 1: EXECUTE ... MAKE_SYM
    if version >= 2:
        rights |= REFER
    if version >= 3:
        rights |= TRUNCATE
    if version >= 5:
        rights |= IOCTL_DEV
    return rights


def _rw(version: int) -> int:
    return handled_fs(version) & ~EXECUTE


def restrict(policy: Policy, version: int | None = None) -> int:
    """Restrict this process (and what it execs) to `policy`. Returns the ABI used.
    Raises SandboxError; the caller must not go on unsandboxed."""
    libc = _libc()
    version = abi() if version is None else version
    if libc is None or version <= 0:
        raise SandboxError("Landlock isn't available on this kernel")
    fs = handled_fs(version)
    attr = _RulesetAttr(fs, (NET_BIND | NET_CONNECT) if version >= 4 else 0,
                        (SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL) if version >= 6 else 0)  # fmt: skip
    size = 24 if version >= 6 else 16 if version >= 4 else 8
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SandboxError(f"no_new_privs: {os.strerror(ctypes.get_errno())}")
    fd = libc.syscall(ctypes.c_long(_SYS_CREATE), ctypes.byref(attr), ctypes.c_size_t(size),
                      ctypes.c_uint32(0))  # fmt: skip
    if fd < 0:
        raise SandboxError(f"landlock_create_ruleset: {os.strerror(ctypes.get_errno())}")
    try:
        for paths, access in ((policy.rx, RX), (policy.read, READ), (policy.write, _rw(version)),
                              (policy.list, READ_DIR)):  # fmt: skip
            for p in paths:
                _add_path(libc, fd, p, access & fs)
        if version >= 4:
            for port in policy.connect:
                rule = _NetPort(NET_CONNECT, port)
                if libc.syscall(ctypes.c_long(_SYS_ADD), ctypes.c_int(fd), ctypes.c_int(_RULE_PORT),
                                ctypes.byref(rule), ctypes.c_uint32(0)) != 0:  # fmt: skip
                    raise SandboxError(f"port {port}: {os.strerror(ctypes.get_errno())}")
        if libc.syscall(ctypes.c_long(_SYS_RESTRICT), ctypes.c_int(fd), ctypes.c_uint32(0)) != 0:
            raise SandboxError(f"landlock_restrict_self: {os.strerror(ctypes.get_errno())}")
    finally:
        os.close(fd)
    return version


def _add_path(libc: ctypes.CDLL, ruleset: int, path: str, access: int) -> None:
    try:
        pfd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except FileNotFoundError:
        return  # a listed folder this system doesn't have (/lib64, /sbin)
    except OSError as ex:
        raise SandboxError(f"{path}: {ex.strerror}") from ex
    try:
        if not Path(path).is_dir():
            access &= _FILE_RIGHTS
        rule = _PathBeneath(access, pfd)
        if libc.syscall(ctypes.c_long(_SYS_ADD), ctypes.c_int(ruleset), ctypes.c_int(_RULE_PATH),
                        ctypes.byref(rule), ctypes.c_uint32(0)) != 0:  # fmt: skip
            raise SandboxError(f"{path}: {os.strerror(ctypes.get_errno())}")
    finally:
        os.close(pfd)


# --- policies -------------------------------------------------------------------------------


def _install_roots(exe: str | None) -> list[str]:
    """Where a tool outside the system folders lives (a dev machine's ~/.local install):
    its resolved folder's parent, and the Python a venv there points at."""
    if not exe:
        return []
    real = Path(exe).resolve()
    root = real.parent.parent
    out = [str(root)]
    cfg = root / "pyvenv.cfg"
    try:
        for line in cfg.read_text().splitlines():
            k, _, v = line.partition("=")
            if k.strip() == "home" and v.strip():
                out.append(str(Path(v.strip()).resolve().parent))
    except OSError:
        pass
    return out


def workspace_of(cwd: Path) -> Path:
    """The scan's workspace: the folder directly under the temp folder that holds `cwd`
    (every workspace is a mkdtemp there). Outside it, `cwd` itself."""
    tmp = Path(tempfile.gettempdir()).resolve()
    cwd = cwd.resolve()
    if cwd.is_relative_to(tmp) and cwd != tmp:
        return tmp / cwd.relative_to(tmp).parts[0]
    return cwd


def policy_for(
    tool: str,
    cwd: Path,
    exe: str | None = None,
    write: tuple[Path, ...] = (),
    read: tuple[Path, ...] = (),
) -> Policy:
    """The policy for one run of `tool` (semgrep | uv | osv-scanner) from `cwd`."""
    ws = workspace_of(cwd)
    home, tmp = ws / ".tool-home", ws / ".tool-tmp"
    # Landlock can only grant a folder that exists, and a tool can't create its own cache
    # folder in a parent it may not write (uv's /data/cache/uv on a fresh standalone
    # install, 2026-11-18). Barkley's own folders, so Barkley makes them first.
    for d in (home, tmp, *write):
        Path(d).mkdir(parents=True, exist_ok=True)
    rx = [*_SYSTEM_RX, sys.prefix, sys.base_prefix, *_install_roots(exe)]
    return Policy(
        rx=tuple(dict.fromkeys(rx)),
        read=tuple(dict.fromkeys([*_SYSTEM_READ, *map(str, read)])),
        write=tuple(dict.fromkeys([*_DEV_RW, str(ws), *map(str, write)])),
        # osv-scanner 2.7.1 opens `/` before the lockfile (the 0.10.3 AppArmor failure).
        # A Landlock rule covers a whole tree, so it may list folder names anywhere, but
        # reads no file beyond its other rules.
        list=("/",) if tool == "osv-scanner" else (),
        connect=() if tool == "semgrep" else (HTTPS,),
        env={"HOME": str(home), "TMPDIR": str(tmp)},
    )


# --- using it ---------------------------------------------------------------------------------


def wrap(cmd: list[str], policy: Policy) -> list[str]:
    """`cmd` run through the sandbox wrapper."""
    spec = json.dumps({k: v for k, v in asdict(policy).items() if k != "env"})
    return [sys.executable, "-I", "-m", "sniff_test.sandbox", "--policy", spec, "--", *cmd]


# The app's launcher into its AppArmor child profile `tools` (rootfs; apparmor.txt).
APPARMOR_LAUNCHER = "/usr/lib/barkley/tool"
APPARMOR_CHILD = "tools"
# The Supervisor names the app's profile after its id: local_sniff_test, <hash>_sniff_test.
_APP_PROFILE_SUFFIX = "_sniff_test"


def apparmor_label() -> str | None:
    """The AppArmor profile this process runs under ("local_sniff_test"), without the
    mode; None when there is none to read (not Linux, no AppArmor, unconfined)."""
    for f in ("/proc/self/attr/apparmor/current", "/proc/self/attr/current"):
        try:
            text = Path(f).read_text(encoding="utf-8", errors="replace").strip("\x00\n ")
        except OSError:
            continue
        label = text.split(" (", 1)[0].strip()
        if label and label != "unconfined":
            return label
    return None


def no_new_privs() -> bool:
    """Is no_new_privs already set on this process (Docker's no-new-privileges)?"""
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("NoNewPrivs:"):
                return line.split(":", 1)[1].strip() == "1"
    except OSError:
        pass
    return False


def mode() -> str:
    """How the scanner tools are sandboxed here: "landlock", "apparmor" (the app's
    profile on a kernel without Landlock) or "none"."""
    if abi() > 0:
        return "landlock"
    label = apparmor_label()
    if (
        label
        and label.endswith(_APP_PROFILE_SUFFIX)
        and "//" not in label
        and not no_new_privs()  # the kernel refuses the move into `tools` then
        and apparmor_child_works()
    ):
        return "apparmor"
    return "none"


@functools.cache
def apparmor_child_works() -> bool:
    """Does a program started through the launcher really run in `tools`? Asked once:
    `cat` reads its own label. A profile that didn't load (a Rebuild doesn't reload it)
    or a refused move says no, and then no tool runs (fail closed)."""
    if not os.access(APPARMOR_LAUNCHER, os.X_OK):
        return False
    try:
        out = subprocess.run(  # fixed paths, no input
            [APPARMOR_LAUNCHER, "/bin/cat", "/proc/self/attr/current"],
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/bin:/bin"},
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    label = out.stdout.strip("\x00\n ").split(" (", 1)[0]
    return out.returncode == 0 and label.endswith("//" + APPARMOR_CHILD)


def status() -> tuple[int, str]:
    """(ABI, one line for Diagnostics). ABI is 0 without Landlock."""
    v = abi()
    if v:
        net = "ports limited" if v >= 4 else "ports NOT limited (kernel too old for that)"
        return v, f"Landlock ABI {v}: each scanner tool is sandboxed (files, {net})"
    if mode() == "apparmor":
        return 0, (
            "no Landlock in this kernel: each scanner tool runs in the app's AppArmor "
            f"profile for tools ({APPARMOR_CHILD})"
        )
    if platform.system() != "Linux":
        why = "not Linux"
    elif apparmor_label() and no_new_privs():
        why = (
            "no Landlock in this kernel, and no-new-privileges is set, so the tools "
            "can't enter the app's AppArmor profile for them"
        )
    else:
        why = "no Landlock in this kernel, and no AppArmor profile of the app's"
    return 0, f"scanner tools are NOT sandboxed ({why})"


def enabled() -> bool:
    """Is there a sandbox for the scanner tools here?"""
    return mode() != "none"


def apparmor_wrap(cmd: list[str]) -> list[str]:
    """`cmd` started through the launcher, so it runs in the `tools` profile."""
    return [APPARMOR_LAUNCHER, *cmd]


def main(argv: list[str]) -> int:
    if len(argv) < 4 or argv[0] != "--policy" or argv[2] != "--":
        print("usage: python -m sniff_test.sandbox --policy JSON -- CMD ...", file=sys.stderr)
        return 2
    try:
        spec = json.loads(argv[1])
        keys = ("rx", "read", "write", "list", "connect")
        policy = Policy(**{k: tuple(spec.get(k, ())) for k in keys})
        restrict(policy)
    except (SandboxError, ValueError, TypeError) as ex:
        print(f"sandbox: {ex}; not running {argv[3]}", file=sys.stderr)
        return EXIT_SANDBOX_FAILED
    cmd = argv[3:]
    if not Path(cmd[0]).is_absolute():  # _proc.sandboxed resolves it; no PATH lookup here
        print(f"sandbox: {cmd[0]} is not an absolute path", file=sys.stderr)
        return 2
    try:
        os.execv(cmd[0], cmd)  # noqa: S606 - the tool's own resolved path, no shell
    except OSError as ex:
        print(f"sandbox: can't run {cmd[0]}: {ex.strerror}", file=sys.stderr)
        return 127
    return 0  # pragma: no cover - exec doesn't return


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
