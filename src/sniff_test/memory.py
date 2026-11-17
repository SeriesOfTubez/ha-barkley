"""Memory guard for the add-on: the Supervisor sets no per-add-on memory limit.

Semgrep is the memory hog, and HA shares the box. Before each scan we read
`MemAvailable` from /proc/meminfo (inside the container this is the whole box's
figure, since no cgroup limit applies) and:

- warn under ~2 GB available: the scan runs, the panel and Diagnostics say why it may
  be slow or get killed;
- refuse under ~1 GB: the scan doesn't start, so it can't push HA itself out of memory.

Standalone (a container next to HA or on another machine) the container may have a
memory limit (`docker run --memory`, compose `mem_limit`), and /proc/meminfo inside it
still shows the whole machine. So the cgroup's limit and use are read too (v2
`memory.max`/`memory.current`, v1 `memory.limit_in_bytes`/`memory.usage_in_bytes`,
page cache that can be dropped not counted), and the lower of the two figures wins.

The guard never touches a score: a refused scan simply doesn't exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

GIB = 1024**3
WARN_BELOW = 2 * GIB
REFUSE_BELOW = 1 * GIB
MEMINFO = Path("/proc/meminfo")
CGROUP = Path("/sys/fs/cgroup")
_UNLIMITED = 1 << 60  # cgroup v1 says "no limit" with a huge number


@dataclass(frozen=True, slots=True)
class Memory:
    level: str  # ok | warn | refuse | unknown
    available: int | None  # bytes
    total: int | None
    limited: bool = False  # `total` is the container's limit, not the machine's

    @property
    def refuse(self) -> bool:
        return self.level == "refuse"

    def message(self) -> str:
        if self.available is None:
            return "available memory unknown (no /proc/meminfo); scans run unguarded"
        of = "the container's limit of " if self.limited else ""
        have = f"{self.available / GIB:.1f} GB available of {of}{(self.total or 0) / GIB:.1f} GB"
        if self.level == "refuse":
            why = (
                "so the container isn't killed in the middle of one. Raise its memory limit"
                if self.limited
                else "to keep Home Assistant itself safe. Free some memory"
            )
            return (
                f"{have}: under {REFUSE_BELOW / GIB:.0f} GB, so scans are refused {why} "
                "and try again."
            )
        if self.level == "warn":
            return (
                f"{have}: under {WARN_BELOW / GIB:.0f} GB, so a big scan may be slow or be "
                "killed (it then shows as incomplete)."
            )
        return have


def parse(text: str) -> Memory:
    vals: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if key in ("MemTotal", "MemAvailable") and parts and parts[0].isdigit():
            unit = 1024 if len(parts) > 1 and parts[1].lower() == "kb" else 1
            vals[key] = int(parts[0]) * unit
    avail = vals.get("MemAvailable")
    if avail is None:
        return Memory("unknown", None, vals.get("MemTotal"))
    return Memory(_level(avail), avail, vals.get("MemTotal"))


def _level(avail: int) -> str:
    return "refuse" if avail < REFUSE_BELOW else "warn" if avail < WARN_BELOW else "ok"


def _read_int(path: Path) -> int | None:
    try:
        text = path.read_text().strip()
    except OSError:
        return None
    return int(text) if text.isdigit() else None


def _stat(path: Path, key: str) -> int:
    try:
        for line in path.read_text().splitlines():
            k, _, v = line.partition(" ")
            if k == key and v.strip().isdigit():
                return int(v)
    except OSError:
        pass
    return 0


def cgroup_limit(root: Path = CGROUP) -> tuple[int, int] | None:
    """(limit, in use) of this process's memory cgroup in bytes; None without a limit.
    Page cache the kernel can drop (inactive_file) isn't counted as in use."""
    for limit_f, used_f, stat_f, key in (
        ("memory.max", "memory.current", "memory.stat", "inactive_file"),  # v2
        ("memory/memory.limit_in_bytes", "memory/memory.usage_in_bytes",
         "memory/memory.stat", "total_inactive_file"),  # v1
    ):  # fmt: skip
        limit = _read_int(root / limit_f)  # v2 says "max" without a limit: None
        if limit is None or limit >= _UNLIMITED:
            continue
        used = _read_int(root / used_f) or 0
        return limit, max(0, used - _stat(root / stat_f, key))
    return None


def check(path: Path = MEMINFO, cgroup: Path = CGROUP) -> Memory:
    try:
        m = parse(path.read_text())
    except OSError:
        m = Memory("unknown", None, None)
    lim = cgroup_limit(cgroup)
    if lim is None or (m.total is not None and lim[0] >= m.total):
        return m
    limit, used = lim
    avail = max(0, limit - used)
    if m.available is not None:
        avail = min(avail, m.available)
    return Memory(_level(avail), avail, limit, limited=True)
