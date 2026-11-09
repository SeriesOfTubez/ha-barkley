"""Memory guard for the add-on: the Supervisor sets no per-add-on memory limit.

Semgrep is the memory hog, and HA shares the box. Before each scan we read
`MemAvailable` from /proc/meminfo (inside the container this is the whole box's
figure, since no cgroup limit applies) and:

- warn under ~2 GB available: the scan runs, the panel and Diagnostics say why it may
  be slow or get killed;
- refuse under ~1 GB: the scan doesn't start, so it can't push HA itself out of memory.

The guard never touches a score: a refused scan simply doesn't exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

GIB = 1024**3
WARN_BELOW = 2 * GIB
REFUSE_BELOW = 1 * GIB
MEMINFO = Path("/proc/meminfo")


@dataclass(frozen=True, slots=True)
class Memory:
    level: str  # ok | warn | refuse | unknown
    available: int | None  # bytes
    total: int | None

    @property
    def refuse(self) -> bool:
        return self.level == "refuse"

    def message(self) -> str:
        if self.available is None:
            return "available memory unknown (no /proc/meminfo); scans run unguarded"
        have = f"{self.available / GIB:.1f} GB available of {(self.total or 0) / GIB:.1f} GB"
        if self.level == "refuse":
            return (
                f"{have}: under {REFUSE_BELOW / GIB:.0f} GB, so scans are refused "
                "to keep Home Assistant itself safe. Free some memory and try again."
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
    level = "refuse" if avail < REFUSE_BELOW else "warn" if avail < WARN_BELOW else "ok"
    return Memory(level, avail, vals.get("MemTotal"))


def check(path: Path = MEMINFO) -> Memory:
    try:
        return parse(path.read_text())
    except OSError:
        return Memory("unknown", None, None)
