"""(0.14.1, #18) A CPU without the x86-64-v2 instructions.

The scanner tools' bundled libraries are built for x86-64-v2. A virtual machine whose
CPU type hides those instructions (Proxmox's default `kvm64` CPU type does) can't load
them, and every scan fails with "CPU ISA level is lower than required". Barkley says so
in plain words, with the fix, on the scan and in Diagnostics.
"""

from __future__ import annotations

import platform
from pathlib import Path

LOADER_TEXT = "CPU ISA level is lower than required"
# The CPU flags x86-64-v2 adds over the baseline (as /proc/cpuinfo names them).
V2_FLAGS = ("cx16", "lahf_lm", "popcnt", "pni", "sse4_1", "sse4_2", "ssse3")
FIX = (
    "This machine's CPU, as Barkley sees it, lacks the x86-64-v2 instructions the "
    "scanner tools need. In a virtual machine, set its CPU type to one that passes them "
    "through (on Proxmox: x86-64-v2-AES or host), shut the VM down completely and start "
    "it again; a restart from inside isn't enough."
)


def missing_v2(cpuinfo: str | None = None, machine: str | None = None) -> list[str] | None:
    """The x86-64-v2 flags this CPU lacks ([] when it has them all), or None when that
    can't be told (not x86-64, or no /proc/cpuinfo)."""
    machine = machine if machine is not None else platform.machine()
    if machine not in ("x86_64", "AMD64"):
        return None
    if cpuinfo is None:
        try:
            cpuinfo = Path("/proc/cpuinfo").read_text()
        except OSError:
            return None
    for line in cpuinfo.splitlines():
        if line.startswith("flags"):
            flags = set(line.split(":", 1)[-1].split())
            return [f for f in V2_FLAGS if f not in flags]
    return None


def explain(detail: str) -> str:
    """`detail` with the fix added when a tool failed for this reason."""
    if LOADER_TEXT in detail and FIX not in detail:
        return f"{detail} {FIX}"
    return detail
