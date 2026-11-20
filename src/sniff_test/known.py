"""Well-known services by host: who runs an address, in a few plain words.

The list ships with Barkley (`data/known_services.txt`) and is matched locally, so no
host from a scan is ever sent anywhere to be looked up. It adds a name to a host and
nothing else: no class, finding or score depends on it. The panel shows the name where
the host is listed.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from importlib import resources


@dataclass(frozen=True)
class Service:
    suffix: str
    name: str  # who runs it
    what: str  # what it is
    shared: bool = False  # customers get their own host under the suffix

    @property
    def label(self) -> str:
        return f"{self.name}, {self.what}"


@cache
def services() -> tuple[Service, ...]:
    text = (resources.files("sniff_test") / "data" / "known_services.txt").read_text("utf-8")
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) not in (3, 4) or (len(parts) == 4 and parts[3] != "shared"):
            raise ValueError(f"known_services.txt: bad line {line!r}")
        out.append(Service(parts[0].lower(), parts[1], parts[2], len(parts) == 4))
    # longest suffix first, so api.together.xyz wins over a shorter entry it sits under
    return tuple(sorted(out, key=lambda s: -len(s.suffix)))


def lookup(host: str | None) -> Service | None:
    host = (host or "").strip().strip(".").lower()
    if not host:
        return None
    for s in services():
        if host == s.suffix or host.endswith("." + s.suffix):
            return s
    return None
