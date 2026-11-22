"""(0.15, his decision 2026-11-21) How far behind a card's own npm packages are: for each
package its package.json lists, the newest release, its date and how many releases are
newer than the one in its lock file (or the lowest its version range allows). One
registry document per package, at most MAX_PACKAGES. Context on the package line only:
never a finding, and a lookup that fails (a rate limit, no answer) only leaves the line
without it. Names come from the scanned repo: checked against npm's naming rules before
they go into an address."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from sniff_test.analyzers import osv
from sniff_test.fetch import http

MAX_PACKAGES = 30
TIMEOUT = 10.0
_MAX_JSON = 4 * 1024 * 1024  # package.json / package-lock.json read from the repo
_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]{0,100}/)?[a-z0-9][a-z0-9._~-]{0,213}")
_PLAIN = re.compile(r"[\^~=v ]*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]{1,40})?)")


def _read(path: Path) -> dict[str, Any]:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > _MAX_JSON:
            return {}
        data = json.loads(path.read_text("utf-8", "replace"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _locked(lock: dict[str, Any], name: str) -> str | None:
    pkgs = lock.get("packages")
    if isinstance(pkgs, dict):  # lockfile v2/v3
        entry = pkgs.get(f"node_modules/{name}")
        if isinstance(entry, dict) and isinstance(entry.get("version"), str):
            return entry["version"]
    deps = lock.get("dependencies")  # lockfile v1
    if isinstance(deps, dict) and isinstance(deps.get(name), dict):
        v = deps[name].get("version")
        return v if isinstance(v, str) else None
    return None


def installed(source_root: Path) -> dict[str, str]:
    """Each package the card's package.json lists (`dependencies`) and its version: the
    lock file's, else the lowest the range allows (`^3.1.0` → 3.1.0); a range Barkley
    can't read (`*`, a URL, a tag) leaves the package out."""
    pkg = _read(source_root / "package.json")
    lock = _read(source_root / "package-lock.json")
    out: dict[str, str] = {}
    deps = pkg.get("dependencies")
    for name, spec in list(deps.items() if isinstance(deps, dict) else [])[:MAX_PACKAGES]:
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            continue
        v = _locked(lock, name)
        if v is None and isinstance(spec, str) and (m := _PLAIN.fullmatch(spec.strip())):
            v = m.group(1)
        if v:
            out[name] = v[:60]
    return out


def lookup(source_root: Path | None) -> dict[str, dict[str, Any]]:
    """name -> {newest, newest_date, newer} for the card's own packages."""
    if source_root is None:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for name, version in installed(source_root).items():
        try:
            doc = http.lookup_json(
                "https://registry.npmjs.org/" + name.replace("/", "%2F"), TIMEOUT
            )
        except http.HttpError:
            continue  # never a scan result: the line just has no "newest"
        newest, date, newer = osv.latest_from_meta(doc, "npm", version)
        if newest:
            out[name] = {"newest": newest[:40], "newer": newer, "installed": version,
                         **({"newest_date": date} if date else {})}  # fmt: skip
    return out
