"""(0.15, his decision 2026-11-21/22) Apps the Marketplace has removed, and the ones it
removed as critical (a security problem), as a plain line on an app's page and a chip on
its card. Never a reading: it's the Marketplace's own word, shown as theirs.

The list is the Marketplace's public data file (the catalog Home Assistant 2026.11's
Marketplace reads, `marketplace/profiles.py`): one fixed https address, no redirects
followed, at most 2 MB, fetched at most once a day in the background and kept in
Barkley's cache. If it can't be fetched, nothing is shown (never a guess, never a scan
result). Panel only (logic.PANEL_ONLY): the scan never reads it.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

URL = "https://data-v2.hacs.xyz/removed/data.json"
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = 15.0
FRESH = 24 * 3600  # seconds a fetched list is used before asking again
RETRY = 3600  # after a failed fetch
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a redirect is an error: only the one fixed address is read


def _fetch() -> bytes:
    from sniff_test import __version__

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(URL, headers={"User-Agent": f"sniff-test/{__version__}"})
    with opener.open(req, timeout=TIMEOUT) as resp:  # a fixed https URL, no redirects
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("the Marketplace's removed list is larger than expected")
    return data


def parse(data: Any) -> dict[str, dict[str, str]]:
    """repo (lower case) -> {"type": critical | removed, "reason": text}. The reason is
    the Marketplace's text: kept short here, escaped by the page."""
    out: dict[str, dict[str, str]] = {}
    for x in data if isinstance(data, list) else []:
        if not isinstance(x, dict) or not _REPO.fullmatch(str(x.get("repository") or "")):
            continue
        kind = "critical" if x.get("removal_type") == "critical" else "removed"
        reason = str(x.get("reason") or "").strip()[:200]
        out[str(x["repository"]).lower()] = {"type": kind, "reason": reason}
    return out


class Listings:
    def __init__(self, cache: Path | None = None, fetch: Any = _fetch):
        from sniff_test import paths

        self.path = (cache or paths.cache_root()) / "marketplace-removed.json"
        self.fetch = fetch
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, str]] | None = None
        self._next = 0.0  # when to ask again
        self._busy = False

    def get(self, repo: str) -> dict[str, str] | None:
        """The listing for `repo`, or None. Starts a background refresh when due."""
        self._load_cached()
        self.refresh_soon()
        return (self._data or {}).get(repo.lower())

    def _load_cached(self) -> None:
        if self._data is not None:
            return
        try:
            raw = json.loads(self.path.read_text("utf-8"))
            self._data = parse(raw.get("list"))
            self._next = float(raw.get("at", 0)) + FRESH
        except (OSError, ValueError, AttributeError):
            self._data = {}

    def refresh_soon(self) -> None:
        with self._lock:
            if self._busy or time.time() < self._next:
                return
            self._busy = True
        threading.Thread(target=self.refresh, name="listings", daemon=True).start()

    def refresh(self) -> None:
        try:
            raw = json.loads(self.fetch())
            data = parse(raw)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"at": time.time(), "list": raw}), "utf-8")
            tmp.replace(self.path)
            self._data, self._next = data, time.time() + FRESH
        except Exception as ex:  # a failed fetch only means nothing is shown
            import sys

            print(f"marketplace removed list not fetched: {type(ex).__name__}", file=sys.stderr)
            self._next = time.time() + RETRY
        finally:
            with self._lock:
                self._busy = False


def note_html(listing: dict[str, str] | None) -> str:
    """The plain line for an app's page."""
    from sniff_test.ui import e, icon

    if not listing:
        return ""
    why = f" Their reason: {e(listing['reason'], 200)}" if listing.get("reason") else ""
    if listing["type"] == "critical":
        return (f'<div class="banner bad">{icon("alert", 16)} <b>The Marketplace removed this app '
                f"as critical, for a security problem.</b>{why}</div>")  # fmt: skip
    return f'<div class="banner">The Marketplace has removed this app.{why}</div>'


def chip(listing: dict[str, str] | None) -> tuple[str, str] | None:
    if not listing:
        return None
    if listing["type"] == "critical":
        return ("bad", "Removed as critical")
    return ("", "Removed from the Marketplace")
