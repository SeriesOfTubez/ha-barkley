"""Small HTTPS client for package indexes (stdlib only).

Package URLs come out of index responses, which an attacker can influence (a malicious
package's metadata, a lockfile). So every request is https-only, restricted to a short
allowlist of hosts, size-capped, and downloads are verified against the expected sha256.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from sniff_test import __version__

ALLOWED_HOSTS = frozenset(
    {
        "pypi.org",
        "files.pythonhosted.org",
        "wheels.home-assistant.io",
        # (0.7.4) newest release and its date for a card's vulnerable npm dependency
        "registry.npmjs.org",
    }
)
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
_TIMEOUT = 60


class HttpError(Exception):
    pass


class NotFoundError(HttpError):
    pass


class _AllowlistRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise HttpError(f"refusing to fetch {url!r}: not an allowed https package host")


def _open(url: str):
    _check_url(url)
    req = urllib.request.Request(url)  # noqa: S310 - scheme and host checked above
    req.add_header("User-Agent", f"sniff-test/{__version__}")
    opener = urllib.request.build_opener(_AllowlistRedirects())
    try:
        return opener.open(req, timeout=_TIMEOUT)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise NotFoundError(url) from e
        raise HttpError(f"HTTP {e.code} for {url}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise HttpError(f"network error for {url}: {e.reason}") from e
    except TimeoutError as e:
        raise HttpError(f"timeout for {url}") from e


def get_json(url: str) -> Any:
    with _open(url) as resp:
        data = resp.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise HttpError(f"response too large: {url}")
    try:
        return json.loads(data)
    except ValueError as e:
        raise HttpError(f"invalid JSON from {url}") from e


def download(url: str, dest: Path, sha256: str | None, max_bytes: int = MAX_DOWNLOAD_BYTES) -> str:
    """Stream url to dest (which must not exist). Verifies sha256 when given; returns it."""
    h = hashlib.sha256()
    total = 0
    try:
        with _open(url) as resp, dest.open("xb") as out:
            while chunk := resp.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise HttpError(f"download exceeds {max_bytes} bytes: {url}")
                h.update(chunk)
                out.write(chunk)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    digest = h.hexdigest()
    if sha256 and digest != sha256.lower():
        dest.unlink(missing_ok=True)
        raise HttpError(f"sha256 mismatch for {url}")
    return digest
