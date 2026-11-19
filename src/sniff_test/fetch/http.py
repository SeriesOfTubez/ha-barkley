"""Small HTTPS client for package indexes (stdlib only).

Package URLs come out of index responses, which an attacker can influence (a malicious
package's metadata, a lockfile). So every request is https-only, restricted to a short
allowlist of hosts, size-capped, and downloads are verified against the expected sha256.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from sniff_test import __version__
from sniff_test.fetch import retry

ALLOWED_HOSTS = frozenset(
    {
        "pypi.org",
        "files.pythonhosted.org",
        "wheels.home-assistant.io",
        # (0.7.4) newest release and its date for a card's vulnerable npm dependency;
        # (0.14.1) also a recognised library's publish date (analyzers/libraries.py)
        "registry.npmjs.org",
        # (0.14.1) analyzers/libraries.py, only with "Recognise published libraries" on:
        # the SHA-256 of an integration's larger JavaScript files (public code from the
        # app, never anything of the user's) to name an unchanged published npm file,
        # and that package's downloads last week. A failure means the file is read.
        "data.jsdelivr.com",
        "api.npmjs.org",
        # (0.14.1) the CVE record of a dependency's advisory (CVE id only), for CISA's
        # SSVC decision and KEV listing, which set its severity by exposure (osv.ssvc)
        "cveawg.mitre.org",
    }
)
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
_TIMEOUT = 60


class HttpError(Exception):
    """`status`: the HTTP status, if any; `kind`: a fixed reason for fetch.retry
    (not_found, too_big, checksum, refused); `failure`: set by retry.attempt."""

    status: int | None = None
    retry_after: float | None = None
    kind: str | None = None
    failure: retry.Failure | None = None


class NotFoundError(HttpError):
    kind = "not_found"
    status = 404


class _AllowlistRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        err = HttpError(f"refusing to fetch {url!r}: not an allowed https package host")
        err.kind = "refused"
        raise err


def _open(url: str, timeout: float = _TIMEOUT):
    _check_url(url)
    req = urllib.request.Request(url)  # noqa: S310 - scheme and host checked above
    req.add_header("User-Agent", f"sniff-test/{__version__}")
    opener = urllib.request.build_opener(_AllowlistRedirects())
    try:
        return opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise NotFoundError(f"HTTP 404 for {url}") from e
        err = HttpError(f"HTTP {e.code} for {url}: {e.reason}")
        err.status = e.code
        after = (e.headers.get("Retry-After") or "").strip() if e.headers else ""
        err.retry_after = float(after) if after.isdigit() else None
        raise err from e
    except urllib.error.URLError as e:
        raise HttpError(f"network error for {url}: {e.reason}") from e
    except TimeoutError as e:
        raise HttpError(f"timed out after {timeout} s: {url}") from e


def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or "?"


def get_json(url: str) -> Any:
    """The JSON at `url`, retried on transient errors (fetch.retry)."""
    return retry.attempt(
        lambda: _get_json_once(url),
        file=url.rsplit("/", 2)[-2] if url.endswith("/json") else url.rsplit("/", 1)[-1],
        source=_host(url),
        retry=(HttpError, OSError, http.client.HTTPException),
    )


def lookup_json(url: str, timeout: float, max_bytes: int = 8 * 1024 * 1024) -> Any | None:
    """(0.14.1) One try with a short timeout, no retry, for lookups where a failure only
    means "not recognised" (analyzers/libraries.py). None on 404; HttpError otherwise
    (a rate limit included: the caller reads the file, it never waits)."""
    try:
        with _open(url, timeout) as resp:
            data = resp.read(max_bytes + 1)
    except NotFoundError:
        return None
    except (OSError, http.client.HTTPException) as e:
        if isinstance(e, HttpError):
            raise
        raise HttpError(f"{type(e).__name__} for {url}") from e
    if len(data) > max_bytes:
        raise HttpError(f"response too large: {url}")
    try:
        return json.loads(data)
    except ValueError as e:
        raise HttpError(f"invalid JSON from {url}") from e


def _get_json_once(url: str) -> Any:
    with _open(url) as resp:
        data = resp.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise HttpError(f"response too large: {url}")
    try:
        return json.loads(data)
    except ValueError as e:
        raise HttpError(f"invalid JSON from {url}") from e


def download(url: str, dest: Path, sha256: str | None, max_bytes: int = MAX_DOWNLOAD_BYTES) -> str:
    """Stream url to dest (which must not exist). Verifies sha256 when given; returns it.
    Only this file is retried on a transient error (fetch.retry); the partial file is
    deleted between tries. A connection or read error is raised as HttpError."""

    def once() -> str:
        try:
            return _download_once(url, dest, sha256, max_bytes)
        except (OSError, http.client.HTTPException) as e:
            if isinstance(e, HttpError):
                raise
            raise HttpError(f"{type(e).__name__} while downloading {url}: {e}") from e

    return retry.attempt(
        once,
        file=urllib.parse.unquote(url.rsplit("/", 1)[-1].split("#", 1)[0]),
        source=_host(url),
        retry=(HttpError,),
    )


def _download_once(url: str, dest: Path, sha256: str | None, max_bytes: int) -> str:
    h = hashlib.sha256()
    total = 0
    try:
        with _open(url) as resp, dest.open("xb") as out:
            while chunk := resp.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    err = HttpError(f"bigger than {max_bytes // (1024 * 1024)} MB: {url}")
                    err.kind = "too_big"
                    raise err
                h.update(chunk)
                out.write(chunk)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    digest = h.hexdigest()
    if sha256 and digest != sha256.lower():
        dest.unlink(missing_ok=True)
        err = HttpError(f"sha256 mismatch for {url}")
        err.kind = "checksum"
        raise err
    return digest
