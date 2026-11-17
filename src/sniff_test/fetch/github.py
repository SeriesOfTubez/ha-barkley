"""Minimal GitHub REST client (stdlib only)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sniff_test import __version__

API = "https://api.github.com"
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
_TIMEOUT = 60
_REPO_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<name>[\w.-]+?)(?:\.git)?/?$"
)
_OWNER_REPO = re.compile(r"^(?P<owner>[\w.-]+)/(?P<name>[\w.-]+)$")


class GitHubError(Exception):
    pass


class NotFoundError(GitHubError):
    pass


class RateLimitError(GitHubError):
    """GitHub's API budget is used up until `reset_at` (epoch seconds).

    Without a token GitHub allows 60 API requests an hour per IP address (304 answers to
    conditional requests count too, checked 2026-11-09), and a scan makes 6-7; with a
    token it's 5,000. Seen on the user's box without a token (2026-11-09): every job
    after the budget ran out failed with a 403. Callers that can wait (the add-on's
    worker) wait for `reset_at` and retry; the CLI says when it resets.
    """

    def __init__(self, url: str, reset_at: float, authenticated: bool):
        self.reset_at = reset_at
        self.authenticated = authenticated
        when = time.strftime("%H:%M UTC", time.gmtime(reset_at))
        budget = (
            "5,000 requests/hour with a token"
            if authenticated
            else ("60 requests/hour without a token")
        )
        super().__init__(
            f"GitHub's API limit is used up ({budget}); it resets at {when}"
            + ("" if authenticated else ". A GitHub token raises it to 5,000/hour")
            + f" [{url}]"
        )


@dataclass(frozen=True)
class RateLimit:
    remaining: int
    limit: int
    reset_at: float
    authenticated: bool


def parse_repo(source: str) -> tuple[str, str] | None:
    """Return (owner, name) for a GitHub URL or 'owner/name', else None."""
    for rx in (_REPO_URL, _OWNER_REPO):
        m = rx.match(source.strip())
        if m:
            return m["owner"], m["name"]
    return None


def _token() -> str | None:
    if tok := os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"):
        return tok
    if path := os.environ.get("GITHUB_TOKEN_FILE"):  # a container secret (standalone)
        try:
            return Path(path).read_text(encoding="utf-8")[:512].strip() or None
        except OSError:
            return None
    gh = shutil.which("gh")
    if not gh:
        return None
    try:
        out = subprocess.run(
            [gh, "auth", "token"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    tok = out.stdout.strip()
    return tok or None


def _rate_limit_reset(e: urllib.error.HTTPError) -> float | None:
    """When a 403/429 is GitHub's rate limit: the epoch second it lifts, else None."""
    h = e.headers
    if h is None:
        return None
    if (after := h.get("Retry-After")) and after.strip().isdigit():  # secondary limit
        return time.time() + int(after)
    if h.get("X-RateLimit-Remaining") == "0":
        reset = h.get("X-RateLimit-Reset", "")
        return float(reset) if reset.strip().isdigit() else time.time() + 60
    return None


class _NoCrossHostAuth(urllib.request.HTTPRedirectHandler):
    """Drop Authorization when a redirect leaves api.github.com (e.g. to codeload/S3)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).hostname != "api.github.com":
            new.remove_header("Authorization")
        return new


@dataclass
class GitHub:
    token: str | None = None

    @classmethod
    def from_env(cls) -> GitHub:
        return cls(token=_token())

    def _opener(self) -> urllib.request.OpenerDirector:
        return urllib.request.build_opener(_NoCrossHostAuth())

    def _request(self, url: str, accept: str = "application/vnd.github+json"):
        if not url.startswith("https://"):
            raise GitHubError(f"refusing non-https URL: {url}")
        req = urllib.request.Request(url)  # noqa: S310 - scheme checked above
        req.add_header("Accept", accept)
        req.add_header("User-Agent", f"sniff-test/{__version__}")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if self.token and urllib.parse.urlsplit(url).hostname == "api.github.com":
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            return self._opener().open(req, timeout=_TIMEOUT)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise NotFoundError(url) from e
            if e.code in (403, 429) and (reset := _rate_limit_reset(e)) is not None:
                raise RateLimitError(url, reset, bool(self.token)) from e
            raise GitHubError(f"GitHub {e.code} for {url}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise GitHubError(f"network error for {url}: {e.reason}") from e

    def get_json(self, path: str) -> Any:
        with self._request(f"{API}{path}") as resp:
            return json.load(resp)

    def get_text(self, path: str) -> str:
        with self._request(f"{API}{path}", accept="application/vnd.github.raw+json") as resp:
            return resp.read(5 * 1024 * 1024).decode("utf-8", "replace")

    def rate_limit(self) -> RateLimit | None:
        """The core API budget. GitHub doesn't count this request; None if unknown."""
        try:
            with self._request(f"{API}/rate_limit") as resp:
                core = json.load(resp)["resources"]["core"]
            return RateLimit(
                int(core["remaining"]), int(core["limit"]), float(core["reset"]), bool(self.token)
            )
        except (GitHubError, ValueError, KeyError, TypeError):
            return None

    def download(self, url: str, dest: Path, accept: str = "application/octet-stream") -> str:
        """Stream to dest with a size cap. Returns sha256 hex."""
        h = hashlib.sha256()
        total = 0
        with self._request(url, accept=accept) as resp, dest.open("xb") as out:
            while chunk := resp.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise GitHubError(f"download exceeds {MAX_DOWNLOAD_BYTES} bytes: {url}")
                h.update(chunk)
                out.write(chunk)
        return h.hexdigest()

    # --- convenience wrappers -------------------------------------------------

    def repo(self, owner: str, name: str) -> dict[str, Any]:
        return self.get_json(f"/repos/{owner}/{name}")

    def latest_release(self, owner: str, name: str) -> dict[str, Any] | None:
        try:
            return self.get_json(f"/repos/{owner}/{name}/releases/latest")
        except NotFoundError:
            return None

    def release_by_tag(self, owner: str, name: str, tag: str) -> dict[str, Any] | None:
        try:
            return self.get_json(
                f"/repos/{owner}/{name}/releases/tags/{urllib.parse.quote(tag, safe='')}"
            )
        except NotFoundError:
            return None

    def hacs_releases(self, owner: str, name: str) -> list[dict[str, Any]]:
        """The one page HACS 2.0 reads (`releases.list`, 30 per page, newest first)."""
        batch = self.get_json(f"/repos/{owner}/{name}/releases?per_page=30")
        return [r for r in batch if isinstance(r, dict)] if isinstance(batch, list) else []

    def releases(self, owner: str, name: str, max_pages: int = 5) -> list[dict[str, Any]]:
        """Newest first, drafts excluded (drafts are only visible with push access)."""
        out: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            batch = self.get_json(f"/repos/{owner}/{name}/releases?per_page=100&page={page}")
            if not isinstance(batch, list):
                break
            out.extend(r for r in batch if isinstance(r, dict) and not r.get("draft"))
            if len(batch) < 100:
                break
        return out

    def ref_date(self, owner: str, name: str, ref: str) -> str:
        """When `ref` came out: its release's publish date, else its commit date (UTC)."""
        if (release := self.release_by_tag(owner, name, ref)) and release.get("published_at"):
            return str(release["published_at"])
        data = self.get_json(f"/repos/{owner}/{name}/commits/{urllib.parse.quote(ref, safe='')}")
        return str(data["commit"]["committer"]["date"])

    def commit_sha(self, owner: str, name: str, ref: str) -> str:
        data = self.get_json(f"/repos/{owner}/{name}/commits/{urllib.parse.quote(ref, safe='')}")
        return data["sha"]

    def file_at(self, owner: str, name: str, path: str, ref: str) -> str | None:
        try:
            return self.get_text(
                f"/repos/{owner}/{name}/contents/{urllib.parse.quote(path)}"
                f"?ref={urllib.parse.quote(ref, safe='')}"
            )
        except NotFoundError:
            return None

    def tarball(self, owner: str, name: str, sha: str, dest: Path) -> str:
        return self.download(f"{API}/repos/{owner}/{name}/tarball/{sha}", dest, accept="*/*")
