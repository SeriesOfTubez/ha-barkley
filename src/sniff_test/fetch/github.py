"""Minimal GitHub REST client (stdlib only)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
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
            raise GitHubError(f"GitHub {e.code} for {url}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise GitHubError(f"network error for {url}: {e.reason}") from e

    def get_json(self, path: str) -> Any:
        with self._request(f"{API}{path}") as resp:
            return json.load(resp)

    def get_text(self, path: str) -> str:
        with self._request(f"{API}{path}", accept="application/vnd.github.raw+json") as resp:
            return resp.read(5 * 1024 * 1024).decode("utf-8", "replace")

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
