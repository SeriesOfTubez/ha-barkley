"""The one place we invoke `uv pip compile`. See python_deps for the safety rationale."""

from __future__ import annotations

import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

from sniff_test.analyzers import _proc
from sniff_test.deps.reqs import normalize

# From home-assistant/docker-base alpine/Dockerfile: EXTRA_INDEX_URL, exported as
# UV_EXTRA_INDEX_URL in the image. HA installs custom requirements with
# `--index-strategy unsafe-first-match` (homeassistant/util/package.py).
HA_WHEELS_INDEX = "https://wheels.home-assistant.io/musllinux-index/"
# HA OS / Container run the Alpine (musl) image; 32-bit arches were dropped in 2025.
PLATFORMS = {
    "x86_64": "x86_64-unknown-linux-musl",
    "aarch64": "aarch64-unknown-linux-musl",
}
TIMEOUT = 600


def exe() -> str | None:
    return shutil.which("uv")


def compile_lock(
    uv: str,
    req_file: Path,
    out: Path,
    *,
    constraints: Path,
    python_version: str,
    platform: str,
    cache_dir: Path,
    run_dir: Path,
    excludes: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Resolve req_file to a pylock.toml at `out` (name must be pylock[.<x>].toml).

    `--no-build` is uv's alias for `--only-binary :all:` (the two flags can't be combined):
    nothing is ever built, so no setup.py or build backend runs. The cache dir is ours
    alone, because uv will reuse previously *built* wheels from a shared cache.
    """
    cmd = [
        uv,
        "pip",
        "compile",
        "--no-config",
        str(req_file),
        "--constraints",
        str(constraints),
        "--python-version",
        python_version,
        "--python-platform",
        PLATFORMS[platform],
        "--no-build",
        "--index",
        HA_WHEELS_INDEX,
        "--index-strategy",
        "unsafe-first-match",
        "--format",
        "pylock.toml",
        "--no-header",
        "--quiet",
        "--cache-dir",
        str(cache_dir),
        "--output-file",
        str(out),
    ]
    if excludes is not None:
        cmd += ["--excludes", str(excludes)]
    # `--python-version` only sets the markers uv resolves for; it needs no interpreter of
    # that version. Without this, uv downloads a managed CPython of that version from
    # GitHub into ~/.local/share/uv and runs it (seen in the add-on image 2026-11-11:
    # 3.14.10 fetched during the first integration scan, since `tool_env` drops the
    # image's UV_PYTHON_DOWNLOADS). The image's own Python resolves the same lock.
    env = _proc.tool_env(UV_NO_PROGRESS="1", UV_PYTHON_DOWNLOADS="never")
    return _proc.run(cmd, run_dir, TIMEOUT, env)


@dataclass
class Artifact:
    url: str
    filename: str
    sha256: str | None
    kind: str  # "wheel" | "sdist"
    local: Path | None = None  # extracted directory, once fetched


def parse_pylock(path: Path) -> list[tuple[str, str, list[Artifact]]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out: list[tuple[str, str, list[Artifact]]] = []
    for pkg in data.get("packages", []):
        arts = []
        for w in pkg.get("wheels", []):
            url = str(w.get("url", ""))
            arts.append(
                Artifact(
                    url=url,
                    filename=url.rsplit("/", 1)[-1].split("#", 1)[0],
                    sha256=(w.get("hashes") or {}).get("sha256"),
                    kind="wheel",
                )
            )
        out.append((normalize(str(pkg["name"])), str(pkg.get("version", "")), arts))
    return out
