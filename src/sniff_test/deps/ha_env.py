"""The Home Assistant environment that custom-integration requirements get installed into.

For a given HA release we need:
- `homeassistant/package_constraints.txt`: HA passes it as `--constraint` to every
  requirement install;
- `.python-version`: the interpreter in the official image (wheels are tagged by it);
- `requirements.txt` + `requirements_all.txt`: the official image installs *all* of them
  (see core's Dockerfile), so their resolved tree is in every HA OS / Container install.
  A dependency that resolves to exactly one of those (name, version) pairs is the same
  package HA itself ships, and scanning it again is noise.

Everything is cached per version under the user cache dir; a release never changes.
"""

from __future__ import annotations

import json
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from sniff_test.deps import uv
from sniff_test.deps.reqs import ReqKind, constraint_names, normalize, parse
from sniff_test.fetch.github import GitHub, GitHubError
from sniff_test.paths import cache_root

HA_REPO = ("home-assistant", "core")
HA_WHEELS_INDEX = uv.HA_WHEELS_INDEX
_VERSION_RX = re.compile(r"^\d{4}\.\d{1,2}\.\d+(?:b\d+)?$")
# cache file name -> path in home-assistant/core
_FILES = {
    "package_constraints.txt": "homeassistant/package_constraints.txt",
    "python-version": ".python-version",
    "requirements.txt": "requirements.txt",
    "requirements_all.txt": "requirements_all.txt",
    "pyproject.toml": "pyproject.toml",  # Python version before .python-version existed
}


class HAEnvError(Exception):
    pass


@dataclass
class HAEnv:
    version: str
    python_version: str
    dir: Path
    constraints: dict[str, str | None]  # normalized name -> pinned version (or None)
    core_names: frozenset[str]  # every package named in requirements(_all).txt
    _shipped: dict[str, frozenset[tuple[str, str]] | None] = field(default_factory=dict)

    @property
    def constraints_path(self) -> Path:
        return self.dir / "package_constraints.txt"

    def is_known(self, name: str) -> bool:
        """Named by HA core itself: reviewed upstream, never a typosquat."""
        return name in self.constraints or name in self.core_names

    def known_names(self) -> frozenset[str]:
        names = set(self.constraints) | set(self.core_names)
        for plat in uv.PLATFORMS:
            names |= {n for n, _v in self.shipped(plat) or ()}
        return frozenset(names)

    def shipped(self, platform: str) -> frozenset[tuple[str, str]] | None:
        """(name, version) of every package in the official image, or None if unknown."""
        if platform in self._shipped:
            return self._shipped[platform]
        result = _load_shipped(self, platform)
        self._shipped[platform] = result
        return result

    def is_ha_provided(self, name: str, version: str, platforms: set[str]) -> bool:
        """True when this exact package version ships in HA's image on every platform."""
        if not platforms:
            return False
        for plat in platforms:
            shipped = self.shipped(plat)
            if shipped is None:  # couldn't resolve HA's own set: fall back to exact pins
                if self.constraints.get(name) != version:
                    return False
            elif (name, version) not in shipped:
                return False
        return True


def valid_version(version: str) -> bool:
    return bool(_VERSION_RX.match(version))


_CLASSIFIER = re.compile(r"Programming Language :: Python :: (3\.\d+)\b")


def _python_version(text: str | None, pyproject: str | None = None) -> str:
    """HA's Python: `.python-version`, else the newest Python classifier, else 3.13.

    `.python-version` appeared between HA 2025.6 and 2026.1. Checked on 2026-11-09
    against HA's own images: 2025.1.0 lists 3.12 and 3.13 and runs 3.13.1 (the newest
    classifier); 2026.1.0 lists 3.13 and 3.14 but runs 3.13.11, as its .python-version
    says, so that file wins whenever it exists. Matters for diffs of old releases
    (`--ha-version auto`): wheels and bytecode depend on the Python minor.
    """
    v = (text or "").strip()
    if re.fullmatch(r"3\.\d+(?:\.\d+)?", v):
        return v
    found = _CLASSIFIER.findall(pyproject or "")
    if found:
        return max(found, key=lambda x: int(x.split(".")[1]))
    return "3.13"


def _plain_lines(text: str) -> list[str]:
    """HA's own requirement files minus options (-r/-c) and comments."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith("-") and parse(line).kind is ReqKind.PLAIN:
            out.append(line)
    return out


def _load_shipped(env: HAEnv, platform: str) -> frozenset[tuple[str, str]] | None:
    cached = env.dir / f"shipped.{platform}.txt"
    if cached.is_file():
        return _read_shipped(cached)
    exe = uv.exe()
    if not exe:
        return None
    lines = _plain_lines((env.dir / "requirements.txt").read_text(encoding="utf-8"))
    lines += _plain_lines((env.dir / "requirements_all.txt").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="sniff-test-ha-") as tmp:
        t = Path(tmp)
        (t / "run").mkdir()
        req = t / "requirements.txt"
        req.write_text("\n".join(lines) + "\n", encoding="utf-8")
        out = t / "pylock.toml"
        try:
            proc = uv.compile_lock(
                exe,
                req,
                out,
                constraints=env.constraints_path,
                python_version=env.python_version,
                platform=platform,
                cache_dir=cache_root() / "uv",
                run_dir=t / "run",
            )
        except OSError:
            return None
        if proc.returncode != 0 or not out.is_file():
            return None
        pairs = sorted({(name, ver) for name, ver, _arts in uv.parse_pylock(out)})
    tmp_file = env.dir / f".shipped.{platform}.tmp"
    tmp_file.write_text("".join(f"{n}=={v}\n" for n, v in pairs), encoding="utf-8")
    tmp_file.replace(cached)
    return frozenset(pairs)


def _read_shipped(path: Path) -> frozenset[tuple[str, str]]:
    pairs = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        name, _, ver = line.partition("==")
        if name and ver:
            pairs.add((normalize(name), ver))
    return frozenset(pairs)


def _from_dir(version: str, d: Path) -> HAEnv:
    core = (d / "requirements.txt").read_text(encoding="utf-8")
    req_all = (d / "requirements_all.txt").read_text(encoding="utf-8")
    return HAEnv(
        version=version,
        python_version=_python_version(
            (d / "python-version").read_text(encoding="utf-8"),
            (d / "pyproject.toml").read_text(encoding="utf-8"),
        ),
        dir=d,
        constraints=constraint_names((d / "package_constraints.txt").read_text("utf-8")),
        core_names=frozenset(constraint_names(core)) | frozenset(constraint_names(req_all)),
    )


def load(version: str | None = None, gh: GitHub | None = None) -> HAEnv:
    gh = gh or GitHub.from_env()
    try:
        if version is None:
            release = gh.latest_release(*HA_REPO)
            if not release:
                raise HAEnvError("could not determine the latest Home Assistant release")
            version = str(release["tag_name"])
        if not valid_version(version):
            raise HAEnvError(f"not a Home Assistant version: {version!r} (want YYYY.M.P)")
        d = cache_root() / "ha" / version
        if all((d / n).is_file() for n in _FILES):
            return _from_dir(version, d)
        texts = {name: gh.file_at(*HA_REPO, path, version) for name, path in _FILES.items()}
    except GitHubError as e:
        raise HAEnvError(f"could not fetch Home Assistant {version or 'release'} data: {e}") from e
    if texts["package_constraints.txt"] is None:
        raise HAEnvError(f"Home Assistant {version} has no package_constraints.txt")
    d.mkdir(parents=True, exist_ok=True)
    for name, text in texts.items():
        tmp = d / f".{name}.tmp"
        tmp.write_text(text or "", encoding="utf-8")
        tmp.replace(d / name)
    return _from_dir(version, d)


_RELEASES_TTL = 24 * 3600


def _stable_releases(gh: GitHub) -> list[tuple[str, str]]:
    """(published_at, version) of HA's stable releases, newest first, cached a day."""
    path = cache_root() / "ha" / "releases.json"
    try:
        if time.time() - path.stat().st_mtime < _RELEASES_TTL:
            return [tuple(x) for x in json.loads(path.read_text(encoding="utf-8"))]
    except (OSError, ValueError):
        pass
    try:
        rels = gh.releases(*HA_REPO, max_pages=10)
    except GitHubError as e:
        raise HAEnvError(f"could not list Home Assistant releases: {e}") from e
    out = sorted(
        (
            (str(r["published_at"]), str(r["tag_name"]))
            for r in rels
            if not r.get("prerelease")
            and r.get("published_at")
            and valid_version(str(r.get("tag_name", "")))
        ),
        reverse=True,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(out), encoding="utf-8")
    tmp.replace(path)
    return out


def version_at(when: str, gh: GitHub | None = None) -> str:
    """The newest stable HA release published at or before `when` (ISO 8601, UTC).

    For the old side of `diff --from ... --ha-version auto`: the HA a user was most
    likely running when that release came out, so its pins resolve as they did then.
    """
    releases = _stable_releases(gh or GitHub.from_env())
    if not releases:
        raise HAEnvError("no Home Assistant releases found")
    for published, version in releases:  # newest first; ISO 8601 UTC sorts as text
        if published <= when:
            return version
    oldest = releases[-1]
    raise HAEnvError(
        f"{when[:10]} is older than the oldest Home Assistant release we list "
        f"({oldest[1]}, {oldest[0][:10]}); pass --ha-version YYYY.M.P"
    )
