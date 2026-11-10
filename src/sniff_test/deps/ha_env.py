"""The Home Assistant environment that custom-integration requirements get installed into.

For a given HA release we need:
- `homeassistant/package_constraints.txt`: HA passes it as `--constraint` to every
  requirement install;
- `.python-version`: the interpreter in the official image (wheels are tagged by it);
- `requirements.txt` + `requirements_all.txt`: the official image installs *all* of them
  (see core's Dockerfile), so their resolved tree is in every HA OS / Container install.
  A dependency that resolves to exactly one of those (name, version) pairs is the same
  package HA itself ships, and scanning it again is noise.

The image's set is resolved *as of the HA release*: packages HA doesn't pin exactly
(transitive ones such as `regex`) keep getting new versions, and a resolution made today
would call today's newest `regex` "shipped by HA" when the image has an older one. HA
installs integration requirements with `uv pip install --upgrade`, which lifts such a
package to its newest version, so that newer copy is the integration's, not HA's, and
must be scanned. Checked 2026-11-10 against HA 2026.11.0's own image (x86_64): a plain
resolution matched 1636 of 1655 versions; dated, 1654 (the miss was uploaded 38 minutes
before the release, after the image was built). See `_dated_bounds`.

Everything is cached per version under the user cache dir; a release never changes.
"""

from __future__ import annotations

import json
import re
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from sniff_test.deps import uv
from sniff_test.deps.reqs import ReqKind, constraint_names, final_version_key, normalize, parse
from sniff_test.fetch import http
from sniff_test.fetch.github import GitHub, GitHubError, RateLimitError
from sniff_test.paths import atomic_write, cache_root

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


_SHIPPED_CACHE = "shipped-dated.{platform}.txt"  # older undated caches are ignored
_BOUNDS_CACHE = "dated-bounds.txt"
_RELEASED_AT = "released_at"  # the GitHub release's published_at ("" if unknown)
PYPI_JSON = "https://pypi.org/pypi/{name}/json"


class HAEnvError(Exception):
    pass


@dataclass
class HAEnv:
    version: str
    python_version: str
    dir: Path
    constraints: dict[str, str | None]  # normalized name -> pinned version (or None)
    core_names: frozenset[str]  # every package named in requirements(_all).txt
    released_at: str = ""  # the release's published_at (ISO 8601 UTC), "" if unknown
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


def _resolve(env: HAEnv, exe: str, platform: str, bounds: list[str]) -> dict[str, str] | None:
    """HA's requirements(_all).txt resolved under its constraints (+ `bounds`)."""
    lines = _plain_lines((env.dir / "requirements.txt").read_text(encoding="utf-8"))
    lines += _plain_lines((env.dir / "requirements_all.txt").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="sniff-test-ha-") as tmp:
        t = Path(tmp)
        (t / "run").mkdir()
        req = t / "requirements.txt"
        req.write_text("\n".join(lines) + "\n", encoding="utf-8")
        constraints = env.constraints_path
        if bounds:
            constraints = t / "constraints.txt"
            constraints.write_text(
                env.constraints_path.read_text(encoding="utf-8") + "\n" + "\n".join(bounds) + "\n",
                encoding="utf-8",
            )
        out = t / "pylock.toml"
        try:
            proc = uv.compile_lock(
                exe,
                req,
                out,
                constraints=constraints,
                python_version=env.python_version,
                platform=platform,
                cache_dir=cache_root() / "uv",
                run_dir=t / "run",
            )
        except OSError:
            return None
        if proc.returncode != 0 or not out.is_file():
            return None
        return {normalize(name): ver for name, ver, _arts in uv.parse_pylock(out)}


def _exact_pins(env: HAEnv) -> frozenset[str]:
    """Names HA pins to one version (`==`) in any of its three files: never dated."""
    names = set()
    for f in ("package_constraints.txt", "requirements.txt", "requirements_all.txt"):
        for name, pin in constraint_names((env.dir / f).read_text(encoding="utf-8")).items():
            if pin:
                names.add(normalize(name))
    return frozenset(names)


def newest_at(meta: dict, at: str, at_most: str) -> str | None:
    """The newest final release <= `at_most` whose first file was uploaded by `at`."""
    best: tuple[tuple, str] | None = None
    ceiling = final_version_key(at_most)
    if ceiling is None:
        return None
    for ver, files in (meta.get("releases") or {}).items():
        times = [
            f.get("upload_time_iso_8601") or ""
            for f in files or []
            if isinstance(f, dict) and not f.get("yanked")
        ]
        times = [x for x in times if x]
        if not times or min(times) > at:
            continue
        v = final_version_key(ver)
        if v is None or v > ceiling:
            continue
        if best is None or v > best[0]:
            best = (v, ver)
    return best[1] if best else None


def _dated_bounds(env: HAEnv, resolved: dict[str, str]) -> list[str] | None:
    """`name<=version` for unpinned packages that got a new release after HA's release.

    One PyPI JSON request per package HA doesn't pin exactly (about 400 for 2026.11.0),
    once per HA version: the bounds are cached and shared by both platforms. None when
    the release date is unknown or a lookup failed (then nothing is cached, so the next
    scan tries again; until then the plain resolution is used, as before).
    """
    cached = env.dir / _BOUNDS_CACHE
    if cached.is_file():
        return [x for x in cached.read_text(encoding="utf-8").splitlines() if x]
    at = env.released_at
    if not at:
        return None
    pins = _exact_pins(env)
    todo = sorted(n for n in resolved if n not in pins)

    def lookup(name: str) -> tuple[str, str | None, bool]:
        try:
            meta = http.get_json(PYPI_JSON.format(name=name))
        except http.NotFoundError:
            return name, None, True  # only on HA's wheel index: nothing to date
        except http.HttpError:
            return name, None, False
        return name, newest_at(meta, at, resolved[name]), True

    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lookup, todo))
    if not all(ok for _n, _v, ok in results):
        return None
    bounds = sorted(
        f"{n}<={v}"
        for n, v, _ok in results
        if v is not None and final_version_key(v) < final_version_key(resolved[n])
    )
    atomic_write(cached, "".join(b + "\n" for b in bounds))
    return bounds


def _load_shipped(env: HAEnv, platform: str) -> frozenset[tuple[str, str]] | None:
    cached = env.dir / _SHIPPED_CACHE.format(platform=platform)
    if cached.is_file():
        return _read_shipped(cached)
    exe = uv.exe()
    if not exe:
        return None
    resolved = _resolve(env, exe, platform, [])
    if resolved is None:
        return None
    bounds = _dated_bounds(env, resolved)
    if bounds:
        dated = _resolve(env, exe, platform, bounds)
        if dated is None:
            bounds = None  # the bounds don't resolve together: keep the plain set, uncached
        else:
            resolved = dated
    pairs = sorted(resolved.items())
    if bounds is not None:
        atomic_write(cached, "".join(f"{n}=={v}\n" for n, v in pairs))
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
        released_at=(d / _RELEASED_AT).read_text(encoding="utf-8").strip()
        if (d / _RELEASED_AT).is_file()
        else "",
    )


def _fetch_released_at(gh: GitHub, version: str) -> str | None:
    """The release's published_at; "" when there is no such release; None on an error.

    An error isn't cached (None), so the next load asks again; meanwhile the shipped
    set is resolved undated and not cached either. A rate limit goes through.
    """
    try:
        rel = gh.release_by_tag(*HA_REPO, version)
    except RateLimitError:
        raise
    except GitHubError:
        return None
    return str((rel or {}).get("published_at") or "")


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
            if not (d / _RELEASED_AT).is_file():  # caches from before 0.7.0
                released = _fetch_released_at(gh, version)
                if released is not None:
                    atomic_write(d / _RELEASED_AT, released)
            return _from_dir(version, d)
        texts = {name: gh.file_at(*HA_REPO, path, version) for name, path in _FILES.items()}
        released = _fetch_released_at(gh, version)
    except RateLimitError:
        raise  # not "no HA data": the caller waits for GitHub and scans again
    except GitHubError as e:
        raise HAEnvError(f"could not fetch Home Assistant {version or 'release'} data: {e}") from e
    if texts["package_constraints.txt"] is None:
        raise HAEnvError(f"Home Assistant {version} has no package_constraints.txt")
    d.mkdir(parents=True, exist_ok=True)
    for name, text in texts.items():
        atomic_write(d / name, text or "")
    if released is not None:
        atomic_write(d / _RELEASED_AT, released)
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
    except RateLimitError:
        raise
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
    atomic_write(path, json.dumps(out))
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
