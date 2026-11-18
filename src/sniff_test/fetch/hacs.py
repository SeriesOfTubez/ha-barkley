"""Work out exactly which bytes HACS would install, and fetch them.

Mirrors HACS's install logic closely enough for security purposes:
- version: the requested tag, else the latest (non-prerelease) release, else, as HACS does
  for repos without releases, the default branch, pinned here to its commit SHA;
- integrations: `zip_release` + `filename` -> that release asset; otherwise
  `custom_components/<domain>/` from the tag's source (or repo root with `content_in_root`);
- plugins (cards): every asset of the release (HACS installs them all), else `dist/`,
  else repo root.

We always also download the full source tree at the resolved commit (`source_root`),
which later analyzers use for lockfiles and release-vs-source comparison.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sniff_test.fetch.github import GitHub, parse_repo
from sniff_test.models import Category, Finding, Severity, Target, TargetKind
from sniff_test.workspace import copy_tree_safely, extract, new_subdir, single_top_dir


class FetchError(Exception):
    pass


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def detect_kind(source_root: Path, hacs: dict[str, Any]) -> TargetKind:
    if (source_root / "custom_components").is_dir():
        return TargetKind.INTEGRATION
    if hacs.get("content_in_root") and (source_root / "manifest.json").is_file():
        return TargetKind.INTEGRATION
    return TargetKind.PLUGIN


def integration_dir(source_root: Path, hacs: dict[str, Any]) -> tuple[Path, list[Finding]]:
    notes: list[Finding] = []
    if hacs.get("content_in_root"):
        return source_root, notes
    cc = source_root / "custom_components"
    subdirs = sorted(p for p in cc.iterdir() if p.is_dir()) if cc.is_dir() else []
    if not subdirs:
        raise FetchError("no custom_components/<domain>/ directory found")
    if len(subdirs) > 1:
        notes.append(
            Finding(
                rule_id="repo-multiple-integrations",
                title="Repository ships more than one integration directory",
                severity=Severity.INFO,
                category=Category.REPO,
                message=(
                    f"Found {len(subdirs)} directories under custom_components/; "
                    f"HACS installs only the first ({subdirs[0].name}). Only that one is scanned."
                ),
                analyzer="fetch",
            )
        )
    return subdirs[0], notes


def plugin_filenames(repo_name: str, hacs: dict[str, Any]) -> list[str]:
    base = repo_name.lower().removeprefix("lovelace-")
    names = [f"{base}.js", f"{base}.umd.js", f"{base}-bundle.js"]
    if fn := hacs.get("filename"):
        names.insert(0, str(fn))
    return names


def _manifest_domain(root: Path) -> str | None:
    domain = _read_json(root / "manifest.json").get("domain")
    return str(domain) if domain else None


def _plugin_from_tree(source_root: Path, names: list[str], dest: Path) -> bool:
    """Copy the card files HACS would pick from the repo tree into dest."""
    for location in (source_root / "dist", source_root):
        if not location.is_dir():
            continue
        present = {p.name.lower() for p in location.iterdir() if p.is_file()}
        if any(n.lower() in present for n in names):
            for p in location.iterdir():
                if p.is_file() and p.suffix in (".js", ".mjs", ".gz", ".map", ".json"):
                    (dest / p.name).write_bytes(p.read_bytes())
            return True
    # Fallback: any .js in dist/ (HACS would reject the repo, but scan what's there).
    js = sorted((source_root / "dist").glob("*.js")) if (source_root / "dist").is_dir() else []
    for p in js:
        (dest / p.name).write_bytes(p.read_bytes())
    return bool(js)


# (0.14.0) Limits for a card release's assets, now that all of them are fetched. One
# file was capped at github.MAX_DOWNLOAD_BYTES (256 MB) before; the whole set gets the
# same cap. Real chunked cards are far below both (102 assets, 5 MB; 51 assets, 3.4 MB).
MAX_RELEASE_ASSETS = 300
MAX_RELEASE_BYTES = 256 * 1024 * 1024


def _release_assets(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The assets to fetch, after the limits and a check of each name (a plain file
    name, as HACS writes it into the card's folder). Over a limit: FetchError, so the
    scan is never reported as if it had read everything."""
    if len(assets) > MAX_RELEASE_ASSETS:
        raise FetchError(
            f"The release has {len(assets)} files; HACS would install all of them and "
            f"Barkley reads at most {MAX_RELEASE_ASSETS}, so it can't check this version."
        )
    total = sum(int(a.get("size") or 0) for a in assets)
    if total > MAX_RELEASE_BYTES:
        raise FetchError(
            f"The release's files add up to {total // (1024 * 1024)} MB; Barkley reads at "
            f"most {MAX_RELEASE_BYTES // (1024 * 1024)} MB per version, so it can't check it."
        )
    for a in assets:
        n = str(a.get("name", ""))
        if not n or n in (".", "..") or "/" in n or "\\" in n or "\0" in n or len(n) > 255:
            raise FetchError(f"A release file has a name Barkley won't write: {n[:80]!r}")
    return assets


HACS_RELEASE_WINDOW = 30


def hacs_choice(
    releases: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """(default, beta): what HACS 2.0 installs, and what it offers with "show beta" on.

    HACS (`repositories/base.py`, `common_update_data`) walks the first page of
    `releases.list` (30, in API order), skips drafts, and installs the first
    non-prerelease as `last_version`. A prerelease listed before it is offered only
    with "show beta". No stable release in that window means the default branch. This
    is not GitHub's `/releases/latest`, which follows the "make latest" flag.
    """
    default = beta = None
    for r in releases[:HACS_RELEASE_WINDOW]:
        if r.get("draft"):
            continue
        if r.get("prerelease"):
            beta = beta or r
            continue
        default = r
        break
    return default, beta


def _no_release_note(default_branch: str, sha: str) -> Finding:
    return Finding(
        rule_id="repo-no-releases",
        title="No releases: HACS installs whatever is on the default branch",
        severity=Severity.LOW,
        category=Category.REPO,
        message=(
            f"The repository has no GitHub releases, so HACS installs the tip of "
            f"'{default_branch}'. Scanned commit {sha[:12]}; any later push changes what "
            f"you get, with no release step in between."
        ),
        analyzer="fetch",
    )


def fetch_remote(
    source: str,
    ws: Path,
    ref: str | None = None,
    kind: TargetKind | None = None,
    gh: GitHub | None = None,
) -> Target:
    parsed = parse_repo(source)
    if not parsed:
        raise FetchError(f"not a GitHub repository: {source}")
    owner, name = parsed
    gh = gh or GitHub.from_env()
    repo = gh.repo(owner, name)
    full_name: str = repo["full_name"]
    owner, name = full_name.split("/", 1)

    notes: list[Finding] = []
    if ref:
        release = gh.release_by_tag(owner, name, ref)
        install_source = "tag_source"
    else:
        release, _beta = hacs_choice(gh.hacs_releases(owner, name))
        if release:
            ref = release["tag_name"]
            install_source = "tag_source"
        else:
            ref = repo["default_branch"]
            install_source = "default_branch"
    sha = gh.commit_sha(owner, name, ref)
    if install_source == "default_branch":
        notes.append(_no_release_note(ref, sha))

    tarball = ws / "source.tar.gz"
    gh.tarball(owner, name, sha, tarball)
    src_dir = new_subdir(ws, "source")
    extract(tarball, src_dir)
    source_root = single_top_dir(src_dir)
    hacs = _read_json(source_root / "hacs.json")
    kind = kind or detect_kind(source_root, hacs)
    assets = {a["name"]: a for a in (release or {}).get("assets", [])}

    install = new_subdir(ws, "install")
    artifact_sha: str | None = None

    if kind is TargetKind.INTEGRATION:
        filename = hacs.get("filename")
        if hacs.get("zip_release") and filename and filename in assets:
            asset_path = ws / "asset.zip"
            artifact_sha = gh.download(assets[filename]["url"], asset_path)
            extract(asset_path, install)
            root = install
            install_source = "release_asset"
        else:
            if hacs.get("zip_release"):
                notes.append(
                    Finding(
                        rule_id="repo-release-asset-missing",
                        title="hacs.json expects a release zip that isn't attached",
                        severity=Severity.LOW,
                        category=Category.REPO,
                        message=(
                            f"hacs.json sets zip_release with filename={filename!r}, but release "
                            f"{ref!r} has no such asset. Scanned the tag source instead."
                        ),
                        analyzer="fetch",
                    )
                )
            root, more = integration_dir(source_root, hacs)
            notes += more
    else:
        names = [n.lower() for n in plugin_filenames(name, hacs)]
        if assets:
            # (0.14.0) HACS installs *every* asset of the release for a card (2.0.5,
            # `repositories/base.py` gather_files_to_download), and a card's file may
            # import the others (bundlers split code into chunks). 0.13.0 fetched only
            # the asset named like the card, so the chunks were never read.
            for a in _release_assets(list(assets.values())):
                digest = gh.download(a["url"], install / a["name"])
                if a["name"].lower() in names:  # the card's own file, as before
                    artifact_sha = digest
            install_source = "release_asset"
        elif not _plugin_from_tree(source_root, names, install):
            raise FetchError("could not locate a card .js file the way HACS would")
        root = install

    return Target(
        source=source,
        kind=kind,
        root=root,
        source_root=source_root,
        repo=full_name,
        ref=ref,
        commit_sha=sha,
        install_source=install_source,
        artifact_sha256=artifact_sha,
        domain=_manifest_domain(root) if kind is TargetKind.INTEGRATION else None,
        notes=notes,
        requested_repo=f"{parsed[0]}/{parsed[1]}",
        repo_meta=repo,
    )


def fetch_local(source: str, ws: Path, kind: TargetKind | None = None) -> Target:
    path = Path(source).expanduser().resolve()
    if not path.is_dir():
        raise FetchError(f"not a directory: {source}")
    src_dir = new_subdir(ws, "source")
    copy_tree_safely(path, src_dir)
    hacs = _read_json(src_dir / "hacs.json")
    kind = kind or detect_kind(src_dir, hacs)
    notes: list[Finding] = []
    if kind is TargetKind.INTEGRATION:
        root, notes = integration_dir(src_dir, hacs)
    else:
        install = new_subdir(ws, "install")
        if not _plugin_from_tree(src_dir, plugin_filenames(path.name, hacs), install):
            # Local scans are for development: fall back to every .js in the tree.
            root = src_dir
        else:
            root = install
    return Target(
        source=source,
        kind=kind,
        root=root,
        source_root=src_dir,
        install_source="local",
        domain=_manifest_domain(root) if kind is TargetKind.INTEGRATION else None,
        notes=notes,
    )


def fetch(source: str, ws: Path, ref: str | None = None, kind: TargetKind | None = None) -> Target:
    if Path(source).expanduser().exists():
        return fetch_local(source, ws, kind)
    return fetch_remote(source, ws, ref=ref, kind=kind)
