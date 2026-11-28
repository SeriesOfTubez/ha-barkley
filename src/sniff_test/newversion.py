"""(0.15, his decision 2026-11-27) Standalone: say when a newer Barkley is out.

As a Home Assistant app, the Supervisor shows Barkley's updates itself. Standalone,
nothing did, and the compose file pins one version. With Settings → New Barkley
versions on (the default), the panel asks GitHub for Barkley's latest release once a
day. A newer one shows a banner on the list with the exact image to use, and one Home
Assistant notification per version. Off: Barkley doesn't ask.

The image's owner is the owner of the repository that answered (ghcr.io/<owner>/barkley,
as build.yaml publishes it). Moving the repository to the ha-barkley organization
therefore names the new image without a change here. The banner says so when that
differs from the image this version was published as (IMAGE, which tests keep equal to
config.yaml's `image`).

Only GitHub's "latest" release counts (never a draft or a pre-release), and only a tag
that is a plain version (0.16.0 or v0.16.0) newer than this one. If nothing can be
fetched, nothing is shown. Panel only (logic.PANEL_ONLY): the scan never reads it.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from typing import Any

# the organization first; until the repository moves there, the personal account
REPOS = ("ha-barkley/ha-barkley", "SeriesOfTubez/ha-barkley")
IMAGE = "ghcr.io/seriesoftubez/barkley"  # the image this version was published as
KEY = "new_version"  # the store setting: the last answer, and the version notified
FRESH = 24 * 3600  # seconds an answer is used before asking again
NOTIFICATION_ID = "barkley_new_version"
_VERSION = re.compile(r"v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})")
_RELEASE = re.compile(
    r"https://github\.com/([A-Za-z0-9-]{1,39})/ha-barkley/releases/tag/[^\s]{1,60}"
)


def parse_version(text: Any) -> tuple[int, int, int] | None:
    m = _VERSION.fullmatch(str(text or "").strip())
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def read_release(rel: Any) -> dict[str, str] | None:
    """GitHub's answer, as {version, image, url}, or None when it isn't one of ours."""
    if not isinstance(rel, dict) or rel.get("draft") or rel.get("prerelease"):
        return None
    if (v := parse_version(rel.get("tag_name"))) is None:
        return None
    m = _RELEASE.fullmatch(str(rel.get("html_url") or ""))
    owners = {r.split("/")[0].lower() for r in REPOS}
    if not m or m[1].lower() not in owners:
        return None
    return {
        "version": ".".join(map(str, v)),
        "image": f"ghcr.io/{m[1].lower()}/barkley",
        "url": m[0],
    }


def fetch_latest() -> dict[str, str] | None:
    """Barkley's latest release on GitHub, or None if neither repository has one."""
    from sniff_test.fetch.github import GitHub

    gh = GitHub.from_env()
    for repo in REPOS:
        owner, name = repo.split("/")
        if (rel := gh.latest_release(owner, name)) is not None:
            return read_release(rel)
    return None


def _state(store: Any) -> dict[str, Any]:
    try:
        raw = json.loads(store.setting(KEY) or "{}")
    except ValueError:
        return {}
    return raw if isinstance(raw, dict) else {}


def newer(store: Any, current: str) -> dict[str, str] | None:
    """The stored release when it's newer than `current`, else None."""
    st = _state(store)
    have, out = parse_version(current), parse_version(st.get("version"))
    if have is None or out is None or out <= have:
        return None
    if not isinstance(st.get("image"), str) or not isinstance(st.get("url"), str):
        return None
    return {"version": st["version"], "image": st["image"], "url": st["url"]}


def check(
    store: Any,
    current: str,
    fetch: Callable[[], dict[str, str] | None] = fetch_latest,
    notify: Callable[[str, str], None] | None = None,
    now: float | None = None,
) -> None:
    """Ask GitHub when the last answer is a day old, then notify once per newer version.
    A failed fetch keeps the last answer and is tried again on the next call."""
    import sys

    now = time.time() if now is None else now
    st = _state(store)
    at = st.get("at")
    # never asked, a day old, or a clock that went back
    if not isinstance(at, (int, float)) or not 0 <= now - at < FRESH:
        try:
            got = fetch()
        except Exception as ex:  # a failed fetch only means nothing new is shown
            print(f"Barkley's latest release not fetched: {type(ex).__name__}",
                  file=sys.stderr, flush=True)  # fmt: skip
        else:
            st = {**st, "at": now, "version": "", "image": "", "url": ""}
            if got:
                st.update(got)
            store.set_setting(KEY, json.dumps(st, sort_keys=True))
    if notify is None or (rel := newer(store, current)) is None:
        return
    if st.get("notified") == rel["version"]:
        return
    try:
        notify(f"Barkley {rel['version']} is out", message(rel, current))
    except Exception as ex:  # tried again on the next call
        print(f"New version notification not sent: {type(ex).__name__}",
              file=sys.stderr, flush=True)  # fmt: skip
        return
    store.set_setting(KEY, json.dumps({**st, "notified": rel["version"]}, sort_keys=True))


def message(rel: dict[str, str], current: str) -> str:
    """The notification's text (Home Assistant shows it as Markdown)."""
    moved = " The image has a new address." if rel["image"] != IMAGE else ""
    return (
        f"You have {current}.{moved} To update, change the image in your compose file to "
        f"`{rel['image']}:{rel['version']}` and run `docker compose up -d`. "
        f"[What's new]({rel['url']})"
    )


def banner_html(rel: dict[str, str] | None, current: str) -> str:
    from sniff_test.ui import e, icon

    if not rel:
        return ""
    moved = (
        f" The image has a new address: it was <code>{e(IMAGE)}</code>."
        if rel["image"] != IMAGE
        else ""
    )
    return (
        f'<div class="banner">{icon("download", 16)} <b>Barkley {e(rel["version"])} is out.</b> '
        f"You have {e(current)}.{moved} To update, change the image in your compose file to "
        f"<code>{e(rel['image'])}:{e(rel['version'])}</code> and run "
        "<code>docker compose up -d</code>. "
        f'<a href="{e(rel["url"])}" target="_blank" rel="noopener noreferrer">What\'s new</a>'
        "</div>"
    )
