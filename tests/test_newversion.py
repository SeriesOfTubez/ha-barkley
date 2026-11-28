"""(0.15) Standalone: a newer Barkley on the list and in one notification. GitHub is never
asked here: `fetch` is a stand-in."""

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from sniff_test import newversion, server, settings
from sniff_test.store import Store

ROOT = Path(__file__).resolve().parent.parent
ORG = {"tag_name": "v0.16.0", "draft": False, "prerelease": False,
       "html_url": "https://github.com/ha-barkley/ha-barkley/releases/tag/v0.16.0"}  # fmt: skip
OLD = {**ORG, "html_url": "https://github.com/SeriesOfTubez/ha-barkley/releases/tag/v0.16.0"}


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "s.db")


def test_only_a_published_plain_version_of_barkley_counts():
    assert newversion.read_release(ORG) == {
        "version": "0.16.0",
        "image": "ghcr.io/ha-barkley/barkley",
        "url": ORG["html_url"],
    }
    assert newversion.read_release(OLD)["image"] == "ghcr.io/seriesoftubez/barkley"
    assert newversion.read_release({**ORG, "prerelease": True}) is None
    assert newversion.read_release({**ORG, "draft": True}) is None
    assert newversion.read_release({**ORG, "tag_name": "0.16.0-beta"}) is None
    other = {**ORG, "html_url": "https://github.com/someone/ha-barkley/releases/tag/v0.16.0"}
    assert newversion.read_release(other) is None
    assert newversion.read_release(None) is None


def test_the_image_this_version_names_is_the_apps():
    config = (ROOT / "addon/sniff_test/config.yaml").read_text()
    assert re.search(r"^image: (\S+)$", config, re.M)[1] == newversion.IMAGE


def test_asked_once_a_day_and_notified_once_per_version(store):
    calls, sent = [], []

    def fetch():
        calls.append(1)
        return newversion.read_release(ORG)

    def notify(title, message):
        sent.append((title, message))

    newversion.check(store, "0.15.0", fetch, notify, now=1000.0)
    newversion.check(store, "0.15.0", fetch, notify, now=2000.0)  # same day: no fetch
    assert calls == [1]
    assert sent == [("Barkley 0.16.0 is out", newversion.message(newversion.newer(
        store, "0.15.0"), "0.15.0"))]  # fmt: skip
    assert "`ghcr.io/ha-barkley/barkley:0.16.0`" in sent[0][1]
    assert "new address" in sent[0][1]
    newversion.check(store, "0.15.0", fetch, notify, now=1000.0 + newversion.FRESH)
    assert calls == [1, 1] and len(sent) == 1  # asked again a day later, not sent again


def test_nothing_shown_once_updated_or_when_github_cant_be_reached(store):
    newversion.check(store, "0.15.0", lambda: newversion.read_release(ORG), now=1.0)
    assert newversion.newer(store, "0.16.0") is None  # the user updated
    assert newversion.newer(store, "0.17.0") is None

    def broken():
        raise OSError("unreachable")

    newversion.check(store, "0.15.0", broken, now=1.0 + newversion.FRESH)
    assert newversion.newer(store, "0.15.0")["version"] == "0.16.0"  # the last answer stays


def test_a_failed_notification_is_tried_again(store):
    tries = []

    def notify(title, message):
        tries.append(1)
        if len(tries) == 1:
            raise OSError("Home Assistant unreachable")

    fetch = lambda: newversion.read_release(ORG)  # noqa: E731
    newversion.check(store, "0.15.0", fetch, notify, now=1.0)
    newversion.check(store, "0.15.0", fetch, notify, now=2.0)
    newversion.check(store, "0.15.0", fetch, notify, now=3.0)
    assert tries == [1, 1]


def test_the_banner_names_the_image_and_says_when_its_address_changed(store):
    newversion.check(store, "0.15.0", lambda: newversion.read_release(ORG), now=1.0)
    panel = SimpleNamespace(standalone=True, settings=settings.DEFAULTS, store=store)
    html = server._new_version_banner(panel)
    assert "Barkley 0.16.0 is out" in html
    assert "<code>ghcr.io/ha-barkley/barkley:0.16.0</code>" in html
    assert "new address" in html and ORG["html_url"] in html
    same = newversion.banner_html(newversion.read_release(OLD), "0.15.0")
    assert "new address" not in same
    off = SimpleNamespace(**{**vars(panel), "settings": settings.from_dict(
        {"new_versions": "0"})})  # fmt: skip
    assert server._new_version_banner(off) == ""
    app = SimpleNamespace(**{**vars(panel), "standalone": False})
    assert server._new_version_banner(app) == ""


def test_the_setting_is_offered_standalone_only():
    standalone = server.render_settings("", settings.DEFAULTS, "t", ha_token_html="x").decode()
    assert "New Barkley versions" in standalone and "Tell me (default)" in standalone
    app = server.render_settings("", settings.DEFAULTS, "t").decode()
    assert "New Barkley versions" not in app
    assert "new_versions" in settings.PARTS["checking"]
