"""`sniff-test releases`: timeline, HACS default, handovers."""

import io
import json

import pytest
from rich.console import Console

from sniff_test import cli, releases
from sniff_test.analyzers.repo_signals import to_release
from sniff_test.report import human


def _raw(tag, date, login, prerelease=False, bot=False, uploaders=()):
    return {
        "tag_name": tag,
        "published_at": f"{date}T00:00:00Z",
        "author": {"login": login, "type": "Bot" if bot else "User"},
        "prerelease": prerelease,
        "assets": [{"uploader": {"login": u}} for u in uploaders],
    }


RAW = [
    _raw("v4.2.1-202604", "2026-03-30", "dcapslock", prerelease=True),
    _raw("v4.2.1", "2026-02-08", "dcapslock"),
    _raw("v4.0.0-beta.1", "2025-10-12", "dcapslock", prerelease=True),
    _raw("v3.4.5", "2025-07-02", "thomasloven"),
    _raw("v3.4.4", "2025-01-06", "thomasloven", uploaders=["github-actions[bot]"]),
    _raw("v1.0.0", "2019-06-08", "github-actions[bot]", bot=True),
]


class FakeGitHub:
    def __init__(self, full_name="thomasloven/lovelace-card-mod"):
        self.full_name = full_name

    def repo(self, owner, name):
        return {"full_name": self.full_name, "id": 1, "default_branch": "master"}

    def releases(self, owner, name):
        return RAW


def test_handovers_skip_bots_and_mark_first_human_release():
    hs = releases.handovers([to_release(r) for r in RAW])
    assert [(h.tag, h.publisher, h.previous, h.prior_releases) for h in hs] == [
        ("v4.0.0-beta.1", "dcapslock", ["thomasloven"], 2)
    ]


def test_build_marks_hacs_default_and_beta():
    t = releases.build("thomasloven/lovelace-card-mod", gh=FakeGitHub())
    assert (t.hacs_default, t.hacs_beta) == ("v4.2.1", "v4.2.1-202604")
    d = releases.to_dict(t)
    assert [r["tag"] for r in d["releases"] if r["hacs_default"]] == ["v4.2.1"]
    assert [r["tag"] for r in d["releases"] if r["first_by_publisher"]] == ["v4.0.0-beta.1"]
    assert not d["renamed_or_transferred"]


def test_redirect_is_shown():
    t = releases.build("custom-components/old", gh=FakeGitHub("alandtse/new"))
    assert t.renamed and t.requested_as == "custom-components/old"


def test_render_keeps_picks_and_handovers_beyond_the_limit():
    t = releases.build("thomasloven/lovelace-card-mod", gh=FakeGitHub())
    buf = io.StringIO()
    human.render_releases(t, Console(file=buf, width=200), limit=1)
    text = buf.getvalue()
    assert "◀ HACS installs this by default" in text
    assert "★ first release by dcapslock" in text
    assert "v3.4.5" not in text  # beyond the limit and not special
    assert "⋮" in text


@pytest.mark.network
def test_alexa_timeline_marks_installed_default(capsys):
    assert cli.main(["releases", "alandtse/alexa_media_player", "--json"]) == 0
    d = json.loads(capsys.readouterr().out)
    defaults = [r for r in d["releases"] if r["hacs_default"]]
    assert len(defaults) == 1 and defaults[0]["tag"] == d["hacs_default"]
    assert not defaults[0]["prerelease"]
    assert {p["login"] for p in d["publishers"]} == {"alandtse"}
