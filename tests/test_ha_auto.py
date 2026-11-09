"""`diff --from OLD --ha-version auto`: the old side resolves against the HA of its time."""

import json

import pytest
from test_store import report

from sniff_test import cli
from sniff_test.deps import ha_env

# Real dates (GitHub releases of home-assistant/core), plus a beta and a non-HA tag.
RELEASES = [
    {"tag_name": "2026.11.0", "published_at": "2026-11-04T19:01:12Z"},
    {"tag_name": "2026.11.0b3", "published_at": "2026-11-01T10:00:00Z", "prerelease": True},
    {"tag_name": "2026.10.4", "published_at": "2026-10-24T18:30:00Z"},
    {"tag_name": "2026.10.0", "published_at": "2026-10-01T19:00:00Z"},
    {"tag_name": "dev-snapshot", "published_at": "2026-10-20T00:00:00Z"},
]


class FakeGH:
    def __init__(self, dates=None):
        self.dates = dates or {}
        self.listed = 0

    def releases(self, owner, name, max_pages=5):
        assert (owner, name) == ha_env.HA_REPO
        self.listed += 1
        return RELEASES

    def ref_date(self, owner, name, ref):
        return self.dates[(f"{owner}/{name}", ref)]


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("SNIFF_TEST_CACHE", str(tmp_path / "cache"))
    return tmp_path / "cache"


def test_version_at_picks_the_newest_stable_release_before_the_date(cache):
    gh = FakeGH()
    assert ha_env.version_at("2026-10-30T00:00:00Z", gh) == "2026.10.4"
    assert ha_env.version_at("2026-11-02T00:00:00Z", gh) == "2026.10.4"  # beta skipped
    assert ha_env.version_at("2026-11-04T19:01:12Z", gh) == "2026.11.0"  # same instant
    assert ha_env.version_at("2026-10-21T00:00:00Z", gh) == "2026.10.0"  # non-HA tag skipped
    assert gh.listed == 1  # cached for a day
    with pytest.raises(ha_env.HAEnvError, match="older than the oldest"):
        ha_env.version_at("2025-01-01T00:00:00Z", gh)


def test_python_version_sources_in_order():
    pyproject = '"Programming Language :: Python :: 3.12",\n"... :: Python :: 3.13",'
    pyproject = pyproject.replace("...", "Programming Language")
    assert ha_env._python_version("3.14.10\n", pyproject) == "3.14.10"  # the file wins
    assert ha_env._python_version("", pyproject) == "3.13"  # HA 2025.1.0's image ran 3.13.1
    assert ha_env._python_version("", '"Programming Language :: Python :: 3.9"') == "3.9"
    assert ha_env._python_version(None, None) == "3.13"


@pytest.mark.parametrize(
    "argv",
    [
        ["diff", "acme/acme", "acme/other", "--ha-version", "auto"],  # no --from
        ["diff", "acme/acme", "--from", "v1", "--ha-version", "auto", "--offline"],
        ["scan", "acme/acme", "--ha-version", "auto"],  # only diff understands auto
        ["diff", "acme/acme", "--from", "v1", "--ha-version", "2026.11"],
    ],
)
def test_auto_is_only_for_diff_from_online(argv):
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    assert e.value.code == 2


def test_diff_auto_dates_only_the_old_side(cache, tmp_path, monkeypatch):
    gh = FakeGH({("acme/acme", "v1"): "2026-10-25T08:00:00Z"})
    monkeypatch.setattr(cli.GitHub, "from_env", classmethod(lambda cls: gh))
    seen = []

    def fake_side(spec, ref, args, err, store, ha=None):
        seen.append((ref, ha, args.ha_version))
        return report(ref=ref or "v2", ha=ha or "2026.11.0")

    monkeypatch.setattr(cli, "_load_or_scan", fake_side)
    out = tmp_path / "d.json"
    argv = ["diff", "acme/acme", "--from", "v1", "--ha-version", "auto", "--json", "-o", str(out)]
    assert cli.main(argv) == 0
    assert seen == [("v1", "2026.10.4", None), (None, None, None)]
    warnings = json.loads(out.read_text())["warnings"]
    assert any("2026.10.4 and 2026.11.0" in w for w in warnings)  # said, not hidden


def test_diff_auto_reports_an_undatable_ref(cache, monkeypatch, capsys):
    gh = FakeGH({("acme/acme", "v1"): "2019-01-01T00:00:00Z"})
    monkeypatch.setattr(cli.GitHub, "from_env", classmethod(lambda cls: gh))
    monkeypatch.setattr(cli, "_load_or_scan", lambda *a, **k: pytest.fail("scanned"))
    assert cli.main(["diff", "acme/acme", "--from", "v1", "--ha-version", "auto"]) == 1
    assert "older than the oldest" in " ".join(capsys.readouterr().err.split())
