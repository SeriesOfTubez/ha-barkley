"""(0.15, his decision 2026-11-21) How far behind a package is: context on the package line
(newest release, its date, releases newer than the one installed, Home Assistant's pin
holding it back), never a finding. Python from the PyPI JSON the scan already reads; a
card's own npm packages from one registry document each. Offline: the registry is a
stand-in here."""

import json

from sniff_test.analyzers import npm_meta, pypi_meta
from sniff_test.fetch import http


def _pypi(versions, latest, yanked=()):
    return {
        "info": {"version": latest},
        "releases": {
            v: [{"upload_time_iso_8601": f"2026-0{i % 9 + 1}-01T00:00:00Z", "yanked": v in yanked}]
            for i, v in enumerate(versions)
        },
    }


def test_python_releases_newer_than_the_installed_one_are_counted():
    meta = _pypi(["1.0.0", "1.1.0", "1.2.0rc1", "1.2.0", "2.0.0"], "2.0.0", yanked=("1.1.0",))
    got = pypi_meta.versions_behind(meta, "1.0.0")
    assert got == {"newest": "2.0.0", "newer": 2, "newest_date": "2026-05-01"}
    assert pypi_meta.versions_behind(meta, "2.0.0")["newer"] == 0
    assert pypi_meta.versions_behind({"info": {}}, "1.0.0") is None


def test_home_assistants_pin_holding_a_package_back_is_noted():
    meta = _pypi(["1.0.0", "1.1.0"], "1.1.0")
    assert pypi_meta.versions_behind(meta, "1.0.0", pinned="1.0.0")["held_by_ha"] is True
    assert "held_by_ha" not in pypi_meta.versions_behind(meta, "1.0.0", pinned="0.9.0")
    assert "held_by_ha" not in pypi_meta.versions_behind(meta, "1.1.0", pinned="1.1.0")


def _card(tmp_path, deps, lock=None):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": deps}))
    if lock is not None:
        (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    return tmp_path


def test_a_cards_installed_versions_come_from_its_lock_file_or_its_range(tmp_path):
    root = _card(tmp_path, {"acme-lit": "^3.1.0", "@acme/utils": "~1.2.3", "acme-x": "*",
                            "Bad Name": "1.0.0", "acme-y": "github:acme/y"},
                 lock={"packages": {"node_modules/acme-lit": {"version": "3.2.1"}}})  # fmt: skip
    assert npm_meta.installed(root) == {"acme-lit": "3.2.1", "@acme/utils": "1.2.3"}


def test_one_registry_document_per_package_and_a_failure_is_no_result(tmp_path, monkeypatch):
    root = _card(tmp_path, {"acme-lit": "3.1.0", "@acme/utils": "1.2.3"})
    asked = []

    def fake(url, timeout, max_bytes=0):
        asked.append(url)
        if "utils" in url:
            raise http.HttpError("rate limited")
        return {"dist-tags": {"latest": "3.3.0"},
                "versions": {"3.1.0": {}, "3.2.0": {}, "3.3.0-beta.1": {}, "3.3.0": {}},
                "time": {"3.3.0": "2026-10-02T10:00:00Z"}}  # fmt: skip

    monkeypatch.setattr(http, "lookup_json", fake)
    got = npm_meta.lookup(root)
    assert asked == ["https://registry.npmjs.org/acme-lit",
                     "https://registry.npmjs.org/@acme%2Futils"]  # fmt: skip
    assert got == {"acme-lit": {"newest": "3.3.0", "newer": 2, "installed": "3.1.0",
                                "newest_date": "2026-10-02"}}  # fmt: skip


def test_the_package_line_says_it_plainly():
    from sniff_test import ui

    b = {"newest": "2.0.0", "newest_date": "2026-05-01", "newer": 3, "held_by_ha": True}
    assert ui.behind_facts(b) == ["3 releases behind", "newest 2.0.0 (2026-05-01)",
                                  "pinned by Home Assistant"]  # fmt: skip
    assert ui.behind_facts({"newest": "2.0.0", "newer": 1}) == ["1 release behind",
                                                                 "newest 2.0.0"]  # fmt: skip
    assert ui.behind_facts({"newest": "2.0.0", "newer": 0}) == ["up to date"]
    # (his decision 2026-11-24) a card's range: the lock file's version, when it isn't the
    # range's own, is the one the count starts from
    lock = {"newest": "2.1.1", "newer": 2, "installed": "1.0.4"}
    assert ui.behind_facts(lock, "^1.0.2") == ["built with 1.0.4", "2 releases behind",
                                               "newest 2.1.1"]  # fmt: skip
    assert ui.behind_facts({**lock, "installed": "1.0.2"}, "^1.0.2")[0] == "2 releases behind"
    assert ui.behind_facts(None) == []
