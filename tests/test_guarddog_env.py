"""GuardDog's typosquat lists are cached under our cache root, never written into the
tool's own install (the app's AppArmor profile keeps /opt read-only)."""

from pathlib import Path

from sniff_test.analyzers import guarddog


def _fake_venv(root: Path) -> str:
    exe = root / "venv" / "bin" / "guarddog"
    exe.parent.mkdir(parents=True)
    exe.write_text("#!/bin/sh\n")
    res = root / "venv/lib/python3.13/site-packages/guarddog/analyzer/metadata/resources"
    res.mkdir(parents=True)
    (res / "top_pypi_packages.json").write_text('{"packages": ["requests"]}')
    (res / "top_npm_packages.json").write_text('{"packages": ["lodash"]}')
    (res / "placeholder_email_domains.txt").write_text("x\n")
    return str(exe)


def test_lists_are_seeded_into_the_cache_and_then_left_alone(tmp_path, monkeypatch):
    monkeypatch.setenv("SNIFF_TEST_CACHE", str(tmp_path / "cache"))
    exe = _fake_venv(tmp_path)
    env = guarddog.tool_env(exe)
    cache = tmp_path / "cache" / "guarddog"
    assert env["GUARDDOG_TOP_PACKAGES_CACHE_LOCATION"] == str(cache)
    names = ["top_npm_packages.json", "top_pypi_packages.json"]
    assert sorted(p.name for p in cache.iterdir()) == names
    assert "requests" in (cache / "top_pypi_packages.json").read_text()
    # GuardDog refreshed a list: the next run keeps it (seeding never overwrites)
    (cache / "top_pypi_packages.json").write_text('{"packages": ["refreshed"]}')
    guarddog.tool_env(exe)
    assert "refreshed" in (cache / "top_pypi_packages.json").read_text()
    assert set(env) >= {"PATH"} and "UV_CACHE_DIR" not in env  # still the minimal tool env


def test_without_the_shipped_lists_guarddog_is_left_alone(tmp_path, monkeypatch):
    monkeypatch.setenv("SNIFF_TEST_CACHE", str(tmp_path / "cache"))
    exe = tmp_path / "bin" / "guarddog"
    exe.parent.mkdir()
    exe.write_text("")
    assert "GUARDDOG_TOP_PACKAGES_CACHE_LOCATION" not in guarddog.tool_env(str(exe))
    assert not (tmp_path / "cache").exists()
