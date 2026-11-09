"""Bytecode HA would run instead of source. Headers are crafted; nothing is unmarshalled."""

import importlib.util
import shutil
import struct
import sys
import zipfile

import pytest
from conftest import requires_semgrep

from sniff_test.analyzers import bytecode
from sniff_test.models import Target, TargetKind
from sniff_test.scanner import scan
from sniff_test.workspace import extract

PY314 = bytecode.MAGIC["3.14"]
PY312 = bytecode.MAGIC["3.12"]
BODY = b"\xe3not-real-bytecode"  # never read past the 16-byte header
RULE = "py-bytecode-runs-instead-of-source"


def pyc(magic: int, flags: int, extra: bytes = b"\0" * 8) -> bytes:
    return magic.to_bytes(2, "little") + b"\r\n" + struct.pack("<I", flags) + extra + BODY


def _target(root):
    return Target(source="t", kind=TargetKind.INTEGRATION, root=root, domain="acme")


def _hits(root, python="3.14.10"):
    return {f.file for f in bytecode.run(_target(root), python).findings}


def test_source_hash_matches_cpython_314():
    # Vectors from importlib.util.source_hash on CPython 3.14.10.
    assert bytecode.source_hash(PY314, b'WHO = "source"\n').hex() == "c3297714e29b53e7"
    assert bytecode.source_hash(PY314, b"").hex() == "61f5b7cb653a6aa4"
    assert bytecode.source_hash(PY314, b"0123456789abcdefXYZ").hex() == "810ac62d485ec28b"


def test_source_hash_matches_running_interpreter():
    magic = int.from_bytes(importlib.util.MAGIC_NUMBER[:2], "little")
    for src in (b"", b"x = 1\n", b"a" * 1000):
        assert bytecode.source_hash(magic, src) == importlib.util.source_hash(src)


def test_magic_table_has_running_interpreter():
    minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    assert bytecode.MAGIC[minor] == int.from_bytes(importlib.util.MAGIC_NUMBER[:2], "little")


@pytest.fixture
def pkg(tmp_path):
    root = tmp_path / "acme"
    (root / "__pycache__").mkdir(parents=True)
    (root / "__init__.py").write_text("")
    (root / "mod.py").write_text('WHO = "source"\n')
    return root


def test_unchecked_hash_pyc_is_flagged(pkg):
    (pkg / "__pycache__" / "mod.cpython-314.pyc").write_bytes(pyc(PY314, 0b01))
    assert _hits(pkg) == {"__pycache__/mod.cpython-314.pyc"}


def test_checked_hash_pyc_matching_source_is_flagged(pkg):
    h = bytecode.source_hash(PY314, (pkg / "mod.py").read_bytes())
    (pkg / "__pycache__" / "mod.cpython-314.pyc").write_bytes(pyc(PY314, 0b11, h))
    assert _hits(pkg) == {"__pycache__/mod.cpython-314.pyc"}


def test_checked_hash_pyc_for_other_source_is_ignored(pkg):
    h = bytecode.source_hash(PY314, b"something else\n")
    (pkg / "__pycache__" / "mod.cpython-314.pyc").write_bytes(pyc(PY314, 0b11, h))
    assert _hits(pkg) == set()


def test_timestamp_pyc_is_stale_after_install(pkg):
    # HACS extracts with zipfile, so the .py mtime is the install time: recompiled.
    (pkg / "__pycache__" / "mod.cpython-314.pyc").write_bytes(pyc(PY314, 0))
    assert _hits(pkg) == set()


def test_other_python_versions_are_ignored(pkg):
    # hacs/integration 2.0.5 ships two stale cpython-312 pycs like these.
    (pkg / "__pycache__" / "mod.cpython-312.pyc").write_bytes(pyc(PY312, 0b01))
    (pkg / "__pycache__" / "mod.cpython-314.pyc").write_bytes(pyc(PY312, 0b01))  # wrong magic
    (pkg / "__pycache__" / "mod.cpython-314.opt-1.pyc").write_bytes(pyc(PY314, 0b01))
    assert _hits(pkg) == set()


def test_cached_pyc_without_source_is_ignored(pkg):
    (pkg / "__pycache__" / "gone.cpython-314.pyc").write_bytes(pyc(PY314, 0b01))
    assert _hits(pkg) == set()


def test_sourceless_pyc_is_flagged_unless_source_wins(pkg):
    (pkg / "payload.pyc").write_bytes(pyc(PY314, 0))  # any flags: no validation
    (pkg / "mod.pyc").write_bytes(pyc(PY314, 0b01))  # mod.py exists: source wins
    (pkg / "old.pyc").write_bytes(pyc(PY312, 0b01))  # wrong magic: ImportError
    assert _hits(pkg) == {"payload.pyc"}


def test_unknown_ha_version_falls_back_to_recent_pythons(pkg):
    (pkg / "__pycache__" / "mod.cpython-314.pyc").write_bytes(pyc(PY314, 0b01))
    assert _hits(pkg, python=None) == {"__pycache__/mod.cpython-314.pyc"}
    assert _hits(pkg, python="3.13.9") == set()  # HA on 3.13 wouldn't load a 3.14 pyc


def test_planted_pyc_in_release_zip_is_caught(tmp_path, pkg):
    # The release-asset path: a zip extracted the way the scanner extracts HACS assets.
    (pkg / "__pycache__" / "__init__.cpython-314.pyc").write_bytes(pyc(PY314, 0b01))
    z = tmp_path / "acme.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for p in sorted(pkg.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(pkg).as_posix())
    out = tmp_path / "install"
    out.mkdir()
    extract(z, out)
    findings = bytecode.run(_target(out), "3.14.10").findings
    assert [(f.rule_id, f.file, str(f.severity)) for f in findings] == [
        (RULE, "__pycache__/__init__.cpython-314.pyc", "high")
    ]


@requires_semgrep
def test_planted_pyc_in_integration_scan(tmp_path, fixtures):
    repo = tmp_path / "repo"
    shutil.copytree(fixtures / "clean_integration", repo)
    cache = repo / "custom_components" / "acme_weather" / "__pycache__"
    cache.mkdir()
    (cache / "sensor.cpython-314.pyc").write_bytes(pyc(PY314, 0b01))
    r = scan(str(repo), offline=True)
    assert [f.rule_id for f in r.findings] == [RULE]
    assert r.score.score <= 89
