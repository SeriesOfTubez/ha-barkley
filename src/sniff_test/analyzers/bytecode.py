"""Compiled Python that HA's interpreter would run instead of, or without, readable source.

Checked against CPython 3.14.10 (HA 2026.11's Python) on 2026-11-08 with test modules:

- `pkg/__pycache__/mod.cpython-314.pyc` next to `pkg/mod.py` (PEP 3147/552):
  - timestamp pyc: validated against the .py's mtime and size. HACS 2.0 installs with
    `zipfile.extractall`, which sets every mtime to the install time, so a shipped
    timestamp pyc is stale and Python recompiles from source. Not flagged.
  - checked-hash pyc: loaded only when its stored SipHash of the source matches the
    shipped .py. The hash covers the *source*, not the bytecode, so a matching header
    can sit on any code. Flagged when the hash matches.
  - unchecked-hash pyc: loaded without looking at the .py at all. Flagged.
  - a cached pyc whose .py is missing is ignored.
- `pkg/mod.pyc` with no `pkg/mod.py` (sourceless, legacy location): loaded whatever its
  flags. Flagged. If `mod.py` exists, the source wins.
- A pyc with another Python's magic number is rejected (cached: source is used instead;
  sourceless: ImportError). HACS's own zip ships two stale cpython-312 pycs. Not flagged.

HA's image sets no PYTHONPYCACHEPREFIX, -B or --check-hash-based-pycs and runs
`python3 -P -m homeassistant`, so the defaults above apply. Nothing here imports,
unmarshals or runs the bytecode: we read the 16-byte header and hash the .py text.
"""

from __future__ import annotations

import struct
from pathlib import Path

from sniff_test.models import (
    AnalyzerResult,
    AnalyzerState,
    Category,
    Finding,
    Severity,
    Target,
    TargetKind,
)

NAME = "bytecode"
# importlib.util.MAGIC_NUMBER per CPython minor version (read from real interpreters).
MAGIC = {"3.12": 3531, "3.13": 3571, "3.14": 3627, "3.15": 3666}
_FALLBACK = ("3.13", "3.14", "3.15")  # HA's Python unknown (offline): recent releases
_FLAG_HASH = 0b01
_FLAG_CHECK_SOURCE = 0b10
_MAX_SOURCE = 16 * 1024 * 1024
_M64 = (1 << 64) - 1


def _rotl(x: int, b: int) -> int:
    return ((x << b) | (x >> (64 - b))) & _M64


def siphash13(k0: int, k1: int, data: bytes) -> int:
    """SipHash-1-3, as CPython's `_Py_KeyedHash` (used by `importlib.util.source_hash`)."""
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    def rnd() -> None:
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & _M64
        v1 = _rotl(v1, 13) ^ v0
        v0 = _rotl(v0, 32)
        v2 = (v2 + v3) & _M64
        v3 = _rotl(v3, 16) ^ v2
        v0 = (v0 + v3) & _M64
        v3 = _rotl(v3, 21) ^ v0
        v2 = (v2 + v1) & _M64
        v1 = _rotl(v1, 17) ^ v2
        v2 = _rotl(v2, 32)

    n = len(data)
    end = n - n % 8
    for i in range(0, end, 8):
        m = struct.unpack_from("<Q", data, i)[0]
        v3 ^= m
        rnd()
        v0 ^= m
    b = (n & 0xFF) << 56
    for i, ch in enumerate(data[end:]):
        b |= ch << (8 * i)
    v3 ^= b
    rnd()
    v0 ^= b
    v2 ^= 0xFF
    for _ in range(3):
        rnd()
    return (v0 ^ v1 ^ v2 ^ v3) & _M64


def source_hash(magic: int, source: bytes) -> bytes:
    """What `importlib.util.source_hash` returns on the Python with this magic number."""
    key = int.from_bytes(magic.to_bytes(2, "little") + b"\r\n", "little")
    return struct.pack("<Q", siphash13(key, 0, source))


def _versions(python_version: str | None) -> dict[int, str]:
    """Magic number -> 'X.Y' for the Python(s) HA would load bytecode with."""
    if python_version:
        minor = ".".join(python_version.split(".")[:2])
        if minor in MAGIC:
            return {MAGIC[minor]: minor}
        return {}  # a Python newer than our table: handled by the cache tag only
    return {MAGIC[v]: v for v in _FALLBACK}


def _header(p: Path) -> bytes | None:
    try:
        with p.open("rb") as fh:
            head = fh.read(16)
    except OSError:
        return None
    return head if len(head) == 16 and head[2:4] == b"\r\n" else None


def why_loaded(pyc: Path, versions: dict[int, str], unknown_tag: str | None) -> str | None:
    """Why HA's Python would run this pyc, or None if it wouldn't."""
    head = _header(pyc)
    if head is None:
        return None
    magic = int.from_bytes(head[:2], "little")
    flags = int.from_bytes(head[4:8], "little")
    if pyc.parent.name == "__pycache__":
        stem, _, tag = pyc.name.removesuffix(".pyc").partition(".")
        if magic in versions:
            if tag != f"cpython-{versions[magic].replace('.', '')}":
                return None  # Python only looks for its own cache tag
        elif not (unknown_tag and tag == unknown_tag):
            return None
        source = pyc.parent.parent / f"{stem}.py"
        if not source.is_file():
            return None  # cached bytecode without its source is ignored
        if flags == _FLAG_HASH:
            return "unchecked-hash bytecode: Python runs it without looking at the .py"
        if flags == _FLAG_HASH | _FLAG_CHECK_SOURCE:  # keyed by its own magic number
            try:
                if source.stat().st_size > _MAX_SOURCE:
                    return None
                matches = source_hash(magic, source.read_bytes()) == head[8:16]
            except OSError:
                return None
            if matches:
                return (
                    "checked-hash bytecode matching the shipped .py: the hash covers the "
                    "source text, not the bytecode, so Python runs whatever code is inside"
                )
        return None  # timestamp pycs are stale after HACS extracts the files
    if magic not in versions:
        return None
    stem = pyc.name.removesuffix(".pyc")
    if "." in stem or (pyc.parent / f"{stem}.py").exists() or (pyc.parent / stem).is_dir():
        return None  # not importable under that name, or the source/package wins
    return "sourceless bytecode: there is no .py, so Python imports the .pyc directly"


def run(target: Target, python_version: str | None) -> AnalyzerResult:
    if target.kind is not TargetKind.INTEGRATION:
        return AnalyzerResult(NAME, AnalyzerState.NOT_APPLICABLE, detail="not an integration")
    root = target.root
    versions = _versions(python_version)
    unknown_tag = None
    if python_version and not versions:
        unknown_tag = "cpython-" + "".join(python_version.split(".")[:2])
    findings = []
    pycs = sorted(p for p in root.rglob("*.pyc") if p.is_file() and not p.is_symlink())
    for p in pycs:
        if (why := why_loaded(p, versions, unknown_tag)) is None:
            continue
        rel = p.relative_to(root).as_posix()
        findings.append(
            Finding(
                rule_id="py-bytecode-runs-instead-of-source",
                title="Compiled bytecode that HA would run instead of readable source",
                severity=Severity.HIGH,
                category=Category.CODE_EXEC,
                message=(
                    f"{rel} is {why}. It matches HA's Python version, so this is the code "
                    "that actually runs, and no rule (ours or a human reviewer's) can read "
                    "it. Legitimate integrations ship .py files only."
                ),
                file=rel,
                evidence=why.split(":", 1)[0],
                analyzer=NAME,
            )
        )
    py = python_version or f"{_FALLBACK[0]} to {_FALLBACK[-1]} (HA version unknown)"
    detail = f"{len(pycs)} .pyc file(s), checked against Python {py}"
    return AnalyzerResult(NAME, AnalyzerState.OK, findings=findings, detail=detail)
