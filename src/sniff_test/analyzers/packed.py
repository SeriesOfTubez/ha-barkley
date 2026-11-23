"""(0.15, his decision 2026-11-22) Packed files: long encoded text in an app's Python,
unpacked as data and read like the app's own files.

A real installer in the full Marketplace run carried one base64 + zlib blob holding JSON:
a 1.39 MB card script that differs from the repo's own build (the file a user gets is not
the one the repo shows) and six text edits to another integration's files. None of it was
read. Now:

- Every string constant of 300+ characters in base64 or hex is decoded, and compressed
  data (zlib, gzip, bz2, lzma/xz) is decompressed, up to two levels deep. Never run: bytes
  in, bytes out. Caps: 32 MB unpacked per app, 100 times the packed size per blob, 200
  files; past a cap the blob is left as it was (its finding stays) and a note says so.
- Text that comes out is written next to the scan's copy of the app, under
  `.barkley-unpacked/<file>-line-<n>/`, and read by every check that reads the app's
  files while it is there (Semgrep, the address check). JSON is walked: a value that is
  itself packed is unpacked again, and a long text value is kept as a file of its own,
  named after a file name next to it when there is one.
- Facts, never scored: "Carries packed files (Barkley unpacked and read them)", and, when
  the unpacked text names another app's folder (`custom_components/<other>/…`), "Changes
  files of another app". Extending another integration is a normal reason to do that (his
  call 2026-11-22: a fact line, no Exposure).
- Recognised binary formats (pictures, fonts, keys) are data: a `py-obfuscation` finding
  on one is dropped unless the same function hands something to exec, eval, compile,
  marshal or pickle. Binary Barkley doesn't recognise keeps counting.

Parse only (`ast`), and the decoders run with output limits (`decompressobj` with a
maximum length), so a hostile blob costs at most its caps.
"""

from __future__ import annotations

import ast
import base64
import binascii
import bz2
import contextlib
import json
import lzma
import re
import shutil
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from sniff_test.models import Category, Finding, Severity

NAME = "packed"
FOLDER = ".barkley-unpacked"
CARRIES = "packed-files"
OTHER_APP = "changes-other-app"
TOO_BIG = "packed-too-big"
MIN_LEN = 300
MAX_TOTAL = 32 * 1024 * 1024
MAX_RATIO = 100
MAX_FILES = 200
MAX_DEPTH = 2
_MAX_PY = 50 * 1024 * 1024
_MAX_LITERAL = 64 * 1024 * 1024
_B64 = re.compile(r"[A-Za-z0-9+/=_\-\s]+")
_HEX = re.compile(r"[0-9a-fA-F\s]+")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_OTHER = re.compile(r"custom_components/([a-z0-9_]{1,64})/")
_CODE_EXT = (".js", ".mjs", ".py", ".ts", ".json", ".yaml", ".yml", ".html", ".css")

# Recognised binary data: what it is, by its first bytes
_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "a PNG picture"),
    (b"\xff\xd8\xff", "a JPEG picture"),
    (b"GIF87a", "a GIF picture"),
    (b"GIF89a", "a GIF picture"),
    (b"RIFF", "a WebP picture or WAV sound"),
    (b"\x00\x00\x01\x00", "an icon"),
    (b"wOFF", "a font"),
    (b"wOF2", "a font"),
    (b"OTTO", "a font"),
    (b"\x00\x01\x00\x00", "a font"),
    (b"\x30\x82", "a key or certificate"),
    (b"\x30\x81", "a key or certificate"),
    (b"\x30\x59\x30\x13", "a key"),
    (b"%PDF", "a PDF"),
    # tables a camera stream puts in front of each picture (JPEG segments)
    (b"\xff\xc4", "part of a JPEG picture"),
    (b"\xff\xdb", "part of a JPEG picture"),
)


def binary_kind(data: bytes) -> str | None:
    for magic, what in _MAGIC:
        if data.startswith(magic):
            return what
    return None


class _Budget:
    def __init__(self) -> None:
        self.left = MAX_TOTAL
        self.files = 0
        self.over = False


def _decompress(data: bytes, budget: _Budget) -> bytes | None:
    """Compressed data's content, within the caps; None when it isn't compressed or is
    over a cap (then `budget.over` is set)."""
    limit = min(budget.left, max(1, len(data)) * MAX_RATIO)
    makers = []
    if data[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
        makers.append(lambda: zlib.decompressobj())
    if data[:2] == b"\x1f\x8b":
        makers.append(lambda: zlib.decompressobj(16 + zlib.MAX_WBITS))
    if data[:3] == b"BZh":
        makers.append(lambda: bz2.BZ2Decompressor())
    if data[:6] == b"\xfd7zXZ\x00" or data[:1] == b"\x5d":
        makers.append(lambda: lzma.LZMADecompressor())
    for make in makers:
        try:
            d = make()
            out = d.decompress(data, limit + 1)
        except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError):
            continue
        if len(out) > limit:
            budget.over = True
            return None
        budget.left -= len(out)
        return out
    return None


def decode(value: str, min_len: int = MIN_LEN) -> bytes | None:
    """The bytes a long base64 or hex string spells; None when it isn't one."""
    s = value.strip()
    if len(s) < min_len or len(s) > _MAX_LITERAL:
        return None
    if _HEX.fullmatch(s) and len(re.sub(r"\s", "", s)) % 2 == 0:
        with contextlib.suppress(ValueError):
            return bytes.fromhex(re.sub(r"\s", "", s))
    if _B64.fullmatch(s):
        t = re.sub(r"\s", "", s)
        alt = "-_" if ("-" in t or "_" in t) else None
        try:
            return base64.b64decode(t + "=" * (-len(t) % 4), altchars=alt, validate=True)
        except (binascii.Error, ValueError):
            return None
    return None


@dataclass
class Unpacked:
    files: list[str] = field(default_factory=list)  # relative to the app root
    blobs: dict[tuple[str, int], str] = field(default_factory=dict)  # (file, line) -> kind
    other_apps: set[str] = field(default_factory=set)
    sources: list[tuple[str, int]] = field(default_factory=list)  # packed strings unpacked
    too_big: list[tuple[str, int]] = field(default_factory=list)


def classify(
    value: str, budget: _Budget | None = None, min_len: int = MIN_LEN
) -> tuple[str, bytes | None]:
    """("binary:<what>" | "text" | "unknown" | "too-big" | "", content) for a constant."""
    budget = budget or _Budget()
    raw = decode(value, min_len)
    if raw is None:
        return "", None
    for _ in range(MAX_DEPTH):
        if (what := binary_kind(raw)) is not None:
            return f"binary:{what}", raw
        out = _decompress(raw, budget)
        if out is None:
            break
        raw = out
    if budget.over:
        return "too-big", None
    if (what := binary_kind(raw)) is not None:
        return f"binary:{what}", raw
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return "unknown", None
    return "text", raw


# (0.15, seen on his box 2026-11-23) a real integration packs two Lua libraries; read as
# JavaScript they showed as "JavaScript file could not be parsed". Lua starts with a `--`
# comment or a `local` line; JavaScript does neither.
_LUA = re.compile(r"(?:--|local\s)")
_LANG = {".lua": "Lua", ".js": "JavaScript", ".mjs": "JavaScript", ".py": "Python",
         ".ts": "TypeScript", ".json": "JSON", ".yaml": "YAML", ".yml": "YAML",
         ".html": "HTML", ".css": "CSS"}  # fmt: skip


def _name_for(text: str, hint: str) -> str:
    ext = Path(hint).suffix.lower() if hint else ""
    if ext not in _CODE_EXT:
        t = text.lstrip()[:200]
        ext = (".json" if t[:1] in "{[" else ".py" if re.match(r"(import|from|def|class)\s", t)
               else ".lua" if _LUA.match(t) else ".js")  # fmt: skip
    base = _SAFE.sub("_", Path(hint).name)[:60] if hint else "payload"
    return base if base.endswith(ext) else base + ext


def _walk_json(node: object, path: str, sink: list[tuple[str, str]], budget: _Budget,
               depth: int) -> None:  # fmt: skip
    """Long text values of unpacked JSON, each as (a name for it, its text)."""
    if isinstance(node, dict):
        hint = next((str(v) for k, v in node.items() if k in ("file", "path", "name")
                     and isinstance(v, str) and "." in v), "")  # fmt: skip
        for k, v in list(node.items())[:2000]:
            _walk_json(v, f"{path}.{k}" if path else str(k), sink, budget, depth)
            if isinstance(v, str) and len(v) >= 64 and k not in ("file", "path", "name"):
                kind, content = classify(v, budget, 64) if depth < MAX_DEPTH else ("", None)
                if kind == "text" and content is not None:
                    sink.append((_name_for(content.decode(), str(k)), content.decode()))
                elif not kind:
                    label = f"{_SAFE.sub('_', path or 'value')[:60]}.{_SAFE.sub('_', str(k))[:30]}"
                    sink.append((_name_for(v, hint) if hint else f"{label}.txt", v))
    elif isinstance(node, list):
        for i, v in enumerate(node[:2000]):
            _walk_json(v, f"{path}.{i}", sink, budget, depth)


def _constants(text: str) -> Iterator[tuple[int, str]]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) >= MIN_LEN:
            yield n.lineno, n.value


def unpack(root: Path) -> Unpacked:
    """Write what the app's packed text holds under root/FOLDER (see above)."""
    out = Unpacked()
    budget = _Budget()
    dest = root / FOLDER
    for p in sorted(root.rglob("*.py")):
        if FOLDER in p.parts or not p.is_file() or p.is_symlink():
            continue
        try:
            if p.stat().st_size > _MAX_PY:
                continue
            text = p.read_text("utf-8", "replace")
        except OSError:
            continue
        rel = p.relative_to(root).as_posix()
        for line, value in _constants(text):
            before = budget.over
            kind, content = classify(value, budget)
            if not kind:
                continue
            out.blobs[(rel, line)] = kind
            if kind == "too-big" or (budget.over and not before):
                out.too_big.append((rel, line))
                budget.over = False
                continue
            if kind != "text" or content is None:
                continue
            body = content.decode("utf-8")
            out.sources.append((rel, line))
            parts: list[tuple[str, str]] = [(_name_for(body, ""), body)]
            if body.lstrip()[:1] in "{[":
                with contextlib.suppress(ValueError, RecursionError):
                    _walk_json(json.loads(body), "", parts, budget, 1)
            here = dest / f"{_SAFE.sub('_', rel)[:120]}-line-{line}"
            for name, t in parts:
                if out.files and len(out.files) >= MAX_FILES:
                    out.too_big.append((rel, line))
                    break
                out.other_apps.update(_OTHER.findall(t))
                target = here / name
                n = 2
                while target.exists():
                    target = here / f"{n}-{name}"
                    n += 1
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(t, "utf-8")
                out.files.append(target.relative_to(root).as_posix())
    return out


@contextlib.contextmanager
def unpacked(root: Path) -> Iterator[Unpacked]:
    """`unpack`, removed again when the block ends (nothing later compares files with
    them in place)."""
    try:
        yield unpack(root)
    finally:
        shutil.rmtree(root / FOLDER, ignore_errors=True)


def notes(u: Unpacked, domain: str | None) -> list[Finding]:
    out: list[Finding] = []
    if u.files:
        n, k = len(u.sources), len(u.files)
        rel, line = u.sources[0]
        langs: dict[str, int] = {}
        for f in u.files:
            lang = _LANG.get(Path(f).suffix.lower(), "text")
            langs[lang] = langs.get(lang, 0) + 1
        what = "code" if set(langs) & {"Lua", "JavaScript", "Python", "TypeScript"} else "text"
        kinds = (
            f"of {next(iter(langs))} {what}" if len(langs) == 1
            else ": " + ", ".join(f"{c} in {lang}"
                                  for lang, c in sorted(langs.items(), key=lambda x: -x[1]))
        )  # fmt: skip
        lua = (" Barkley has no checks for Lua code, so in those it only looks for web "
               "addresses.") if "Lua" in langs else ""  # fmt: skip
        out.append(Finding(
            rule_id=CARRIES,
            title="Carries packed files",
            severity=Severity.INFO,
            category=Category.CODE_EXEC,
            message=(f"Its code holds {n} packed {'string' if n == 1 else 'strings'} "
                     "(long encoded text, sometimes compressed too) that "
                     f"{'unpacks' if n == 1 else 'unpack'} "
                     f"to {k} {'piece' if k == 1 else 'pieces'} {kinds}. Barkley unpacked "
                     "them as data, without running anything, and read them like the app's "
                     f"own files.{lua}"),
            file=rel,
            line=line,
            analyzer="packed",
        ))  # fmt: skip
    others = sorted(d for d in u.other_apps if d != (domain or ""))
    if others:
        out.append(Finding(
            rule_id=OTHER_APP,
            title="Changes files of another app",
            severity=Severity.INFO,
            category=Category.TAMPER,
            message=("What it unpacks names files in another app's folder: "
                     + ", ".join(f"custom_components/{d}" for d in others[:5])
                     + ". Apps that extend another integration do this; that app's own "
                     "scan doesn't cover the changes."),
            evidence=", ".join(others[:5]),
            analyzer="packed",
        ))  # fmt: skip
    for rel, line in u.too_big[:3]:
        out.append(Finding(
            rule_id=TOO_BIG,
            title="Packed text too large to unpack",
            severity=Severity.INFO,
            category=Category.CODE_EXEC,
            message=("A packed string unpacks to more than Barkley reads "
                     f"({MAX_TOTAL // (1024 * 1024)} MB, or {MAX_RATIO} times its size). "
                     "What it holds wasn't read."),
            file=rel,
            line=line,
            analyzer="packed",
        ))  # fmt: skip
    return out


_RUNS = frozenset({"exec", "eval", "compile", "__import__"})
# decoders imported by name (`from base64 import b64decode`)
_DECODERS = frozenset({"b64decode", "urlsafe_b64decode", "standard_b64decode", "b32decode",
                       "b16decode", "a85decode", "b85decode", "decodebytes", "unhexlify",
                       "a2b_base64", "a2b_hex"})  # fmt: skip
_LOADS = frozenset({"marshal", "pickle", "dill", "cloudpickle"})


def _runs_code(func: ast.AST) -> bool:
    """exec/eval/compile/__import__ (plain or `builtins.`), or marshal/pickle loads. Not
    `re.compile`: a module-level picture next to a regular expression stayed flagged."""
    for n in ast.walk(func):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name) and f.id in _RUNS:
                return True
            if (
                isinstance(f, ast.Attribute)
                and isinstance(f.value, ast.Name)
                and (
                    (f.value.id in ("builtins", "__builtins__") and f.attr in _RUNS)
                    or (f.value.id in _LOADS and f.attr in ("loads", "load"))
                )
            ):
                return True
    return False


def explained(f: Finding, root: Path, u: Unpacked) -> bool:
    """A `py-obfuscation` finding on decoding packed text that Barkley unpacked and read,
    or a recognised binary format (a picture, a font, a key) where nothing in the same
    function is run or unpickled. Its own string, or a module-level constant of the
    same file; anything else keeps the finding."""
    if f.rule_id != "py-obfuscation" or not f.file or not f.line or not f.file.endswith(".py"):
        return False
    try:
        tree = ast.parse((root / f.file).read_text("utf-8", "replace"))
    except (OSError, SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    consts = {
        t.id: n.value.lineno
        for n in tree.body
        if isinstance(n, (ast.Assign, ast.AnnAssign)) and isinstance(n.value, ast.Constant)
        for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
        if isinstance(t, ast.Name)
    }
    parents: dict[int, ast.AST] = {}
    for n in ast.walk(tree):
        for c in ast.iter_child_nodes(n):
            parents[id(c)] = n
    calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and n.lineno <= f.line <= (n.end_lineno or n.lineno) and n.args
        and ((isinstance(n.func, ast.Attribute)
              and (n.func.attr == "fromhex" or (isinstance(n.func.value, ast.Name)
                                                and n.func.value.id in ("base64", "binascii"))))
             or (isinstance(n.func, ast.Name) and n.func.id in _DECODERS))
    ]  # fmt: skip
    if not calls:
        return False
    for call in calls:
        arg = call.args[0]
        line = (arg.lineno if isinstance(arg, ast.Constant)
                else consts.get(arg.id) if isinstance(arg, ast.Name) else None)  # fmt: skip
        kind = u.blobs.get((f.file, line)) if line else None
        if kind == "text" and (f.file, line) in u.sources:
            continue
        if kind and kind.startswith("binary:"):
            func: ast.AST | None = call
            while func is not None and not isinstance(
                func, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
            ):
                func = parents.get(id(func))  # fmt: skip
            if func is not None and not _runs_code(func):
                continue
        return False
    return True
