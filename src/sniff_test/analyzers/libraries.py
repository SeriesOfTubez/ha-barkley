"""(0.14.1) Published libraries an integration ships unchanged, recognised by content.

Integrations often vendor big JavaScript libraries into their web folder (a PDF viewer, a
code formatter, a terminal). Reading them as code took most of a large app's scan, and
their findings were about the library, not the app. A file is left unread only when its
bytes are exactly a published npm file that passes every check below; anything else, any
error, a rate limit, no reply or no answer means the file is read as code as before.
Skipping by path or name (vendor/, .min.js) is never done: that's where a payload hides.

1. Which files: integrations only (a card's own bundle is often published to npm by its
   author, so a card would be "recognised" as itself). JavaScript files of MIN_BYTES or
   more, the largest MAX_LOOKUPS first, hashed (SHA-256) from the bytes as installed.
2. jsDelivr's hash lookup names a package that ships those exact bytes. It names
   whichever indexed package has them (a real integration's editor add-ons came back as
   files of unrelated packages and of a GitHub repository), and anyone can publish to
   npm, so a name alone proves nothing. The checks, all required:
   - an npm package (jsDelivr also indexes any GitHub repository: refused);
   - that version was published at least MIN_AGE_DAYS ago (the npm registry);
   - the package had at least MIN_WEEKLY downloads last week (npm's download counts);
   - OSV has no malware advisory for that name and version (osv-scanner). A malware
     advisory means the file is read in full and the advisory is a critical finding.
   A hostile author would need a version a month old in a package downloaded ten
   thousand times a week, and no malware advisory by then.
3. A recognised file is set aside while the code is read (both Semgrep passes and with
   them the card rules, js_fold, js_wrapper, endpoints) and put back before anything
   compares files. It is listed in the report, and its package is checked with OSV like
   any dependency (advisories become dep-vuln, osv.VENDORED_POLICY).

Off with the "Recognise published libraries" setting, for cards, and offline.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import re
import shutil
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sniff_test import paths
from sniff_test.analyzers import osv
from sniff_test.fetch import http
from sniff_test.models import AnalyzerResult, AnalyzerState, Finding, Target, TargetKind

NAME = "libraries"
MIN_BYTES = 64 * 1024
MAX_LOOKUPS = 40
TIMEOUT = 5.0  # seconds per request
BUDGET = 20.0  # seconds for all lookups of one scan
WORKERS = 4
MIN_AGE_DAYS = 30
MIN_WEEKLY = 10_000
CACHE_SECONDS = 24 * 3600  # jsDelivr's own answers say max-age=86400
_JS = (".js", ".mjs", ".cjs")
_LOOKUP = "https://data.jsdelivr.com/v1/lookup/hash/"
# npm's own rules for a name (lower case, an optional scope) and a plain version string:
# values from jsDelivr go into URLs and onto the page, so anything else is refused.
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]{0,100}/)?[a-z0-9][a-z0-9._~-]{0,100}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]{1,60})?$")
_PATH = re.compile(r"^[^\x00-\x1f]{1,500}$")


@dataclass(frozen=True)
class Library:
    name: str
    version: str
    files: tuple[str, ...]  # root-relative, as installed
    published: str | None = None  # date the version was published (YYYY-MM-DD)
    weekly: int | None = None  # downloads last week


@dataclass
class Result:
    """`aside`: root-relative path -> its library, the files not read as code."""

    analyzer: AnalyzerResult
    aside: dict[str, Library] = field(default_factory=dict)
    libraries: list[Library] = field(default_factory=list)


def _off(detail: str) -> Result:
    return Result(AnalyzerResult(NAME, AnalyzerState.NOT_APPLICABLE, detail=detail))


def candidates(root: Path, pristine: dict[str, str] | None = None) -> list[tuple[str, str]]:
    """(root-relative path, sha256 of the installed bytes) of the files worth a lookup,
    the largest first. `pristine` holds the original hash of a file normalize_js rewrote."""
    root = root.resolve()
    sized = []
    for p in root.rglob("*"):
        if p.suffix not in _JS or p.is_symlink() or not p.is_file():
            continue
        try:
            size = p.stat().st_size
            rel = p.relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if size >= MIN_BYTES and _PATH.match(rel):
            sized.append((size, rel, p))
    sized.sort(key=lambda t: (-t[0], t[1]))
    out = []
    for _size, rel, p in sized[:MAX_LOOKUPS]:
        digest = (pristine or {}).get(rel)
        if digest is None:
            try:
                digest = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                continue
        out.append((rel, digest))
    return out


# --- jsDelivr, with a small cache of its answers ------------------------------------------


def _cache_file(digest: str) -> Path:
    return paths.cache_root() / "library-lookup" / digest[:2] / f"{digest}.json"


def _cached(digest: str) -> tuple[bool, dict[str, Any] | None]:
    try:
        data = json.loads(_cache_file(digest).read_text("utf-8"))
        if time.time() - float(data["t"]) < CACHE_SECONDS:
            return True, data["answer"]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return False, None


def _remember(digest: str, answer: dict[str, Any] | None) -> None:
    with contextlib.suppress(OSError):
        paths.atomic_write(_cache_file(digest), json.dumps({"t": time.time(), "answer": answer}))


def lookup(digest: str) -> dict[str, Any] | None:
    """jsDelivr's answer for one SHA-256: {type, name, version, file}, or None for no
    match. Raises http.HttpError when there's no answer (error, rate limit, timeout)."""
    hit, answer = _cached(digest)
    if hit:
        return answer
    data = http.lookup_json(_LOOKUP + digest, TIMEOUT, max_bytes=64 * 1024)
    answer = data if isinstance(data, dict) else None
    _remember(digest, answer)
    return answer


def _parallel(fn, items: list, budget: float) -> dict[Any, Any]:
    """fn(item) for each item, WORKERS at a time, within `budget` seconds. Items that
    failed or didn't finish in time are left out."""
    out: dict[Any, Any] = {}
    if not items:
        return out
    pool = ThreadPoolExecutor(max_workers=WORKERS)
    try:
        futures = {pool.submit(fn, it): it for it in items}
        done, _late = wait(futures, timeout=budget)
        for f in done:
            with contextlib.suppress(Exception):
                out[futures[f]] = f.result()
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return out


# --- the package checks -----------------------------------------------------------------


def package_facts(name: str, version: str) -> tuple[str | None, int | None]:
    """(date the version was published, downloads last week). Raises http.HttpError."""
    quoted = name.replace("/", "%2F")
    doc = http.lookup_json(f"https://registry.npmjs.org/{quoted}", TIMEOUT)
    when = ((doc or {}).get("time") or {}).get(version) if isinstance(doc, dict) else None
    counts = http.lookup_json(
        f"https://api.npmjs.org/downloads/point/last-week/{name}", TIMEOUT, 64 * 1024
    )
    weekly = (counts or {}).get("downloads") if isinstance(counts, dict) else None
    return (
        when if isinstance(when, str) else None,
        weekly if isinstance(weekly, int) and not isinstance(weekly, bool) else None,
    )


def _age_days(published: str | None, now: datetime) -> int | None:
    if not published:
        return None
    try:
        return (now - datetime.fromisoformat(published.replace("Z", "+00:00"))).days
    except ValueError:
        return None


def _lockfile(pkgs: list[tuple[str, str]], folder: Path) -> Path:
    """A package-lock.json (v3) naming exactly these packages, for osv-scanner."""
    folder.mkdir(parents=True, exist_ok=True)
    lock = {
        "name": "recognised-libraries",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "recognised-libraries"},
            **{f"node_modules/{n}": {"version": v} for n, v in pkgs},
        },
    }
    path = folder / "package-lock.json"
    path.write_text(json.dumps(lock), "utf-8")
    return path


def recognise(
    target: Target, work: Path, enabled: bool = True, now: datetime | None = None
) -> Result:
    if not enabled:
        return _off("off (Settings: Recognise published libraries)")
    if target.kind is not TargetKind.INTEGRATION:
        return _off("integrations only")
    now = now or datetime.now(UTC)
    files = candidates(target.root, target.pristine_sha256)
    if not files:
        return _off(f"no JavaScript file of {MIN_BYTES // 1024} KB or more")
    started = time.monotonic()
    digests = sorted({d for _rel, d in files})
    answers = _parallel(lookup, digests, BUDGET)
    unanswered = len(digests) - len(answers)

    matched: dict[tuple[str, str], list[str]] = {}
    for rel, digest in files:
        a = answers.get(digest)
        if not isinstance(a, dict) or a.get("type") != "npm":
            continue
        name, version = str(a.get("name") or ""), str(a.get("version") or "")
        if _NPM_NAME.match(name) and _VERSION.match(version):
            matched.setdefault((name, version), []).append(rel)

    left = max(1.0, BUDGET - (time.monotonic() - started))
    facts = _parallel(lambda nv: package_facts(*nv), sorted(matched), left)
    passing: dict[tuple[str, str], Library] = {}
    for (name, version), rels in matched.items():
        published, weekly = facts.get((name, version), (None, None))
        age = _age_days(published, now)
        if age is None or age < MIN_AGE_DAYS or weekly is None or weekly < MIN_WEEKLY:
            continue
        passing[(name, version)] = Library(
            name, version, tuple(sorted(rels)), (published or "")[:10] or None, weekly
        )

    findings: list[Finding] = []
    note = ""
    if passing:
        exe = shutil.which("osv-scanner")
        pkgs = None
        if exe:
            lock = _lockfile(sorted(passing), work / "libraries-osv")
            pkgs, err = osv.scan_lockfile(exe, lock, work)
            note = f"; advisory check failed ({err[:120]})" if pkgs is None else ""
        else:
            note = "; osv-scanner not installed"
        if pkgs is None:
            passing = {}  # unchecked against malware advisories: read everything
        else:
            bad = {
                (p.name, p.version)
                for p in pkgs
                if any(osv.is_malicious(v) for v in p.vulns.values())
            }
            for p in pkgs:
                lib = passing.get((p.name, p.version))
                if lib is None:
                    continue
                # Named after this analyzer, not osv: the daily advisory re-check replaces
                # osv's findings with what the stored lockfiles give, and these libraries
                # aren't in them, so the re-check would drop them (recheck.apply).
                findings += [
                    dataclasses.replace(f, analyzer=NAME)
                    for f in osv.to_findings(
                        [p], lib.files[0], set(), osv.VENDORED_POLICY, lookup=osv.latest_release
                    )
                ]
            for key in bad:
                passing.pop(key, None)  # known malware: read as code, critical finding

    libs = sorted(passing.values(), key=lambda lib: (lib.name, lib.version))
    aside = {rel: lib for lib in libs for rel in lib.files}
    detail = (
        f"{len(digests)} looked up, {len(aside)} file(s) of {len(libs)} published "
        f"librar{'y' if len(libs) == 1 else 'ies'} recognised and not read as code"
    )
    if unanswered:
        detail += f"; {unanswered} lookup(s) unanswered (those files were read)"
    result = AnalyzerResult(NAME, AnalyzerState.OK, findings=findings, detail=detail + note)
    return Result(result, aside, libs)


@contextlib.contextmanager
def set_aside(root: Path, rels: dict[str, Library] | list[str], work: Path) -> Iterator[None]:
    """Move these files out of the scanned copy while the code is read, and back."""
    if not rels:
        yield
        return
    keep = work / "libraries-aside"
    moved: list[tuple[Path, Path]] = []
    try:
        for rel in sorted(rels):
            src = root / rel
            dst = keep / rel
            if src.is_symlink() or not src.is_file():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            src.rename(dst)
            moved.append((src, dst))
        yield
    finally:
        for src, dst in moved:
            src.parent.mkdir(parents=True, exist_ok=True)
            dst.rename(src)


def to_json(libs: list[Library]) -> list[dict[str, Any]]:
    return [
        {
            "name": lib.name,
            "version": lib.version,
            "files": list(lib.files),
            "published": lib.published,
            "weekly_downloads": lib.weekly,
        }
        for lib in libs
    ]
