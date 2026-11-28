"""SQLite scan store: scan history for the add-on (and `--store` in the CLI).

The full JSON report is the source of truth (`scans.report`), so a stored scan loads
back as exactly the dict `scan -o` would have written, and `diff.py` runs on it
unchanged. The other tables are indexes derived from that report, for queries the
add-on needs without parsing every report: which scans have a finding, which
integrations reach a host, a home-wide union of graph nodes (a merge on node id).

Everything in a report that came from the scanned repo is untrusted text. The store
only ever binds it as SQL parameters; whoever renders it must escape it.

Not the HA recorder: see the vault's Architecture note (attribute size limit, purge
schedule). In the add-on the file lives in `/data`, which is included in backups;
config.yaml's backup_pre runs `sniff-test checkpoint` first (checkpoint below).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import time
import zlib
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STORE_VERSION = 1
_INPUTS_KEY = "_recheck_inputs"  # recheck.KEY (not imported: the store stays a leaf)
_INPUTS_MAX = 64 * 1024 * 1024  # never inflate more than this from a stored blob
_SOURCE_KEY = "_app_source"  # sources.KEY (not imported, same reason)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY,
    scanned_at      TEXT NOT NULL,
    repo            TEXT,             -- owner/name after redirects (NULL for local scans)
    source          TEXT NOT NULL,    -- what was asked for (URL, owner/repo or path)
    ref             TEXT,             -- the tag/branch that was installed
    commit_sha      TEXT,
    artifact_sha256 TEXT,
    install_source  TEXT,
    kind            TEXT NOT NULL,    -- integration | plugin
    domain          TEXT,
    exposure        TEXT NOT NULL,
    ha_version      TEXT,             -- HA release dependencies resolved against
    tool_version    TEXT NOT NULL,
    schema_version  INTEGER NOT NULL,
    complete        INTEGER NOT NULL,
    score           INTEGER NOT NULL,
    verdict         TEXT NOT NULL,
    report          TEXT NOT NULL     -- the full JSON report (source of truth)
);
CREATE INDEX IF NOT EXISTS scans_repo_ref ON scans (repo, ref);
CREATE TABLE IF NOT EXISTS findings (
    scan_id  INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    id       TEXT NOT NULL,
    rule_id  TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT,
    file     TEXT,
    line     INTEGER,
    PRIMARY KEY (scan_id, id)
);
CREATE INDEX IF NOT EXISTS findings_rule ON findings (rule_id);
CREATE TABLE IF NOT EXISTS nodes (
    scan_id INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    id      TEXT NOT NULL,
    kind    TEXT NOT NULL,
    ring    TEXT,
    label   TEXT,
    PRIMARY KEY (scan_id, id)
);
CREATE INDEX IF NOT EXISTS nodes_id ON nodes (id);
CREATE TABLE IF NOT EXISTS edges (
    scan_id    INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    id         TEXT NOT NULL,
    source     TEXT NOT NULL,
    target     TEXT NOT NULL,
    relation   TEXT NOT NULL,
    evidence   TEXT NOT NULL,
    count      INTEGER NOT NULL,
    attrs_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, id)
);
CREATE INDEX IF NOT EXISTS edges_target ON edges (target);
CREATE TABLE IF NOT EXISTS explanations (  -- AI explanations (M8); never a score input
    scan_id   INTEGER PRIMARY KEY REFERENCES scans (id) ON DELETE CASCADE,
    created   TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    data      TEXT NOT NULL  -- {"summary": str, "findings": {finding_id: str}}, filtered
);
CREATE TABLE IF NOT EXISTS item_explanations (  -- AI deep analysis (0.7.0); never scored
    scan_id   INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    item_id   TEXT NOT NULL,  -- a finding id or graph edge id in that scan's report
    created   TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    data      TEXT NOT NULL,  -- report.ai_context.accept(): checked claims and questions
    PRIMARY KEY (scan_id, item_id)
);
CREATE TABLE IF NOT EXISTS settings (  -- panel settings (M8), e.g. the chosen AI entity
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_inputs (  -- (0.10.0) the lockfiles of a scan, for re-checks
    scan_id INTEGER PRIMARY KEY REFERENCES scans (id) ON DELETE CASCADE,
    data    BLOB NOT NULL    -- zlib(JSON), recheck.capture(); text from the scan, only parsed
);
CREATE TABLE IF NOT EXISTS advisory_checks (  -- (0.10.0) the last advisory re-check of a scan
    scan_id    INTEGER PRIMARY KEY REFERENCES scans (id) ON DELETE CASCADE,
    checked_at TEXT NOT NULL,
    result     TEXT NOT NULL  -- same | changed:<new scan id> | failed: <why>
);
CREATE TABLE IF NOT EXISTS sources (  -- (0.11.0) an app version's own Python, once per content
    hash    TEXT PRIMARY KEY,   -- sha256 of the JSON before compression
    data    BLOB NOT NULL,      -- zlib(JSON), sources.capture(); text from the scan, never run
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_sources (  -- (0.11.0) which stored source a scan reads from
    scan_id INTEGER PRIMARY KEY REFERENCES scans (id) ON DELETE CASCADE,
    hash    TEXT NOT NULL
);
-- (0.15) findings in a test script Home Assistant never loads (tag "test-code" in the
-- report): the list's readings leave them out, as the page does (readings.in_test_script)
CREATE TABLE IF NOT EXISTS test_findings (
    scan_id INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    id      TEXT NOT NULL,
    PRIMARY KEY (scan_id, id)
);
CREATE TABLE IF NOT EXISTS edge_findings (
    scan_id    INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    edge_id    TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    PRIMARY KEY (scan_id, edge_id, finding_id)
);
"""


class StoreError(Exception):
    pass


# (0.15, his decision 2026-11-25) VACUUM once at least this share of the file is free
# pages: deletes leave free pages that later saves reuse, but the file never shrinks
# without it. VACUUM also puts the pages back in order (SQLite's defragment).
COMPACT_AT = 0.25


def checkpoint(path: str | Path, tries: int = 5, wait: float = 1.0, timeout: float = 10) -> str:
    """(0.15, his decision 2026-11-25) Before a Home Assistant backup (config.yaml's
    backup_pre): write the WAL's changes into the database file and empty the WAL, so
    the backup copies one settled file rather than a database and a WAL taken at
    slightly different moments. Never creates the file. Returns what happened; never
    raises, because a failed backup_pre fails the app's backup, and a backup with the
    WAL beside it is better than none."""
    p = Path(path)
    if not p.is_file():
        return f"no scan store at {p}: nothing to do"
    try:
        with closing(sqlite3.connect(f"file:{p}?mode=rw", uri=True, timeout=timeout)) as db:
            for i in range(tries):
                busy, _log, _done = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if not busy:
                    return "the scan store is ready for the backup"
                if i < tries - 1:
                    time.sleep(wait)
    except sqlite3.Error as e:
        return f"couldn't settle the scan store ({type(e).__name__}); backing it up as it is"
    return "the scan store was busy; backing it up as it is"


# (0.15) What 0.14 stored for reviews, removed once on the first start (his decision
# 2026-11-20): the accepted findings, the addresses the user trusted and the apps set to
# Malware check only. Nothing reads them any more; dropping is a no-op after the first time.
_REVIEW_SETTINGS = ("trusted_addresses", "malware_only")


def _remove_reviews(db: sqlite3.Connection) -> list[str]:
    gone = []
    n = db.execute(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'reviews'"
    ).fetchone()[0]
    if n:
        rows = db.execute("SELECT count(*) FROM reviews").fetchone()[0]
        db.execute("DROP TABLE reviews")
        gone.append(f"{rows} accepted finding{'s' * (rows != 1)}")
    # the index of addresses a user could mark trusted: nothing has read it since
    db.execute("DROP TABLE IF EXISTS finding_addresses")
    for key in _REVIEW_SETTINGS:
        if db.execute("DELETE FROM settings WHERE key = ?", (key,)).rowcount:
            gone.append("trusted addresses" if key == "trusted_addresses"
                        else "Malware check only")  # fmt: skip
    return gone


def _has_table(db: sqlite3.Connection, name: str) -> bool:
    return bool(db.execute(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()[0])  # fmt: skip


# One literal query: every stored finding tagged "test-code", read from the reports
# themselves (json_each). The reports are only read.
_INDEX_TEST_FINDINGS = (
    "INSERT OR IGNORE INTO test_findings (scan_id, id) "
    "SELECT s.id, json_extract(f.value, '$.id') FROM scans s, "
    "json_each(s.report, '$.findings') f, json_each(f.value, '$.tags') t "
    "WHERE json_valid(s.report) AND t.value = 'test-code' "
    "AND json_extract(f.value, '$.id') IS NOT NULL"
)


@dataclass(frozen=True, slots=True)
class ScanRow:
    """One stored scan, without its report."""

    id: int
    scanned_at: str
    repo: str | None
    source: str
    ref: str | None
    commit_sha: str | None
    kind: str
    exposure: str
    ha_version: str | None
    tool_version: str
    complete: bool
    score: int  # the capability score: technical report and CLI only since 0.15
    verdict: str
    # (0.15) the Threat and Exposure readings, set only by the panel's overlay
    readings: dict[str, Any] | None = field(default=None, compare=False)

    def label(self) -> str:
        return f"#{self.id} {self.repo or self.source}@{self.ref or '?'}"


# Fixed column list; queries are literal strings with parameters only.
_SELECT_ROWS = (
    "SELECT id, scanned_at, repo, source, ref, commit_sha, kind, exposure, ha_version, "
    "tool_version, complete, score, verdict FROM scans "
)


def _row(r: sqlite3.Row) -> ScanRow:
    return ScanRow(
        id=r["id"],
        scanned_at=r["scanned_at"],
        repo=r["repo"],
        source=r["source"],
        ref=r["ref"],
        commit_sha=r["commit_sha"],
        kind=r["kind"],
        exposure=r["exposure"],
        ha_version=r["ha_version"],
        tool_version=r["tool_version"],
        complete=bool(r["complete"]),
        score=r["score"],
        verdict=r["verdict"],
    )


class Store:
    def __init__(self, path: str | Path):
        # The panel sets this: rows as the panel shows them (0.15: with their readings).
        # None for the CLI: its rows are as stored.
        self.overlay: Callable[[list[ScanRow]], list[ScanRow]] | None = None
        # Bumped by every write a shown score can depend on (the settings), so the panel
        # can keep what it read until one of them changes.
        self.generation = 0
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > STORE_VERSION:
                raise StoreError(
                    f"{self.path} was written by a newer sniff-test (store v{version})"
                )
            had_tests = _has_table(db, "test_findings")
            db.executescript(_SCHEMA)
            db.execute(f"PRAGMA user_version = {STORE_VERSION}")
            if not had_tests:  # (0.15) once: index the scans stored before, from their reports
                db.execute(_INDEX_TEST_FINDINGS)
            gone = _remove_reviews(db)
        if gone:
            print(f"removed what 0.14 stored for reviews: {', '.join(gone)}", file=sys.stderr,
                  flush=True)  # fmt: skip

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """One short-lived connection per operation (the add-on's server is threaded)."""
        with closing(sqlite3.connect(self.path, timeout=30)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            db.execute("PRAGMA journal_mode = WAL")
            with db:  # one transaction
                yield db

    # --- write ---------------------------------------------------------------------

    def save(
        self,
        report: dict[str, Any],
        scanned_at: datetime | None = None,
        inputs: dict[str, Any] | None = None,
        source: dict[str, Any] | None = None,
    ) -> int:
        """Store a report (as produced by `json_report.to_dict`). Returns the scan id.
        `source`: the app's own Python (sources.capture), kept once per content and linked
        to the scan; like the inputs it may ride along under `_app_source`.
        `inputs`: the scan's lockfiles for later advisory re-checks (recheck.capture); a
        scan function may also hand them over under `_recheck_inputs`, which is taken out
        here and never becomes part of the stored report."""
        if _INPUTS_KEY in report:
            inputs = inputs or report[_INPUTS_KEY]
            report = {k: v for k, v in report.items() if k != _INPUTS_KEY}
        if _SOURCE_KEY in report:
            source = source or report[_SOURCE_KEY]
            report = {k: v for k, v in report.items() if k != _SOURCE_KEY}
        src_raw = (
            json.dumps(source, separators=(",", ":"), sort_keys=True).encode()
            if isinstance(source, dict) and source
            else None
        )
        blob = (
            zlib.compress(json.dumps(inputs, separators=(",", ":")).encode(), 6)
            if isinstance(inputs, dict) and inputs
            else None
        )
        try:
            t = report["target"]
            graph = report.get("graph") or {}
            row = (
                (scanned_at or datetime.now(UTC)).isoformat(timespec="seconds"),
                t.get("repo"),
                t.get("input") or t.get("repo") or "?",
                t.get("ref"),
                t.get("commit_sha"),
                t.get("artifact_sha256"),
                t.get("install_source"),
                t["kind"],
                t.get("domain"),
                report["exposure"],
                report.get("ha_version"),
                # (0.14.1) the scan-logic key decides reuse (logic.py); older reports
                # have only the tool version, which no current key equals
                report["tool"].get("logic") or report["tool"]["version"],
                report["schema_version"],
                int(bool(report["complete"])),
                int(report["score"]),
                report["verdict"]["key"],
                json.dumps(report, separators=(",", ":")),
            )
        except (KeyError, TypeError) as e:
            raise StoreError(f"not a sniff-test report (missing {e})") from e
        with self._connect() as db:
            cur = db.execute(
                "INSERT INTO scans (scanned_at, repo, source, ref, commit_sha, "
                "artifact_sha256, install_source, kind, domain, exposure, ha_version, "
                "tool_version, schema_version, complete, score, verdict, report) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                row,
            )
            sid = int(cur.lastrowid or 0)
            if blob is not None:
                db.execute("INSERT INTO scan_inputs VALUES (?,?)", (sid, blob))
            if src_raw is not None:
                digest = hashlib.sha256(src_raw).hexdigest()
                db.execute(
                    "INSERT OR IGNORE INTO sources VALUES (?,?,?)",
                    (digest, zlib.compress(src_raw, 6), row[0]),
                )
                db.execute("INSERT INTO scan_sources VALUES (?,?)", (sid, digest))
            db.executemany(
                "INSERT OR IGNORE INTO findings VALUES (?,?,?,?,?,?,?)",
                [
                    (sid, f["id"], f["rule_id"], f["severity"], f.get("category"),
                     f.get("file"), f.get("line"))
                    for f in report.get("findings", [])
                ],
            )  # fmt: skip
            db.executemany(
                "INSERT OR IGNORE INTO test_findings (scan_id, id) VALUES (?,?)",
                [(sid, f["id"]) for f in report.get("findings", [])
                 if "test-code" in (f.get("tags") or ())],
            )  # fmt: skip
            db.executemany(
                "INSERT OR IGNORE INTO nodes VALUES (?,?,?,?,?)",
                [
                    (sid, n["id"], n["kind"], n.get("ring"), n.get("label"))
                    for n in graph.get("nodes", [])
                ],
            )
            edges = graph.get("edges", [])
            db.executemany(
                "INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?,?,?)",
                [
                    (sid, e["id"], e["source"], e["target"], e["relation"], e["evidence"],
                     e.get("count", 1), json.dumps(e.get("attrs", {}), separators=(",", ":")))
                    for e in edges
                ],
            )  # fmt: skip
            db.executemany(
                "INSERT OR IGNORE INTO edge_findings VALUES (?,?,?)",
                [(sid, e["id"], fid) for e in edges for fid in e.get("finding_ids", [])],
            )
        return sid

    def inputs(self, scan_id: int) -> dict[str, Any] | None:
        """The lockfiles saved with a scan, or None (an older scan, nothing to resolve,
        or a file too large to keep)."""
        with self._connect() as db:
            r = db.execute("SELECT data FROM scan_inputs WHERE scan_id = ?", (scan_id,)).fetchone()
        if r is None:
            return None
        try:
            d = zlib.decompressobj()
            raw = d.decompress(r["data"], _INPUTS_MAX)
            if d.unconsumed_tail:
                return None
            data = json.loads(raw)
        except (zlib.error, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def source(self, scan_id: int) -> dict[str, Any] | None:
        """The app's own Python kept for a scan (sources.capture), or None: a card, an
        older scan, an app over the size cap, or a version whose copy was dropped."""
        with self._connect() as db:
            r = db.execute(
                "SELECT s.data FROM sources s JOIN scan_sources l ON l.hash = s.hash "
                "WHERE l.scan_id = ?",
                (scan_id,),
            ).fetchone()
        if r is None:
            return None
        try:
            d = zlib.decompressobj()
            raw = d.decompress(r["data"], _INPUTS_MAX)
            if d.unconsumed_tail:
                return None
            data = json.loads(raw)
        except (zlib.error, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def has_source(self, scan_id: int) -> bool:
        with self._connect() as db:
            return (
                db.execute("SELECT 1 FROM scan_sources WHERE scan_id = ?", (scan_id,)).fetchone()
                is not None
            )

    def source_scans(self) -> list[tuple[int, str | None, str | None]]:
        """(scan id, repo, ref) of every scan that has stored source."""
        with self._connect() as db:
            return [
                (int(r[0]), r[1], r[2])
                for r in db.execute(
                    "SELECT l.scan_id, s.repo, s.ref FROM scan_sources l "
                    "JOIN scans s ON s.id = l.scan_id ORDER BY l.scan_id"
                )
            ]

    def link_source(self, scan_id: int, like: int) -> None:
        """Scan `scan_id` reads the same code as scan `like` (an advisory re-check's new
        entry: the code is the old entry's)."""
        with self._connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO scan_sources "
                "SELECT ?, hash FROM scan_sources WHERE scan_id = ?",
                (scan_id, like),
            )

    def drop_source(self, scan_id: int) -> None:
        """Forget a scan's source (the scan stays); copies nothing points at are deleted."""
        with self._connect() as db:
            db.execute("DELETE FROM scan_sources WHERE scan_id = ?", (scan_id,))
            db.execute("DELETE FROM sources WHERE hash NOT IN (SELECT hash FROM scan_sources)")

    def source_bytes(self) -> int:
        with self._connect() as db:
            return int(
                db.execute("SELECT COALESCE(SUM(LENGTH(data)), 0) FROM sources").fetchone()[0]
            )

    def has_inputs(self) -> set[int]:
        with self._connect() as db:
            return {int(r[0]) for r in db.execute("SELECT scan_id FROM scan_inputs")}

    def note_recheck(self, scan_id: int, result: str, when: datetime | None = None) -> None:
        """Remember the outcome of the latest advisory re-check of a scan."""
        at = (when or datetime.now(UTC)).isoformat(timespec="seconds")
        with self._connect() as db:
            db.execute(
                "INSERT INTO advisory_checks VALUES (?,?,?) ON CONFLICT (scan_id) DO UPDATE "
                "SET checked_at = excluded.checked_at, result = excluded.result",
                (scan_id, at, result[:300]),
            )

    def rechecks(self) -> dict[int, tuple[str, str]]:
        """scan id -> (checked_at, result) of its latest advisory re-check."""
        with self._connect() as db:
            rows = db.execute("SELECT scan_id, checked_at, result FROM advisory_checks")
            return {int(r[0]): (str(r[1]), str(r[2])) for r in rows}

    def setting(self, key: str) -> str | None:
        with self._connect() as db:
            row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        with self._connect() as db:
            db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        self.generation += 1

    def _shown(self, rows: list[ScanRow]) -> list[ScanRow]:
        """Each row as the panel shows it (`overlay`), or as stored."""
        if self.overlay is not None and rows:
            return self.overlay(rows)
        return rows

    def findings_index(self, scan_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
        """(0.15) Each scan's findings as the index keeps them (rule, severity, file, and
        the "test-code" tag from test_findings):
        what readings.compute reads, without parsing any report. One literal query; the
        ids go in as one JSON parameter."""
        out: dict[int, list[dict[str, Any]]] = {int(i): [] for i in scan_ids}
        if not out:
            return out
        with self._connect() as db:
            rows = db.execute(
                "SELECT f.scan_id, f.rule_id, f.severity, f.file, t.id AS test FROM findings f "
                "LEFT JOIN test_findings t ON t.scan_id = f.scan_id AND t.id = f.id "
                "WHERE f.scan_id IN (SELECT value FROM json_each(?))",
                (json.dumps(list(out)),),
            )
            for r in rows:
                out[r["scan_id"]].append(
                    {"rule_id": r["rule_id"], "severity": r["severity"], "file": r["file"],
                     **({"tags": ["test-code"]} if r["test"] is not None else {})}
                )  # fmt: skip
        return out

    def save_explanation(self, scan_id: int, entity_id: str, data: dict[str, Any]) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO explanations (scan_id, created, entity_id, data) "
                "VALUES (?, ?, ?, ?)",
                (scan_id, datetime.now(UTC).isoformat(timespec="seconds"), entity_id,
                 json.dumps(data)),
            )  # fmt: skip

    def explanation(self, scan_id: int) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT created, entity_id, data FROM explanations WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        return {"created": row["created"], "entity_id": row["entity_id"], **json.loads(row["data"])}

    def save_item_explanation(
        self, scan_id: int, item_id: str, entity_id: str, data: dict[str, Any]
    ) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO item_explanations "
                "(scan_id, item_id, created, entity_id, data) VALUES (?, ?, ?, ?, ?)",
                (scan_id, item_id, datetime.now(UTC).isoformat(timespec="seconds"), entity_id,
                 json.dumps(data)),
            )  # fmt: skip

    def item_explanations(self, scan_id: int) -> dict[str, dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT item_id, created, entity_id, data FROM item_explanations WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()
        return {
            r["item_id"]: {"created": r["created"], "entity_id": r["entity_id"],
                           **json.loads(r["data"])}
            for r in rows
        }  # fmt: skip

    def size_bytes(self) -> int:
        """The database file and its WAL, as they take up the disk."""
        total = 0
        for suffix in ("", "-wal"):
            with suppress(OSError):
                total += (self.path.parent / (self.path.name + suffix)).stat().st_size
        return total

    def compact(self, at: float = COMPACT_AT) -> bool:
        """VACUUM when at least `at` of the file is free pages (see COMPACT_AT); then
        empty the WAL, which VACUUM fills with the whole database. True if it ran.
        Runs outside a transaction (VACUUM can't run inside one)."""
        with closing(sqlite3.connect(self.path, timeout=30, isolation_level=None)) as db:
            pages = db.execute("PRAGMA page_count").fetchone()[0]
            free = db.execute("PRAGMA freelist_count").fetchone()[0]
            if not pages or free < pages * at:
                return False
            db.execute("VACUUM")
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return True

    def delete(self, scan_id: int) -> bool:
        with self._connect() as db:
            gone = db.execute("DELETE FROM scans WHERE id = ?", (scan_id,)).rowcount > 0
            db.execute("DELETE FROM sources WHERE hash NOT IN (SELECT hash FROM scan_sources)")
            return gone

    # --- read ----------------------------------------------------------------------

    def report(self, scan_id: int) -> dict[str, Any]:
        with self._connect() as db:
            r = db.execute("SELECT report FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if r is None:
            raise StoreError(f"no stored scan #{scan_id}")
        return json.loads(r["report"])

    def get(self, scan_id: int) -> ScanRow | None:
        with self._connect() as db:
            r = db.execute(_SELECT_ROWS + "WHERE id = ?", (scan_id,)).fetchone()
        return self._shown([_row(r)])[0] if r else None

    def history(self, repo: str | None = None, limit: int = 50) -> list[ScanRow]:
        """Newest first; `repo` matches owner/name case-insensitively."""
        with self._connect() as db:
            if repo:
                rows = db.execute(
                    _SELECT_ROWS + "WHERE lower(repo) = lower(?) ORDER BY id DESC LIMIT ?",
                    (repo, limit),
                )
            else:
                rows = db.execute(_SELECT_ROWS + "ORDER BY id DESC LIMIT ?", (limit,))
            found = [_row(r) for r in rows]
        return self._shown(found)

    def find(
        self,
        repo: str,
        ref: str,
        *,
        exposure: str,
        tool_version: str,
        ha_version: str | None = None,
    ) -> ScanRow | None:
        """The newest scan of `repo@ref` that a fresh scan would reproduce.

        Same exposure and scan-logic key (logic.py; the tool version before 0.14.1); for
        integrations also the same HA release (dependencies resolve against it). Cards
        don't depend on the HA release.
        Incomplete scans are never reused: what stopped them (a network error, GitHub's
        rate limit) is usually gone, so a fresh scan wouldn't reproduce them.
        """
        with self._connect() as db:
            rows = db.execute(
                _SELECT_ROWS + "WHERE lower(repo) = lower(?) AND ref = ? "
                "AND exposure = ? AND tool_version = ? ORDER BY id DESC",
                (repo, ref, exposure, tool_version),
            ).fetchall()
        for r in rows:
            row = _row(r)
            if not row.complete:
                continue
            if row.kind == "plugin" or ha_version is None or row.ha_version == ha_version:
                return self._shown([row])[0]
        return None

    def scans_reaching(self, node: str) -> list[tuple[int, str, str]]:
        """(scan_id, relation, evidence) for every stored edge into graph node `node`."""
        with self._connect() as db:
            return [
                (r["scan_id"], r["relation"], r["evidence"])
                for r in db.execute(
                    "SELECT scan_id, relation, evidence FROM edges WHERE target = ? "
                    "ORDER BY scan_id",
                    (node,),
                )
            ]
