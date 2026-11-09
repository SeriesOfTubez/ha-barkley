"""SQLite scan store: scan history for the add-on (and `--store` in the CLI).

The full JSON report is the source of truth (`scans.report`), so a stored scan loads
back as exactly the dict `scan -o` would have written, and `diff.py` runs on it
unchanged. The other tables are indexes derived from that report, for queries the
add-on needs without parsing every report: which scans have a finding, which
integrations reach a host, a home-wide union of graph nodes (a merge on node id).

Everything in a report that came from the scanned repo is untrusted text. The store
only ever binds it as SQL parameters; whoever renders it must escape it.

Not the HA recorder: see the vault's Architecture note (attribute size limit, purge
schedule). In the add-on the file lives in `/data`, which is included in backups.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STORE_VERSION = 1

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
CREATE TABLE IF NOT EXISTS edge_findings (
    scan_id    INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    edge_id    TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    PRIMARY KEY (scan_id, edge_id, finding_id)
);
"""


class StoreError(Exception):
    pass


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
    score: int
    verdict: str

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
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > STORE_VERSION:
                raise StoreError(
                    f"{self.path} was written by a newer sniff-test (store v{version})"
                )
            db.executescript(_SCHEMA)
            db.execute(f"PRAGMA user_version = {STORE_VERSION}")

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

    def save(self, report: dict[str, Any], scanned_at: datetime | None = None) -> int:
        """Store a report (as produced by `json_report.to_dict`). Returns the scan id."""
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
                report["tool"]["version"],
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
            db.executemany(
                "INSERT OR IGNORE INTO findings VALUES (?,?,?,?,?,?,?)",
                [
                    (sid, f["id"], f["rule_id"], f["severity"], f.get("category"),
                     f.get("file"), f.get("line"))
                    for f in report.get("findings", [])
                ],
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

    def delete(self, scan_id: int) -> bool:
        with self._connect() as db:
            return db.execute("DELETE FROM scans WHERE id = ?", (scan_id,)).rowcount > 0

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
        return _row(r) if r else None

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
            return [_row(r) for r in rows]

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

        Same exposure and tool version; for integrations also the same HA release
        (dependencies resolve against it). Cards don't depend on the HA release.
        """
        with self._connect() as db:
            rows = db.execute(
                _SELECT_ROWS + "WHERE lower(repo) = lower(?) AND ref = ? "
                "AND exposure = ? AND tool_version = ? ORDER BY id DESC",
                (repo, ref, exposure, tool_version),
            ).fetchall()
        for r in rows:
            row = _row(r)
            if row.kind == "plugin" or ha_version is None or row.ha_version == ha_version:
                return row
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
