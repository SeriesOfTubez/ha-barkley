"""`sniff-test serve`: the add-on's ingress panel. Stdlib only, one scan at a time.

Behind HA ingress, HA does the login and the Supervisor (172.30.32.2) is the only
client the panel ever sees, so every other address is refused. Forms carry a
per-process token so another page can't make the panel start scans.

Everything shown from a report (repo names, refs, file names, evidence, hosts) came
from scanned repos and is escaped. The JSON view is served as `application/json`
with `nosniff`, and the CSP allows no scripts at all.
"""

from __future__ import annotations

import html
import json
import queue
import re
import secrets
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from sniff_test import __version__, doctor, memory, supervisor
from sniff_test.diff import HEADLINE_MAX, HEADLINE_RANK
from sniff_test.diff import diff as diff_reports
from sniff_test.fetch.github import RateLimit, RateLimitError
from sniff_test.report.json_report import sanitize_untrusted
from sniff_test.scoring import VERDICTS
from sniff_test.store import ScanRow, Store, StoreError

SUPERVISOR_IP = "172.30.32.2"
_INGRESS_PATH = re.compile(r"^/api/hassio_ingress/[A-Za-z0-9_-]+$")
_REPO = re.compile(r"^(?:https://github\.com/)?([A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100})/?$")
_REF = re.compile(r"^[A-Za-z0-9_.+/-]{1,100}$")
_EMOJI = {v.key: v.emoji for _, v in VERDICTS}
_SEV_CLASS = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "low"}
_JOBS_KEPT = 20
# GitHub API requests a job may need, measured 2026-11-09: 6-7 per scan (repo, release,
# commit, tarball, asset, release list, compare); an update check is two scans. Every
# GitHub request in the add-on is made by a job on the one worker thread (the panel's
# own requests go to HA through the Supervisor), so checking the budget before each job
# and waiting out a rate limit inside one covers them all. Without a token GitHub allows
# 60/hour and counts even 304 answers, so nothing can be served from a cache instead.
_GITHUB_NEED = {"scan": 8, "installed": 8, "update": 15}
_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "form-action 'self'; base-uri 'none'; frame-ancestors 'self'"
)


def e(text: Any, limit: int = 300) -> str:
    """Escape for HTML text and attribute values (untrusted text is also truncated)."""
    return html.escape(sanitize_untrusted(str(text), limit) if text is not None else "")


# --- jobs ------------------------------------------------------------------------------


@dataclass
class Job:
    id: int
    kind: str  # scan | update
    repo: str
    ref: str | None
    to: str | None = None  # update: the version HACS would install now (None: work it out)
    state: str = "queued"  # queued | running | waiting | done | failed | refused
    message: str = ""
    scan_ids: list[int] = field(default_factory=list)
    created: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))


ScanFn = Callable[[str, str | None], dict[str, Any]]


class MemoryRefused(Exception):
    """The memory guard stopped a scan before it started."""


class Worker:
    """Runs scans one at a time (Semgrep is the memory hog; never run two at once)."""

    def __init__(
        self,
        store: Store,
        scan_fn: ScanFn,
        tool_version: str = __version__,
        *,
        exposure: str = "local",
        ha_fn: Callable[[], str | None] = lambda: None,
        memory_fn: Callable[[], memory.Memory] = memory.check,
        budget_fn: Callable[[], RateLimit | None] = lambda: None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ):
        self.store = store
        self.scan_fn = scan_fn
        self.tool_version = tool_version
        self.exposure = exposure
        self.ha_fn = ha_fn
        self.memory_fn = memory_fn
        self.budget_fn = budget_fn
        self.sleep_fn = sleep_fn
        self.github_wait: str = ""  # why queued work is paused (shown on the panel)
        self.jobs: list[Job] = []
        self._q: queue.Queue[Job] = queue.Queue()
        self._lock = threading.Lock()
        self._next = 1
        self._thread = threading.Thread(target=self._run, name="sniff-worker", daemon=True)
        self._thread.start()

    def submit(self, kind: str, repo: str, ref: str | None, to: str | None = None) -> Job:
        with self._lock:
            job = Job(self._next, kind, repo, ref, to)
            self._next += 1
            self.jobs.insert(0, job)
            del self.jobs[_JOBS_KEPT:]
        self._q.put(job)
        return job

    def wait(self) -> None:
        """Block until the queue is empty (tests)."""
        self._q.join()

    def _scan(self, repo: str, ref: str | None) -> int:
        mem = self.memory_fn()
        if mem.refuse:
            raise MemoryRefused(mem.message())
        return self.store.save(self.scan_fn(repo, ref))

    def _stored_or_scan(self, repo: str, ref: str | None, exposure: str, ha: str | None) -> int:
        if ref:
            hit = self.store.find(
                repo, ref, exposure=exposure, tool_version=self.tool_version, ha_version=ha
            )
            if hit:
                return hit.id
        return self._scan(repo, ref)

    def _log_incomplete(self, job: Job) -> None:
        """Analyzers that didn't finish go to the add-on's log as well as the page."""
        for sid in job.scan_ids:
            try:
                rep = self.store.report(sid)
            except StoreError:
                continue
            for a in rep.get("analyzers", []):
                if a.get("state") not in ("ok", "not_applicable"):
                    print(
                        f"scan @{sid} {job.repo}: {a.get('name')} {a.get('state')}: "
                        f"{a.get('detail')}",
                        file=sys.stderr,
                        flush=True,
                    )

    def _park(self, job: Job, reset_at: float, why: str) -> None:
        """Wait until GitHub's budget resets; the job then runs (again) from the start.

        Scans a job already stored are reused on the retry (update checks look them up),
        so nothing finished is lost. Never fails the job: the limit always resets.
        """
        when = time.strftime("%H:%M UTC", time.gmtime(reset_at))
        job.state = "waiting"
        job.message = f"waiting for GitHub's rate limit; resumes at {when}"
        self.github_wait = f"{why} Queued scans resume automatically at {when}."
        print(f"job {job.id} {job.repo} waiting until {when}: {why}", file=sys.stderr, flush=True)
        try:
            self.sleep_fn(min(max(reset_at - time.time(), 0) + 5, 3700))
        finally:
            self.github_wait = ""

    def _budget_ok(self, job: Job) -> bool:
        b = self.budget_fn()
        if b is None or b.remaining >= _GITHUB_NEED.get(job.kind, 15):
            return True
        tip = " A GitHub token in the app's options raises it to 5,000."
        token = "" if b.authenticated else tip
        left = f"{b.remaining} of {b.limit} requests left this hour"
        why = f"GitHub's API budget is low ({left}).{token}"
        self._park(job, b.reset_at, why)
        return False

    def _do(self, job: Job) -> None:
        if job.kind == "scan":
            job.scan_ids = [self._scan(job.repo, job.ref)]
            job.message = "scanned"
        elif job.kind == "installed":  # an installed version: reuse a stored scan
            job.scan_ids = [self._stored_or_scan(job.repo, job.ref, self.exposure, self.ha_fn())]
            job.message = "sniffed"
        else:  # update: stored scan of the installed ref vs what HACS installs now
            if job.to:  # HACS told us (installed list): reuse a stored scan of it
                new = self._stored_or_scan(job.repo, job.to, self.exposure, self.ha_fn())
            else:
                new = self._scan(job.repo, None)
            row = self.store.get(new)
            assert row is not None  # noqa: S101 - just saved
            old = self._stored_or_scan(job.repo, job.ref, row.exposure, row.ha_version)
            job.scan_ids = [old, new]
            job.message = f"{job.ref} → {row.ref}"

    def _run(self) -> None:
        while True:
            job = self._q.get()
            try:
                while True:
                    while not self._budget_ok(job):
                        pass
                    job.state = "running"
                    try:
                        self._do(job)
                        break
                    except RateLimitError as ex:  # ran out mid-job: wait, run it again
                        self._park(job, ex.reset_at, str(ex).split(" [", 1)[0] + ".")
                job.state = "done"
                self._log_incomplete(job)
            except MemoryRefused as ex:
                job.state = "refused"
                job.message = str(ex)
                print(f"job {job.id} {job.repo} refused: {job.message}", file=sys.stderr)
            except Exception as ex:
                job.state = "failed"
                job.message = f"{type(ex).__name__}: {ex}"
                print(f"job {job.id} {job.repo} failed: {job.message}", file=sys.stderr)
            finally:
                self._q.task_done()


# --- HTML ------------------------------------------------------------------------------

_STYLE = """
:root { --bg:#fff; --fg:#1c1c1c; --muted:#666; --line:#e3e3e3; --card:#f7f7f7;
  --crit:#b3261e; --high:#c4540a; --med:#9a6b00; --low:#4b6b88; --ok:#2e7d32; }
@media (prefers-color-scheme: dark) { :root { --bg:#111; --fg:#e8e8e8; --muted:#9a9a9a;
  --line:#2a2a2a; --card:#1a1a1a; --crit:#ff7b72; --high:#ffa657; --med:#e3b341;
  --low:#8bb4d9; --ok:#7ee787; } }
body { background:var(--bg); color:var(--fg); font:15px/1.45 system-ui,sans-serif;
  margin:0 auto; max-width:960px; padding:16px; }
a { color:inherit; } h1 { font-size:1.4em; } h2 { font-size:1.1em; margin-top:1.6em; }
table { border-collapse:collapse; width:100%; } td, th { text-align:left; padding:6px 8px;
  border-bottom:1px solid var(--line); vertical-align:top; overflow-wrap:anywhere; }
.muted { color:var(--muted); } .card { background:var(--card); padding:12px; border-radius:8px; }
.crit { color:var(--crit); font-weight:600; } .high { color:var(--high); font-weight:600; }
.med { color:var(--med); } .low { color:var(--low); } .ok { color:var(--ok); }
form { display:flex; gap:8px; flex-wrap:wrap; margin:8px 0; }
input { padding:6px; min-width:0; flex:1 1 180px; } button { padding:6px 12px; }
code { overflow-wrap:anywhere; }
"""


def _page(title: str, body: str) -> bytes:
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{e(title)}</title><style>{_STYLE}</style></head><body>"
        f"{body}</body></html>"
    ).encode()


def _verdict(score: int, key: str) -> str:
    cls = {"good_boy": "ok", "kinda_sus": "med", "very_sus": "high", "bork": "crit"}.get(key, "")
    return f'<span class="{cls}">{score} {_EMOJI.get(key, "")}</span>'


# --- installed HACS items --------------------------------------------------------------


@dataclass
class InstalledState:
    """What HACS reported, cached; `error` says why there's no list."""

    items: list[supervisor.Installed] = field(default_factory=list)
    other: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    fetched: float = 0.0


@dataclass
class Row:
    item: supervisor.Installed
    group: str  # attention | unchecked | checked | current
    installed_scan: ScanRow | None
    available_scan: ScanRow | None
    reasons: list[str] = field(default_factory=list)
    busy: str = ""  # "queued" or "running" while a job for this repo is in the worker


GROUPS = {
    "attention": "Needs a look",
    "unchecked": "Updates not checked yet",
    "checked": "Updates checked: nothing important changed",
}
_GOOD = 90


def _latest(rows: list[ScanRow], ref: str) -> ScanRow | None:
    hits = [r for r in rows if r.ref == ref]
    return next((r for r in hits if r.complete), hits[0] if hits else None)


def _score_reason(r: ScanRow) -> str | None:
    if not r.complete:
        return f"@{r.id} {r.ref}: incomplete scan (scored {r.score})"
    if r.score < _GOOD:
        return f"@{r.id} {r.ref}: scored {r.score}"
    return None


def classify(
    items: list[supervisor.Installed],
    store: Store,
    diff_fn: Callable[[int, int], dict[str, Any]],
    tool_version: str | None = None,
) -> list[Row]:
    """Signal first: what needs attention, then unchecked updates, checked ones, the rest.

    Attention means a checked update whose diff has headline changes (a new publisher,
    new findings, new flows), or a scan of the version you'd run that isn't Good Boy or
    didn't finish. The diff and the scores are read, never recomputed or changed.
    """
    out: list[Row] = []
    for it in items:
        rows = store.history(it.repo, limit=200)
        if tool_version:  # scans made with other rules don't count (they'd be rescanned)
            rows = [r for r in rows if r.tool_version == tool_version]
        inst = _latest(rows, it.installed)
        avail = _latest(rows, it.available) if it.update else inst
        row = Row(it, "current", inst, avail)
        if it.update and inst and avail:
            d = diff_fn(inst.id, avail.id)
            head = [c for c in d.get("changes", []) if c["rank"] >= HEADLINE_RANK]
            row.reasons = [c["text"] for c in head[:HEADLINE_MAX]]
            row.group = "attention" if head else "checked"
        elif it.update:
            row.group = "unchecked"
        for scan in dict.fromkeys(x for x in (inst, avail) if x):  # running, and next
            if why := _score_reason(scan):
                row.reasons.append(why)
                row.group = "attention"
        out.append(row)
    order = {g: i for i, g in enumerate([*GROUPS, "current"])}
    return sorted(out, key=lambda r: order[r.group])


def _version_cell(base: str, r: Row) -> str:
    it = r.item

    def ver(v: str, s: ScanRow | None) -> str:
        if s:
            return f'<a href="{base}/scan/{s.id}">{e(v, 60)}</a> {_verdict(s.score, s.verdict)}'
        return e(v, 60)

    if not it.update:
        return ver(it.installed, r.installed_scan)
    link = ""
    if r.installed_scan and r.available_scan:
        link = (f' · <a href="{base}/diff?old={r.installed_scan.id}&amp;new='
                f'{r.available_scan.id}">diff</a>')  # fmt: skip
    return f"{ver(it.installed, r.installed_scan)} → {ver(it.available, r.available_scan)}{link}"


def _action(base: str, r: Row, token: str) -> str:
    it = r.item
    if r.busy:  # one click is enough: no second button while the job is in the worker
        label = {"running": "checking…", "waiting": "waiting for GitHub…"}.get(r.busy, "queued…")
        return f'<span class="muted">{label}</span>'
    hidden = (f'<input type=hidden name=token value="{token}">'
              f'<input type=hidden name=repo value="{e(it.repo)}">'
              f'<input type=hidden name=ref value="{e(it.installed)}">')  # fmt: skip
    if it.update and not (r.installed_scan and r.available_scan):
        return (f'<form method=post action="{base}/update">{hidden}'
                f'<input type=hidden name=to value="{e(it.available)}">'
                "<button>Check update</button></form>")  # fmt: skip
    if not r.installed_scan:
        return (f'<form method=post action="{base}/installed">{hidden}'
                "<button>Sniff installed</button></form>")  # fmt: skip
    return ""


def _installed_row(base: str, r: Row, token: str) -> str:
    it = r.item
    why = "".join(f'<br><span class="high">{e(t, 300)}</span>' for t in r.reasons)
    tag = it.kind + (" · custom repo" if it.custom else "")
    return (
        f"<tr><td><b>{e(it.name, 80)}</b> <span class=muted>{e(it.repo, 100)} · {e(tag)}</span>"
        f"{why}</td><td>{_version_cell(base, r)}</td><td>{_action(base, r, token)}</td></tr>"
    )


def render_installed(base: str, state: InstalledState, rows: list[Row], token: str) -> str:
    refresh = f'<a href="{base}/?refresh=1">refresh</a>'
    if state.error:
        return (
            "<h2>Installed from the Marketplace (HACS)</h2>"
            "<p class=muted>Can't list installed items: "
            f"{e(state.error, 300)} ({refresh}). Typed checks above still work.</p>"
        )
    out = ["<h2>Installed from the Marketplace (HACS)</h2>"]
    for g, title in GROUPS.items():
        group = [r for r in rows if r.group == g]
        if group:
            out.append(f"<h3>{e(title)} ({len(group)})</h3><table>")
            out.extend(_installed_row(base, r, token) for r in group)
            out.append("</table>")
    current = [r for r in rows if r.group == "current"]
    if current:
        never = sum(1 for r in current if not r.installed_scan)
        note = f", {never} not yet sniffed by Sniff Test {__version__}" if never else ""
        out.append(f"<details><summary>{len(current)} up to date{e(note)}</summary><table>")
        out.extend(_installed_row(base, r, token) for r in current)
        out.append("</table></details>")
        if never:
            out.append(
                f'<form method=post action="{base}/installed-all">'
                f'<input type=hidden name=token value="{token}">'
                f"<button>Sniff the {never} not yet sniffed</button></form>"
            )
    if not rows:
        out.append("<p class=muted>The Marketplace lists no installed integrations or cards.</p>")
    skipped = ", ".join(f"{n} {e(c)}" for c, n in sorted(state.other.items()))
    age = int(time.time() - state.fetched) // 60 if state.fetched else 0
    out.append(
        f'<p class="muted">From the Marketplace {age} min ago ({refresh})'
        + (f". Not scanned (not an integration or card): {skipped}" if skipped else "")
        + ".</p>"
    )
    return "".join(out)


def _memory_banner(mem: memory.Memory) -> str:
    if mem.level == "refuse":
        return f'<p class="card crit">⚠ Memory: {e(mem.message(), 300)}</p>'
    if mem.level == "warn":
        return f'<p class="card med">⚠ Memory: {e(mem.message(), 300)}</p>'
    return ""


def _github_banner(wait: str) -> str:
    return f'<p class="card med">⏳ {e(wait, 400)}</p>' if wait else ""


def render_index(
    base: str,
    store: Store,
    jobs: list[Job],
    token: str,
    installed: str = "",
    mem: memory.Memory | None = None,
    github_wait: str = "",
) -> bytes:
    rows = store.history(limit=100)
    out = [
        "<h1>🐕 Sniff Test</h1>",
        '<p class="muted">Scans run one at a time. Scores never come from an AI.</p>',
        _memory_banner(mem) if mem else "",
        _github_banner(github_wait),
        f'<div class="card"><form method=post action="{base}/scan">'
        f'<input type=hidden name=token value="{token}">'
        '<input name=repo placeholder="owner/repo" required>'
        '<input name=ref placeholder="tag (default: what HACS installs)">'
        "<button>Sniff it</button></form>"
        f'<form method=post action="{base}/update">'
        f'<input type=hidden name=token value="{token}">'
        '<input name=repo placeholder="owner/repo" required>'
        '<input name=ref placeholder="installed tag" required>'
        "<button>What would updating change?</button></form>"
        f'<p class="muted"><a href="{base}/doctor">Diagnostics</a>: can each tool run '
        "on this box?</p></div>",
        installed,
    ]
    if jobs:
        out.append("<h2>Jobs</h2><table>")
        for j in jobs:
            links = " ".join(f'<a href="{base}/scan/{i}">@{i}</a>' for i in j.scan_ids)
            if j.kind == "update" and len(j.scan_ids) == 2:
                old, new = j.scan_ids
                links += f' · <a href="{base}/diff?old={old}&amp;new={new}">diff</a>'
            out.append(
                f"<tr><td>{e(j.kind)}</td><td>{e(j.repo)}{'@' + e(j.ref) if j.ref else ''}"
                f"{' → ' + e(j.to) if j.to else ''}"
                f"</td><td>{e(j.state)}</td><td>{e(j.message)} {links}</td></tr>"
            )
        out.append("</table>")
    out.append("<h2>Stored scans</h2>")
    if not rows:
        out.append('<p class="muted">No scans yet.</p>')
    else:
        out.append("<table><tr><th>#</th><th>score</th><th>repo</th><th>when</th></tr>")
        for r in rows:
            extra = r.kind + (f" · HA {r.ha_version}" if r.ha_version else "")
            if not r.complete:
                extra += " · incomplete"
            out.append(
                f'<tr><td><a href="{base}/scan/{r.id}">@{r.id}</a></td>'
                f"<td>{_verdict(r.score, r.verdict)}</td>"
                f"<td>{e(r.repo or r.source, 100)}@{e(r.ref or '?', 60)}"
                f'<br><span class="muted">{e(extra)}</span></td>'
                f"<td>{e(r.scanned_at[:16].replace('T', ' '))}</td></tr>"
            )
        out.append("</table>")
    return _page("Sniff Test", "".join(out))


def render_scan(base: str, sid: int, report: dict[str, Any], store: Store) -> bytes:
    t = report["target"]
    name = f"{t.get('repo') or t.get('input')}@{t.get('ref') or '?'}"
    findings = report.get("findings", [])
    out = [
        f'<p><a href="{base}/">← all scans</a></p>',
        f"<h1>@{sid} {e(name, 160)}</h1>",
        f'<p class="card">{_verdict(report["score"], report["verdict"]["key"])} '
        f"{e(report['verdict']['label'])}"
        f"{'' if report.get('complete') else ' · <b>incomplete scan</b> (capped at 89)'}"
        f'<br><span class="muted">{e(t.get("kind"))} · {e(t.get("install_source"))} · '
        f"commit {e((t.get('commit_sha') or '')[:12])}"
        f"{' · HA ' + e(report['ha_version']) if report.get('ha_version') else ''}</span></p>",
    ]
    missing = [
        a for a in report.get("analyzers", []) if a.get("state") not in ("ok", "not_applicable")
    ]
    if missing:
        out.append('<p class="med">Didn\'t finish:</p><ul>')
        out.extend(
            f"<li><b>{e(a.get('name'))}</b> {e(a.get('state'))}: {e(a.get('detail'), 400)}</li>"
            for a in missing
        )
        out.append("</ul>")
    older = [r for r in store.history(t.get("repo")) if r.id != sid] if t.get("repo") else []
    if older:
        out.append("<p>Compare with: ")
        out.append(
            " ".join(
                f'<a href="{base}/diff?old={r.id}&amp;new={sid}">@{r.id} {e(r.ref or "?", 40)}</a>'
                for r in older[:8]
            )
        )
        out.append("</p>")
    out.append(f"<h2>Findings ({len(findings)})</h2>")
    if findings:
        out.append("<table>")
        for f in findings:
            loc = f.get("file") or ""
            if loc and f.get("line"):
                loc += f":{f['line']}"
            out.append(
                f'<tr><td class="{_SEV_CLASS.get(f["severity"], "")}">{e(f["severity"])}</td>'
                f"<td><b>{e(f['title'])}</b> <span class=muted>{e(f['rule_id'])}</span>"
                f"<br>{e(f.get('message'), 600)}"
                f"{'<br><code>' + e(loc, 200) + '</code>' if loc else ''}"
                f"{'<br><code>' + e(ev, 200) + '</code>' if (ev := f.get('evidence')) else ''}"
                "</td></tr>"
            )
        out.append("</table>")
    else:
        out.append('<p class="ok">Nothing smelled off. 🦴</p>')
    out.append(f'<p><a href="{base}/scan/{sid}.json">raw JSON report</a></p>')
    return _page(f"Sniff Test @{sid}", "".join(out))


def render_doctor(base: str, checks: list[doctor.Check]) -> bytes:
    out = [f'<p><a href="{base}/">← all scans</a></p>', "<h1>Diagnostics</h1>",
           f'<p class="muted">Sniff Test {e(__version__)}. Each tool runs on a one-line '
           "sample written here, never on scanned code.</p><table>"]  # fmt: skip
    for c in checks:
        cls = "ok" if c.ok else "crit"
        out.append(
            f'<tr><td class="{cls}">{"ok" if c.ok else "FAIL"}</td><td><b>{e(c.name)}</b> '
            f"{e(c.summary, 1000)}"
            + (f"<br><code>{e(c.command, 500)}</code>" if c.command else "")
            + (f" <span class=muted>{c.seconds}s</span>" if c.seconds is not None else "")
            + (f"<br>stderr: <code>{e(c.stderr, 1600)}</code>" if c.stderr else "")
            + (f"<br>stdout: <code>{e(c.stdout, 600)}</code>" if c.stdout and not c.ok else "")
            + "</td></tr>"
        )
    out.append("</table>")
    return _page("Sniff Test diagnostics", "".join(out))


def render_diff(base: str, old: int, new: int, d: dict[str, Any]) -> bytes:
    frm, to = d["from"], d["to"]
    changes = d.get("changes", [])
    head = [c for c in changes if c["rank"] >= HEADLINE_RANK][:HEADLINE_MAX]
    rest = [c for c in changes if c not in head]
    out = [
        f'<p><a href="{base}/">← all scans</a></p>',
        f"<h1>What changes: {e(frm.get('repo'), 100)}</h1>",
        f'<p class="card"><a href="{base}/scan/{old}">@{old}</a> {e(frm.get("ref"), 60)} → '
        f'<a href="{base}/scan/{new}">@{new}</a> {e(to.get("ref"), 60)}<br>'
        f'<span class="muted">score {e(d["score"].get("from"))} → {e(d["score"].get("to"))} '
        "(each side's own score; the diff never scores)</span></p>",
    ]
    for w in d.get("warnings", []):
        out.append(f'<p class="med">⚠ {e(w, 400)}</p>')
    if not head:
        out.append("<p>Nothing important changed. 🦴</p>")
    else:
        out.append("<table>")
        for c in head:
            cls = _SEV_CLASS.get(c.get("severity") or "", "")
            out.append(
                f'<tr><td class="{cls}">{e(c["sign"])}</td><td>{e(c["text"], 400)}</td></tr>'
            )
        out.append("</table>")
    if rest:
        out.append(f"<h2>Also changed ({len(rest)})</h2><table>")
        for c in rest:
            out.append(
                f"<tr><td class=muted>{e(c['sign'])}</td><td class=muted>{e(c['text'], 300)}"
                "</td></tr>"
            )
        out.append("</table>")
    return _page("Sniff Test diff", "".join(out))


# --- HTTP ------------------------------------------------------------------------------


InstalledFn = Callable[[], tuple[list[supervisor.Installed], dict[str, int]]]
_INSTALLED_TTL = 300  # seconds; HACS itself refreshes far less often


class Panel:
    def __init__(
        self,
        store: Store,
        worker: Worker,
        allow: set[str],
        installed_fn: InstalledFn | None = None,
        memory_fn: Callable[[], memory.Memory] = memory.check,
    ):
        self.store = store
        self.worker = worker
        self.allow = allow
        self.token = secrets.token_urlsafe(24)
        self.installed_fn = installed_fn
        self.memory_fn = memory_fn
        self._installed = InstalledState()
        self._installed_lock = threading.Lock()
        self._diffs: dict[tuple[int, int], dict[str, Any]] = {}

    def installed(self, refresh: bool = False) -> InstalledState:
        """HACS's installed list, cached; one websocket round trip at most every 5 minutes."""
        if self.installed_fn is None:
            return InstalledState(error="not running as a Home Assistant add-on")
        with self._installed_lock:
            st = self._installed
            if refresh or not st.fetched or time.time() - st.fetched > _INSTALLED_TTL:
                try:
                    items, other = self.installed_fn()
                    st = InstalledState(items, other, None, time.time())
                except supervisor.SupervisorError as ex:
                    st = InstalledState(error=str(ex), fetched=time.time())
                self._installed = st
            return st

    def diff(self, old: int, new: int) -> dict[str, Any]:
        """Stored reports never change, so a diff of two of them is computed once."""
        key = (old, new)
        if key not in self._diffs:
            self._diffs[key] = diff_reports(self.store.report(old), self.store.report(new))
        return self._diffs[key]

    def installed_html(self, base: str, refresh: bool = False) -> str:
        if self.installed_fn is None:
            return ""
        st = self.installed(refresh)
        tv = self.worker.tool_version
        rows = classify(st.items, self.store, self.diff, tv) if not st.error else []
        busy = {
            j.repo.lower(): j.state
            for j in reversed(list(self.worker.jobs))
            if j.state in ("queued", "running", "waiting")
        }
        for r in rows:
            r.busy = busy.get(r.item.repo.lower(), "")
        return render_installed(base, st, rows, self.token)

    def handler(self) -> type[BaseHTTPRequestHandler]:
        panel = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "sniff-test"
            sys_version = ""

            def log_message(self, fmt: str, *args: Any) -> None:  # quiet, no request lines
                pass

            def _base(self) -> str:
                path = self.headers.get("X-Ingress-Path", "")
                return path if _INGRESS_PATH.match(path) else ""

            def _send(self, status: int, body: bytes, ctype: str = "text/html") -> None:
                self.send_response(status)
                self.send_header("Content-Type", f"{ctype}; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Security-Policy", _CSP)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _text(self, status: int, msg: str) -> None:
                self._send(status, _page("Sniff Test", f"<p>🐕 {e(msg)}</p>"))

            def _redirect(self, to: str) -> None:
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", to or "/")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _allowed(self) -> bool:
                if self.client_address[0] in panel.allow:
                    return True
                self._text(HTTPStatus.FORBIDDEN, "only reachable through Home Assistant")
                return False

            def do_GET(self) -> None:
                if not self._allowed():
                    return
                url = urllib.parse.urlsplit(self.path)
                base = self._base()
                try:
                    if url.path in ("", "/"):
                        jobs = list(panel.worker.jobs)
                        refresh = "refresh=1" in url.query
                        body = render_index(
                            base, panel.store, jobs, panel.token,
                            panel.installed_html(base, refresh), panel.memory_fn(),
                            panel.worker.github_wait,
                        )  # fmt: skip
                        return self._send(200, body)
                    if m := re.fullmatch(r"/scan/(\d+)(\.json)?", url.path):
                        sid = int(m[1])
                        report = panel.store.report(sid)
                        if m[2]:
                            body = json.dumps(report, indent=2).encode()
                            return self._send(200, body, "application/json")
                        return self._send(200, render_scan(base, sid, report, panel.store))
                    if url.path == "/doctor":
                        return self._send(200, render_doctor(base, doctor.run_checks(addon=True)))
                    if url.path == "/diff":
                        q = urllib.parse.parse_qs(url.query)
                        old, new = int(q["old"][0]), int(q["new"][0])
                        d = panel.diff(old, new)
                        return self._send(200, render_diff(base, old, new, d))
                except StoreError as ex:
                    return self._text(HTTPStatus.NOT_FOUND, str(ex))
                except (KeyError, ValueError):
                    return self._text(HTTPStatus.BAD_REQUEST, "bad request")
                self._text(HTTPStatus.NOT_FOUND, "nothing to sniff here")

            def do_POST(self) -> None:
                if not self._allowed():
                    return
                size = int(self.headers.get("Content-Length") or 0)
                if size > 4096:
                    return self._text(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too large")
                form = urllib.parse.parse_qs(self.rfile.read(size).decode("utf-8", "replace"))
                get = lambda k: (form.get(k) or [""])[0].strip()  # noqa: E731
                if not secrets.compare_digest(get("token"), panel.token):
                    return self._text(HTTPStatus.FORBIDDEN, "stale form; reload the page")
                path = urllib.parse.urlsplit(self.path).path
                if path == "/installed-all":
                    st = panel.installed()
                    tv = panel.worker.tool_version
                    stored = {(r.repo or "").lower() + "@" + (r.ref or "")
                              for r in panel.store.history(limit=10000)
                              if r.tool_version == tv}  # fmt: skip
                    for it in st.items:
                        if f"{it.repo.lower()}@{it.installed}" not in stored:
                            panel.worker.submit("installed", it.repo, it.installed)
                    return self._redirect(f"{self._base()}/")
                if path not in ("/scan", "/update", "/installed"):
                    return self._text(HTTPStatus.NOT_FOUND, "nothing to sniff here")
                m = _REPO.match(get("repo"))
                ref = get("ref") or None
                to = get("to") or None
                if (
                    not m
                    or (ref and not _REF.match(ref))
                    or (to and not _REF.match(to))
                    or (path in ("/update", "/installed") and not ref)
                ):
                    return self._text(HTTPStatus.BAD_REQUEST, "want owner/repo and a tag")
                panel.worker.submit(path.lstrip("/"), m[1], ref, to if path == "/update" else None)
                self._redirect(f"{self._base()}/")

        return Handler


supervisor_ha_version = supervisor.ha_version  # kept for callers of the M5 name


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    panel: Panel


def serve(
    store: Store,
    scan_fn: ScanFn,
    host: str,
    port: int,
    allow: set[str],
    *,
    exposure: str = "local",
    ha_fn: Callable[[], str | None] = lambda: None,
    installed_fn: InstalledFn | None = None,
    memory_fn: Callable[[], memory.Memory] = memory.check,
    budget_fn: Callable[[], RateLimit | None] = lambda: None,
) -> PanelServer:
    """Build the server (caller runs `serve_forever`); `.panel.worker` runs the scans."""
    worker = Worker(
        store, scan_fn, exposure=exposure, ha_fn=ha_fn, memory_fn=memory_fn, budget_fn=budget_fn
    )
    panel = Panel(store, worker, allow, installed_fn, memory_fn)
    httpd = PanelServer((host, port), panel.handler())
    httpd.panel = panel
    return httpd
