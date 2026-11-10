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

from sniff_test import __version__, doctor, memory, supervisor, ui
from sniff_test.diff import HEADLINE_MAX, HEADLINE_RANK
from sniff_test.diff import diff as diff_reports
from sniff_test.fetch.github import RateLimit, RateLimitError
from sniff_test.report import ai as report_ai
from sniff_test.report.json_report import sanitize_untrusted
from sniff_test.scoring import VERDICTS
from sniff_test.store import ScanRow, Store, StoreError

SUPERVISOR_IP = "172.30.32.2"
_INGRESS_PATH = re.compile(r"^/api/hassio_ingress/[A-Za-z0-9_-]+$")
_REPO = re.compile(r"^(?:https://github\.com/)?([A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100})/?$")
_REF = re.compile(r"^[A-Za-z0-9_.+/-]{1,100}$")
_EMOJI = {v.key: v.emoji for _, v in VERDICTS}
_SEV_CLASS = {"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium"}
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


# Parallel scans (M8): a job runs beside others only if the box could take one more full
# scan on top of the warn threshold. Each running scan counts as able to grow by this
# much (an integration scan peaked at ~1.1 GB, measured M6), since one that just started
# hasn't allocated yet.
PER_SCAN = int(1.5 * memory.GIB)
PARALLEL_MAX = 4


class Worker:
    """Runs scan jobs on up to `parallel` threads, bounded by memory.

    - The first job always starts (the memory guard may still refuse it).
    - Another starts only while available memory >= warn threshold + PER_SCAN for each
      scan already running; unknown memory means one at a time.
    - Never two jobs for the same repo at once (they would scan the same versions).
    - GitHub: budget checks go through one gate and reserve what running jobs may still
      need; a job that hits the limit anyway waits and reruns (never a scan result).
    """

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
        parallel: int = 1,
    ):
        self.parallel = max(1, min(int(parallel), PARALLEL_MAX))
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
        self._running: list[Job] = []
        self._slots = threading.Condition()
        self._gate = threading.Lock()  # GitHub budget checks, one at a time
        self._threads = [
            threading.Thread(target=self._run, name=f"sniff-worker-{i}", daemon=True)
            for i in range(self.parallel)
        ]
        for th in self._threads:
            th.start()

    def running(self) -> list[Job]:
        with self._slots:
            return list(self._running)

    def _room_for_another(self) -> bool:
        mem = self.memory_fn()
        if mem.available is None:
            return False
        return mem.available >= memory.WARN_BELOW + PER_SCAN * len(self._running)

    def _admit(self, job: Job) -> None:
        """Wait for a slot; the job then counts as running (state set by the caller)."""
        with self._slots:
            while True:
                same = any(j.repo.lower() == job.repo.lower() for j in self._running)
                if not same and (not self._running or self._room_for_another()):
                    break
                job.message = (
                    "waiting for the other check of this repo"
                    if same
                    else "waiting for memory to run beside the scans already running"
                )
                self._slots.wait(timeout=30)  # memory can free up without a job ending
            self._running.append(job)
            job.message = ""

    def _release(self, job: Job) -> None:
        with self._slots:
            if job in self._running:
                self._running.remove(job)
            self._slots.notify_all()

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
        with self._gate:
            b = self.budget_fn()
            others = sum(_GITHUB_NEED.get(j.kind, 15) for j in self.running() if j is not job)
            if b is None or b.remaining >= _GITHUB_NEED.get(job.kind, 15) + others:
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
                self._admit(job)
                try:
                    while True:
                        while not self._budget_ok(job):
                            pass
                        job.state = "running"
                        try:
                            self._do(job)
                            break
                        except RateLimitError as ex:  # ran out mid-job: wait, run again
                            self._park(job, ex.reset_at, str(ex).split(" [", 1)[0] + ".")
                finally:
                    self._release(job)
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


def _page(title: str, body: str) -> bytes:
    return ui.page(title, body)


def _verdict(score: int, key: str) -> str:
    cls = {"good_boy": "ok", "kinda_sus": "sev-medium", "very_sus": "sev-high", "bork": "bad"}.get(
        key, ""
    )
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


def _action(base: str, r: Row, token: str) -> str:
    it = r.item
    hidden = (f'<input type=hidden name=token value="{token}">'
              f'<input type=hidden name=repo value="{e(it.repo)}">'
              f'<input type=hidden name=ref value="{e(it.installed)}">')  # fmt: skip
    # An incomplete scan is never reused, so the same button scans again. Check update
    # scans the installed version too, so it comes first when an update is offered.
    unfinished = [x for x in (r.installed_scan, r.available_scan) if x and not x.complete]
    if it.update and (unfinished or not (r.installed_scan and r.available_scan)):
        label = "Check again" if unfinished else "Check update"
        return (f'<form method=post action="{base}/update">{hidden}'
                f'<input type=hidden name=to value="{e(it.available)}">'
                f'<button class="primary">{label}</button></form>')  # fmt: skip
    if not r.installed_scan or not r.installed_scan.complete:
        label = "Sniff again" if r.installed_scan else "Sniff it"
        return (f'<form method=post action="{base}/installed">{hidden}'
                f'<button class="primary">{label}</button></form>')  # fmt: skip
    return ""


def _diff_link(r: Row) -> str:
    if r.item.update and r.installed_scan and r.available_scan:
        return f"old={r.installed_scan.id}&amp;new={r.available_scan.id}"
    return ""


def render_installed(
    base: str,
    state: InstalledState,
    rows: list[Row],
    token: str,
    report_fn: Callable[[int], dict[str, Any] | None],
    f: str = "all",
) -> str:
    refresh = f'<a href="{base}/?refresh=1">refresh</a>'
    if state.error:
        return (
            '<div class="banner warn">Can\'t list installed items: '
            f"{e(state.error, 300)} ({refresh}). Checking a repository by name still works "
            "(below).</div>"
        )
    cards = [
        ui.Card(
            repo=r.item.repo,
            name=r.item.name,
            kind=r.item.kind,
            installed=r.item.installed,
            available=r.item.available if r.item.update else None,
            scan=r.installed_scan,
            report=report_fn(r.installed_scan.id) if r.installed_scan else None,
            group=r.group,
            reasons=r.reasons,
            busy=r.busy,
            diff_link=_diff_link(r),
            action=_action(base, r, token),
        )
        for r in rows
    ]
    out = (
        [ui.render_grid(base, cards, f)]
        if rows
        else ['<p class="muted">The Marketplace lists no installed integrations or cards.</p>']
    )
    never = sum(1 for r in rows if not r.installed_scan)
    if never:
        out.append(
            f'<form method=post action="{base}/installed-all">'
            f'<input type=hidden name=token value="{token}">'
            f'<button class="primary">Sniff the {never} not yet sniffed by Sniff Test '
            f"{e(__version__)}</button></form>"
        )
    skipped = ", ".join(f"{n} {e(c)}" for c, n in sorted(state.other.items()))
    age = int(time.time() - state.fetched) // 60 if state.fetched else 0
    out.append(
        f'<p class="muted small">Installed list from the Marketplace {age} min ago ({refresh})'
        + (f". Not scanned (not an integration or card): {skipped}" if skipped else "")
        + ".</p>"
    )
    return "".join(out)


def _memory_banner(mem: memory.Memory) -> str:
    if mem.level == "refuse":
        return f'<div class="banner bad">⚠ Memory: {e(mem.message(), 300)}</div>'
    if mem.level == "warn":
        return f'<div class="banner warn">⚠ Memory: {e(mem.message(), 300)}</div>'
    return ""


def _github_banner(wait: str) -> str:
    return f'<div class="banner warn">⏳ {e(wait, 400)}</div>' if wait else ""


def render_index(
    base: str,
    store: Store,
    jobs: list[Job],
    token: str,
    installed: str = "",
    mem: memory.Memory | None = None,
    github_wait: str = "",
    ha: str | None = None,
    parallel: int = 1,
    search: bool = False,
) -> bytes:
    rows = store.history(limit=100)
    against = f" against HA {e(ha)}" if ha else ""
    out = [
        '<div class="head"><h1>🐕 Sniff Test</h1>'
        f'<span class="muted small">Sniff Test {e(__version__)}{against}. '
        + (
            "Scans run one at a time. "
            if parallel <= 1
            else f"Up to {parallel} scans run at once, as memory allows. "
        )
        + "Scores never come from an AI.</span></div>",
        _memory_banner(mem) if mem else "",
        _github_banner(github_wait),
        _search_box(base) if search else "",
        installed,
    ]
    active = [j for j in jobs if j.state in ("queued", "running", "waiting")]
    if jobs:
        out.append(
            f'<details class="box"{" open" if active else ""}><summary>Jobs '
            f"({len(active)} running or queued, {len(jobs) - len(active)} finished)</summary>"
            "<table>"
        )
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
        out.append("</table></details>")
    out.append(
        '<details class="box tools"><summary>Check any repository</summary>'
        f'<form method=post action="{base}/scan">'
        f'<input type=hidden name=token value="{token}">'
        '<input name=repo placeholder="owner/repo" required>'
        '<input name=ref placeholder="tag (default: what the Marketplace installs)">'
        "<button>Sniff it</button></form>"
        f'<form method=post action="{base}/update">'
        f'<input type=hidden name=token value="{token}">'
        '<input name=repo placeholder="owner/repo" required>'
        '<input name=ref placeholder="installed tag" required>'
        "<button>What would updating change?</button></form></details>"
    )
    out.append(f'<details class="box"><summary>All stored scans ({len(rows)})</summary>')
    if not rows:
        out.append('<p class="muted">No scans yet.</p>')
    else:
        out.append("<table><tr><th>#</th><th>score</th><th>repo</th><th>when</th></tr>")
        for r in rows:
            extra = r.kind + (f" · HA {r.ha_version}" if r.ha_version else "")
            extra += f" · rules {r.tool_version}"
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
    out.append("</details>")
    out.append(
        f'<p class="muted small"><a href="{base}/doctor">Diagnostics</a>: can each tool run on '
        "this box?</p>"
    )
    return _page("Sniff Test", "".join(out))


def _update_box(base: str, row: Row | None, token: str) -> str:
    """On an installed app's page: the update it's offered and what checking it found."""
    if row is None or not row.item.update:
        return ""
    it = row.item
    parts = [
        f'<section class="box"><h2>Update available: {e(it.installed, 40)} → '
        f"{e(it.available, 40)}</h2>"
    ]
    if row.busy:
        parts.append('<p class="muted">Checking it now…</p>')
    elif link := _diff_link(row):
        if row.group == "attention" and row.reasons:
            parts.append('<p class="sub">Worth a look before you update:</p><ul class="plain">')
            parts.extend(f"<li>{e(x, 300)}</li>" for x in row.reasons)
            parts.append("</ul>")
        else:
            parts.append('<p class="ok">We checked it: nothing important changes.</p>')
        parts.append(f'<p class="small"><a href="{base}/diff?{link}">Everything the update '
                     "changes</a></p>")  # fmt: skip
    else:
        parts.append('<p class="sub">Not checked yet. Checking scans the new version and '
                     "compares it with the one you have.</p>")  # fmt: skip
    if not row.busy and (act := _action(base, row, token)):
        parts.append(f'<div class="act">{act}</div>')
    parts.append("</section>")
    return "".join(parts)


def _ai_picker(base: str, sid: int, token: str, entity: str,
               choices: list[tuple[str, str]] | None, err: str) -> str:  # fmt: skip
    """A dropdown of the AI Task entities HA has (from the one fixed template)."""
    if err:
        return (f'<p class="small">Couldn\'t list your AI Task entities: {e(err, 300)}. You can '
                "still set <code>ai_entity</code> in the app's Configuration.</p>")  # fmt: skip
    if not choices:
        return ('<p class="small">Your Home Assistant has no AI Task entity yet. Add an '
                "<b>AI Task</b> entry under your AI integration (for OpenRouter: Settings &gt; "
                "Devices &amp; services &gt; OpenRouter &gt; Add AI Task), then reload this "
                "page.</p>")  # fmt: skip
    opts = ['<option value="">Off</option>'] + [
        f'<option value="{e(eid, 120)}"{" selected" if eid == entity else ""}>'
        f"{e(name, 100)} ({e(eid, 120)})</option>"
        for eid, name in choices
    ]
    return (f'<form method=post action="{base}/ai-entity" class="act tools" '
            'style="margin-top:6px">'
            f'<input type=hidden name=token value="{token}">'
            f'<input type=hidden name=scan value="{sid}">'
            f'<select name=entity>{"".join(opts)}</select>'
            "<button>Save</button></form>")  # fmt: skip


def _ai_form(base: str, sid: int, token: str, entity: str, state: str, error: str,
             have: dict[str, Any] | None, choices: list[tuple[str, str]] | None = None,
             choices_err: str = "") -> str:  # fmt: skip
    """The "Explain this app" control. Nothing is sent until the user clicks."""
    picker = _ai_picker(base, sid, token, entity, choices, choices_err)
    if not entity:
        return (
            '<div class="banner" style="margin-top:10px"><b>🤖 Explain this app with AI</b>'
            '<p class="small" style="margin-top:6px">Sniff Test can ask your Home Assistant\'s '
            "AI to explain these findings in plain words. Choose which AI to use:</p>"
            f"{picker}</div>"
        )
    form = (f'<form method=post action="{base}/explain" class="act" style="margin-top:8px">'
            f'<input type=hidden name=token value="{token}">'
            f'<input type=hidden name=scan value="{sid}">'
            f'<button class="primary">{{label}}</button></form>')  # fmt: skip
    note = ('<p class="tech">Sends this scan\'s findings (about a public project, no Home '
            f"Assistant data) to the AI provider behind <code>{e(entity, 120)}</code>. The AI "
            "explains only; it can't change the score or the findings.</p>")  # fmt: skip
    change = f"<details><summary>Change which AI explains</summary>{picker}</details>"
    if state == "running":
        return ('<p class="muted small" style="margin-top:8px">Asking your AI… this page '
                "refreshes by itself.</p>")  # fmt: skip
    if error:
        return (f'<div class="banner warn" style="margin-top:8px">The AI didn\'t answer: '
                f"{e(error, 400)}</div>" + form.replace("{label}", "Try again") + note
                + change)  # fmt: skip
    if have:
        return (f'<p class="tech">AI explanation by <code>{e(have.get("entity_id"), 120)}</code>, '
                f"{e(str(have.get('created', ''))[:16].replace('T', ' '))} UTC. It can be wrong; "
                "it can't change the score.</p>"
                + form.replace("{label}", "Ask again") + change)  # fmt: skip
    return form.replace("{label}", "Explain this app") + note + change


def render_scan(
    base: str,
    sid: int,
    report: dict[str, Any],
    store: Store,
    row: Row | None = None,
    token: str = "",
    ai_entity: str = "",
    ai_state: str = "",
    ai_error: str = "",
    ai_choices: list[tuple[str, str]] | None = None,
    ai_choices_err: str = "",
) -> bytes:
    repo = report.get("target", {}).get("repo")
    rows = store.history(repo, limit=200) if repo else []
    have = store.explanation(sid)
    return ui.render_app(
        base,
        sid,
        report,
        rows,
        name=row.item.name if row else None,
        update=_update_box(base, row, token),
        ai=have,
        ai_form=_ai_form(
            base, sid, token, ai_entity, ai_state, ai_error, have, ai_choices, ai_choices_err
        ),
        refresh=5 if ai_state == "running" else 0,
    )


def _search_box(base: str, q: str = "", kind: str = "") -> str:
    opts = "".join(
        f'<option value="{v}"{" selected" if v == kind else ""}>{label}</option>'
        for v, label in (("", "Integrations and cards"), ("integration", "Integrations"),
                         ("card", "Dashboard cards"))
    )  # fmt: skip
    return (
        f'<form method=get action="{base}/search" class="box tools search" role="search">'
        f'<input name=q value="{e(q, 100)}" maxlength=100 required '
        'placeholder="Find a Marketplace app to sniff before you install it">'
        f"<select name=kind>{opts}</select><button class=primary>Search</button></form>"
    )


def render_search(
    base: str,
    q: str,
    kind: str,
    results: list[supervisor.CatalogItem],
    scans: dict[str, ScanRow],
    busy: dict[str, str],
    token: str,
    error: str = "",
    total: int = 0,
) -> bytes:
    out = [
        f'<p class="crumb"><a href="{base}/">← All apps</a></p>',
        "<h1>Find an app to sniff</h1>",
        '<p class="muted small">Searches the Marketplace catalog your Home Assistant already '
        "has. Sniffing checks exactly what the Marketplace would install, without installing "
        "anything.</p>",
        _search_box(base, q, kind),
    ]
    if error:
        out.append(f'<div class="banner warn">Can\'t search the Marketplace: {e(error, 300)}</div>')
    elif q and not results:
        out.append(f'<p class="muted">No integration or card in the Marketplace matches '
                   f"&ldquo;{e(q, 100)}&rdquo; ({total} searched).</p>")  # fmt: skip
    rows = []
    for it in results:
        scan = scans.get(it.repo.lower())
        if b := busy.get(it.repo.lower()):
            act = '<span class="muted">' + {"running": "sniffing…"}.get(b, "queued…") + "</span>"
        elif scan:
            bd = ui.band(scan.score, scan.complete)
            act = (f'<a class="badge {bd}" style="text-decoration:none" '
                   f'href="{base}/scan/{scan.id}">'
                   f"{scan.score}<small>{e(ui.BANDS[bd][0])}</small></a>")  # fmt: skip
        else:
            act = (f'<form method=post action="{base}/scan">'
                   f'<input type=hidden name=token value="{token}">'
                   f'<input type=hidden name=repo value="{e(it.repo)}">'
                   f'<input type=hidden name=q value="{e(q, 100)}">'
                   f'<input type=hidden name=kind value="{e(kind)}">'
                   '<button class="primary">Sniff it</button></form>')  # fmt: skip
        tag = ' <span class="chip new">installed</span>' if it.installed else ""
        rows.append(
            f"<tr><td><b>{e(it.name, 100)}</b>{tag}<br>"
            f'<span class="muted small">{e(ui.KIND.get(it.kind, it.kind))} · '
            f"{e(it.repo, 120)} · ★ {it.stars:,} · {it.downloads:,} downloads</span>"
            f'<br><span class="small">{e(it.description, 300)}</span></td>'
            f'<td style="width:7em;text-align:right">{act}</td></tr>'
        )
    if rows:
        out.append(f'<p class="muted small">{len(results)} best matches of {total} '
                   "integrations and cards.</p>")  # fmt: skip
        out.append('<table class="box">' + "".join(rows) + "</table>")
    return _page("Sniff Test · search", "".join(out))


def render_doctor(base: str, checks: list[doctor.Check]) -> bytes:
    out = [f'<p class="crumb"><a href="{base}/">← All apps</a></p>', "<h1>Diagnostics</h1>",
           f'<p class="muted">Sniff Test {e(__version__)}. Each tool runs on a one-line '
           "sample written here, never on scanned code.</p><table>"]  # fmt: skip
    for c in checks:
        cls = "ok" if c.ok else "bad"
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
        f'<p class="crumb"><a href="{base}/">← All apps</a></p>',
        f"<h1>What changes: {e(frm.get('repo'), 100)}</h1>",
        f'<p class="box"><a href="{base}/scan/{old}">@{old}</a> {e(frm.get("ref"), 60)} → '
        f'<a href="{base}/scan/{new}">@{new}</a> {e(to.get("ref"), 60)}<br>'
        f'<span class="muted">score {e(d["score"].get("from"))} → {e(d["score"].get("to"))} '
        "(each side's own score; the diff never scores)</span></p>",
    ]
    for w in d.get("warnings", []):
        out.append(f'<div class="banner warn">⚠ {e(w, 400)}</div>')
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
AiFn = Callable[[str, str, dict[str, Any], str], Any]
CatalogFn = Callable[[], list[supervisor.CatalogItem]]
EntitiesFn = Callable[[], list[tuple[str, str]]]
_REPORTS_KEPT = 64
_CATALOG_TTL = 600
_ENTITIES_TTL = 300
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
        self._reports: dict[int, dict[str, Any]] = {}
        self.catalog_fn: CatalogFn | None = None
        self._catalog: tuple[float, list[supervisor.CatalogItem], str] = (0.0, [], "")
        self.ai_entity = ""
        self.entities_fn: EntitiesFn | None = None
        self._entities: tuple[float, list[tuple[str, str]], str] = (0.0, [], "")
        self.ai_fn: AiFn = supervisor.ai_generate_data
        self._ai: dict[int, tuple[str, str]] = {}  # scan id -> (running|failed, error)
        self._ai_lock = threading.Lock()

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

    def explain(self, sid: int) -> bool:
        """Ask the AI Task entity about one stored scan, in the background. One request
        per scan at a time. Only the report's ai_brief is sent (report.ai)."""
        if not self.ai_entity:
            return False
        with self._ai_lock:
            if self._ai.get(sid, ("", ""))[0] == "running":
                return True
            self._ai[sid] = ("running", "")
        report = self.store.report(sid)

        def run() -> None:
            try:
                instructions, structure, _ids = report_ai.build_request(report)
                data = self.ai_fn(self.ai_entity, instructions, structure, report_ai.TASK_NAME)
                accepted = report_ai.accept(report, data)
                if not accepted["summary"] and not accepted["findings"]:
                    raise supervisor.SupervisorError("the answer had no usable text")
                self.store.save_explanation(sid, self.ai_entity, accepted)
                with self._ai_lock:
                    self._ai.pop(sid, None)
            except Exception as ex:  # shown on the page; never affects the scan
                print(f"explain @{sid} failed: {type(ex).__name__}: {ex}", file=sys.stderr)
                with self._ai_lock:
                    self._ai[sid] = ("failed", str(ex))

        threading.Thread(target=run, name=f"explain-{sid}", daemon=True).start()
        return True

    def catalog(self) -> tuple[list[supervisor.CatalogItem], str]:
        """The Marketplace catalog, cached for 10 minutes (one websocket round trip)."""
        if self.catalog_fn is None:
            return [], "not running as a Home Assistant add-on"
        fetched, items, err = self._catalog
        if not fetched or time.time() - fetched > _CATALOG_TTL:
            try:
                items, err = self.catalog_fn(), ""
            except supervisor.SupervisorError as ex:
                items, err = [], str(ex)
            self._catalog = (time.time(), items, err)
        return items, err

    def current_scans(self) -> dict[str, ScanRow]:
        """Newest complete scan per repo made with the current rules (lower-case repo)."""
        out: dict[str, ScanRow] = {}
        for r in self.store.history(limit=10000):
            if r.repo and r.tool_version == self.worker.tool_version and r.complete:
                out.setdefault(r.repo.lower(), r)
        return out

    def busy(self) -> dict[str, str]:
        return {
            j.repo.lower(): j.state
            for j in reversed(list(self.worker.jobs))
            if j.state in ("queued", "running", "waiting")
        }

    def not_installed_html(self, base: str, installed: set[str]) -> str:
        """Cards for apps sniffed from search (or by name) that aren't installed."""
        names = {c.repo.lower(): c.name for c in self.catalog()[0]} if self.catalog_fn else {}
        busy = self.busy()
        cards = []
        for repo, scan in self.current_scans().items():
            if repo in installed:
                continue
            cards.append(
                ui.Card(
                    repo=scan.repo or repo,
                    name=names.get(repo) or (scan.repo or repo).rsplit("/", 1)[-1],
                    kind=scan.kind,
                    installed=scan.ref or "?",
                    available=None,
                    scan=scan,
                    report=self.report(scan.id),
                    busy=busy.get(repo, ""),
                )
            )
        if not cards:
            return ""
        cards.sort(key=lambda c: (c.scan.score if c.scan else -1, c.name.lower()))
        return (
            f'<h2 style="margin-top:8px">Sniffed, not installed ({len(cards)})</h2>'
            '<div class="grid">' + "".join(ui.card_html(base, c) for c in cards) + "</div>"
        )

    def ai_choices(self, refresh: bool = False) -> tuple[list[tuple[str, str]] | None, str]:
        """AI Task entities for the picker (None outside an add-on), cached 5 minutes."""
        if self.entities_fn is None:
            return None, ""
        fetched, items, err = self._entities
        if refresh or not fetched or time.time() - fetched > _ENTITIES_TTL:
            try:
                items, err = self.entities_fn(), ""
            except supervisor.SupervisorError as ex:
                items, err = [], str(ex)
            self._entities = (time.time(), items, err)
        return items, err

    def ai_state(self, sid: int) -> tuple[str, str]:
        with self._ai_lock:
            return self._ai.get(sid, ("", ""))

    def report(self, sid: int) -> dict[str, Any] | None:
        """Stored reports never change, so parsed ones are kept (bounded)."""
        if sid not in self._reports:
            try:
                rep = self.store.report(sid)
            except StoreError:
                return None
            if len(self._reports) >= _REPORTS_KEPT:
                self._reports.pop(next(iter(self._reports)))
            self._reports[sid] = rep
        return self._reports[sid]

    def rows(self, refresh: bool = False) -> tuple[InstalledState, list[Row]]:
        if self.installed_fn is None:
            return InstalledState(error="not running as a Home Assistant add-on"), []
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
        return st, rows

    def row_for(self, repo: str | None) -> Row | None:
        if not repo or self.installed_fn is None:
            return None
        _, rows = self.rows()
        return next((r for r in rows if r.item.repo.lower() == repo.lower()), None)

    def installed_html(self, base: str, refresh: bool = False, f: str = "all") -> str:
        if self.installed_fn is None:
            return ""
        st, rows = self.rows(refresh)
        html = render_installed(base, st, rows, self.token, self.report, f)
        if not st.error:
            html += self.not_installed_html(base, {r.item.repo.lower() for r in rows})
        return html

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
                        q = urllib.parse.parse_qs(url.query)
                        refresh = q.get("refresh") == ["1"]
                        f = (q.get("f") or ["all"])[0]
                        body = render_index(
                            base, panel.store, jobs, panel.token,
                            panel.installed_html(base, refresh, f), panel.memory_fn(),
                            panel.worker.github_wait, panel.worker.ha_fn(),
                            panel.worker.parallel, panel.catalog_fn is not None,
                        )  # fmt: skip
                        return self._send(200, body)
                    if m := re.fullmatch(r"/scan/(\d+)(\.json)?", url.path):
                        sid = int(m[1])
                        report = panel.store.report(sid)
                        if m[2]:
                            body = json.dumps(report, indent=2).encode()
                            return self._send(200, body, "application/json")
                        row = panel.row_for(report.get("target", {}).get("repo"))
                        state, err = panel.ai_state(sid)
                        choices, choices_err = panel.ai_choices()
                        page = render_scan(
                            base, sid, report, panel.store, row, panel.token,
                            panel.ai_entity, state, err, choices, choices_err,
                        )  # fmt: skip
                        return self._send(200, page)
                    if url.path == "/search" and panel.catalog_fn is not None:
                        q = urllib.parse.parse_qs(url.query)
                        text = (q.get("q") or [""])[0].strip()[:100]
                        kind = (q.get("kind") or [""])[0]
                        kind = kind if kind in ("integration", "card") else ""
                        items, err = panel.catalog()
                        found = supervisor.search(items, text, kind) if text else []
                        page = render_search(
                            base, text, kind, found, panel.current_scans(), panel.busy(),
                            panel.token, err, len(items),
                        )  # fmt: skip
                        return self._send(200, page)
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
                if path == "/ai-entity":
                    value = get("entity")
                    choices, _err = panel.ai_choices(refresh=True)
                    if value and (choices is None or value not in {c[0] for c in choices}):
                        return self._text(
                            HTTPStatus.BAD_REQUEST, "not one of your AI Task entities"
                        )
                    panel.store.set_setting("ai_entity", value or "off")
                    panel.ai_entity = value
                    print(f"AI explanations: {'on, via ' + value if value else 'off'} (chosen in "
                          "the panel)", file=sys.stderr, flush=True)  # fmt: skip
                    sid = get("scan")
                    return self._redirect(f"{self._base()}/scan/{sid}" if sid.isdigit()
                                          else f"{self._base()}/")  # fmt: skip
                if path == "/explain":
                    if not get("scan").isdigit() or not panel.ai_entity:
                        return self._text(HTTPStatus.BAD_REQUEST, "no AI Task entity set")
                    sid = int(get("scan"))
                    try:
                        panel.explain(sid)
                    except StoreError as ex:
                        return self._text(HTTPStatus.NOT_FOUND, str(ex))
                    return self._redirect(f"{self._base()}/scan/{sid}")
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
                if path == "/scan" and (q := get("q")[:100]):
                    kind = get("kind") if get("kind") in ("integration", "card") else ""
                    back = urllib.parse.urlencode({"q": q, "kind": kind})
                    return self._redirect(f"{self._base()}/search?{back}")
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
    ai_entity: str = "",
    ai_fn: AiFn | None = None,
    parallel: int = 1,
    catalog_fn: CatalogFn | None = None,
    entities_fn: EntitiesFn | None = None,
) -> PanelServer:
    """Build the server (caller runs `serve_forever`); `.panel.worker` runs the scans."""
    worker = Worker(
        store, scan_fn, exposure=exposure, ha_fn=ha_fn, memory_fn=memory_fn,
        budget_fn=budget_fn, parallel=parallel,
    )  # fmt: skip
    panel = Panel(store, worker, allow, installed_fn, memory_fn)
    if ai_entity and not supervisor.ai_entity_ok(ai_entity):
        print(f"ignoring ai_entity {ai_entity!r}: not an ai_task.* entity", file=sys.stderr)
        ai_entity = ""
    stored = store.setting("ai_entity")  # chosen in the panel; wins over the option
    if stored == "off":
        ai_entity = ""
    elif stored and supervisor.ai_entity_ok(stored):
        ai_entity = stored
    panel.ai_entity = ai_entity
    panel.catalog_fn = catalog_fn
    panel.entities_fn = entities_fn
    if ai_fn is not None:
        panel.ai_fn = ai_fn
    httpd = PanelServer((host, port), panel.handler())
    httpd.panel = panel
    return httpd
