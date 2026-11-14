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
from importlib import resources
from typing import Any

from sniff_test import __version__, doctor, memory, recheck, supervisor, trust, ui, watch
from sniff_test.diff import HEADLINE_MAX, HEADLINE_RANK
from sniff_test.diff import diff as diff_reports
from sniff_test.fetch.github import GitHubError, RateLimit, RateLimitError
from sniff_test.releases import ReleasesError
from sniff_test.report import ai as report_ai
from sniff_test.report import ai_context
from sniff_test.report.json_report import sanitize_untrusted
from sniff_test.scoring import VERDICTS
from sniff_test.store import ScanRow, Store, StoreError

SUPERVISOR_IP = "172.30.32.2"
_INGRESS_PATH = re.compile(r"^/api/hassio_ingress/[A-Za-z0-9_-]+$")
# A redirect target: one path on this panel, printable ASCII only. No line break (a
# second header), no `//` or backslash at the start (browsers read `/\host` as another
# site), no scheme.
_LOCAL_PATH = re.compile(r"^/(?![/\\])[\x21-\x7e]*$")


def local_path(to: str) -> str:
    """`to` if it is a path on this panel, else "/". Every caller already builds its
    target from checked pieces (the ingress base, digits, quoted values); this is the
    backstop under them, so a future caller can't turn a form field into a header."""
    return to if _LOCAL_PATH.match(to or "") else "/"


_REPO = re.compile(r"^(?:https://github\.com/)?([A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100})/?$")
_REF = re.compile(r"^[A-Za-z0-9_.+/-]{1,100}$")
_LABEL = {v.key: v.label for _, v in VERDICTS}
_SEV_CLASS = {"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium"}
_JOBS_KEPT = 20
# GitHub API requests a job may need, measured 2026-11-09: 6-7 per scan (repo, release,
# commit, tarball, asset, release list, compare), plus 2 repo-habit lookups since 0.6.0
# (open pull requests, open issues); an update check is two scans. Jobs check the budget
# before they start and wait out a rate limit inside. The one GitHub request outside a
# job is the versions page's release list (cached 10 min; a limit there says "try later").
# Without a token GitHub allows 60/hour and counts even 304 answers.
_GITHUB_NEED = {"scan": 10, "installed": 10, "update": 19, "auto": 19}


def _need(job: Job) -> int:
    """GitHub requests this job may still make."""
    if job.kind == "recheck":
        return 0  # asks OSV and the package registries only, never GitHub
    if job.kind == "auto" and not job.prev:
        return _GITHUB_NEED["installed"]
    return _GITHUB_NEED.get(job.kind, 15)


# No scripts, ever. font-src 'self' (2026-11-12) lets the panel serve its own two woff2
# files (assets/fonts, vendored with provenance): fonts are data, not code.
_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; font-src 'self'; "
    "form-action 'self'; base-uri 'none'; frame-ancestors 'self'"
)
_FONT_FILES = ("Geist-Variable.woff2", "GeistMono-Variable.woff2")


def _font_bytes(name: str) -> bytes | None:
    if name not in _FONT_FILES:
        return None
    try:
        return (resources.files("sniff_test") / "assets" / "fonts" / name).read_bytes()
    except OSError:
        return None


def e(text: Any, limit: int = 300) -> str:
    """Escape for HTML text and attribute values (untrusted text is also truncated)."""
    return html.escape(sanitize_untrusted(str(text), limit) if text is not None else "")


# --- jobs ------------------------------------------------------------------------------


@dataclass
class Job:
    id: int
    kind: str  # scan | installed | update | auto | recheck
    repo: str
    ref: str | None
    to: str | None = None  # update: the version HACS would install now (None: work it out)
    prev: str | None = None  # auto: the version installed before an update (its diff base)
    scan: int | None = None  # recheck: the stored scan whose advisories are asked again
    state: str = "queued"  # queued | running | waiting | done | failed | refused
    message: str = ""
    scan_ids: list[int] = field(default_factory=list)
    created: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))
    finished: float = 0.0  # time.time() when it stopped, for the status strip


ScanFn = Callable[[str, str | None], dict[str, Any]]
# (stored report, saved lockfiles, scan id, when its code was sniffed) -> new report | None
RecheckFn = Callable[[dict[str, Any], dict[str, Any], int, str], dict[str, Any] | None]


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
        recheck_fn: RecheckFn = recheck.recheck,
    ):
        self.recheck_fn = recheck_fn
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
        self.on_done: list[Callable[[Job], None]] = []  # called after every job (auto-sniff)
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

    def submit(
        self,
        kind: str,
        repo: str,
        ref: str | None,
        to: str | None = None,
        prev: str | None = None,
        scan: int | None = None,
    ) -> Job:
        with self._lock:
            job = Job(self._next, kind, repo, ref, to, prev, scan)
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

    def _recheck(self, job: Job) -> None:
        """Ask OSV again about a stored scan's packages (recheck.py). A change becomes a
        new scan entry; the stored one is never edited. Only the newest scan of a version
        is re-checked, so a new entry can't hide a later one."""
        sid = int(job.scan or 0)
        row = self.store.get(sid)
        if row is None or not row.repo or not row.ref:
            raise StoreError(f"no stored scan @{sid} to re-check")
        newest = self.store.find(
            row.repo, row.ref, exposure=row.exposure, tool_version=self.tool_version,
            ha_version=row.ha_version,
        )  # fmt: skip
        job.scan_ids = [sid]
        if row.tool_version != self.tool_version or not row.complete:
            # its findings come from other rules, or it never finished: a fresh sniff's job
            job.message = "not re-checked: only complete scans by this Barkley version are"
            return
        if newest is None or newest.id != sid:
            job.message = "not re-checked: a newer scan of this version exists"
            return
        inputs = self.store.inputs(sid)
        if inputs is None:
            job.message = "not re-checked: this scan saved no package list"
            return
        if self.memory_fn().refuse:
            raise MemoryRefused(self.memory_fn().message())
        report = self.store.report(sid)
        was = report.get("recheck") if isinstance(report.get("recheck"), dict) else {}
        try:
            new = self.recheck_fn(
                report, inputs, sid, str(was.get("code_scanned_at") or row.scanned_at)
            )
        except recheck.RecheckError as ex:
            self.store.note_recheck(sid, f"failed: {ex}")
            raise
        if new is None:
            self.store.note_recheck(sid, "same")
            job.message = "advisories unchanged"
            return
        new_id = self.store.save(new, inputs=inputs)
        self.store.note_recheck(sid, f"changed:{new_id}")
        job.scan_ids = [sid, new_id]
        job.message = "advisories changed"

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
            others = sum(_need(j) for j in self.running() if j is not job)
            if b is None or b.remaining >= _need(job) + others:
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
        elif job.kind == "recheck":
            self._recheck(job)
        elif job.kind == "installed":  # an installed version: reuse a stored scan
            job.scan_ids = [self._stored_or_scan(job.repo, job.ref, self.exposure, self.ha_fn())]
            job.message = "sniffed"
        elif job.kind == "auto":  # the Marketplace installed or updated it: that exact version
            new = self._stored_or_scan(job.repo, job.ref, self.exposure, self.ha_fn())
            if job.prev:  # an update: the version before is the diff's old side
                row = self.store.get(new)
                assert row is not None  # noqa: S101 - just saved or found
                old = self._stored_or_scan(job.repo, job.prev, row.exposure, row.ha_version)
                job.scan_ids = [old, new]
                job.message = f"{job.prev} → {job.ref}"
            else:
                job.scan_ids = [new]
                job.message = "sniffed after install"
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
                job.finished = time.time()
                for fn in list(self.on_done):
                    try:
                        fn(job)
                    except Exception as ex:  # a hook never breaks the worker
                        print(f"job {job.id} hook failed: {type(ex).__name__}: {ex}",
                              file=sys.stderr, flush=True)  # fmt: skip
                self._q.task_done()


# --- HTML ------------------------------------------------------------------------------


def _page(title: str, body: str, base: str = "") -> bytes:
    return ui.page(title, body, base=base)


def _verdict(score: int, key: str) -> str:
    cls = {"good_boy": "ok", "kinda_sus": "sev-medium", "very_sus": "sev-high", "bork": "bad"}.get(
        key, ""
    )
    return f'<span class="{cls}"><b>{score}</b> {e(_LABEL.get(key, ""))}</span>'


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


def _action(base: str, r: Row, token: str, back: str = "", primary: bool = False) -> str:
    """The row's own button. Quiet in the list (one primary per view); `primary` on the
    app's page, where checking its update is the one thing to do."""
    it = r.item
    cls = "primary" if primary else ""
    hidden = (f'<input type=hidden name=token value="{token}">'
              f'<input type=hidden name=back value="{back}">'
              f'<input type=hidden name=repo value="{e(it.repo)}">'
              f'<input type=hidden name=ref value="{e(it.installed)}">')  # fmt: skip
    # An incomplete scan is never reused, so the same button scans again. Check update
    # scans the installed version too, so it comes first when an update is offered.
    unfinished = [x for x in (r.installed_scan, r.available_scan) if x and not x.complete]
    if it.update and (unfinished or not (r.installed_scan and r.available_scan)):
        label = "Check again" if unfinished else "Check update"
        return (f'<form method=post action="{base}/update">{hidden}'
                f'<input type=hidden name=to value="{e(it.available)}">'
                f'<button class="{cls}">{label}</button></form>')  # fmt: skip
    if not r.installed_scan or not r.installed_scan.complete:
        label = "Sniff again" if r.installed_scan else "Sniff it"
        return (f'<form method=post action="{base}/installed">{hidden}'
                f'<button class="{cls}">{label}</button></form>')  # fmt: skip
    return ""


def _diff_link(r: Row) -> str:
    if r.item.update and r.installed_scan and r.available_scan:
        return f"old={r.installed_scan.id}&amp;new={r.available_scan.id}"
    return ""


def not_installed_cards_html(base: str, cards: list[ui.Card]) -> str:
    """The "Sniffed, not installed" section under the installed list."""
    if not cards:
        return ""
    return (
        f"<h2>Sniffed, not installed ({len(cards)})</h2>"
        '<div class="grid">' + "".join(ui.card_html(base, c) for c in cards) + "</div>"
    )


def render_installed(
    base: str,
    state: InstalledState,
    rows: list[Row],
    token: str,
    report_fn: Callable[[int], dict[str, Any] | None],
    v: ui.View | None = None,
) -> str:
    v = v or ui.View()
    back = v.qs()
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
            action=_action(base, r, token, back),
        )
        for r in rows
    ]
    never = sum(1 for r in rows if not r.installed_scan)
    lead = ""
    if never:  # the list's one primary action; nothing when everything is sniffed
        lead = (
            f'<form method=post action="{base}/installed-all">'
            f'<input type=hidden name=token value="{token}">'
            f'<input type=hidden name=back value="{back}">'
            f'<button class="primary">Sniff the {never} not yet sniffed by Barkley '
            f"{e(__version__)}</button></form>"
        )
    out = (
        [ui.render_grid(base, cards, v, lead)]
        if rows
        else ['<p class="muted">The Marketplace lists no installed integrations or cards.</p>']
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
        return f'<div class="banner bad">{ui.icon("alert")} Memory: {e(mem.message(), 300)}</div>'
    if mem.level == "warn":
        return f'<div class="banner warn">{ui.icon("alert")} Memory: {e(mem.message(), 300)}</div>'
    return ""


def _github_banner(wait: str) -> str:
    return f'<div class="banner warn">{ui.icon("clock")} {e(wait, 400)}</div>' if wait else ""


STATUS_RECENT = 600  # seconds a finished job stays in the status strip


def status_html(
    base: str, jobs: list[Job], names: dict[str, str], here: str, now: float | None = None
) -> str:
    """The strip at the top: what's being sniffed now and what just finished."""
    now = time.time() if now is None else now
    active = [j for j in jobs if j.state in ("running", "waiting", "queued")]
    # A daily advisory re-check that found nothing new isn't news: it stays out of the strip.
    recent = [
        j for j in jobs
        if j.finished and now - j.finished < STATUS_RECENT
        and not (j.kind == "recheck" and j.state == "done" and len(j.scan_ids) < 2)
    ][-3:]  # fmt: skip
    if not active and not recent:
        return ""

    def name(j: Job) -> str:
        return e(names.get(j.repo.lower()) or j.repo, 100)

    lines = []
    for j in active:
        if j.state == "running":
            what = "Sniffing" if j.kind != "update" else "Checking the update of"
            if j.kind == "auto":
                what = "Auto-sniffing the update of" if j.prev else "Auto-sniffing"
            if j.kind == "recheck":
                what = "Re-checking the advisories of"
            lines.append(f'<b><span class="dot"></span>{what} {name(j)}…</b>')
        elif j.state == "waiting":
            lines.append(f"{ui.icon('clock', 14, 'muted')} {name(j)}: {e(j.message, 200)}")
    queued = sum(j.state == "queued" for j in active)
    if queued:
        nxt = ", ".join(name(j) for j in active if j.state == "queued")
        lines.append(f'<span class="muted">{queued} waiting their turn: {nxt}</span>')
    for j in reversed(recent):
        sid = j.scan_ids[-1] if j.scan_ids else None
        if j.state == "done" and sid is not None:
            link = f'<a href="{base}/scan/{sid}">see the result</a>'
            if j.kind in ("update", "auto") and len(j.scan_ids) == 2:
                old, new = j.scan_ids
                link = f'<a href="{base}/diff?old={old}&amp;new={new}">what the update changes</a>'
            if j.kind == "recheck":
                old, new = j.scan_ids
                lines.append(
                    f"{ui.icon('alert', 14, 'muted')} The known advisories of {name(j)} changed: "
                    f'<a href="{base}/diff?old={old}&amp;new={new}">what changed</a>'
                )
                continue
            lines.append(f"{ui.icon('check', 14, 'ok')} {name(j)} is done: {link}")
        else:
            lines.append(f"{ui.icon('x', 14, 'bad')} {name(j)} {e(j.state)}: {e(j.message, 200)}")
    tail = (
        '<span class="muted small">This page refreshes by itself while a scan runs.</span>'
        if active
        else ""
    )
    return (
        '<div class="box status" role="status">'
        + "".join(f'<div class="row">{x}</div>' for x in lines)
        + f'<div class="row">{tail}<a class="small" href="{base}/?{here}">{ui.icon("refresh")} '
        "Refresh</a></div></div>"
    )


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
    status: str = "",
    here: str = "",
    auto: str = "",
) -> bytes:
    rows = store.history(limit=100)
    against = f" against HA {e(ha)}" if ha else ""
    out = [
        f'<div class="head"><h1>{ui.logo_img()}Barkley</h1>'
        f'<a class="small" href="{base}/?{here}">{ui.icon("refresh")} Refresh</a></div>',
        status,
        _memory_banner(mem) if mem else "",
        _github_banner(github_wait),
        _search_box(base) if search else "",
        installed,
        auto,
    ]
    active = [j for j in jobs if j.state in ("queued", "running", "waiting")]
    if jobs:
        out.append(
            f'<details class="box"{" open" if active else ""}><summary>Jobs '
            f"({len(active)} running or queued, {len(jobs) - len(active)} finished)</summary>"
            '<div class="tablebox"><table>'
        )
        for j in jobs:
            links = " ".join(f'<a href="{base}/scan/{i}">@{i}</a>' for i in j.scan_ids)
            if j.kind in ("update", "auto", "recheck") and len(j.scan_ids) == 2:
                old, new = j.scan_ids
                links += f' · <a href="{base}/diff?old={old}&amp;new={new}">diff</a>'
            kind = {"auto": "auto-sniff", "recheck": "advisory re-check"}.get(j.kind, j.kind)
            out.append(
                f'<tr><td class="nowrap">{e(kind)}</td><td class="wrap">{e(j.repo)}'
                f"{'@' + e(j.prev) + ' → ' if j.prev else ''}{'@' + e(j.ref) if j.ref else ''}"
                f"{' → ' + e(j.to) if j.to else ''}"
                f'</td><td class="nowrap">{e(j.state)}</td><td class="wrap">{e(j.message)} '
                f"{links}</td></tr>"
            )
        out.append("</table></div></details>")
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
        out.append('<div class="tablebox"><table><tr><th>#</th><th>score</th><th>repo</th>'
                   "<th>when</th></tr>")  # fmt: skip
        for r in rows:
            extra = r.kind + (f" · HA {r.ha_version}" if r.ha_version else "")
            extra += f" · rules {r.tool_version}"
            if not r.complete:
                extra += " · incomplete"
            out.append(
                f'<tr><td><a href="{base}/scan/{r.id}">@{r.id}</a></td>'
                f"<td>{_verdict(r.score, r.verdict)}</td>"
                f'<td class="wrap">{e(r.repo or r.source, 100)}'
                f"{'@' + e(r.ref, 60) if r.ref else ''}"
                f'<br><span class="muted">{e(extra)}</span></td>'
                f'<td class="nowrap">{e(r.scanned_at[:16].replace("T", " "))}</td></tr>'
            )
        out.append("</table></div>")
    out.append("</details>")
    out.append(
        f'<p class="foot">Barkley {e(__version__)}{against}. '
        + (
            "Scans run one at a time. "
            if parallel <= 1
            else f"Up to {parallel} scans run at once, as memory allows. "
        )
        + f'Scores never come from an AI. <a href="{base}/doctor">Diagnostics</a>: can each '
        f'tool run on this box? <a href="{base}/trusted">Addresses you trust</a>.</p>'
    )
    return ui.page("Barkley", "".join(out), refresh=5 if active else 0, base=base)


AUTO_NOTE = (
    "<b>A new integration runs as soon as it's installed:</b> Home Assistant opens its setup "
    "right away, which loads its code. The auto-sniff of a new install comes after that, so "
    "the protection for a new install is sniffing it from search <i>before</i> you install. "
    "An update is sniffed <b>as soon as the Marketplace offers it</b>, so the heads-up and "
    "what it changes come before you update; its new code waits for a restart anyway."
)


def render_auto(base: str, w: watch.Watcher, token: str, now: float | None = None) -> str:
    """The auto-sniff box: what it does, the plain timing note, settings, recent results."""
    now = time.time() if now is None else now
    on = w.enabled
    targets, terr = w.targets()
    chosen = w.notify_target
    who = f"bell + notify.{e(chosen)}" if chosen else "bell notification"
    ok, diag = w.diagnostics()
    hidden = f'<input type=hidden name=token value="{token}">'
    opts = ['<option value="">no one else (bell notification only)</option>'] + [
        f'<option value="{e(t)}"{" selected" if t == chosen else ""}>notify.{e(t)}</option>'
        for t in targets
    ]
    if chosen and chosen not in targets:
        opts.append(f'<option value="{e(chosen)}" selected>notify.{e(chosen)} (not offered now)'
                    "</option>")  # fmt: skip
    rows = []
    for x in w.log()[:10]:
        ids = [int(i) for i in x.get("scan_ids", []) if isinstance(i, int)]
        links = " ".join(f'<a href="{base}/scan/{i}">@{i}</a>' for i in ids)
        if len(ids) == 2:
            links += f' · <a href="{base}/diff?old={ids[0]}&amp;new={ids[1]}">diff</a>'
        if x.get("action") == "advisories":
            did = f"{e(x.get('version'))}: package advisories changed"
        elif x.get("action") == "available":
            did = f"update {e(x.get('previous'))} → {e(x.get('version'))} waiting"
        elif x.get("previous"):
            did = f"updated {e(x.get('previous'))} → {e(x.get('version'))}"
        else:
            did = f"installed {e(x.get('version'))}"
        if "score" in x:
            result = _verdict(int(x["score"]), str(x.get("verdict", "")))
            if x.get("changes"):
                result += f' <span class="muted">{e(x["changes"], 200)}</span>'
            if not x.get("complete", True):
                result += ' <span class="muted">(incomplete)</span>'
        else:
            result = f"{e(x.get('state'))}: {e(x.get('message'), 200)}"
        rows.append(
            f'<tr><td class="nowrap">{e(str(x.get("when", ""))[:16].replace("T", " "))}</td>'
            f'<td class="wrap">{e(x.get("repo"))} {did}</td><td class="wrap">{result} {links}'
            "</td></tr>"
        )
    recent = (
        '<div class="tablebox"><table><tr><th>when</th><th>what happened</th><th>result</th>'
        "</tr>" + "".join(rows) + "</table></div>"
        if rows
        else '<p class="muted small">Nothing installed or updated since Barkley started '
        "watching.</p>"
    )  # fmt: skip
    return (
        f'<div class="box auto"><h2>Auto-sniff: {"on" if on else "off"} · {who}</h2>'
        '<p class="sub">When the Marketplace offers an update, installs or updates an '
        "integration or card, Barkley sniffs that version (reusing a stored scan of that exact "
        "version, for example one you sniffed from search) and sends a notification: the app, "
        "its version, the verdict and score, what's worth a look, and for an update what "
        "changes compared with the version you have. Once a day it also asks again whether "
        "the packages of your installed apps (and of updates waiting) have new known "
        "vulnerabilities or were found to be malicious, and tells you only when that "
        "changed. That re-check doesn't fetch or scan the app's code again.</p>"
        f"<p>{AUTO_NOTE}</p>"
        '<div class="again">'
        f'<form method=post action="{base}/auto-scan">{hidden}'
        f'<input type=hidden name=on value="{0 if on else 1}">'
        f'<button class="{"" if on else "primary"}">Turn auto-sniff {"off" if on else "on"}'
        "</button></form>"
        f'<form method=post action="{base}/notify-target">{hidden}'
        f"<label>Also notify <select name=target>{''.join(opts)}</select></label> "
        "<button>Save</button></form>"
        f'<form method=post action="{base}/notify-test">{hidden}'
        "<button>Send a test notification</button></form>"
        + (f'<span class="small">{e(w.last_test, 300)}</span>' if w.last_test else "")
        + "</div>"
        + (f'<p class="muted small">Notify targets: {e(terr, 300)}</p>' if terr else "")
        + f'<p class="muted small">{"" if ok else ui.icon("alert", 14, "warn") + " "}'
        f"{e(diag, 600)}. Scans of apps that "
        f"aren't installed are deleted after {w.age_out_days:g} days; scans of installed apps "
        "are kept.</p>"
        f"<details><summary>Recent auto-sniffs ({len(w.log())})</summary>{recent}</details>"
        "</div>"
    )


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
    if not row.busy and (act := _action(base, row, token, primary=True)):
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
    return (f'<form method=post action="{base}/ai-entity" class="act tools mt2">'
            f'<input type=hidden name=token value="{token}">'
            f'<input type=hidden name=scan value="{sid}">'
            f'<select name=entity>{"".join(opts)}</select>'
            "<button>Save</button></form>")  # fmt: skip


AI_MODES = {
    "summary": "AI summary only",
    "deep": "AI deep analysis (reads the code around each finding)",
}


def _mode_picker(base: str, sid: int, token: str, mode: str) -> str:
    opts = "".join(
        f'<option value="{k}"{" selected" if k == mode else ""}>{e(v)}</option>'
        for k, v in AI_MODES.items()
    )
    return (f'<form method=post action="{base}/ai-mode" class="act tools mt2">'
            f'<input type=hidden name=token value="{token}">'
            f'<input type=hidden name=scan value="{sid}">'
            f"<select name=mode>{opts}</select><button>Save</button></form>"
            '<p class="tech">Deep analysis adds an "Explain in context" button to each finding, '
            "port and unknown address. The AI then reads that part of the app's code, and every "
            "statement it makes must cite lines that check out. Code is sent only when you "
            "click.</p>")  # fmt: skip


def _ai_form(base: str, sid: int, token: str, entity: str, state: str, error: str,
             have: dict[str, Any] | None, choices: list[tuple[str, str]] | None = None,
             choices_err: str = "", mode: str = "summary",
             readings: list[str] | None = None) -> str:  # fmt: skip
    """The "Explain this app" control. Nothing is sent until the user clicks.
    `readings`: ids of this scan's "Explain in context" answers with something shown."""
    picker = _ai_picker(base, sid, token, entity, choices, choices_err)
    if entity:
        picker += _mode_picker(base, sid, token, mode)
    if not entity:
        return (
            f'<div class="banner mt3"><b>{ui.icon("sparkle", 16)} Explain this app with AI</b>'
            '<p class="small mt2">Barkley can ask your Home Assistant\'s '
            "AI to explain these findings in plain words. Choose which AI to use:</p>"
            f"{picker}</div>"
        )
    form = (f'<form method=post action="{base}/explain" class="act mt2">'
            f'<input type=hidden name=token value="{token}">'
            f'<input type=hidden name=scan value="{sid}">'
            f'<button class="ai">{ui.icon("sparkle", 16)} {{label}}</button></form>')  # fmt: skip
    note = ('<p class="tech">Sends this scan\'s findings (about a public project, no Home '
            f"Assistant data) to the AI provider behind <code>{e(entity, 120)}</code>. The AI "
            "explains only; it can't change the score or the findings.</p>")  # fmt: skip
    change = (f"<details><summary>Change which AI explains, or how much "
              f"({e(AI_MODES.get(mode, mode))})</summary>{picker}</details>")  # fmt: skip
    if state == "running":
        return ('<p class="muted small mt2">Asking your AI… this page '
                "refreshes by itself.</p>")  # fmt: skip
    if error:
        return (f'<div class="banner warn mt2">The AI didn\'t answer: '
                f"{e(error, 400)}</div>" + form.replace("{label}", "Try again") + note
                + change)  # fmt: skip
    if have:
        used = list(have.get("readings") or [])
        newer = [r for r in readings or [] if r not in used]
        n = len(used)
        incl = (f" Includes {n} code reading{'s' if n != 1 else ''} from Explain in context."
                if n else "")  # fmt: skip
        d = int(have.get("dropped") or 0)
        left = (f" Left out {d} sentence{'s' if d != 1 else ''} that dismissed something."
                if d else "")  # fmt: skip
        label = "Ask again"
        if newer:
            k = len(newer)
            label = f"Ask again to include {k} newer code reading{'s' if k != 1 else ''}"
        return (f'<p class="tech">AI explanation by <code>{e(have.get("entity_id"), 120)}</code>, '
                f"{e(str(have.get('created', ''))[:16].replace('T', ' '))} UTC.{incl}{left} It "
                "can be wrong; it can't change the score.</p>"
                + form.replace("{label}", label) + change)  # fmt: skip
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
    ai_mode: str = "summary",
    item_states: dict[str, tuple[str, str]] | None = None,
    open_item: str = "",
    rechecking: bool = False,
) -> bytes:
    """`open_item`: the item whose AI sheet is open (`?open=`), kept open across refreshes.
    `rechecking`: an advisory re-check of this scan is queued or running (the page then
    reloads itself until it ends)."""
    repo = report.get("target", {}).get("repo")
    rows = store.history(repo, limit=200) if repo else []
    have = store.explanation(sid)
    item_states = item_states or {}
    # While anything is being read the page refreshes itself. With a sheet open it goes to
    # a fresh URL that reopens it (`?open=`); otherwise it's a plain reload, which keeps the
    # reader's scroll position but needs an address without a fragment, so the sheets'
    # links are URLs for that long (see ui.deep_html).
    running = ai_state == "running" or any(st == "running" for st, _ in item_states.values())
    deep = None
    if ai_mode == "deep" and ai_entity and report.get("context"):
        answers = store.item_explanations(sid)

        def deep(item_id: str) -> str:
            snip = ai_context.snippet_of(report, item_id)
            if snip is None:
                it = (report["context"].get("items") or {}).get(item_id) or {}
                if it.get("kind") == "dependency" and it.get("unread"):
                    return (f'<p class="small muted">{ui.icon("sparkle")} Explain in context: '
                            "this package's advisory appeared after the code was sniffed, so "
                            "Barkley hasn't looked for where the app uses "
                            f"{e(it.get('package'), 120)}. Sniff this version again to include "
                            "that.</p>")  # fmt: skip
                if it.get("kind") == "dependency":  # nothing of the app's own to read
                    return (f'<p class="small muted">{ui.icon("sparkle")} Explain in context: we '
                            "couldn't find "
                            f"where the app's own code uses {e(it.get('package'), 120)}, so "
                            "there's no code to send. It may come in through another library, "
                            "or a bundle hides the name.</p>")  # fmt: skip
                return ""
            state, err = item_states.get(item_id, ("", ""))
            form = (f'<form method=post action="{base}/explain-item">'
                    f'<input type=hidden name=token value="{token}">'
                    f'<input type=hidden name=scan value="{sid}">'
                    f'<input type=hidden name=item value="{e(item_id, 40)}">'
                    "<button>{label}</button></form>")  # fmt: skip
            return ui.deep_html(form, item_id=item_id, title=ai_context.title(report, item_id),
                                answer=answers.get(item_id), state=state, error=err,
                                snip=snip, entity=ai_entity,
                                open_url=_scan_url(base, sid, item_id) if running else "",
                                close_url=e(f"{base}/scan/{sid}") if running else "")  # fmt: skip

    return ui.render_app(
        base,
        sid,
        report,
        rows,
        name=row.item.name if row else None,
        update=_update_box(base, row, token),
        again=_again_box(base, report, token)
        + _advisory_line(base, sid, report, store, token, rechecking),
        trust=trust_block(base, sid, report, token),
        ai=have,
        ai_form=_ai_form(
            base,
            sid,
            token,
            ai_entity,
            ai_state,
            ai_error,
            have,
            ai_choices,
            ai_choices_err,
            ai_mode,
            [
                k
                for k, v in store.item_explanations(sid).items()
                if v.get("claims") or v.get("questions")
            ],
        ),
        refresh=5 if running or rechecking else 0,
        deep=deep,
        refresh_url=_scan_url(base, sid, open_item, fresh=True) if open_item else "",
    )


def _scan_url(base: str, sid: int, open_item: str = "", fresh: bool = False) -> str:
    """An app page's URL, with the AI sheet for `open_item` open. `fresh` adds the time so
    a meta refresh never targets the page's own URL (with a fragment that never reloads)."""
    q = {}
    if open_item:
        q["open"] = open_item
    if fresh:
        q["t"] = str(int(time.time()))
    url = f"{base}/scan/{sid}" + (f"?{urllib.parse.urlencode(q)}" if q else "")
    return e(url + (f"#ai-{open_item}" if open_item else ""))


def _again_box(base: str, report: dict[str, Any], token: str) -> str:
    """Sniff this exact version again (a fresh scan, never the stored one), or pick another."""
    t = report.get("target", {})
    repo, ref = t.get("repo"), t.get("ref")
    if not (repo and _REPO.match(str(repo)) and (not ref or _REF.match(str(ref)))):
        return ""
    return (
        f'<div class="again small"><form method=post action="{base}/scan">'
        f'<input type=hidden name=token value="{token}">'
        f'<input type=hidden name=repo value="{e(repo)}">'
        f'<input type=hidden name=ref value="{e(ref or "")}">'
        '<button class="link" title="Runs a fresh scan instead of reusing this one">'
        "Sniff this version again</button></form>"
        f'<span class="muted">·</span> {_versions_link(base, repo)}</div>'
    )


def _utc(iso: str) -> str:
    """'2026-11-13T02:10:00+00:00' -> '2026-11-13 02:10 UTC' (stored times are UTC)."""
    return f"{iso[:10]} {iso[11:16]} UTC" if len(iso) >= 16 else iso


def _advisory_line(
    base: str, sid: int, report: dict[str, Any], store: Store, token: str, busy: bool = False
) -> str:
    """When this scan's package advisories were last asked about, from the store: the
    entry it was re-checked from, the outcome of its own latest re-check, and the text
    action that asks again. Nothing for a scan that saved no package list."""
    bits = []
    rc = report.get("recheck")
    if isinstance(rc, dict) and str(rc.get("of", "")).isdigit():
        of = int(rc["of"])
        bits.append(
            f"The known advisories for its packages changed, so this entry replaced "
            f'<a href="{base}/scan/{of}">scan @{of}</a> on {e(_utc(str(rc.get("at", ""))))} '
            f'(<a href="{base}/diff?old={of}&amp;new={sid}">what changed</a>). The code is as '
            f"sniffed on {e(str(rc.get('code_scanned_at', ''))[:10])}; only the advisories "
            "were asked again."
        )
    last = store.rechecks().get(sid)
    if last:
        when, result = e(_utc(last[0])), last[1]
        if result == "same":
            bits.append(f"Advisories asked again {when}: nothing changed.")
        elif result.startswith("changed:") and result[8:].isdigit():
            new = int(result[8:])
            bits.append(f"An advisory re-check on {when} found changes: see "
                        f'<a href="{base}/scan/{new}">scan @{new}</a>.')  # fmt: skip
        elif result.startswith("failed"):
            bits.append(f"The advisory re-check on {when} couldn't be done, so the advisories "
                        f"shown are older ({e(result, 200)}).")  # fmt: skip
    row = store.get(sid)
    can = (
        row is not None
        and row.repo
        and row.ref
        and row.complete
        and row.tool_version == __version__
        and sid in store.has_inputs()
        and not (last and last[1].startswith("changed:"))
    )
    if busy:
        bits.append('<span class="dot"></span>Asking OSV again about its packages…')
    elif can:
        bits.append(
            f'<form method=post action="{base}/recheck">'
            f'<input type=hidden name=token value="{token}">'
            f'<input type=hidden name=scan value="{sid}">'
            '<button class="link" title="Asks OSV again about the packages this scan found. '
            'The code is not fetched or scanned again.">Check advisories again</button></form>'
        )
    # `.again` is a flex row: each sentence is one item, so links stay inside their text
    return (
        '<div class="again small muted">' + "".join(f"<span>{b}</span>" for b in bits) + "</div>"
        if bits
        else ""
    )


def _search_box(base: str, q: str = "", kind: str = "", primary: bool = False) -> str:
    opts = "".join(
        f'<option value="{v}"{" selected" if v == kind else ""}>{label}</option>'
        for v, label in (("", "Integrations and cards"), ("integration", "Integrations"),
                         ("card", "Dashboard cards"))
    )  # fmt: skip
    return (
        f'<form method=get action="{base}/search" class="box tools search" role="search">'
        f'<input name=q value="{e(q, 100)}" maxlength=100 required '
        'placeholder="Find a Marketplace app to sniff before you install it">'
        f'<select name=kind>{opts}</select><button class="{"primary" if primary else ""}">'
        "Search</button></form>"
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
        f'<p class="crumb"><a href="{base}/">{ui.icon("back")} All apps</a></p>',
        "<h1>Find an app to sniff</h1>",
        '<p class="muted small">Searches the Marketplace catalog your Home Assistant already '
        "has. Sniffing checks exactly what the Marketplace would install, without installing "
        "anything.</p>",
        _search_box(base, q, kind, primary=True),
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
            act = ('<span class="muted"><span class="dot"></span>'
                   + {"running": "sniffing…"}.get(b, "queued…") + "</span>")  # fmt: skip
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
                   "<button>Sniff it</button></form>")  # fmt: skip
        tag = ' <span class="chip new">installed</span>' if it.installed else ""
        rows.append(
            f'<tr><td class="wrap"><b>{e(it.name, 100)}</b>{tag}<br>'
            f'<span class="muted small">{e(ui.KIND.get(it.kind, it.kind))} · '
            f"{e(it.repo, 120)} · {ui.icon('star', 14, 'muted')} {it.stars:,} · "
            f"{it.downloads:,} downloads</span>"
            f'<br><span class="small">{e(it.description, 300)}</span></td>'
            f'<td class="actcol">{act}'
            f'<div class="small">{_versions_link(base, it.repo)}</div></td></tr>'
        )
    if rows:
        out.append(f'<p class="muted small">{len(results)} best matches of {total} '
                   "integrations and cards.</p>")  # fmt: skip
        out.append('<table class="box">' + "".join(rows) + "</table>")
    return _page("Barkley · search", "".join(out), base)


def _versions_link(base: str, repo: str) -> str:
    q = urllib.parse.urlencode({"repo": repo})
    return f'<a href="{base}/versions?{e(q)}">Other versions</a>'


def render_versions(
    base: str,
    repo: str,
    name: str,
    releases: list[Any],
    default: str | None,
    installed: str | None,
    scans: dict[str, ScanRow],
    busy: dict[str, str],
    token: str,
    error: str = "",
) -> bytes:
    """A repo's newest releases, betas included, each with its score or a Sniff button."""
    out = [
        f'<p class="crumb"><a href="{base}/">{ui.icon("back")} All apps</a></p>',
        f"<h1>Versions of {e(name, 100)}</h1>",
        f'<p class="muted small">{e(repo, 120)} · the {len(releases) or "newest"} newest '
        "releases on GitHub, betas included. Sniffing a version checks exactly what the "
        "Marketplace installs when you pick that version.</p>",
    ]
    if error:
        out.append(f'<div class="banner warn">Can\'t list the releases right now: '
                   f"{e(error, 300)}</div>")  # fmt: skip
    rows = []

    def button(ref: str | None, label: str) -> str:
        return (f'<form method=post action="{base}/scan">'
                f'<input type=hidden name=token value="{token}">'
                f'<input type=hidden name=repo value="{e(repo)}">'
                f'<input type=hidden name=ref value="{e(ref or "")}">'
                '<input type=hidden name=back_to value="versions">'
                f"<button>{label}</button></form>")  # fmt: skip

    def action(ref: str | None) -> str:
        key = (ref or "").lower()
        if b := busy.get(key):
            return ('<span class="muted"><span class="dot"></span>'
                    + {"running": "sniffing…"}.get(b, "queued…") + "</span>")  # fmt: skip
        if scan := scans.get(key):
            bd = ui.band(scan.score, scan.complete)
            return (f'<a class="badge {bd}" style="text-decoration:none" '
                    f'href="{base}/scan/{scan.id}">'
                    f"{scan.score}<small>{e(ui.BANDS[bd][0])}</small></a>")  # fmt: skip
        return button(ref, "Sniff it")

    for r in releases:
        chips = []
        if r.tag == default:
            chips.append('<span class="chip">Marketplace default</span>')
        if r.prerelease:
            chips.append('<span class="chip warn">beta</span>')
        if installed and r.tag == installed:
            chips.append('<span class="chip new">installed</span>')
        who = f" · published by {e(r.publisher, 60)}" + (" (a bot)" if r.bot else "")
        when = e((r.published_at or "")[:10])
        act = action(r.tag) if _REF.match(r.tag) else '<span class="muted">odd tag name</span>'
        rows.append(
            f'<tr><td class="wrap"><b><code>{e(r.tag, 100)}</code></b> {"".join(chips)}<br>'
            f'<span class="muted small">{when}{who if r.publisher else ""}</span></td>'
            f'<td class="actcol">{act}</td></tr>'
        )
    if rows:
        out.append('<table class="box">' + "".join(rows) + "</table>")
    elif not error:
        out.append('<p class="muted">No releases: the Marketplace installs the newest code on '
                   "the default branch.</p>")  # fmt: skip
        out.append(f"<p>{action(None)}</p>")
    running = any(v in ("running", "queued", "waiting") for v in busy.values())
    return ui.page(f"Barkley · versions of {name}", "".join(out), refresh=5 if running else 0,
                   base=base)  # fmt: skip


def trust_block(base: str, sid: int, report: dict[str, Any], token: str) -> ui.TrustFn:
    """The "Trust this address?" block under a finding that is only about where an
    address points, or the "you trust this" note with its undo. Server-built (it holds
    the form token); every address is escaped and came from the scanner's own parse."""
    repo = str(report.get("target", {}).get("repo") or "")
    has_repo = bool(_REPO.match(repo))
    trusted = {f["id"]: f for f in report.get("trusted_findings", [])}

    def hidden(f: dict[str, Any]) -> str:
        return (f'<input type=hidden name=token value="{token}">'
                f'<input type=hidden name=scan value="{sid}">'
                f'<input type=hidden name=finding value="{e(f["id"], 16)}">')  # fmt: skip

    def block(f: dict[str, Any]) -> str:
        addrs = [a for a in f.get("addresses") or [] if isinstance(a, str)]
        if not addrs:
            return ""
        lines = "".join(ui.address_line(a) for a in addrs[:6])
        if f["id"] in trusted:
            scope = trusted[f["id"]].get("trusted")
            undo = "".join(
                f'<form method=post action="{base}/untrust"><input type=hidden name=token '
                f'value="{token}"><input type=hidden name=scan value="{sid}">'
                f'<input type=hidden name=address value="{e(a, 253)}">'
                f'<input type=hidden name=repo value="{e(repo) if sc == "app" else ""}">'
                f"<button>Stop trusting {e(a, 80)}"
                f"{' (for every app)' if sc == 'all' else ''}</button></form>"
                for a in addrs[:6]
                if (sc := store_scope(report, a))
            )
            where = {"app": "for this app", "all": "for every app"}.get(scope, "")
            return (f'<div class="trustbox on"><p class="small"><b>{ui.icon("check")} You trust '
                    f"{'this address' if len(addrs) == 1 else 'these addresses'} {where}</b>, "
                    "so this finding costs no points. A new or changed address is flagged "
                    f'again.</p><ul class="plain small">{lines}</ul><div class="row">{undo}</div>'
                    "</div>")  # fmt: skip
        one = len(addrs) == 1
        name = e(addrs[0], 80) if one else "these addresses"
        buttons = (
            (f'<form method=post action="{base}/trust">{hidden(f)}'
             "<input type=hidden name=scope value=app><button>Trust for this app</button></form>"
             if has_repo else "")
            + f'<form method=post action="{base}/trust">{hidden(f)}'
            "<input type=hidden name=scope value=all><button>Trust for every app</button></form>"
        )  # fmt: skip
        return (f'<div class="trustbox"><p class="small"><b>Trust {name}?</b> This finding is '
                f"only about where {'this address points' if one else 'these addresses point'}"
                ", not about what is sent. Check that "
                f"{'it is an address' if one else 'they are addresses'} you expect this app to "
                "use before you run it. If you mark "
                f"{'it' if one else 'them'} trusted, this finding costs no points, now and in "
                f"future sniffs, until the address changes.</p><ul class=\"plain small\">{lines}"
                f'</ul><div class="row">{buttons}</div></div>')  # fmt: skip

    def store_scope(rep: dict[str, Any], a: str) -> str:
        return rep.get("trust", {}).get("scopes", {}).get(a, "")

    return block


def render_trusted(base: str, trusted: trust.Trusted, names: dict[str, str], token: str) -> bytes:
    """Every address the user trusts, with an undo each. Addresses and repos were
    validated when they were stored; still escaped."""

    def row(a: str, repo: str) -> str:
        return (f'<tr><td><code>{e(a, 253)}</code></td><td class="wrap">{ui.known_text(a)}</td>'
                f'<td class="act"><form method=post action="{base}/untrust">'
                f'<input type=hidden name=token value="{token}">'
                f'<input type=hidden name=address value="{e(a, 253)}">'
                f'<input type=hidden name=repo value="{e(repo)}">'
                "<button>Stop trusting</button></form></td></tr>")  # fmt: skip

    out = [f'<p class="crumb"><a href="{base}/">{ui.icon("back")} All apps</a></p>',
           "<h1>Addresses you trust</h1>",
           '<p class="muted">Some findings are only about where an address points: an '
           "internet address written into the code as a number, or an address in a code "
           "library that an automatic check finds suspicious-looking. When you mark such an "
           "address trusted on an app's page, those findings stop costing points. Nothing "
           "else is affected: a finding about what an app sends, or about a paste site, "
           "tunnel or chat webhook, can't be switched off here. Barkley's own score stays "
           "on each app's page.</p>"]  # fmt: skip
    if not trusted:
        out.append('<p class="muted">You haven\'t marked any address trusted.</p>')
    if trusted.everywhere:
        rows = "".join(row(a, "") for a in sorted(trusted.everywhere))
        out.append(f"<h2>For every app</h2><table>{rows}</table>")
    for repo in sorted(trusted.apps):
        if trusted.apps[repo]:
            title = names.get(repo) or repo
            out.append(f"<h2>Only for {e(title, 80)} <span class=\"muted small\">{e(repo, 200)}"
                       "</span></h2><table>"
                       + "".join(row(a, repo) for a in sorted(trusted.apps[repo]))
                       + "</table>")  # fmt: skip
    return _page("Barkley · Addresses you trust", "".join(out), base)


class Diagnostics:
    """The Diagnostics page's checks, run off the request thread: the tool runs take
    about 15 s together, and the page used to stay blank for all of it. A visit starts a
    run (unless one is going, or the last one just ended) and shows what is known so far;
    the page reloads itself until the run ends."""

    FRESH = 60.0  # a finished run this recent is shown again instead of starting another

    def __init__(self, run: Callable[..., list[doctor.Check]] | None = None):
        self._run = run
        self._lock = threading.Lock()
        self.checks: list[doctor.Check] = []
        self.pending: list[str] = []
        self.total = 0
        self.running = False
        self.started = 0.0
        self.ended = 0.0

    def start(self, force: bool = False) -> None:
        with self._lock:
            if self.running:
                return
            if not force and self.ended and time.monotonic() - self.ended < self.FRESH:
                return
            self.running = True
            self.checks = []
            self.pending = [name for name, _ in doctor.steps(addon=True)]
            self.total = len(self.pending)
            self.started = time.monotonic()
        threading.Thread(target=self._work, name="diagnostics", daemon=True).start()

    def _step(self, name: str, got: list[doctor.Check]) -> None:
        with self._lock:
            self.checks += got
            if name in self.pending:
                self.pending.remove(name)

    def _work(self) -> None:
        try:
            # Looked up here, not at import, so the function can be replaced.
            checks = (self._run or doctor.run_checks)(addon=True, on_step=self._step)
        except Exception as ex:  # a failed run must end, and say why
            failed = doctor.Check("diagnostics", False, f"{type(ex).__name__}: {ex}")
            with self._lock:
                checks = [*self.checks, failed]
        with self._lock:
            self.checks = list(checks)
            self.pending = []
            self.running = False
            self.ended = time.monotonic()

    def state(self) -> dict[str, Any]:
        with self._lock:
            now = time.monotonic()
            return {
                "checks": list(self.checks),
                "pending": list(self.pending),
                "total": self.total,
                "running": self.running,
                "age": int(now - self.ended) if self.ended else 0,
                "took": round(self.ended - self.started) if self.ended else 0,
            }


def render_doctor(
    base: str, checks: list[doctor.Check], state: dict[str, Any] | None = None
) -> bytes:
    """`state` (Diagnostics.state()): the steps still to come and whether a run is going.
    While one is, the page reloads every 2 s and names what it is waiting for."""
    state = state or {}
    pending = list(state.get("pending") or [])
    running = bool(state.get("running"))
    out = [f'<p class="crumb"><a href="{base}/">{ui.icon("back")} All apps</a></p>',
           "<h1>Diagnostics</h1>",
           f'<p class="muted">Barkley {e(__version__)}. Each tool runs on a one-line '
           "sample written here, never on scanned code.</p>"]  # fmt: skip
    if running:
        total = int(state.get("total") or 0)
        out.append(
            f'<p><span class="dot"></span>Running the checks: {total - len(pending)} of {total} '
            "done. The tools take a few seconds each; this page updates by itself.</p>"
        )
    elif state:
        age = int(state.get("age") or 0)
        when = "just now" if age < 5 else f"{age} s ago"
        out.append(f'<p class="muted">All checks ran {when}, in {int(state.get("took") or 0)} s. '
                   f'<a href="{base}/doctor?again=1">Run them again</a></p>')  # fmt: skip
    out.append("<table>")
    for c in checks:
        cls = "ok" if c.ok else "bad"
        out.append(
            f'<tr><td class="{cls}">{"ok" if c.ok else "FAIL"}</td>'
            f'<td class="wrap"><b>{e(c.name)}</b> '
            f"{e(c.summary, 1000)}"
            + (f"<br><code>{e(c.command, 500)}</code>" if c.command else "")
            + (f" <span class=muted>{c.seconds}s</span>" if c.seconds is not None else "")
            + (f"<br>stderr: <code>{e(c.stderr, 1600)}</code>" if c.stderr else "")
            + (f"<br>stdout: <code>{e(c.stdout, 600)}</code>" if c.stdout and not c.ok else "")
            + "</td></tr>"
        )
    for i, name in enumerate(pending if running else []):
        out.append(
            '<tr><td class="muted">' + ('<span class="dot"></span>' if i == 0 else "…") + "</td>"
            f'<td class="wrap muted"><b>{e(name)}</b> {"running…" if i == 0 else "waiting"}'
            "</td></tr>"
        )
    out.append("</table>")
    return ui.page("Barkley diagnostics", "".join(out), refresh=2 if running else 0, base=base)


def _side_words(base: str, side: dict[str, Any], sid: int) -> str:
    link = f'<a href="{base}/scan/{sid}">scan @{sid}</a>'
    return f"<b>{e(side['ref'], 60)}</b> ({link})" if side.get("ref") else link


def render_diff(
    base: str,
    old: int,
    new: int,
    d: dict[str, Any],
    name: str | None = None,
    recheck_of: bool = False,
) -> bytes:
    """What an update changes, in plain words: the headline changes as a list with the
    same level labels as findings, the rest folded behind a disclosure; the diff's own
    text stays available per line under "Technical details". `recheck_of`: the new side
    is an advisory re-check of the old one (same version, same code), and says so."""
    what = "What the advisory re-check changed" if recheck_of else "What the update changes"
    how = (
        "Same version and the same code: only the known advisories for its packages were "
        "asked again. It lists what is listed now that wasn't before, and the other way "
        "round."
        if recheck_of
        else "It lists what the new version does that the old one didn't, and the other way round."
    )
    frm, to = d["from"], d["to"]
    changes = d.get("changes", [])
    head = [c for c in changes if c["rank"] >= HEADLINE_RANK][:HEADLINE_MAX]
    rest = [c for c in changes if c not in head]
    title = name or str(frm.get("repo") or "?").rsplit("/", 1)[-1]
    s_from, s_to = d["score"].get("from"), d["score"].get("to")
    out = [
        f'<p class="crumb"><a href="{base}/">{ui.icon("back")} All apps</a></p>',
        '<section class="box dhead"><div class="dscore">'
        f"{ui.ring(int(s_to or 0), ui.band(s_to))}</div>"
        f"<div><h1>{what}: {e(title, 100)}</h1>"
        f"<div>From {_side_words(base, frm, old)} to {_side_words(base, to, new)} · "
        f"{e(frm.get('repo'), 120)}</div>"
        f'<div class="muted small">Score {e(s_from)} → {e(s_to)}: each side\'s own score; '
        f"this comparison never scores. {how}</div></div></section>",
    ]
    for w in d.get("warnings", []):
        out.append(f'<div class="banner warn">{ui.icon("alert")} {e(w, 400)}</div>')

    def lines(cs: list[dict[str, Any]], quiet: bool = False) -> str:
        items = []
        for c in cs:
            lead, text, raw = ui.change_line(c)
            sev = str(c.get("severity") or "")
            cls = sev if sev in ("critical", "high", "medium") and c.get("sign") == "+" else ""
            tech = (f'<details><summary>Technical details</summary><code class="ev">'
                    f"{e(raw, 400)}</code></details>")  # fmt: skip
            items.append(
                f'<div class="finding{" quiet" if quiet else ""}"><div class="lvl {cls}">'
                f"{e(lead)}</div><div><div>{text}</div>{tech}</div></div>"
            )
        return "".join(items)

    if not head:
        out.append(f'<section class="box"><h2>In short</h2><p class="ok">'
                   f'{ui.icon("check", 16, "ok")} Nothing important changed.</p>'
                   "</section>")  # fmt: skip
    else:
        out.append(f'<section class="box"><h2>Worth a look ({len(head)})</h2>{lines(head)}'
                   "</section>")  # fmt: skip
    if rest:
        out.append(f'<details class="box"><summary>Also changed ({len(rest)}): smaller things, '
                   f"none of them a concern on its own</summary>{lines(rest, True)}"
                   "</details>")  # fmt: skip
    return _page("Barkley · what changes", "".join(out), base)


# --- HTTP ------------------------------------------------------------------------------


InstalledFn = Callable[[], tuple[list[supervisor.Installed], dict[str, int]]]
AiFn = Callable[[str, str, dict[str, Any], str], Any]
CatalogFn = Callable[[], list[supervisor.CatalogItem]]
EntitiesFn = Callable[[], list[tuple[str, str]]]
ReleasesFn = Callable[[str], tuple[list[Any], str | None]]  # releases.recent
_RELEASES_TTL = 600
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
        store.trust_overlay = True  # rows show scores with the user's trusted addresses
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
        self.releases_fn: ReleasesFn | None = None
        self._releases: dict[str, tuple[float, list[Any], str | None, str]] = {}
        self.ai_entity = ""
        self.entities_fn: EntitiesFn | None = None
        self._entities: tuple[float, list[tuple[str, str]], str] = (0.0, [], "")
        self.ai_fn: AiFn = supervisor.ai_generate_data
        self._ai: dict[int, tuple[str, str]] = {}  # scan id -> (running|failed, error)
        self._ai_items: dict[tuple[int, str], tuple[str, str]] = {}  # (scan, item) -> same
        self._ai_lock = threading.Lock()
        self.ai_mode = "summary"
        self.watcher: watch.Watcher | None = None  # auto-sniff (set by `serve` in an add-on)
        self.diagnostics = Diagnostics()

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

    def set_installed(self, items: list[supervisor.Installed], other: dict[str, int]) -> None:
        """A fresh list read elsewhere (the auto-sniff watcher) replaces the cached one."""
        with self._installed_lock:
            self._installed = InstalledState(list(items), dict(other), None, time.time())

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
                readings = self.store.item_explanations(sid)
                instructions, structure, _ids = report_ai.build_request(report, readings)
                data = self.ai_fn(self.ai_entity, instructions, structure, report_ai.TASK_NAME)
                accepted = report_ai.accept(report, data, readings)
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

    def explain_item(self, sid: int, item_id: str) -> bool:
        """Deep analysis of one finding, port or address, in the background: the AI reads
        that item's stored snippet (report.ai_context). One request per item at a time."""
        if not self.ai_entity or self.ai_mode != "deep":
            return False
        report = self.store.report(sid)
        if ai_context.item_of(report, item_id) is None:
            return False
        key = (sid, item_id)
        with self._ai_lock:
            if self._ai_items.get(key, ("", ""))[0] == "running":
                return True
            self._ai_items[key] = ("running", "")
        entity = self.ai_entity

        def run() -> None:
            started = time.monotonic()
            try:
                instructions, structure = ai_context.build_request(report, item_id)
                data = self.ai_fn(entity, instructions, structure, ai_context.TASK_NAME)
                accepted = ai_context.accept(report, item_id, data)
                self.store.save_item_explanation(sid, item_id, entity, accepted)
                print(f"explain @{sid} {item_id} ({time.monotonic() - started:.0f} s): "
                      f"{len(accepted['claims'])} claim(s), "
                      f"{len(accepted['questions'])} question(s), {len(accepted['dropped'])} "
                      f"dropped {sorted(set(accepted['dropped']))}", file=sys.stderr,
                      flush=True)  # fmt: skip
                with self._ai_lock:
                    self._ai_items.pop(key, None)
            except Exception as ex:  # shown on the page; never affects the scan
                print(f"explain @{sid} {item_id} failed after {time.monotonic() - started:.0f} s: "
                      f"{type(ex).__name__}: {ex}",
                      file=sys.stderr, flush=True)  # fmt: skip
                with self._ai_lock:
                    self._ai_items[key] = ("failed", str(ex))

        threading.Thread(target=run, name=f"explain-{sid}-{item_id}", daemon=True).start()
        return True

    def item_states(self, sid: int) -> dict[str, tuple[str, str]]:
        with self._ai_lock:
            return {item: st for (s, item), st in self._ai_items.items() if s == sid}

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

    def releases(self, repo: str) -> tuple[list[Any], str | None, str]:
        """(newest releases, Marketplace default tag, error), cached 10 minutes per repo.
        A GitHub limit is shown as "try later", never as anything about the app."""
        if self.releases_fn is None:
            return [], None, "listing releases isn't available here"
        key = repo.lower()
        hit = self._releases.get(key)
        if hit and time.time() - hit[0] < _RELEASES_TTL:
            return hit[1], hit[2], hit[3]
        try:
            rel, default = self.releases_fn(repo)
            err = ""
        except RateLimitError as ex:
            when = datetime.fromtimestamp(ex.reset_at).strftime("%H:%M")
            rel, default, err = (
                [],
                None,
                f"GitHub's hourly limit is used up; try again after {when}.",
            )
        except (GitHubError, ReleasesError, ValueError) as ex:
            rel, default, err = [], None, str(ex)[:300]
        if not err:
            if len(self._releases) > 64:
                self._releases.clear()
            self._releases[key] = (time.time(), rel, default, err)
        return rel, default, err

    def names(self) -> dict[str, str]:
        """Display names by lower-case repo, for the status strip (cached lists only)."""
        out = {c.repo.lower(): c.name for c in self.catalog()[0]} if self.catalog_fn else {}
        if self.installed_fn is not None:
            out.update({it.repo.lower(): it.name for it in self.installed().items})
        return out

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
                    report=self.shown_report(scan.id),
                    busy=busy.get(repo, ""),
                )
            )
        if not cards:
            return ""
        cards.sort(key=lambda c: (c.scan.score if c.scan else -1, c.name.lower()))
        return not_installed_cards_html(base, cards)

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

    def shown_report(self, sid: int) -> dict[str, Any] | None:
        """The report as the panel shows it (trust.view): findings whose addresses the
        user trusts are set aside and the score counts the rest. The stored report, the
        raw JSON link, the AI's input and diffs always use `report()`."""
        rep = self.report(sid)
        return trust.view(rep, self.store.trusted()) if rep is not None else None

    def trust_finding(self, sid: int, finding_id: str, everywhere: bool) -> bool:
        """Mark every address of one finding trusted, for its app or for every app.
        Only addresses the scanner attached to that finding can be added."""
        report = self.store.report(sid)
        f = next((x for x in report.get("findings", []) if x.get("id") == finding_id), None)
        addrs = [a for a in (f or {}).get("addresses") or [] if isinstance(a, str)]
        repo = report.get("target", {}).get("repo")
        if not addrs or not (everywhere or (repo and _REPO.match(str(repo)))):
            return False
        t = self.store.trusted()
        if not all(t.add(a, None if everywhere else str(repo)) for a in addrs):
            return False
        self.store.set_trusted(t)
        print(f"trusted by the user ({'every app' if everywhere else repo}): "
              f"{', '.join(addrs)}", file=sys.stderr, flush=True)  # fmt: skip
        return True

    def untrust(self, address: str, repo: str | None) -> None:
        t = self.store.trusted()
        t.remove(address, repo)
        self.store.set_trusted(t)
        print(f"no longer trusted ({repo or 'every app'}): {address}", file=sys.stderr, flush=True)

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

    def installed_html(self, base: str, refresh: bool = False, v: ui.View | None = None) -> str:
        if self.installed_fn is None:
            return ""
        st, rows = self.rows(refresh)
        html = render_installed(base, st, rows, self.token, self.shown_report, v)
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

            def _send(
                self, status: int, body: bytes, ctype: str = "text/html", cache: str = "no-store"
            ) -> None:
                self.send_response(status)
                charset = "" if ctype.startswith("font/") else "; charset=utf-8"
                self.send_header("Content-Type", f"{ctype}{charset}")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Security-Policy", _CSP)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Cache-Control", cache)
                self.end_headers()
                self.wfile.write(body)

            def _text(self, status: int, msg: str) -> None:
                self._send(status, _page("Barkley", f"<p>{e(msg)}</p>", self._base()))

            def _redirect(self, to: str) -> None:
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", local_path(to))
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
                        v = ui.View.parse(q, panel.store.setting("view") or "cards")
                        if q.get("view") and v.view != panel.store.setting("view"):
                            panel.store.set_setting("view", v.view)  # remembered for next time
                        auto = (render_auto(base, panel.watcher, panel.token)
                                if panel.watcher is not None else "")  # fmt: skip
                        body = render_index(
                            base, panel.store, jobs, panel.token,
                            panel.installed_html(base, refresh, v), panel.memory_fn(),
                            panel.worker.github_wait, panel.worker.ha_fn(),
                            panel.worker.parallel, panel.catalog_fn is not None,
                            status_html(base, jobs, panel.names(), v.qs()), v.qs(), auto,
                        )  # fmt: skip
                        return self._send(200, body)
                    if m := re.fullmatch(r"/fonts/([A-Za-z-]+\.woff2)", url.path):
                        if (font := _font_bytes(m[1])) is None:
                            return self._text(HTTPStatus.NOT_FOUND, "no such font")
                        return self._send(200, font, "font/woff2",
                                          "public, max-age=31536000, immutable")  # fmt: skip
                    if m := re.fullmatch(r"/scan/(\d+)(\.json)?", url.path):
                        sid = int(m[1])
                        report = panel.store.report(sid)
                        if m[2]:
                            body = json.dumps(report, indent=2).encode()
                            return self._send(200, body, "application/json")
                        report = trust.view(report, panel.store.trusted())
                        row = panel.row_for(report.get("target", {}).get("repo"))
                        state, err = panel.ai_state(sid)
                        choices, choices_err = panel.ai_choices()
                        q = urllib.parse.parse_qs(url.query)
                        open_item = (q.get("open") or [""])[0]
                        if not re.fullmatch(r"[0-9a-f]{16}", open_item):
                            open_item = ""
                        page = render_scan(
                            base, sid, report, panel.store, row, panel.token,
                            panel.ai_entity, state, err, choices, choices_err,
                            panel.ai_mode, panel.item_states(sid), open_item,
                            rechecking=any(
                                j.kind == "recheck" and j.scan == sid
                                and j.state in ("queued", "running", "waiting")
                                for j in list(panel.worker.jobs)
                            ),
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
                    if url.path == "/versions":
                        q = urllib.parse.parse_qs(url.query)
                        m = _REPO.match((q.get("repo") or [""])[0])
                        if not m:
                            return self._text(HTTPStatus.BAD_REQUEST, "want owner/repo")
                        repo = m[1]
                        rel, default, err = panel.releases(repo)
                        tv = panel.worker.tool_version
                        scans: dict[str, ScanRow] = {}
                        for r in panel.store.history(repo, limit=500):
                            if r.tool_version == tv and r.complete:
                                scans.setdefault((r.ref or "").lower(), r)
                        busy = {(j.ref or "").lower(): j.state for j in panel.worker.jobs
                                if j.repo.lower() == repo.lower()
                                and j.state in ("queued", "running", "waiting")}  # fmt: skip
                        row = panel.row_for(repo)
                        name = panel.names().get(repo.lower()) or repo.rsplit("/", 1)[-1]
                        page = render_versions(
                            base, repo, name, rel, default, row.item.installed if row else None,
                            scans, busy, panel.token, err,
                        )  # fmt: skip
                        return self._send(200, page)
                    if url.path == "/trusted":
                        return self._send(200, render_trusted(
                            base, panel.store.trusted(), panel.names(), panel.token))  # fmt: skip
                    if url.path == "/doctor":
                        # Never waits for the tools: the run goes on in its own thread.
                        if "again=1" in url.query:
                            panel.diagnostics.start(force=True)
                            return self._redirect(f"{base}/doctor")
                        panel.diagnostics.start()
                        state = panel.diagnostics.state()
                        checks = state["checks"]
                        if panel.watcher is not None:
                            ok, summary = panel.watcher.diagnostics()
                            checks.insert(3, doctor.Check("Auto-sniff (Marketplace events)", ok,
                                                          summary))  # fmt: skip
                        return self._send(200, render_doctor(base, checks, state))
                    if url.path == "/diff":
                        q = urllib.parse.parse_qs(url.query)
                        old, new = int(q["old"][0]), int(q["new"][0])
                        d = panel.diff(old, new)
                        repo = str((d.get("to") or {}).get("repo") or "")
                        name = panel.names().get(repo.lower()) if repo else None
                        rc = panel.store.report(new).get("recheck")
                        again = isinstance(rc, dict) and rc.get("of") == old
                        return self._send(200, render_diff(base, old, new, d, name, again))
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
                # Back to the same filter, view and page (rebuilt from known values only)
                v = ui.View.parse(urllib.parse.parse_qs(get("back")[:200]))
                home = f"{self._base()}/?{v.qs('&')}" if get("back") else f"{self._base()}/"
                if path in ("/auto-scan", "/notify-target", "/notify-test"):
                    w = panel.watcher
                    if w is None:
                        return self._text(HTTPStatus.BAD_REQUEST, "auto-sniff needs the add-on")
                    if path == "/auto-scan":
                        w.set_enabled(get("on") == "1")
                    elif path == "/notify-target":
                        if not w.set_target(get("target")[:100]):
                            return self._text(HTTPStatus.BAD_REQUEST,
                                              "not one of the notify targets Home Assistant "
                                              "offers")  # fmt: skip
                    else:
                        w.notify_test()
                    return self._redirect(f"{self._base()}/")
                if path == "/recheck":
                    if not get("scan").isdigit():
                        return self._text(HTTPStatus.BAD_REQUEST, "bad request")
                    sid = int(get("scan"))
                    row = panel.store.get(sid)
                    if row is None or not row.repo:
                        return self._text(HTTPStatus.NOT_FOUND, f"no stored scan @{sid}")
                    panel.worker.submit("recheck", row.repo, row.ref, scan=sid)
                    return self._redirect(f"{self._base()}/scan/{sid}")
                if path == "/trust":
                    fid, scope = get("finding"), get("scope")
                    if (not get("scan").isdigit() or not re.fullmatch(r"[0-9a-f]{16}", fid)
                            or scope not in ("app", "all")):  # fmt: skip
                        return self._text(HTTPStatus.BAD_REQUEST, "bad request")
                    sid = int(get("scan"))
                    try:
                        if not panel.trust_finding(sid, fid, scope == "all"):
                            return self._text(HTTPStatus.BAD_REQUEST,
                                              "that finding has no address to trust")  # fmt: skip
                    except StoreError as ex:
                        return self._text(HTTPStatus.NOT_FOUND, str(ex))
                    return self._redirect(f"{self._base()}/scan/{sid}")
                if path == "/untrust":
                    address, repo = get("address"), get("repo")
                    if not trust.valid_address(address) or (repo and not _REPO.match(repo)):
                        return self._text(HTTPStatus.BAD_REQUEST, "bad request")
                    panel.untrust(address, repo or None)
                    sid = get("scan")
                    return self._redirect(f"{self._base()}/scan/{sid}" if sid.isdigit()
                                          else f"{self._base()}/trusted")  # fmt: skip
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
                if path == "/ai-mode":
                    mode = get("mode")
                    if mode not in AI_MODES:
                        return self._text(HTTPStatus.BAD_REQUEST, "unknown AI mode")
                    panel.store.set_setting("ai_mode", mode)
                    panel.ai_mode = mode
                    print(f"AI mode: {mode} (chosen in the panel)", file=sys.stderr, flush=True)
                    sid = get("scan")
                    return self._redirect(f"{self._base()}/scan/{sid}" if sid.isdigit()
                                          else f"{self._base()}/")  # fmt: skip
                if path == "/explain-item":
                    item = get("item")
                    if not get("scan").isdigit() or not re.fullmatch(r"[0-9a-f]{16}", item):
                        return self._text(HTTPStatus.BAD_REQUEST, "bad item")
                    sid = int(get("scan"))
                    try:
                        if not panel.explain_item(sid, item):
                            return self._text(
                                HTTPStatus.BAD_REQUEST,
                                "deep analysis is off, or there's no code for it",
                            )
                    except StoreError as ex:
                        return self._text(HTTPStatus.NOT_FOUND, str(ex))
                    return self._redirect(f"{self._base()}/scan/{sid}?open={item}#ai-{item}")
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
                    return self._redirect(home)
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
                if path == "/scan" and get("back_to") == "versions":
                    back = urllib.parse.urlencode({"repo": m[1]})
                    return self._redirect(f"{self._base()}/versions?{back}")
                if path == "/scan" and (q := get("q")[:100]):
                    kind = get("kind") if get("kind") in ("integration", "card") else ""
                    back = urllib.parse.urlencode({"q": q, "kind": kind})
                    return self._redirect(f"{self._base()}/search?{back}")
                self._redirect(home)

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
    ai_mode: str = "summary",
    parallel: int = 1,
    catalog_fn: CatalogFn | None = None,
    entities_fn: EntitiesFn | None = None,
    releases_fn: ReleasesFn | None = None,
    watcher: watch.Watcher | None = None,
) -> PanelServer:
    """Build the server (caller runs `serve_forever`); `.panel.worker` runs the scans.
    `watcher`: auto-sniff; built by the caller with the worker from `make_worker`."""
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
    stored_mode = store.setting("ai_mode")  # chosen in the panel; wins over the option
    panel.ai_mode = (
        stored_mode if stored_mode in AI_MODES else (ai_mode if ai_mode in AI_MODES else "summary")
    )
    panel.catalog_fn = catalog_fn
    panel.entities_fn = entities_fn
    panel.releases_fn = releases_fn
    if ai_fn is not None:
        panel.ai_fn = ai_fn
    if watcher is not None:
        panel.watcher = watcher
        watcher.worker = worker
        watcher.on_list = panel.set_installed
        worker.on_done.append(watcher.on_job_done)
    httpd = PanelServer((host, port), panel.handler())
    httpd.panel = panel
    return httpd
