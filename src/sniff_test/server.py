"""`sniff-test serve`: the add-on's ingress panel. Stdlib only, one scan at a time.

Behind HA ingress, HA does the login and the Supervisor (172.30.32.2) is the only
client the panel ever sees, so every other address is refused. Standalone (no
Supervisor), the panel is reachable from the network instead, so every page but the
login asks for a session from "log in with Home Assistant" (login.py; administrators
only). Forms carry a per-process token so another page can't make the panel start scans.

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
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any

from sniff_test import (
    __version__,
    cpu,
    doctor,
    ha_token,
    listings,
    login,
    memory,
    readings,
    recheck,
    scancache,
    supervisor,
    ui,
    watch,
)
from sniff_test import settings as settings_mod
from sniff_test import shown as shown_mod
from sniff_test.diff import HEADLINE_MAX, HEADLINE_RANK, WHAT, what_sentence
from sniff_test.diff import diff as diff_reports
from sniff_test.fetch.github import GitHubError, NotFoundError, RateLimit, RateLimitError
from sniff_test.releases import ReleasesError
from sniff_test.report import ai as report_ai
from sniff_test.report import ai_context, ai_words, context
from sniff_test.report.json_report import sanitize_untrusted
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
BAD_REQUEST = "Barkley couldn't use that link or form."
_SEV_CLASS = {"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium"}
_JOBS_KEPT = 20
# GitHub API requests a job may need, measured 2026-11-09: 6-7 per scan (repo, release,
# commit, tarball, asset, release list, compare), plus 2 repo-habit lookups since 0.6.0
# (open pull requests, open issues); an update check is two scans. Jobs check the budget
# before they start and wait out a rate limit inside. The one GitHub request outside a
# job is the versions page's release list (cached 10 min; a limit there says "try later").
# Without a token GitHub allows 60/hour and counts even 304 answers.
# (0.12.0) + 2 per scan: Home Assistant's original of a function the app replaces
# (report.compare.MAX_FETCH; cached per HA release, so usually none are made).
# Measured again 2026-11-20 with an empty cache: a card 8, integrations 13 and 17 (habit
# lookups, a related fork's repo, release assets). 12 was too few for integrations; a job
# that runs short waits out the limit, so this only decides when a job may start.
_GITHUB_NEED = {"scan": 20, "installed": 20, "update": 40, "auto": 40}
# (0.14.0) Explain and read code by default: still nothing is sent before a click, and
# what a click sends is the app's own public code, never anything from Home Assistant.
AI_MODE_DEFAULT = "deep"


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


def csp_with_login(ha_url: str) -> str:
    """(0.14.0) Standalone: browsers check form-action against where a form's redirects
    end up, and Create token (a form) ends at Home Assistant's login page. `ha_url` is
    login.base_url's scheme://host[:port], so nothing but an origin goes into the header."""
    return _CSP.replace("form-action 'self'", f"form-action 'self' {ha_url}")


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


def failure_message(ex: BaseException) -> str:
    """A failed job's message for the panel and notifications: a fixed sentence per kind
    of failure. An exception's own text can quote what the scanned project chose (an
    archive member's name, a tag), and a notification carries only counts, readings and
    validated names; the full text goes to the app log."""
    from sniff_test.deps.ha_env import HAEnvError
    from sniff_test.fetch.hacs import FetchError
    from sniff_test.fetch.http import HttpError
    from sniff_test.recheck import RecheckError
    from sniff_test.workspace import UnsafeArchiveError

    kinds: tuple[tuple[type[BaseException], str], ...] = (
        # (0.15) before GitHubError: the full run's three gone repositories read "GitHub
        # didn't answer"
        (
            NotFoundError,
            "GitHub has no such repository or release any more: it may have "
            "been deleted or made private",
        ),
        (UnsafeArchiveError, "the release archive has a file Barkley won't unpack"),
        (RecheckError, "the advisory check couldn't run"),
        (ReleasesError, "Barkley couldn't find that release"),
        (GitHubError, "GitHub didn't answer"),
        (HttpError, "a download failed"),
        (FetchError, "Barkley couldn't download the app"),
        (HAEnvError, "Home Assistant's package list couldn't be fetched"),
        (StoreError, "Barkley's scan store couldn't be read or written"),
        (MemoryError, "the scan ran out of memory"),
        (TimeoutError, "the scan took too long"),
    )
    for cls, text in kinds:
        if isinstance(ex, cls):
            return f"{text} (the app log has the details)"
    return "something went wrong inside Barkley (the app log has the details)"


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
        self.memory_gb_fn: Callable[[], int] = lambda: 0  # (0.14.0) Memory for scans
        self.floor_fn: Callable[[], int] = lambda: memory.REFUSE_BELOW  # (0.15) Low memory
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
            for i in range(PARALLEL_MAX)  # admission keeps it to `parallel` (changeable)
        ]
        for th in self._threads:
            th.start()

    def running(self) -> list[Job]:
        with self._slots:
            return list(self._running)

    def _room_for_another(self) -> str:
        """ "" when one more scan fits beside the running ones, else why not.

        Auto (Memory for scans 0): free memory must cover a reserve plus PER_SCAN for each
        running scan (each may still grow); the reserve is WARN_BELOW on a machine Home
        Assistant shares, CONTAINER_RESERVE inside a container's own limit. A fixed amount:
        as many scans as fit in it at PER_SCAN each (never past a container's limit), and
        never below REFUSE_BELOW of real free memory after the running scans' growth."""
        mem = self.memory_fn()
        if mem.available is None:
            return "waiting: Barkley can't tell how much memory is free, so scans run one at a time"
        floor = self.floor_fn()
        n = len(self._running)
        gb = self.memory_gb_fn()
        if gb:
            budget = gb * memory.GIB
            if mem.limited and mem.total:
                budget = min(budget, mem.total)
            need = floor + PER_SCAN * n
            if PER_SCAN * (n + 1) > budget:
                fits = max(1, int(budget // PER_SCAN))
                return (f"waiting for a running scan to finish. {gb} GB (Memory for scans "
                        f"in Settings) fits {fits} scan{'s' * (fits != 1)} at a time.")  # fmt: skip
        else:
            reserve = memory.CONTAINER_RESERVE if mem.limited else memory.WARN_BELOW
            need = reserve + PER_SCAN * n
        if mem.available < need:
            runs = "other scan runs" if n == 1 else "other scans run"
            return (f"waiting for memory. {mem.available / memory.GIB:.1f} GB is free and "
                    f"{need / memory.GIB:.1f} GB is needed while {n} {runs} (see Memory for "
                    "scans in Settings).")  # fmt: skip
        return ""

    def _admit(self, job: Job) -> None:
        """Wait for a slot; the job then counts as running (state set by the caller)."""
        with self._slots:
            while True:
                same = any(j.repo.lower() == job.repo.lower() for j in self._running)
                full = len(self._running) >= self.parallel  # (0.14.0) a Settings choice
                why = "" if same or full or not self._running else self._room_for_another()
                if not same and (not self._running or (not full and not why)):
                    break
                job.message = (
                    "waiting for the other check of this repo"
                    if same
                    else "waiting for a free slot (Parallel scans in Settings)"
                    if full
                    else why
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

    def _mem(self) -> memory.Memory:
        return self.memory_fn().with_floor(self.floor_fn())

    def _scan(self, repo: str, ref: str | None) -> int:
        mem = self._mem()
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
            job.message = (
                "not checked again: Barkley only re-checks finished scans made by this version "
                "of Barkley"
            )
            return
        if newest is None or newest.id != sid:
            job.message = "not checked again: there's a newer scan of this version"
            return
        inputs = self.store.inputs(sid)
        if inputs is None:
            job.message = "not re-checked: this scan saved no package list"
            return
        if (mem := self._mem()).refuse:
            raise MemoryRefused(mem.message())
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
        self.store.link_source(new_id, sid)  # the same code: only the advisories were asked again
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
        self.github_wait = f"{why} Queued scans start again by themselves at {when}."
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
        tip = " A GitHub token raises the limit to 5,000."
        token = "" if b.authenticated else tip
        left = f"{b.remaining} of {b.limit} requests left this hour"
        why = f"GitHub's request limit is almost used up ({left}).{token}"
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
                job.message = failure_message(ex)
                # the detail only here; repr keeps a crafted name to one escaped line
                print(f"job {job.id} {job.repo} failed: {type(ex).__name__}: {str(ex)!r}",
                      file=sys.stderr)  # fmt: skip
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
    ai: bool = False  # (0.15) an AI request about this app is waiting for its answer


GROUPS = {
    "attention": "Needs a look",
    "unchecked": "Updates not checked yet",
    "checked": "Updates checked: nothing important changed",
}


def _latest(rows: list[ScanRow], ref: str) -> ScanRow | None:
    hits = [r for r in rows if r.ref == ref]
    return next((r for r in hits if r.complete), hits[0] if hits else None)


def _score_reason(r: ScanRow) -> str | None:
    """(0.15) Why a scan needs a look, from its readings (the panel's rows carry them)."""
    if not r.complete:
        return f"@{r.id} {r.ref}: the check didn't finish"
    rd = r.readings or {}
    if rd.get("threat_level") == "found":
        return f"@{r.id} {r.ref}: malicious behavior found"
    if rd.get("threat_level") == "possible":
        return f"@{r.id} {r.ref}: a possible sign of malicious behavior"
    if rd.get("exposure_level") == "high":
        return f"@{r.id} {r.ref}: high exposure"
    return None


def classify(
    items: list[supervisor.Installed],
    store: Store,
    diff_fn: Callable[[int, int], dict[str, Any]],
    tool_version: str | None = None,
) -> list[Row]:
    """Signal first: what needs attention, then unchecked updates, checked ones, the rest.

    Attention means a checked update whose diff has headline changes (a new publisher,
    new findings, new flows), or a scan of the version you'd run with a possible or found
    threat, high exposure, or a check that didn't finish. Nothing stored is changed.
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
    # (0.14.0, his report: rescanning was app page by app page) a fresh scan of the
    # installed version, never the stored one
    return (f'<form method=post action="{base}/scan">{hidden}'
            '<button title="Runs a fresh scan of the installed version">Sniff again</button>'
            "</form>")  # fmt: skip


def _diff_link(r: Row) -> str:
    if r.item.update and r.installed_scan and r.available_scan:
        return f"old={r.installed_scan.id}&amp;new={r.available_scan.id}"
    return ""


def not_installed_cards_html(
    base: str, cards: list[ui.Card], v: ui.View | None = None, token: str = ""
) -> str:
    """The "Sniffed, not installed" section under the installed list: its own pages, and
    one button for the apps last sniffed with earlier rules."""
    if not cards:
        return ""
    v = v or ui.View()
    per = ui.PER_PAGE[v.view]
    pages = max(1, -(-len(cards) // per))
    v = replace(v, pg2=min(v.pg2, pages))
    window = cards[(v.pg2 - 1) * per : v.pg2 * per]
    stale = sum(1 for c in cards if c.stale and not c.busy)
    again = ""
    if stale and token:
        again = (
            f'<form method=post action="{base}/not-installed-again">'
            f'<input type=hidden name=token value="{token}">'
            f'<input type=hidden name=back value="{v.qs()}">'
            f"<button>Sniff {stale} again with the current rules</button></form>"
        )
    page = f'<span class="muted small">Page {v.pg2} of {pages}</span>' if pages > 1 else ""
    bar = f'<div class="bar"><span class="lead">{again}{page}</span></div>' if again or page else ""
    if v.view == "table":
        body = (
            '<div class="box tablebox"><table class="apps"><tr><th>Readings</th><th>App</th>'
            "<th>Notes</th><th></th></tr>"
            + "".join(ui.card_row(base, c) for c in window)
            + "</table></div>"
        )
    else:
        body = '<div class="grid">' + "".join(ui.card_html(base, c) for c in window) + "</div>"
    return (
        f'<h2 id="not-installed">Sniffed, not installed ({len(cards)})</h2>{bar}{body}'
        + ui._pager(base, v, pages, "pg2", "#not-installed")
    )


def render_installed(
    base: str,
    state: InstalledState,
    rows: list[Row],
    token: str,
    report_fn: Callable[[int], dict[str, Any] | None],
    v: ui.View | None = None,
    listing_fn: Callable[[str], dict[str, str] | None] = lambda _r: None,
) -> str:
    v = v or ui.View()
    back = v.qs()
    refresh = f'<a href="{base}/?refresh=1">refresh</a>'
    if state.error:
        return (
            '<div class="banner warn">Barkley can\'t list your installed apps: '
            f"{e(state.error, 300)} ({refresh}). You can still check a repository by name "
            "below.</div>"
        )
    cards = [
        ui.Card(
            repo=r.item.repo,
            name=r.item.name,
            kind=r.item.kind,
            installed=r.item.installed,
            available=r.item.available if r.item.update else None,
            prerelease=r.item.prerelease,
            listing=listing_fn(r.item.repo),
            scan=r.installed_scan,
            report=report_fn(r.installed_scan.id) if r.installed_scan else None,
            group=r.group,
            reasons=r.reasons,
            busy=r.busy,
            ai=r.ai,
            diff_link=_diff_link(r),
            action=_action(base, r, token, back),
        )
        for r in rows
    ]
    never = sum(1 for r in rows if not r.installed_scan)
    # An unfinished scan is never reused, so it needs another run too; one that is
    # already queued or running isn't counted again.
    again = sum(1 for r in rows if r.installed_scan and not r.installed_scan.complete
                and not r.busy)  # fmt: skip
    lead = ""
    if never or again:  # the list's one primary action; nothing when everything is sniffed
        if never and again:
            label = (f"Sniff {never} apps not yet sniffed with the current rules, "
                     f"and {again} unfinished again")  # fmt: skip
        elif never:
            label = f"Sniff {never} apps not yet sniffed with the current rules"
        else:
            label = f"Sniff {again} unfinished again"
        lead = (
            f'<form method=post action="{base}/installed-all">'
            f'<input type=hidden name=token value="{token}">'
            f'<input type=hidden name=back value="{back}">'
            f'<button class="primary">{label}</button></form>'
        )
    elif rows and not any(r.busy for r in rows):
        lead = (
            f'<form method=post action="{base}/sniff-all-again">'
            f'<input type=hidden name=token value="{token}">'
            f'<input type=hidden name=back value="{back}">'
            f'<button title="A fresh scan of every installed app, one after another">'
            f"Sniff all {len(rows)} again</button></form>"
        )
    found = sum(  # (preview) a found threat puts one sentence above the list
        1 for c in cards if ((c.report or {}).get("readings") or {}).get("threat_level") == "found"
    )
    out = (
        [ui.threat_banner(None, found) + ui.render_grid(base, cards, v, lead)]
        if rows
        else ['<p class="muted">The Marketplace lists no installed integrations or cards.</p>']
    )
    skipped = ", ".join(f"{n} {e(_OTHER_KINDS.get(c, c))}" for c, n in sorted(state.other.items()))
    age = int(time.time() - state.fetched) // 60 if state.fetched else 0
    out.append(
        f'<p class="muted small">Barkley read the installed list from the Marketplace {age} '
        f"min ago ({refresh}). Barkley currently checks integrations and dashboard cards only"
        + (f". Not checked: {skipped}" if skipped else "")
        + ".</p>"
    )
    return "".join(out)


# (0.15, his decision 2026-11-22) the Marketplace's other kinds, in plain words
_OTHER_KINDS = {
    "theme": "themes",
    "python_script": "Python scripts",
    "appdaemon": "AppDaemon apps",
    "template": "templates",
    "netdaemon": "NetDaemon apps",
    "unknown": "of an unknown kind",
    "unreadable": "Barkley couldn't read",
}


def _token_banner(base: str, panel: Panel) -> str:
    """Standalone: no Home Assistant token yet, or the last rotation failed."""
    if not panel.standalone:
        return ""
    src = ha_token.source()
    if not src:
        return (
            '<div class="banner warn"><b>Barkley needs its own Home Assistant token</b> to '
            f'list your apps and notify you. <a href="{base}/setup">Set it up</a>.</div>'
        )
    meta = ha_token.Meta.load(panel.store)
    if src == "barkley" and meta.error:
        return (f'<div class="banner warn">{e(meta.error, 300)}. The current token keeps '
                f'working. <a href="{base}/settings#ha-token">Settings</a></div>')  # fmt: skip
    return ""


def _memory_banner(mem: memory.Memory) -> str:
    if mem.level == "refuse":
        return f'<div class="banner bad">{ui.icon("alert")} Memory: {e(mem.message(), 300)}</div>'
    if mem.level == "warn":
        return f'<div class="banner warn">{ui.icon("alert")} Memory: {e(mem.message(), 300)}</div>'
    return ""


def _cpu_banner(gap: list[str] | None) -> str:
    """(0.15, #18) At the top of the page from the start, not only in Diagnostics and on a
    failed scan: a VM's default CPU type hides the x86-64-v2 instructions and every scan
    fails until it's changed. `gap`: cpu.missing_v2() at startup ([] or None: nothing)."""
    if not gap:
        return ""
    return (
        f'<div class="banner bad">{ui.icon("alert")} <b>Scans can\'t run on this CPU.</b> '
        f"{e(cpu.FIX, 600)} Missing: {e(', '.join(gap), 100)}. "
        f'<a href="{DOCS_CPU}" target="_blank" rel="noopener noreferrer">How to fix it</a>'
        "</div>"
    )


def _github_banner(wait: str) -> str:
    return f'<div class="banner warn">{ui.icon("clock")} {e(wait, 400)}</div>' if wait else ""


STATUS_RECENT = 600  # seconds a finished job stays in the status strip


@dataclass
class AiRun:
    """(0.15) One AI request waiting for its answer: the scan, the item ("" for Explain
    this app), when it started, and the app's repository."""

    sid: int
    item: str
    started: float
    repo: str


def ai_why(ex: BaseException, timeout: float | None = None) -> str:
    """(0.15) Why an AI request ended without an answer, as one plain sentence for the
    page. A time-out and Stop waiting say what happened and what to do; anything else is
    Home Assistant's own message (an AI Task error), cut short."""
    if isinstance(ex, supervisor.AiTimeout):
        mins = round(ex.seconds / 60) or 1
        return (f"Your AI didn't answer within {mins} minute{'s' * (mins != 1)}. Nothing here "
                "changes the readings. You can try again, pick a faster model, or allow more "
                "time in Settings → AI answers.")  # fmt: skip
    if isinstance(ex, supervisor.AiStopped):
        return ("You stopped waiting. Home Assistant may still finish the answer, but Barkley "
                "won't use it.")  # fmt: skip
    return f"The AI didn't answer: {str(ex)[:300]}"


def ai_reason(ex: BaseException) -> str:
    """The same, as a few words that fit inside a sentence of the page's."""
    if isinstance(ex, supervisor.AiTimeout):
        mins = round(ex.seconds / 60) or 1
        return f"no answer within {mins} minute{'s' * (mins != 1)}"
    if isinstance(ex, supervisor.AiStopped):
        return "you stopped waiting"
    return str(ex)[:300]


def ai_wait(seconds: float) -> str:
    """How long the AI has been at it, in plain words."""
    n = max(0, int(seconds))
    if n < 60:
        return f"{n} s"
    return f"{n // 60} min {n % 60:02d} s"


def status_html(
    base: str,
    jobs: list[Job],
    names: dict[str, str],
    here: str,
    now: float | None = None,
    ai: list[AiRun] | None = None,
    refresh_href: str = "",
) -> str:
    """The strip at the top: what's being sniffed now, what the AI is answering (in its
    colour), and what just finished."""
    now = time.time() if now is None else now
    ai = ai or []
    active = [j for j in jobs if j.state in ("running", "waiting", "queued")]
    # A daily advisory re-check that found nothing new isn't news: it stays out of the strip.
    recent = [
        j for j in jobs
        if j.finished and now - j.finished < STATUS_RECENT
        and not (j.kind == "recheck" and j.state == "done" and len(j.scan_ids) < 2)
    ][-3:]  # fmt: skip
    if not active and not recent and not ai:
        return ""

    def name(j: Job) -> str:
        return e(names.get(j.repo.lower()) or j.repo, 100)

    def app(a: AiRun) -> str:
        return e(names.get(a.repo.lower()) or a.repo or f"scan @{a.sid}", 100)

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
    for a in ai:
        what = "Explain this app" if not a.item else "Explain in context"
        lines.append(
            f'<span class="aiwait"><span class="thinking">{ui.icon("sparkle", 14)}</span>'
            f'<b>Your AI is answering about {app(a)}…</b> <span class="small">({what}, '
            f"{ai_wait(now - a.started)} so far) "
            f'<a href="{base}/scan/{a.sid}">open</a></span></span>'
        )
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
                    f"{ui.icon('alert', 14, 'muted')} The known advisories for {name(j)} changed. "
                    f'See <a href="{base}/diff?old={old}&amp;new={new}">what changed</a>.'
                )
                continue
            lines.append(f"{ui.icon('check', 14, 'ok')} {name(j)} is done: {link}")
        else:
            lines.append(f"{ui.icon('x', 14, 'bad')} {name(j)} {e(j.state)}: {e(j.message, 200)}")
    tail = ""
    if active or ai:
        why = "a scan runs" if active else "your AI answers"
        tail = f'<span class="muted small">This page refreshes by itself while {why}.</span>'
    return (
        '<div class="box status" role="status">'
        + "".join(f'<div class="row">{x}</div>' for x in lines)
        + f'<div class="row">{tail}<a class="small" href="{refresh_href or f"{base}/?{here}"}">'
        f"{ui.icon('refresh')} "
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
    account: str = "",
    token_banner: str = "",
    ai_busy: bool = False,
    cpu_gap: list[str] | None = None,
) -> bytes:
    rows = store.history(limit=100)
    against = f", checking against Home Assistant {e(ha)}" if ha else ""
    out = [
        f'<div class="head"><h1>{ui.logo_img()}Barkley</h1>'
        f'<a class="small" href="{base}/?{here}">{ui.icon("refresh")} Refresh</a>'
        f'<a class="small" href="{base}/settings">{ui.icon("wrench")} Settings</a></div>',
        status,
        _cpu_banner(cpu_gap),
        _memory_banner(mem) if mem else "",
        _github_banner(github_wait),
        token_banner,
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
        out.append('<div class="tablebox"><table><tr><th>#</th><th>readings</th><th>repo</th>'
                   "<th>when</th></tr>")  # fmt: skip
        for r in rows:
            extra = r.kind + (f" · HA {r.ha_version}" if r.ha_version else "")
            extra += f" · rules {ui.rules_label(r.tool_version)}"
            out.append(
                f'<tr><td><a href="{base}/scan/{r.id}">@{r.id}</a></td>'
                f"<td>{ui.readings_text(r.readings, r.complete)}</td>"
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
        + f'The readings never come from an AI. <a href="{base}/doctor">Diagnostics</a> shows '
        f'whether each tool can run on this machine. <a href="{e(report_issue_url(ha))}" '
        'target="_blank" rel="noopener noreferrer" title="Opens a new public issue on '
        "Barkley's GitHub, with the versions filled in\">Report an issue</a> · "
        f'<a href="{base}/settings">Settings</a></p>'
    )
    out.append(account)
    return ui.page("Barkley", "".join(out), refresh=5 if active or ai_busy else 0, base=base)


DOCS_GITHUB_HELP = "https://ha-barkley.github.io/docs/options/#github-token"
DOCS_HA_SETUP = "https://ha-barkley.github.io/docs/standalone/#barkleys-home-assistant-token"
DOCS_CPU = (
    "https://ha-barkley.github.io/docs/diagnostics-and-troubleshooting/"
    "#every-scan-fails-cpu-isa-level-is-lower-than-required"
)


def github_token_url(now: datetime | None = None) -> str:
    """(0.14.0) GitHub's new fine-grained token page, filled in (its template URL: name up
    to 40 characters, description, expiry in days; its docs say up
    to 366, but its form takes 365 at most, tried 2026-11-18). No permission is asked for: Barkley
    only reads public repositories. GitHub can't send the token back; the user pastes it."""
    now = now or datetime.now(UTC)
    q = urllib.parse.urlencode({
        "name": f"Barkley {now:%Y-%m-%d}",
        "description": "Barkley: reads public repositories for its scans (a higher rate limit)",
        "expires_in": "365",
    })  # fmt: skip
    return f"https://github.com/settings/personal-access-tokens/new?{q}"


def github_create_link(now: datetime | None = None) -> str:
    return (f'<a class="button" href="{e(github_token_url(now))}" target="_blank" '
            'rel="noopener noreferrer">Create token on GitHub</a>')  # fmt: skip


GITHUB_STEPS = (
    "On GitHub, leave Repository access on <b>Public repositories</b>, add no permissions, "
    "click <b>Generate token</b>, copy it and paste it here."
)


def ha_token_block(base: str, store: Store, period: int, token: str) -> str:
    """Standalone only: Barkley's own Home Assistant token (part 4). Never shows a token:
    where it comes from, when it rotates, Create token, paste one, Rotate now."""
    hidden = f'<input type=hidden name=token value="{token}">'
    src = ha_token.source()
    line = ha_token.status_line(store, period)
    meta = ha_token.Meta.load(store)
    err = (f'<p class="small" style="color:var(--orange)">{e(meta.error, 300)}</p>'
           if meta.error and src == "barkley" else "")  # fmt: skip
    ctl = ""
    if src in ("", "barkley"):
        ctl = (
            f'<form method=post action="{base}/ha-token/create" class="setform">{hidden}'
            f"<button{' class=primary' if not src else ''}>Create token</button></form>"
            f'<form method=post action="{base}/ha-token" class="setform ctl">{hidden}'
            '<input type=password name=value autocomplete=off aria-label="Home Assistant token" '
            'placeholder="Or paste a long-lived token"><button>Save token</button></form>'
        )
        if src == "barkley":
            ctl += (f'<form method=post action="{base}/ha-token/rotate" class="setform">{hidden}'
                    "<button>Rotate now</button></form>")  # fmt: skip
    return (
        '<div class="setrow" id="ha-token"><div><b>Home Assistant token</b>'
        '<p class="muted small">'
        "Barkley uses its own token to read your apps and send notifications. It must be an "
        "administrator's token, because Home Assistant only lists apps to administrators. "
        "Create token has you log in to Home Assistant once more and makes the token. The "
        "tokens from that login are revoked right after. Barkley keeps its token in its own "
        f"file, never in its database.</p>{err}</div>"
        f'<div class="ctl"><span class="muted small">{e(line)}</span>{ctl}</div></div>'
    )


# "How this works" under each setting on the Settings page: what it changes, in plain
# words, checked against the code (scoring.Policy, kinds.MINOR, shown.py, watch.py).
SETTING_HELP = {
    "Where Home Assistant runs": (
        "This changes the Exposure reading only: on a shared or work network it goes up by "
        "a quarter, and when Home Assistant can be reached from the internet, by half. "
        "Reachable from the internet also changes what new sniffs find: pages that work "
        "without a login, pages other websites may call and webhooks count one level "
        "higher, and a known vulnerability in a library counts as critical if attackers "
        "are already using it (with a home or work network, as medium at most). A stored "
        "scan keeps the choice it was made with. Data leaving your home and other signs of "
        "malicious behavior count the same either way."
    ),
    "Minor items": (
        "These touch no password or login, change nothing, and usually have a plain "
        "reason: listing user accounts (names only), reading other apps' settings (their "
        "options, not their stored data), writing its own files in Home Assistant's "
        ".storage folder, a vulnerability in a build tool that never ships in a card, "
        "installing its own declared libraries, and usage reporting that is disclosed or "
        "optional. When hidden, an app's page says how many it left out and has a link to "
        "show them. "
        "Changing who can log in, reading other apps' stored data or passwords, and code "
        "Barkley couldn't read are never minor. Minor items never change the readings."
    ),
    "Auto-sniff": (
        "When the Marketplace installs or updates an app, or offers an update, Barkley "
        "sniffs that version and notifies you. Once a day it also checks whether the "
        "libraries in your installed apps and waiting updates have new known "
        "vulnerabilities or have been found to be malware. That check doesn't download or "
        "scan the app's code again. A new integration runs as soon as it's installed. "
        "Home Assistant opens its setup right away, and that loads its code before the "
        "auto-sniff can finish. So sniff a new app from search before you install it. "
        "Barkley sniffs an update as soon as the Marketplace offers it, so you hear what it "
        "changes before you update."
    ),
    "Notify": (
        "Every result goes to Home Assistant's bell. Pick a notify service, such as your "
        "phone, to get it there too. A notification carries the app's name, its version, "
        "the readings and counts, never text from the app's code."
    ),
    "Notify when": (
        "Every auto-sniff is listed under Auto-sniff activity and on the app's page either "
        "way. This only decides which ones also notify you. Signs of malicious behavior "
        "always notify, and so does a sniff that didn't finish or couldn't run, because "
        "then Barkley can't say the app is fine."
    ),
    "AI": (
        "Explanations go through the Home Assistant AI Task entity you pick, so they use the "
        "AI provider you set up in Home Assistant. Nothing is sent until you click Explain. "
        "The AI never sets, clears or changes a reading or a finding, and it's only as good "
        "as the model behind the entity."
    ),
    "AI mode": (
        "Explain only sends what Barkley found. Explain and read code also lets you ask about "
        "one item, address or port, and sends the app's own code around it. That code is "
        "public on GitHub, and Barkley kept it from the scan. Nothing from your Home "
        "Assistant is ever sent."
    ),
    "Parallel scans": (
        "Each parallel scan checks a different app. Another scan starts only when there's "
        "memory for it (see Memory for scans); otherwise it waits its turn. Two checks of the "
        "same app never run together. Scans also share the processor. Keep Parallel scans "
        "times Semgrep jobs at or below the number of processor cores (4 on many Home "
        "Assistant boxes). Above that, a big app's checks can run out of time, and its scan "
        "shows as Incomplete."
    ),
    "Semgrep jobs": (
        "Inside one scan, Semgrep (the code checker) reads this many files at once. A "
        "higher number helps apps with many files, such as cards split into chunks. It "
        "doesn't help with one big file, and Barkley's own checks of the code still run "
        "one after another. Downloading the app takes the same time either way. Each "
        "extra job needs its own memory. With 1 parallel scan, set this to the number of "
        "cores. With more, keep Parallel scans "
        "times this at or below the number of cores."
    ),
    "Memory for scans": (
        "Barkley allows 1.5 GB for each scan. That covers almost every app: across 6,753 "
        "Marketplace apps, 18 scans used more, the biggest about 8.5 GB. On Auto, "
        "another scan starts only when free memory covers 1.5 GB for every running scan, "
        "plus a reserve. The reserve is 2 GB on a machine Home Assistant shares, and 0.5 GB "
        "inside a container with its own memory limit. With a fixed amount, Barkley runs as "
        "many scans as fit in it (two in 4 GB). It never goes past a container's limit, and "
        "never runs with under 1 GB really free. If a scan runs out of memory, the system "
        "stops it and it shows as Incomplete."
    ),
    "Low memory": (
        "Before each scan Barkley checks how much memory is free. At the default it doesn't "
        "start a scan with less than 1 GB free. Lower or off, a big scan can use the "
        "memory Home Assistant needs: Home Assistant may slow down, and the system may stop "
        "the scan, or another program, to free memory. A stopped scan shows as Incomplete. "
        "Memory for scans still decides how many scans run at once."
    ),
    "Token rotation": (
        "Barkley uses its current token to make a new one, checks that it works, saves it, "
        "and then deletes the old one. Each token lasts twice this period plus a week, so "
        "one missed rotation breaks nothing. If a rotation fails, Barkley keeps the current "
        "token, shows why here and notifies you. It tries again a day later."
    ),
    "GitHub token": (
        "GitHub allows 60 requests an hour without a token and 5,000 with one. A scan makes "
        "about 10 to 20. Barkley keeps the token in its own file next to its database, never "
        "in the database, and never shows it again. A token saved here is used instead of "
        "the one in the app's options."
    ),
}


def render_settings(
    base: str,
    s: settings_mod.Settings,
    token: str,
    *,
    ai_entity: str = "",
    ai_mode: str = AI_MODE_DEFAULT,
    ai_choices: list[tuple[str, str]] | None = None,
    watcher: watch.Watcher | None = None,
    token_source: str = "",
    external: bool | None = None,
    saved: bool = False,
    bad: str = "",
    bad_detail: str = "",
    mem: memory.Memory | None = None,
    defaults: settings_mod.Settings = settings_mod.DEFAULTS,
    ha_token_html: str = "",
    store_mb: float | None = None,
) -> bytes:
    """Barkley's Settings page (part 3, the agreed wording 2026-11-18): the readings,
    Checking and notifications (0.15: Scoring and Reviews went with the score).
    One form; each section can go back to Barkley's defaults. No script: plain selects
    and buttons."""

    def row(label: str, help_: str, control: str, more: str = "") -> str:
        # `more`: the longer "How this works", folded (<details>: no script, works on phones)
        more = more or SETTING_HELP.get(label, "")
        fold = (f'<details class="more"><summary>How this works</summary>'
                f'<p class="small">{e(more, 800)}</p></details>') if more else ""  # fmt: skip
        return (f'<div class="setrow"><div><b>{e(label)}</b><p class="muted small">{help_}</p>'
                f'{fold}</div><div class="ctl">{control}</div></div>')  # fmt: skip

    def sel(name: str, current: Any, opts: list[tuple[Any, str]]) -> str:
        return (f'<select name={name} aria-label="{e(name)}">' + "".join(
            f'<option value="{e(v)}"{" selected" if str(v) == str(current) else ""}>{e(t)}</option>'
            for v, t in opts) + "</select>")  # fmt: skip

    def onoff(name: str, current: bool, on: str, off: str, default: bool) -> str:
        return sel(name, "1" if current else "0",
                   [("1", on + (" (default)" if default else "")),
                    ("0", off + ("" if default else " (default)"))])  # fmt: skip

    def reset(part: str) -> str:
        return (f'<form method=post action="{base}/settings-reset" class="setform">'
                f'<input type=hidden name=token value="{token}">'
                f'<input type=hidden name=part value="{part}">'
                "<button>Reset to defaults</button></form>")  # fmt: skip

    hint = ""
    if external is False:
        hint = ('<p class="muted small">Your Home Assistant has no external URL set, so one of '
                "the first two fits.</p>")  # fmt: skip
    elif external:
        hint = ('<p class="muted small">Your Home Assistant has an external URL set. If it '
                "can be reached from the internet, choose Reachable from the internet."
                "</p>")  # fmt: skip
    readings_rows = (
        row("Where Home Assistant runs", "Choose where your Home Assistant can be reached "
            "from. This changes the Exposure reading. If it can be reached from the "
            "internet, new sniffs also count open pages and webhooks higher.",
            sel("where", s.where,
                [(x, label + (" (default)" if defaults.where == x else ""))
                 for x, label in (("home", "Only my home network"),
                                  ("shared", "A shared or work network"),
                                  ("internet", "Reachable from the internet"))])
            + hint)
        + row("Minor items", "Things that touch no password or login and change nothing, "
              "such as listing user names. Hidden items are counted on each app's page, with "
              "a link to show them.",
              sel("show_minor", "1" if s.show_minor else "0",
                  [("0", "Hide (default)"), ("1", "Show")]))
        + row("Build tool known to be malware", "A tool the developer used to build the "
              "app is listed as malware. It runs on their machine, not in your home, but it "
              "could change what ships. How much it counts toward Threat: 7 and up is "
              "found, anything under is possible.",
              sel("build_tool_points", s.build_tool_points,
                  [("2", "2"), ("2.5", "2.5 (default)"), ("3", "3")]))
        + row("Quiet projects", "An app's page and card say when nothing has been pushed to "
              "its project on GitHub for this long. It changes no reading.",
              sel("quiet_months", s.quiet_months,
                  [(n, ("Never say it" if n == 0 else
                        f"{n} months" if n < 24 else f"{n // 12} years")
                    + (" (default)" if n == defaults.quiet_months else ""))
                   for n in settings_mod.CHOICES["quiet_months"]]))
    )  # fmt: skip
    check_rows = ""
    if watcher is not None:
        targets, _terr = watcher.targets()
        chosen = watcher.notify_target
        opts = [("", "Bell only")] + [(t, f"notify.{t}") for t in targets]
        if chosen and chosen not in targets:
            opts.append((chosen, f"notify.{chosen} (not offered now)"))
        check_rows += row("Auto-sniff", "Check new installs and offered updates on its own.",
                          sel("auto_scan", "on" if watcher.enabled else "off",
                              [("on", "On (default)"), ("off", "Off")]))  # fmt: skip
        test = (f'<form method=post action="{base}/notify-test" class="setform">'
                f'<input type=hidden name=token value="{token}">'
                "<button>Send a test notification</button></form>")  # fmt: skip
        check_rows += row("Notify", "Choose where results go. Notifications carry only app "
                          "names, versions, counts, readings and Barkley's own fixed words.",
                          sel("notify_target", chosen, opts) + test)  # fmt: skip
        check_rows += row("Notify when", "Which results reach the bell and your notify "
                          "service. A sniff that didn't finish always does.",
                          sel("notify_when", s.notify_when, [
                              ("all", "Every result (default)"),
                              ("medium", "Exposure medium or high, or signs of malicious "
                                         "behavior"),
                              ("high", "Exposure high, or signs of malicious behavior"),
                              ("threat", "Only signs of malicious behavior")]))  # fmt: skip
        check_rows += (
            f'<div class="setrow"><div><b>Auto-sniff activity</b>'
            f"{render_auto_activity(base, watcher)}</div><div></div></div>"
        )
    if ai_choices is not None:
        opts = [("", "Off")] + [(i, f"{n} ({i})") for i, n in ai_choices]
        if ai_entity and ai_entity not in {i for i, _ in ai_choices}:
            opts.append((ai_entity, f"{ai_entity} (not offered now)"))
        check_rows += row("AI", "The Home Assistant AI Task entity that writes the "
                          "explanations. They're only as good as the model you pick.",
                          sel("ai_entity", ai_entity, opts))  # fmt: skip
    check_rows += row("AI mode", "Choose whether the AI only explains what Barkley found, "
                      "or can also read the code around one item when you ask.",
                      sel("ai_mode", ai_mode, [
                          ("summary", "Explain only"),
                          ("deep", "Explain and read code (default)")]))  # fmt: skip
    marks = "".join(
        f"<span>{n:,} characters · {settings_mod.AI_PAIRED_MINUTES[n]} min"
        f"{' (default)' if n == defaults.ai_size else ''}</span>"
        for n in settings_mod.CHOICES["ai_size"]
    )
    check_rows += row("AI answers", "How much of the developer's README and code "
                      "descriptions one request may carry. More gives your AI more to go on, "
                      "and it may write up to 6 sentences (4 at 6,000). A bigger request can "
                      "take your AI longer. Picking a size fills in its minutes below.",
                      '<input form="settings" type=range name=ai_size min=6000 max=18000 '
                      f'step=6000 value="{s.ai_size}" aria-label="AI answers size">'
                      f'<div class="stops">{marks}</div>')  # fmt: skip
    check_rows += row("AI time limit", "How long Barkley waits for an answer. Off waits as "
                      "long as your model takes, for a slow model on your own machine; the "
                      "page has a Stop waiting button. Home Assistant may still finish an "
                      "answer Barkley stopped waiting for, but Barkley won't use it.",
                      sel("ai_limit", "1" if s.ai_limit else "0",
                          [("1", "Stop waiting after (default)"),
                           ("0", "Wait as long as it takes")])
                      + ' <input form="settings" type=number name=ai_minutes min=1 max=60 '
                      f'value="{s.ai_minutes}"'
                      ' class="mins" aria-label="minutes"> minutes')  # fmt: skip
    check_rows += row("Parallel scans", "How many apps Barkley scans at the same time.",
                      sel("parallel", s.parallel,
                          [(n, f"{n}{' (default)' if n == defaults.parallel else ''}")
                           for n in settings_mod.CHOICES["parallel"]]))  # fmt: skip
    check_rows += row("Semgrep jobs", "How many files one scan's code check reads at once.",
                      sel("jobs", s.jobs,
                          [(n, f"{n}{' (default)' if n == defaults.jobs else ''}")
                           for n in settings_mod.CHOICES["jobs"]]))  # fmt: skip
    check_rows += row("Published libraries", "Some integrations include a large "
                      "JavaScript file that is an exact copy of a well-known npm library file "
                      "(at least a month old, at least 10,000 downloads a week, no malware "
                      "advisory). Barkley lists that file and checks it for advisories instead "
                      "of reading it as code. To find out, it sends the file's fingerprint "
                      "(SHA-256) to jsDelivr, a public library service. When off, Barkley "
                      "reads every file.",
                      sel("libraries", "1" if s.libraries else "0",
                          [("1", "Recognise them (default)"), ("0", "Off")]))  # fmt: skip
    used = scancache.size_mb()
    check_rows += row("Cache of code already read", "Barkley remembers what it found in "
                      "each file, matched by the file's content, so it doesn't read the same "
                      "file twice. That speeds up a new release of an app and Sniff again. New "
                      "rules or new scanner tools start a fresh cache. It uses "
                      f"{used:,.0f} MB now.",
                      sel("cache_mb", s.cache_mb,
                          [(n, "Off" if n == 0 else
                            (f"{n // 1024} GB" if n >= 1024 else f"{n} MB")
                            + (" (default)" if n == defaults.cache_mb else ""))
                           for n in settings_mod.CHOICES["cache_mb"]]))  # fmt: skip
    size = (
        ""
        if store_mb is None
        else f" The scan store uses {store_mb:,.{1 if store_mb < 10 else 0}f} MB now."
    )
    check_rows += row("Versions kept per app", "Each update of an installed app adds a scan "
                      "of the new version. This is how many versions keep their scans; older "
                      "ones are deleted once a day. The installed version and a waiting "
                      f"update are always kept.{size}",
                      sel("keep_versions", s.keep_versions,
                          [(n, ("All of them" if n == 0 else f"The last {n}")
                            + (" (default)" if n == defaults.keep_versions else ""))
                           for n in settings_mod.CHOICES["keep_versions"]]))  # fmt: skip
    now_free = ""
    if mem is not None and mem.available is not None and mem.total:
        total = f"{mem.total / memory.GIB:.1f} GB"
        of = f"this container's {total} limit" if mem.limited else total
        now_free = (f'<span class="muted small">{mem.available / memory.GIB:.1f} GB is free '
                    f"now, out of {of}.</span>")  # fmt: skip
        if mem.limited and s.memory_gb * memory.GIB > mem.total:
            now_free += ('<span class="muted small">The container\'s limit (mem_limit) is '
                         "lower, so Barkley stays within it.</span>")  # fmt: skip
    check_rows += row("Memory for scans", "How much memory scans may use at once. Auto goes "
                      "by what's free.",
                      sel("memory_gb", s.memory_gb,
                          [(n, "Auto (default)" if n == 0 else f"{n} GB")
                           for n in settings_mod.CHOICES["memory_gb"]]) + now_free)  # fmt: skip
    check_rows += row("Low memory", "Scans don't start when less than this is free, so a "
                      "scan can't push Home Assistant out of memory. Lower it only if you "
                      "accept that risk, for example on a machine with 2 GB.",
                      sel("memory_floor_mb", s.memory_floor_mb,
                          [(1024, "1 GB free (default)"), (512, "0.5 GB free"),
                           (0, "Scan anyway")]))  # fmt: skip
    hidden = f'<input type=hidden name=token value="{token}">'
    have = {"settings": "Set here", "option": "Set in the app's options",
            "file": "Set by GITHUB_TOKEN_FILE"}.get(token_source, "")  # fmt: skip
    token_ctl = (
        (f'<span class="muted">{ui.icon("check", 14, "ok")} {e(have)}</span>' if have else "")
        + f'<form method=post action="{base}/github-token" class="setform ctl">{hidden}'
        '<input type=password name=value autocomplete=off aria-label="GitHub token" '
        f'placeholder="{"Replace with a new token" if have else "Paste a token"}">'
        f"<button>{'Replace token' if have else 'Save token'}</button></form>"
        + (f'<form method=post action="{base}/github-token" class="setform">{hidden}'
           '<input type=hidden name=remove value=1><button>Remove</button></form>'
           if token_source == "settings" else "")  # noqa: S105 - a source name
    )  # fmt: skip
    token_row = row(
        "GitHub token",
        "A token is optional. It raises GitHub's limit from 60 to 5,000 requests an hour, "
        f"and it needs no permissions. {GITHUB_STEPS} "
        f'<a href="{DOCS_GITHUB_HELP}" target="_blank" rel="noopener noreferrer">'
        "More about it</a>",
        github_create_link() + token_ctl,
    )
    if ha_token_html:
        check_rows += row("Token rotation", "How often Barkley replaces its own Home "
                          "Assistant token. The old one is deleted once the new one works.",
                          sel("token_days", s.token_days,
                              [(n, f"Every {n} days" + (" (default)" if n == 60 else ""))
                               for n in settings_mod.CHOICES["token_days"]]))  # fmt: skip
    note = ""
    if saved:
        note = f'<div class="banner">{ui.icon("check", 14, "ok")} Saved.</div>'
    bad_text = {
        "token": "That doesn't look like a GitHub token, so nothing was saved.",
        "hatoken": "Home Assistant didn't accept that token as an administrator's, so nothing "
        "was saved. The app's log says why.",
        "rotate": "The token couldn't be replaced; the current one keeps working. See below.",
        "nologin": "Create token only works when Barkley's login is set up (BARKLEY_URL). "
        "Paste a token instead.",
        "create": bad_detail or "Barkley couldn't create its token. The app's log says why.",
    }  # fmt: skip
    if bad in bad_text:
        note = f'<div class="banner warn">{e(bad_text[bad], 300)}</div>'
    if ha_token_html:
        token_row = ha_token_html + token_row

    def section(title: str, rows: str, part: str) -> str:
        return (f'<section class="box"><h2>{title}</h2>{rows}'
                f'<div class="setrow"><div></div><div class="ctl"><button form="settings" '
                f'class="primary">Save</button>{reset(part)}</div></div></section>')  # fmt: skip

    body = (
        f'<p class="crumb"><a href="{base}/">{ui.icon("back")} All apps</a></p>'
        "<h1>Settings</h1>"
        f"{note}"
        f'<form method=post action="{base}/settings" id="settings" class="setform">{hidden}</form>'
        + section("Readings", readings_rows.replace("<select ", '<select form="settings" '),
                  "readings")
        + section("Checking and notifications",
                  check_rows.replace("<select ", '<select form="settings" ') + token_row,
                  "checking")
        + '<p class="muted small">Barkley stores these settings itself, whether it runs as a '
        "Home Assistant app or on its own. The app's Configuration tab only sets the starting "
        "values.</p>"
    )  # fmt: skip
    return _page("Barkley · Settings", body, base)


def render_account(base: str, name: str, token: str) -> str:
    """Standalone only: who is logged in, and a way out."""
    return (
        f'<form class="foot" method=post action="{base}/logout">'
        f"You're logged in with Home Assistant as {e(name, 100)}. "
        f'<input type=hidden name=token value="{token}">'
        '<button class="link">Log out</button></form>'
    )


def render_setup(
    base: str,
    store: Store,
    token: str,
    step: str,
    *,
    period: int = 60,
    github_source: str = "",
    error: str = "",
    bad: str = "",
    saved: bool = False,
    held: bool = False,
    now: datetime | None = None,
) -> bytes:
    """(0.14.0) Standalone's first run, after the login: 1. Barkley's Home Assistant token
    (made with the login, or pasted), 2. a GitHub token (optional), then the list.
    `held`: the first login is still held, so Create token needs no second login. No
    script: links and plain forms."""
    hidden = (f'<input type=hidden name=token value="{token}">'
              "<input type=hidden name=back value=setup>")  # fmt: skip
    src = ha_token.source()
    if step == "github":
        title = "2 of 2: GitHub token (optional)"
        have = {"settings": "Barkley has a GitHub token.",
                "option": "Barkley has a GitHub token from the app's options.",
                "file": "Barkley has a GitHub token from GITHUB_TOKEN_FILE."}  # fmt: skip
        have = have.get(github_source, "")
        state = f"<p>{ui.icon('check', 14, 'ok')} {e(have)}</p>" if have else ""
        if bad == "token":
            state += ('<div class="banner warn">That doesn\'t look like a GitHub token, so '
                      "nothing was saved.</div>")  # fmt: skip
        elif saved:
            state += f'<div class="banner">{ui.icon("check", 14, "ok")} Saved.</div>'
        body = (
            "<p>Without a token, GitHub allows 60 requests an hour, enough for about 3 to 5 scans. "
            "With one, it allows 5,000. Barkley only reads public repositories, so the token "
            f"needs no permissions.</p>{state}"
            + (
                ""
                if have
                else f'<p>{github_create_link(now)}</p><p class="muted small">{GITHUB_STEPS}</p>'
            )
            + f'<form method=post action="{base}/github-token" class="setform ctl">{hidden}'
            '<input type=password name=value autocomplete=off aria-label="GitHub token" '
            f'placeholder="{"Replace with a new token" if have else "Paste the token"}">'
            "<button>Save token</button></form>"
            f'<p class="actions"><a class="button primary" href="{base}/">'
            f"{'Done' if have else 'Skip'}</a></p>"
        )
    else:
        title = "1 of 2: Home Assistant token"
        made = ha_token.Meta.load(store)
        if src == "barkley":
            when = made.created[:10] or "now"
            state = (f'<p>{ui.icon("check", 14, "ok")} Barkley has its own Home Assistant '
                     f"token ({e(made.how or 'created')} {e(when)}). Barkley replaces it "
                     f"with a new one every {period} days (Settings, Token "
                     "rotation).</p>")  # fmt: skip
        elif src:
            state = (f'<p>{ui.icon("check", 14, "ok")} Barkley uses the token you set in '
                     "its environment (HA_TOKEN_FILE or HA_TOKEN). You manage that one. "
                     "Barkley doesn't replace it.</p>")  # fmt: skip
        else:
            state = ("<p>Barkley needs its own Home Assistant token to list your apps and "
                     "notify you. Create one now using the login you just did, or paste one you "
                     "made yourself.</p>")  # fmt: skip
        if error:
            state += f'<div class="banner warn">{e(error, 300)}</div>'
        if bad == "hatoken":
            state += ('<div class="banner warn">Home Assistant didn\'t accept that token as '
                      "an administrator's, so nothing was saved.</div>")  # fmt: skip
        elif saved:
            state += f'<div class="banner">{ui.icon("check", 14, "ok")} Saved.</div>'
        paste = (f'<form method=post action="{base}/ha-token" class="setform ctl">{hidden}'
                 '<input type=password name=value autocomplete=off aria-label="Home Assistant '
                 'token" placeholder="Paste a long-lived token"><button>Save token</button>'
                 "</form>")  # fmt: skip
        if not src:
            label = "Create token" if held else "Create token (you'll log in again)"
            ctl = (f'<form method=post action="{base}/ha-token/create" class="setform">'
                   f"{hidden}<button class=primary>{label}</button></form>"
                   f"{paste}")  # fmt: skip
        elif src == "barkley":
            ctl = (f'<details class="more"><summary>Use a token you made instead</summary>'
                   f"{paste}</details>")  # fmt: skip
        else:
            ctl = ""
        # a form: the end of this step lets go of the held login
        nxt = (f'<form method=post action="{base}/setup/next" class="setform">{hidden}'
               + ("<button class=primary>Next</button>" if src
                  else "<button>Skip for now</button>") + "</form>")  # fmt: skip
        body = (f"{state}{ctl}<p class=\"muted small\"><a href=\"{DOCS_HA_SETUP}\" "
                'target="_blank" rel="noopener noreferrer">About this token</a></p>'
                f'<p class="actions">{nxt}</p>')  # fmt: skip
    page = (f'<div class="head"><h1>{ui.logo_img()}Set up Barkley</h1></div>'
            f'<section class="box"><h2>{e(title)}</h2>{body}</section>')  # fmt: skip
    return ui.page("Barkley: set up", page)


def render_login(message: str = "", first: bool = False) -> bytes:
    """The one page a standalone panel shows before the login. `first`: Barkley has no
    Home Assistant token yet, so this login also makes it."""
    note = f'<p class="sev-high">{e(message, 400)}</p>' if message else ""
    first_note = (
        "<p><b>First time:</b> after the login, a short setup gives Barkley its own Home "
        "Assistant token.</p>"
        if first else ""
    )  # fmt: skip
    body = (
        f'<div class="head"><h1>{ui.logo_img()}Barkley</h1></div>{note}'
        "<p>Barkley runs next to your Home Assistant, so you log in with your Home Assistant "
        "account. "
        f"Only Home Assistant administrators can use it.</p>{first_note}"
        # A link, not a form: CSP form-action 'self' would stop the redirect to HA.
        '<p><a class="button" href="/login">Log in with Home Assistant</a></p>'
        '<p class="muted">Barkley keeps no password or token of yours, only a session that '
        "ends after 12 hours or when Barkley restarts.</p>"
    )
    return ui.page("Barkley: log in", body)


def render_auto_activity(base: str, w: watch.Watcher) -> str:
    """(0.14.0) On Settings, under the auto-sniff rows: its state, the last test
    notification, and recent auto-sniffs (the box on the list moved here)."""
    ok, diag = w.diagnostics()
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
        if "readings" in x or "score" in x:  # (0.15) older entries kept a score: not shown
            result = ui.readings_text(x.get("readings"), bool(x.get("complete", True)))
            if x.get("changes"):
                result += f' <span class="muted">{e(x["changes"], 200)}</span>'
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
        else '<p class="muted small">Nothing has been installed or updated since Barkley '
        "started watching.</p>"
    )  # fmt: skip
    kept = w.keep_versions_fn()
    kept_text = (
        "scans of installed apps are kept"
        if kept <= 0
        else f"installed apps keep the scans of their last {kept} versions"
    )
    return (
        (f'<p class="small">{e(w.last_test, 300)}</p>' if w.last_test else "")
        + f'<p class="muted small">{"" if ok else ui.icon("alert", 14, "warn") + " "}'
        f"{e(diag, 600)}. Scans of apps that "
        f"aren't installed are deleted after {w.age_out_days:g} days; {kept_text}.</p>"
        f"<details><summary>Recent auto-sniffs ({len(w.log())})</summary>{recent}</details>"
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
            parts.append('<p class="sub">Check these before you update:</p><ul class="plain">')
            parts.extend(f"<li>{e(x, 300)}</li>" for x in row.reasons)
            parts.append("</ul>")
        else:
            parts.append('<p class="ok">Barkley checked it. Nothing important changes.</p>')
        parts.append(f'<p class="small"><a href="{base}/diff?{link}">Everything the update '
                     "changes</a></p>")  # fmt: skip
    else:
        parts.append('<p class="sub">This update isn\'t checked yet. Checking it scans the '
                     "new version and compares it with the one you have.</p>")  # fmt: skip
    if not row.busy and (act := _action(base, row, token, primary=True)):
        parts.append(f'<div class="act">{act}</div>')
    parts.append("</section>")
    return "".join(parts)


def _ai_picker(base: str, sid: int, token: str, entity: str,
               choices: list[tuple[str, str]] | None, err: str) -> str:  # fmt: skip
    """A dropdown of the AI Task entities HA has (from the one fixed template)."""
    if err:
        return (f'<p class="small">Barkley couldn\'t list your AI Task entities: '
                f"{e(err, 300)}. You can still set <code>ai_entity</code> in the app's "
                "Configuration.</p>")  # fmt: skip
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
    "summary": "Explain only",
    "deep": "Explain and read code",
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
            '<p class="tech">Explain and read code adds an "Explain in context" button to each '
            "item, port and unknown address. The AI then reads that part of the app's code. "
            "Every statement it makes has to point to lines that Barkley can confirm. Code is "
            "sent only when you click.</p>")  # fmt: skip


def _ai_form(base: str, sid: int, token: str, entity: str, state: str, error: str,
             have: dict[str, Any] | None, choices: list[tuple[str, str]] | None = None,
             choices_err: str = "", mode: str = AI_MODE_DEFAULT,
             readings: list[str] | None = None, since: float = 0.0) -> str:  # fmt: skip
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
    note = ('<p class="tech">Explain this app sends what this scan found to the AI provider '
            f"behind <code>{e(entity, 120)}</code>. It's about a public project and contains "
            "no Home Assistant data. The AI only explains. It can't change the readings or what "
            "Barkley found.</p>")  # fmt: skip
    change = (f"<details><summary>Change which AI explains, or how much "
              f"({e(AI_MODES.get(mode, mode))})</summary>{picker}</details>")  # fmt: skip
    if state == "running":
        waited = f" It has been {ai_wait(time.time() - since)}." if since else ""
        stop = (f'<form method=post action="{base}/ai-stop" class="act">'
                f'<input type=hidden name=token value="{token}">'
                f'<input type=hidden name=scan value="{sid}">'
                "<button>Stop waiting</button></form>")  # fmt: skip
        return (f'<div class="aibox wait mt2">'
                f'<span class="thinking">{ui.icon("sparkle", 20)}</span>'
                f"<div><b>Your AI is answering…</b><br><span class=small>This can take a few "
                f"minutes, depending on your AI.{waited} You don't have to wait here: the "
                "answer is saved, and this page refreshes by itself.</span></div>"
                f"{stop}</div>")  # fmt: skip
    if error:
        said = error if error.endswith(".") else f"The AI didn't answer: {error}"
        return (f'<div class="banner warn mt2">{e(said, 400)}</div>'
                + form.replace("{label}", "Try again") + note
                + change)  # fmt: skip
    if have:
        used = list(have.get("readings") or [])
        newer = [r for r in readings or [] if r not in used]
        n = len(used)
        incl = (f" It includes {n} code reading{'s' if n != 1 else ''} from Explain in context."
                if n else "")  # fmt: skip
        d = int(have.get("dropped") or 0)
        left = (f" Barkley left out {d} sentence{'s' if d != 1 else ''} that dismissed a concern."
                if d else "")  # fmt: skip
        label = "Ask again"
        if newer:
            k = len(newer)
            label = f"Ask again to include {k} newer code reading{'s' if k != 1 else ''}"
        return (f'<p class="tech">AI explanation by <code>{e(have.get("entity_id"), 120)}</code>, '
                f"{e(str(have.get('created', ''))[:16].replace('T', ' '))} UTC.{incl}{left} It "
                "can be wrong. It can't change the readings.</p>"
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
    ai_mode: str = AI_MODE_DEFAULT,
    item_states: dict[str, tuple[str, str]] | None = None,
    open_item: str = "",
    rechecking: bool = False,
    item_asked: dict[str, list[str]] | None = None,
    listing: dict[str, str] | None = None,
    ai_since: float = 0.0,
    jobs: list[Job] | None = None,
    full: bool = False,
) -> bytes:
    """`open_item`: the item whose AI sheet is open (`?open=`), kept open across refreshes.
    `full` (`?all=1`, Show details): a phone shows the whole page, not the short view.
    `listing`: the Marketplace's removed list entry for this app (listings.py), if any.
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
    # (0.15, his report) a sniff of this app that is queued, running or just done: the same
    # lines as the list's status box, so the page says so and reloads until it ends
    mine = [j for j in jobs or [] if repo and j.repo.lower() == str(repo).lower()
            and j.kind != "recheck"]  # fmt: skip
    sniffing = any(j.state in ("queued", "running", "waiting") for j in mine)
    shown_name = row.item.name if row else str(repo or "")
    strip = status_html(base, mine, {str(repo or "").lower(): shown_name}, "",
                        refresh_href=f"{base}/scan/{sid}") if mine else ""  # fmt: skip
    deep = None
    if ai_mode == "deep" and ai_entity and report.get("context"):
        answers = store.item_explanations(sid)
        # asked of the index only: the page is rendered often, the copy is unpacked on a click
        src_note = None if store.has_source(sid) else (report["context"].get("source") or {})

        def deep(item_id: str, part: str = "both") -> str:
            snip = ai_context.snippet_of(report, item_id)
            if snip is None:
                it = (report["context"].get("items") or {}).get(item_id) or {}
                if part != "both":  # the notes below are for the item's own place only
                    return ""
                if it.get("kind") == "dependency" and it.get("unread"):
                    return (f'<p class="small muted">{ui.icon("sparkle")} Explain in context: '
                            "this package's advisory appeared after the code was sniffed, so "
                            "Barkley hasn't looked for where the app uses "
                            f"{e(it.get('package'), 120)}. Sniff this version again to include "
                            "that.</p>")  # fmt: skip
                if it.get("kind") == "dependency":  # nothing of the app's own to read
                    return (f'<p class="small muted">{ui.icon("sparkle")} Explain in context: '
                            "Barkley couldn't find "
                            f"where the app's own code uses {e(it.get('package'), 120)}, so "
                            "there's no code to send. It may come in through another library, "
                            "or a bundle may hide the name.</p>")  # fmt: skip
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
                                asking=(item_asked or {}).get(item_id),
                                more=ui.more_note(snip, src_note),
                                also=ui.also_note(ai_context.comparison_of(report, item_id),
                                                  ai_context.readme_of(report, item_id)),
                                open_url=_scan_url(base, sid, item_id) if running else "",
                                close_url=e(f"{base}/scan/{sid}") if running else "",
                                part=part)  # fmt: skip

    return ui.render_app(
        base,
        sid,
        report,
        rows,
        name=row.item.name if row else None,
        update=strip + listings.note_html(listing) + _update_box(base, row, token),
        again=_again_box(base, report, token, sid)
        + _advisory_line(base, sid, report, store, token, rechecking),
        trust=address_block,
        review=report_block(report) if "shown" in report else None,
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
            ai_since,
        ),
        refresh=5 if running or rechecking or sniffing else 0,
        deep=deep,
        refresh_url=_scan_url(base, sid, open_item, fresh=True) if open_item else "",
        open_item=open_item,
        full=full or bool(open_item),  # an open sheet may sit in the hidden part
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


def _again_box(base: str, report: dict[str, Any], token: str, sid: int = 0) -> str:
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


# (0.14.1) The scan-logic key stored scans are compared with (logic.key(); serve sets it).
# A scan made by other rules isn't offered an advisory re-check: it'll be sniffed again.
CURRENT_RULES = __version__


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
            f"The known advisories for its packages changed, so this scan replaced "
            f'<a href="{base}/scan/{of}">scan @{of}</a> on {e(_utc(str(rc.get("at", ""))))} '
            f'(<a href="{base}/diff?old={of}&amp;new={sid}">what changed</a>). The code is the '
            f"same as sniffed on {e(str(rc.get('code_scanned_at', ''))[:10])}. Only the "
            "advisories were looked up again."
        )
    last = store.rechecks().get(sid)
    if last:
        when, result = e(_utc(last[0])), last[1]
        if result == "same":
            bits.append(f"Advisories checked again on {when}. Nothing changed.")
        elif result.startswith("changed:") and result[8:].isdigit():
            new = int(result[8:])
            bits.append(f"An advisory re-check on {when} found changes: see "
                        f'<a href="{base}/scan/{new}">scan @{new}</a>.')  # fmt: skip
        elif result.startswith("failed"):
            bits.append(f"Barkley couldn't check the advisories again on {when}, so the ones "
                        f"shown are older ({e(result, 200)}).")  # fmt: skip
    row = store.get(sid)
    can = (
        row is not None
        and row.repo
        and row.ref
        and row.complete
        and row.tool_version == CURRENT_RULES
        and sid in store.has_inputs()
        and not (last and last[1].startswith("changed:"))
    )
    if busy:
        bits.append(
            '<span class="dot"></span>Checking its packages against the OSV advisory '
            "database again…"
        )
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
        '<p class="muted small">This searches the Marketplace list your Home Assistant already '
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
            act = (f'<a style="text-decoration:none" href="{base}/scan/{scan.id}">'
                   f"{ui.readings_text(scan.readings, scan.complete)}</a>")  # fmt: skip
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
        out.append(f'<p class="muted small">The {len(results)} best matches out of {total} '
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
        f'<p class="muted small">{e(repo, 120)} · the {f"{len(releases)} " if releases else ""}'
        "newest releases on GitHub, betas included. Sniffing a version checks exactly what the "
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
            return (f'<a style="text-decoration:none" href="{base}/scan/{scan.id}">'
                    f"{ui.readings_text(scan.readings, scan.complete)}</a>")  # fmt: skip
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
        act = (
            action(r.tag)
            if _REF.match(r.tag)
            else '<span class="muted">can\'t sniff this tag name</span>'
        )
        rows.append(
            f'<tr><td class="wrap"><b><code>{e(r.tag, 100)}</code></b> {"".join(chips)}<br>'
            f'<span class="muted small">{when}{who if r.publisher else ""}</span></td>'
            f'<td class="actcol">{act}</td></tr>'
        )
    if rows:
        out.append('<table class="box">' + "".join(rows) + "</table>")
    elif not error:
        out.append('<p class="muted">This app has no releases. The Marketplace installs the '
                   "newest code on its default branch.</p>")  # fmt: skip
        out.append(f"<p>{action(None)}</p>")
    running = any(v in ("running", "queued", "waiting") for v in busy.values())
    return ui.page(f"Barkley · versions of {name}", "".join(out), refresh=5 if running else 0,
                   base=base)  # fmt: skip


ISSUES = "https://github.com/SeriesOfTubez/ha-barkley/issues/new"


def issue_url(template: str, **fields: str) -> str:
    """A pre-filled new-issue link on Barkley's own GitHub (issue forms fill their fields
    from the query by id). No token: the user opens it in their own browser, reads it,
    and submits it themselves, in public."""
    q = {"template": template, **{k: v[:500] for k, v in fields.items() if v}}
    return f"{ISSUES}?{urllib.parse.urlencode(q)}"


def report_fp_url(report: dict[str, Any], f: dict[str, Any]) -> str:
    """Report a false positive: the versions, the rule, the file and line filled in; the
    user writes why it's wrong. Only text from the stored report (names are validated by
    the scanner; the title is Barkley's own)."""
    t = report.get("target") or {}
    repo = str(t.get("repo") or "")
    where = f"{f.get('file') or ''}{':' + str(f['line']) if f.get('line') else ''}"
    return issue_url(
        "2-scan-result.yml",
        title=f"[Scan]: {f.get('rule_id')} on {repo.rsplit('/', 1)[-1]}"[:120],
        **{
            # (his report 2026-11-23) the form's field was `repo`, which GitHub doesn't fill
            # from the query; `app-repo` is
            "app-repo": f"https://github.com/{repo}" if _REPO.fullmatch(repo) else "",
            "app-version": str(t.get("ref") or ""),
            "barkley-version": str((report.get("tool") or {}).get("version") or __version__),
            "ha-version": str(report.get("ha_version") or ""),
            "rule": str(f.get("rule_id") or ""),
            "location": where,
        },
    )


def report_issue_url(ha_version: str | None) -> str:
    return issue_url("1-bug.yml", version=__version__, **{"ha-version": ha_version or ""})


_REPORT_TITLE = (
    "Opens a new public issue on Barkley's GitHub, filled in with the versions, the rule, the "
    "file and the line. You add why it's wrong, then submit it yourself."
)


def _ago_text(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d")
    except ValueError:
        return ""


def report_block(report: dict[str, Any]) -> ui.ReviewFn:
    """The row under each item: Report a false positive (0.15: the only action; reviews
    were removed, his decision 2026-11-20)."""

    def block(f: dict[str, Any], _fs: list[dict[str, Any]]) -> str:
        return (f'<div class="rev"><a href="{e(report_fp_url(report, f), 1500)}" '
                f'target="_blank" rel="noopener noreferrer" title="{e(_REPORT_TITLE)}">Report a '
                "false positive</a></div>")  # fmt: skip

    return block


def address_block(f: dict[str, Any]) -> str:
    """Under an item that is only about where an address points: each address and what
    it is (0.15: the Trust buttons went with reviews). Every address came from the
    scanner's own parse; still escaped."""
    addrs = [a for a in f.get("addresses") or [] if isinstance(a, str)]
    if not addrs:
        return ""
    return f'<ul class="plain small">{"".join(ui.address_line(a) for a in addrs[:6])}</ul>'


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
           f'<p class="muted">This is Barkley {e(__version__)}. Each tool runs on a one-line '
           "sample Barkley writes here, never on scanned code.</p>"]  # fmt: skip
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


def what_html(d: dict[str, Any]) -> str:
    """(0.15, his ask 2026-11-23) What the update changes beyond security: one sentence of
    counts, and a fold that names them. Names come from the scanned code: escaped."""
    what = [w for w in d.get("what") or [] if isinstance(w, dict) and w.get("kind") in WHAT]
    if not d.get("what_known"):
        return ('<p class="small mt2 muted">What else the update changes (actions, kinds of '
                "entity, packages, sites) shows once both versions are sniffed by Barkley "
                "0.15 or later.</p>")  # fmt: skip
    said = (
        what_sentence(what)
        or "It adds and removes no actions, kinds of entity, pages, packages or sites."
    )
    rows = []
    for w in what:
        one, many, _add, _drop = WHAT[w["kind"]]
        for side, word in (("added", "New"), ("removed", "Gone")):
            shown = [str(x) for x in w.get(side) or []][:20]
            if shown:
                total = max(int(w.get(f"n_{side}") or 0), len(shown))
                rest = f" and {total - len(shown)} more" if total > len(shown) else ""
                rows.append(f"<li>{word} {e(one if total == 1 else many)}: "
                            + ", ".join(f"<code>{e(n, 120)}</code>" for n in shown)
                            + f"{rest}</li>")  # fmt: skip
    fold = (f'<details class="small"><summary>Which ones</summary><ul>{"".join(rows)}</ul>'
            "</details>" if rows else "")  # fmt: skip
    return f'<p class="mt2"><b>What the update changes:</b> {e(said, 600)}</p>{fold}'


def render_diff(
    base: str,
    old: int,
    new: int,
    d: dict[str, Any],
    name: str | None = None,
    recheck_of: bool = False,
    readings_of: tuple[dict[str, Any] | None, dict[str, Any] | None] = (None, None),
) -> bytes:
    """What an update changes, in plain words: the headline changes as a list with the
    same level labels as findings, the rest folded behind a disclosure; the diff's own
    text stays available per line under "Technical details". `recheck_of`: the new side
    is an advisory re-check of the old one (same version, same code), and says so."""
    what = "What the advisory re-check changed" if recheck_of else "What the update changes"
    how = (
        "Same version, same code. Barkley only looked up the known advisories for its "
        "packages again. This page lists advisories that are new since then, and ones that "
        "are gone."
        if recheck_of
        else "This page lists what the new version does that the old one didn't, and what the "
        "old one did that the new one doesn't."
    )
    frm, to = d["from"], d["to"]
    changes = d.get("changes", [])
    head = [c for c in changes if c["rank"] >= HEADLINE_RANK][:HEADLINE_MAX]
    rest = [c for c in changes if c not in head]
    title = name or str(frm.get("repo") or "?").rsplit("/", 1)[-1]
    r_from, r_to = readings_of
    out = [
        f'<p class="crumb"><a href="{base}/">{ui.icon("back")} All apps</a></p>',
        '<section class="box dhead">'
        f"<div><h1>{what}: {e(title, 100)}</h1>"
        f"<div>From {_side_words(base, frm, old)} to {_side_words(base, to, new)} · "
        f"{e(frm.get('repo'), 120)}</div>"
        + (
            f'<div class="small mt2">Before: {ui.readings_text(r_from)}<br>After: '
            f"{ui.readings_text(r_to)}</div>"
            if r_from or r_to
            else ""
        )
        + what_html(d)
        + f'<div class="muted small">Each version has its own readings. The comparison itself '
        f"doesn't change them. {how}</div></div></section>",
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
        out.append(f'<section class="box"><h2>Changes to check ({len(head)})</h2>{lines(head)}'
                   "</section>")  # fmt: skip
    if rest:
        out.append(f'<details class="box"><summary>Smaller changes ({len(rest)}). None is a '
                   f"concern on its own.</summary>{lines(rest, True)}"
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


@dataclass(frozen=True)
class _Inputs:
    generation: int
    settings: settings_mod.Settings


class Panel:
    def __init__(
        self,
        store: Store,
        worker: Worker,
        allow: set[str] | None,
        installed_fn: InstalledFn | None = None,
        memory_fn: Callable[[], memory.Memory] = memory.check,
    ):
        self.store = store
        # (0.15) rows carry their Threat and Exposure readings (overlay_rows)
        store.overlay = self.overlay_rows
        self.worker = worker
        self.start_settings = settings_mod.DEFAULTS  # from the add-on options / BARKLEY_*
        self.option_token = ""  # the add-on option's GitHub token (Remove falls back to it)
        self._cache: _Inputs | None = None  # see _inputs()
        self._rows: dict[int, dict[str, Any]] = {}  # readings per scan for that same input
        self.standalone = False  # (0.14.0 part 4) set by `serve`: Barkley's own HA token
        # (0.15) the Marketplace's removed list (listings.py); set by `serve` only, so tests
        # never reach the real server
        self.listings: listings.Listings | None = None
        self.allow = allow  # None: any address (standalone, behind the login)
        self.login: login.Login | None = None  # standalone: "log in with Home Assistant"
        self.cpu_gap: list[str] | None = None  # set by `serve`: cpu.missing_v2() at startup
        self.csp = _CSP
        self.setup_errors: dict[str, str] = {}  # session id: why Create token failed
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
        # (0.15) the panel's own AI call: it reads the time limit and the Stop waiting flag
        # set for the request in hand (_ask_ai); tests put a plain function here
        self._ai_local = threading.local()
        self._ai_cancel: dict[tuple[int, str], threading.Event] = {}
        self.ai_fn: AiFn = self._ai_call
        self._ai: dict[int, tuple[str, str]] = {}  # scan id -> (running|failed, error)
        self._ai_items: dict[tuple[int, str], tuple[str, str]] = {}  # (scan, item) -> same
        self._ai_asked: dict[tuple[int, str], list[str]] = {}  # second round: what it asked for
        # (0.15) when each AI run started: (scan, "" for Explain this app or the item id)
        self._ai_started: dict[tuple[int, str], float] = {}
        self._ai_lock = threading.Lock()
        self.ai_mode = AI_MODE_DEFAULT
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

    def _ai_call(
        self, entity: str, instructions: str, structure: dict[str, Any], task_name: str
    ) -> Any:
        """The real AI call, with this request's time limit and Stop waiting flag."""
        return supervisor.ai_generate_data(
            entity, instructions, structure, task_name,
            timeout=getattr(self._ai_local, "timeout", supervisor._AI_TIMEOUT),
            cancel=getattr(self._ai_local, "cancel", None),
        )  # fmt: skip

    def ai_timeout(self) -> float | None:
        """Settings → AI answers: seconds to wait, None when the time limit is off."""
        s = self.settings
        return s.ai_minutes * 60.0 if s.ai_limit else None

    def stop_ai(self, sid: int, item: str = "") -> bool:
        """Stop waiting for one AI request (Home Assistant may still finish it; the
        answer isn't used). False when nothing is running for it."""
        with self._ai_lock:
            ev = self._ai_cancel.get((sid, item))
        if ev is None:
            return False
        ev.set()
        return True

    def _ai_begin(self, key: tuple[int, str]) -> None:  # with _ai_lock held
        self._ai_started[key] = time.time()
        self._ai_cancel[key] = threading.Event()

    def _ai_end(self, key: tuple[int, str]) -> None:  # with _ai_lock held
        self._ai_started.pop(key, None)
        self._ai_cancel.pop(key, None)

    def _ask_ai(
        self, sid: int, step: str, entity: str, instructions: str, structure: dict[str, Any],
        task_name: str, key: tuple[int, str] | None = None,
    ) -> Any:  # fmt: skip
        """One AI Task call, with one log line: how long it took and how many characters
        were sent (instructions + the answer's structure), whether it answered or not."""
        sent = len(instructions) + len(json.dumps(structure))
        started = time.monotonic()
        with self._ai_lock:
            self._ai_local.cancel = self._ai_cancel.get(key or (sid, ""))
        self._ai_local.timeout = self.ai_timeout()
        try:
            data = self.ai_fn(entity, instructions, structure, task_name)
        except Exception as ex:
            print(f"ai call @{sid} {step}: failed after {time.monotonic() - started:.0f} s, "
                  f"{sent} chars sent: {type(ex).__name__}",
                  file=sys.stderr, flush=True)  # fmt: skip
            raise
        print(f"ai call @{sid} {step}: answered in {time.monotonic() - started:.0f} s, "
              f"{sent} chars sent",
              file=sys.stderr, flush=True)  # fmt: skip
        return data

    def explain(self, sid: int) -> bool:
        """Ask the AI Task entity about one stored scan, in the background. One request
        per scan at a time. Only the report's ai_brief is sent (report.ai)."""
        if not self.ai_entity:
            return False
        with self._ai_lock:
            if self._ai.get(sid, ("", ""))[0] == "running":
                return True
            self._ai[sid] = ("running", "")
            self._ai_begin((sid, ""))
        report = self.store.report(sid)
        size = self.settings.ai_size

        def run() -> None:
            try:
                readings = self.store.item_explanations(sid)
                shown = (self.shown_report(sid) or {}).get("readings")
                instructions, structure, _ids = report_ai.build_request(report, readings, shown)
                data = self._ask_ai(sid, "explain this app", self.ai_entity, instructions,
                                    structure, report_ai.TASK_NAME)  # fmt: skip
                accepted = report_ai.accept(report, data, readings)
                if not accepted["summary"] and not accepted["findings"]:
                    raise supervisor.SupervisorError("the answer had no usable text")
                # (0.15) "AI inferred": in the read-code mode, one more request with the
                # README passages and docstrings the scan stored. Its failure never costs
                # the explanation above; the page says it didn't answer.
                if self.ai_mode == "deep" and ai_words.wanted(report, size):
                    started = time.monotonic()
                    try:
                        instructions, structure = ai_words.build_request(report, size)
                        said = self._ask_ai(
                            sid, "developer's words", self.ai_entity, instructions, structure,
                            ai_words.TASK_NAME,
                        )  # fmt: skip
                        accepted["words"] = ai_words.accept(report, said, size)
                        w = accepted["words"]
                        print(f"explain @{sid} developer's words "
                              f"({time.monotonic() - started:.0f} s): {len(w['says'])} "
                              f"sentence(s), {len(w['dropped'])} dropped "
                              f"{sorted(set(w['dropped']))}",
                              file=sys.stderr, flush=True)  # fmt: skip
                    except Exception as ex:
                        why = f"{type(ex).__name__}: {ex}"
                        accepted["words"] = {"says": [], "dropped": [],
                                             "failed": ai_why(ex, self.ai_timeout())}  # fmt: skip
                        print(f"explain @{sid} developer's words failed: {why}",
                              file=sys.stderr, flush=True)  # fmt: skip
                self.store.save_explanation(sid, self.ai_entity, accepted)
                with self._ai_lock:
                    self._ai.pop(sid, None)
                    self._ai_end((sid, ""))
            except Exception as ex:  # shown on the page; never affects the scan
                print(f"explain @{sid} failed: {type(ex).__name__}: {ex}", file=sys.stderr)
                with self._ai_lock:
                    self._ai[sid] = ("failed", ai_why(ex, self.ai_timeout()))
                    self._ai_end((sid, ""))

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
            self._ai_begin(key)
        entity = self.ai_entity

        def run() -> None:
            started = time.monotonic()
            try:
                # Round one: the stored snippet, and (integrations with stored source) a
                # menu of names the AI may ask to see. Round two, inside the same click,
                # only if it picked something from that menu. Never a third.
                snip = ai_context.snippet_of(report, item_id) or {}
                source = self.store.source(sid)
                entries = ai_context.menu(snip, source)
                instructions, structure = ai_context.build_request(report, item_id, entries)
                data = self._ask_ai(sid, f"{item_id} round 1", entity, instructions, structure,
                                    ai_context.TASK_NAME, key)  # fmt: skip
                accepted = ai_context.accept(report, item_id, data)
                picked, refused = ai_context.needs(data, entries)
                extra = (
                    context.more(snip, (source or {}).get("files") or {},
                                 [(m["file"], m["start"], m["end"]) for m in picked])
                    if picked
                    else None
                )  # fmt: skip
                if extra:
                    asked = [f"{m['file']}: {m['name']}" for m in picked]
                    with self._ai_lock:
                        self._ai_asked[key] = asked
                    try:
                        full = context.merged(snip, extra)
                        instructions, structure = ai_context.build_request(
                            report, item_id, snip=full
                        )
                        again = self._ask_ai(sid, f"{item_id} round 2", entity, instructions,
                                             structure, ai_context.TASK_NAME, key)  # fmt: skip
                        # Both readings count: the first one's checked statements stay
                        # (they cite code that was sent both times).
                        accepted = ai_context.combine(
                            accepted, ai_context.accept(report, item_id, again, snip=full)
                        )
                    except Exception as ex:  # the first answer stands; the page says why
                        accepted["second_failed"] = ai_reason(ex)
                    accepted["asked"] = asked
                    accepted["more"] = extra
                if refused:
                    accepted["refused"] = len(refused)
                    accepted["refused_asks"] = refused
                self.store.save_item_explanation(sid, item_id, entity, accepted)
                print(f"explain @{sid} {item_id} ({time.monotonic() - started:.0f} s, "
                      f"{2 if extra else 1} round(s), menu {len(entries)}, asked {len(picked)}, "
                      f"refused {len(refused)}{' ' + repr(refused) if refused else ''}): "
                      f"{len(accepted['claims'])} claim(s), "
                      f"{'a' if accepted.get('alignment') else 'no'} README opinion, "
                      f"{len(accepted['questions'])} question(s), {len(accepted['dropped'])} "
                      f"dropped {sorted(set(accepted['dropped']))}", file=sys.stderr,
                      flush=True)  # fmt: skip
                with self._ai_lock:
                    self._ai_items.pop(key, None)
                    self._ai_asked.pop(key, None)
                    self._ai_end(key)
            except Exception as ex:  # shown on the page; never affects the scan
                print(f"explain @{sid} {item_id} failed after {time.monotonic() - started:.0f} s: "
                      f"{type(ex).__name__}: {ex}",
                      file=sys.stderr, flush=True)  # fmt: skip
                with self._ai_lock:
                    self._ai_items[key] = ("failed", ai_why(ex, self.ai_timeout()))
                    self._ai_asked.pop(key, None)
                    self._ai_end(key)

        threading.Thread(target=run, name=f"explain-{sid}-{item_id}", daemon=True).start()
        return True

    def item_states(self, sid: int) -> dict[str, tuple[str, str]]:
        with self._ai_lock:
            return {item: st for (s, item), st in self._ai_items.items() if s == sid}

    def item_asked(self, sid: int) -> dict[str, list[str]]:
        """Items whose reading is in its second round, with what the AI asked to see."""
        with self._ai_lock:
            return {item: list(a) for (s, item), a in self._ai_asked.items() if s == sid}

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

    def jobs_now(self) -> list[Job]:
        """A copy of every job as it is now: the worker changes the live ones while a page
        is drawn."""
        return [replace(j, scan_ids=list(j.scan_ids)) for j in list(self.worker.jobs)]

    def busy(self, jobs: list[Job] | None = None) -> dict[str, str]:
        return {
            j.repo.lower(): j.state
            for j in reversed(jobs if jobs is not None else list(self.worker.jobs))
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

    def not_installed_scans(self, installed: set[str]) -> dict[str, ScanRow]:
        """Newest complete scan per repo of the apps that aren't installed (lower-case
        repo). A scan made with earlier rules still counts: an update of Barkley re-sniffs
        installed apps only, and an app sniffed from search must not vanish with it."""
        out: dict[str, ScanRow] = {}
        for r in self.store.history(limit=10000):
            if r.repo and r.complete and r.repo.lower() not in installed:
                out.setdefault(r.repo.lower(), r)
        return out

    def not_installed_html(
        self, base: str, installed: set[str], v: ui.View | None = None,
        jobs: list[Job] | None = None,
    ) -> str:  # fmt: skip
        """Cards for apps sniffed from search (or by name) that aren't installed."""
        v = v or ui.View()
        names = {c.repo.lower(): c.name for c in self.catalog()[0]} if self.catalog_fn else {}
        busy = self.busy(jobs)
        thinking = {a.repo.lower() for a in self.ai_running() if a.repo}
        tv = self.worker.tool_version
        cards = []
        for repo, scan in self.not_installed_scans(installed).items():
            stale = scan.tool_version != tv
            action = ""
            if stale and scan.repo and scan.ref:
                action = (
                    f'<form method=post action="{base}/scan">'
                    f'<input type=hidden name=token value="{self.token}">'
                    f'<input type=hidden name=back value="{v.qs()}">'
                    f'<input type=hidden name=repo value="{e(scan.repo)}">'
                    f'<input type=hidden name=ref value="{e(scan.ref)}">'
                    "<button>Sniff again</button></form>"
                )
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
                    ai=repo in thinking,
                    action=action,
                    stale=stale,
                )
            )
        if not cards:
            return ""
        cards.sort(key=ui._sort_key)
        return not_installed_cards_html(base, cards, v, self.token)

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

    def ai_since(self, sid: int) -> float:
        """When this scan's Explain this app started (0: it isn't running)."""
        with self._ai_lock:
            return self._ai_started.get((sid, ""), 0.0)

    def ai_running(self) -> list[AiRun]:
        """(0.15) Every AI request still waiting for its answer, oldest first, with the app
        it is about (for the list's cards and the status strip)."""
        with self._ai_lock:
            started = sorted(self._ai_started.items(), key=lambda kv: kv[1])
        out = []
        for (sid, item), since in started:
            row = self.store.get(sid)
            out.append(AiRun(sid, item, since, (row.repo or "") if row else ""))
        return out

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

    def shown_report(self, sid: int, show_minor: bool = False) -> dict[str, Any] | None:
        """The report as the panel shows it (shown.view): the readings added, minor items
        left out unless asked for. The stored report, the raw JSON link, the AI's input
        and diffs always use `report()`."""
        rep = self.report(sid)
        return self.view(rep, show_minor) if rep is not None else None

    def _inputs(self) -> _Inputs:
        """What a shown page depends on, read once and kept until the store records a
        write to any of it (Store.generation): a page with hundreds of rows read the
        settings for each row, 1,500 database opens on one render (3-4 s on a real box,
        0.14.0.1)."""
        gen = self.store.generation
        cached = self._cache
        if cached is not None and cached.generation == gen:
            return cached
        fresh = _Inputs(gen, settings_mod.load(self.store, self.start_settings))
        self._cache = fresh
        self._rows = {}
        return fresh

    @property
    def settings(self) -> settings_mod.Settings:
        return self._inputs().settings

    def listing(self, repo: Any) -> dict[str, str] | None:
        if self.listings is None or not isinstance(repo, str) or not repo:
            return None
        return self.listings.get(repo)

    def view(self, rep: dict[str, Any], show_minor: bool = False) -> dict[str, Any]:
        s = self._inputs().settings
        return shown_mod.view(rep, network=s.network, show_minor=show_minor,
                              always=s.show_minor, quiet_months=s.quiet_months,
                              build_tool=float(s.build_tool_points))  # fmt: skip

    def overlay_rows(self, rows: list[ScanRow]) -> list[ScanRow]:
        """Index rows with their readings (Store.overlay), from the store's findings index:
        no report is parsed. Kept until an input changes."""
        network = self._inputs().settings.network
        build_tool = float(self._inputs().settings.build_tool_points)
        got = {r.id: self._rows[r.id] for r in rows if r.id in self._rows}
        missing = [r.id for r in rows if r.id not in got]
        if missing:
            found = self.store.findings_index(missing)
            for r in rows:
                if r.id in found and r.id not in got:
                    idx = {"findings": found[r.id], "complete": r.complete,
                           "exposure": r.exposure}  # fmt: skip
                    got[r.id] = readings.compute(idx, network, build_tool).to_dict()
            if len(self._rows) < 20000:
                self._rows.update(got)
        return [replace(r, readings=got.get(r.id)) for r in rows]

    def save_settings(self, raw: dict[str, str]) -> None:
        """The Settings page's one form. Every value is checked; one that isn't valid
        keeps what was there. The AI entity and notify target must be ones HA offers."""
        old = self.settings
        new = settings_mod.from_dict(raw, old)
        # (0.15) a new size brings its paired minutes, unless the minutes were edited too
        if new.ai_size != old.ai_size and new.ai_minutes == old.ai_minutes:
            new = replace(new, ai_minutes=settings_mod.AI_PAIRED_MINUTES[new.ai_size])
        settings_mod.save(self.store, new)
        self.worker.exposure = new.exposure
        self.worker.parallel = new.parallel
        if self.watcher is not None:
            on = raw.get("auto_scan")
            if on in ("on", "off") and (on == "on") != self.watcher.enabled:
                self.watcher.set_enabled(on == "on")
            target = raw.get("notify_target")
            if target is not None and target != self.watcher.notify_target:
                self.watcher.set_target(target[:100])
        entity = raw.get("ai_entity")
        if entity is not None and entity != self.ai_entity:
            choices, _err = self.ai_choices(refresh=True)
            if not entity or (choices and entity in {c[0] for c in choices}):
                self.store.set_setting("ai_entity", entity or "off")
                self.ai_entity = entity
        if raw.get("ai_mode") in AI_MODES:
            self.store.set_setting("ai_mode", raw["ai_mode"])
            self.ai_mode = raw["ai_mode"]
        print(f"settings saved in the panel: {settings_mod.describe(new)}", file=sys.stderr,
              flush=True)  # fmt: skip

    def reset_settings(self, part: str) -> None:
        # the starting values: Barkley's defaults with the app's options (or BARKLEY_*)
        s, d = self.settings, self.start_settings
        names = settings_mod.PARTS.get(part, ())
        new = replace(s, **{n: getattr(d, n) for n in names})
        settings_mod.save(self.store, new)
        self.worker.exposure = new.exposure
        self.worker.parallel = new.parallel
        if part == "checking":
            if self.watcher is not None:
                self.watcher.set_enabled(True)
            self.store.set_setting("ai_mode", AI_MODE_DEFAULT)
            self.ai_mode = AI_MODE_DEFAULT

    def rows(
        self, refresh: bool = False, jobs: list[Job] | None = None
    ) -> tuple[InstalledState, list[Row]]:
        if self.installed_fn is None:
            return InstalledState(error="not running as a Home Assistant add-on"), []
        st = self.installed(refresh)
        tv = self.worker.tool_version
        rows = classify(st.items, self.store, self.diff, tv) if not st.error else []
        busy = self.busy(jobs)
        thinking = {a.repo.lower() for a in self.ai_running() if a.repo}
        for r in rows:
            r.busy = busy.get(r.item.repo.lower(), "")
            r.ai = r.item.repo.lower() in thinking
        return st, rows

    def row_for(self, repo: str | None) -> Row | None:
        if not repo or self.installed_fn is None:
            return None
        _, rows = self.rows()
        return next((r for r in rows if r.item.repo.lower() == repo.lower()), None)

    def installed_html(
        self, base: str, refresh: bool = False, v: ui.View | None = None,
        jobs: list[Job] | None = None,
    ) -> str:  # fmt: skip
        if self.installed_fn is None:
            return ""
        st, rows = self.rows(refresh, jobs)
        html = render_installed(base, st, rows, self.token, self.shown_report, v, self.listing)
        if not st.error:
            html += self.not_installed_html(base, {r.item.repo.lower() for r in rows}, v, jobs)
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
                self,
                status: int,
                body: bytes,
                ctype: str = "text/html",
                cache: str = "no-store",
                cookies: tuple[str, ...] = (),
            ) -> None:
                self.send_response(status)
                for c in cookies:
                    self.send_header("Set-Cookie", c)
                charset = "" if ctype.startswith("font/") else "; charset=utf-8"
                self.send_header("Content-Type", f"{ctype}{charset}")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Security-Policy", panel.csp)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Cache-Control", cache)
                self.end_headers()
                self.wfile.write(body)

            def _text(self, status: int, msg: str) -> None:
                self._send(status, _page("Barkley", f"<p>{e(msg)}</p>", self._base()))

            def _redirect(self, to: str, cookies: tuple[str, ...] = ()) -> None:
                self._see_other(local_path(to), cookies)

            def _see_other(self, location: str, cookies: tuple[str, ...] = ()) -> None:
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", location)
                for c in cookies:
                    self.send_header("Set-Cookie", c)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _session(self) -> login.Session | None:
                if panel.login is None:
                    return None
                return panel.login.session(
                    login.read_cookie(self.headers.get("Cookie"), login.SESSION_COOKIE)
                )

            def _allowed(self) -> bool:
                if panel.allow is not None and self.client_address[0] not in panel.allow:
                    self._text(HTTPStatus.FORBIDDEN, "Barkley only opens through Home Assistant.")
                    return False
                lg = panel.login
                if lg is None:
                    return True
                path = urllib.parse.urlsplit(self.path).path
                if self.command == "GET" and (
                    path in ("/login", login.CALLBACK_PATH) or path.startswith("/fonts/")
                ):
                    return True
                if self._session() is not None:
                    return True
                if self.command == "GET":
                    self._send(HTTPStatus.UNAUTHORIZED, render_login(first=self._first()))
                else:
                    self._text(HTTPStatus.FORBIDDEN, "log in first")
                return False

            def _sid(self) -> str:
                return login.read_cookie(self.headers.get("Cookie"), login.SESSION_COOKIE)

            def _first(self) -> bool:
                """Standalone with no Home Assistant token yet: the login makes one."""
                return panel.standalone and not ha_token.source()

            def _login_routes(self, url: urllib.parse.SplitResult) -> bool:
                """/login and the way back from HA; True when one of them answered."""
                lg = panel.login
                if lg is None or url.path not in ("/login", login.CALLBACK_PATH):
                    return False
                if url.path == "/login":
                    # The one redirect off this panel: HA's login page, built from the
                    # configured URL, a fixed path and url-encoded values (login.ha_login_url).
                    # (0.14.0) "for=token|setup" (Create token) only from a logged-in
                    # session; the first login makes the token while there is none.
                    q = urllib.parse.parse_qs(url.query)
                    asked = (q.get("for") or [""])[0]
                    purpose = ""
                    if asked in login.MAKES_TOKEN and self._session():
                        purpose = asked
                    elif self._first():
                        purpose = login.FIRST  # held for the setup's first step
                    state, to = lg.start(purpose)
                    keep = lg.cookie(login.STATE_COOKIE, state, login.STATE_SECONDS)
                    self._see_other(login.ha_login_url(lg.ha_url, to), (keep,))
                    return True
                q = urllib.parse.parse_qs(url.query)
                got = lambda k: (q.get(k) or [""])[0][:1024]  # noqa: E731
                gone = lg.cookie(login.STATE_COOKIE, "", 0)
                purpose = lg.purpose(got("state"))
                made = purpose in login.MAKES_TOKEN
                try:
                    sid, s = lg.finish(got("code"), got("state"),
                                       login.read_cookie(self.headers.get("Cookie"),
                                                         login.STATE_COOKIE))  # fmt: skip
                except login.LoginError as ex:
                    print(f"login refused ({self.client_address[0]}): {ex}", file=sys.stderr)
                    self._send(HTTPStatus.FORBIDDEN, render_login(str(ex), self._first()),
                               cookies=(gone,))  # fmt: skip
                    return True
                did = ""
                if made:
                    did = (f"; {s.token_error}" if s.token_error
                           else " and created Barkley's token")  # fmt: skip
                print(f"login: {s.user} ({s.user_id[:8]}) logged in{did}", file=sys.stderr)
                if purpose == "setup":
                    to = "/setup" + ("?bad=create" if s.token_error else "")
                elif purpose == login.FIRST:
                    to = "/setup"
                elif made:
                    to = "/settings?" + ("bad=create" if s.token_error else "saved=1") + "#ha-token"
                else:
                    to = "/"
                self._redirect(to, (gone, lg.cookie(login.SESSION_COOKIE, sid,
                                                    login.SESSION_SECONDS)))  # fmt: skip
                return True

            def do_GET(self) -> None:
                if not self._allowed():
                    return
                url = urllib.parse.urlsplit(self.path)
                base = self._base()
                if self._login_routes(url):
                    return
                try:
                    if url.path in ("", "/"):
                        # (0.15, his report) one copy of every job's state for the whole page:
                        # the cards, the status box and the reload must agree, or a scan that
                        # ends while the page is drawn leaves a card on "checking…" for good
                        jobs = panel.jobs_now()
                        q = urllib.parse.parse_qs(url.query)
                        refresh = q.get("refresh") == ["1"]
                        v = ui.View.parse(q, panel.store.setting("view") or "cards")
                        if q.get("view") and v.view != panel.store.setting("view"):
                            panel.store.set_setting("view", v.view)  # remembered for next time
                        auto = ""  # (0.14.0) auto-sniff lives on Settings
                        thinking = panel.ai_running()
                        body = render_index(
                            base, panel.store, jobs, panel.token,
                            panel.installed_html(base, refresh, v, jobs), panel.worker._mem(),
                            panel.worker.github_wait, panel.worker.ha_fn(),
                            panel.worker.parallel, panel.catalog_fn is not None,
                            status_html(base, jobs, panel.names(), v.qs(), ai=thinking),
                            v.qs(), auto,
                            render_account(base, s.user, panel.token)
                            if (s := self._session()) else "",
                            _token_banner(base, panel),
                            ai_busy=bool(thinking),
                            cpu_gap=panel.cpu_gap,
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
                        q = urllib.parse.parse_qs(url.query)
                        report = panel.view(report, show_minor=(q.get("minor") or [""])[0] == "1")
                        row = panel.row_for(report.get("target", {}).get("repo"))
                        state, err = panel.ai_state(sid)
                        choices, choices_err = panel.ai_choices()
                        open_item = (q.get("open") or [""])[0]
                        if not re.fullmatch(r"[0-9a-f]{16}", open_item):
                            open_item = ""
                        page = render_scan(
                            base, sid, report, panel.store, row, panel.token,
                            panel.ai_entity, state, err, choices, choices_err,
                            panel.ai_mode, panel.item_states(sid), open_item,
                            item_asked=panel.item_asked(sid),
                            listing=panel.listing(report.get("target", {}).get("repo")),
                            ai_since=panel.ai_since(sid),
                            jobs=panel.jobs_now(),
                            rechecking=any(
                                j.kind == "recheck" and j.scan == sid
                                and j.state in ("queued", "running", "waiting")
                                for j in list(panel.worker.jobs)
                            ),
                            full=(q.get("all") or [""])[0] == "1",
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
                            return self._text(HTTPStatus.BAD_REQUEST, "Give the app as owner/repo.")
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
                    if url.path == "/setup" and panel.standalone:
                        q = urllib.parse.parse_qs(url.query)
                        bad = (q.get("bad") or [""])[0]
                        sess = self._session()
                        late = sess.token_error if sess is not None and bad == "create" else ""
                        err = panel.setup_errors.pop(self._sid(), "") or late
                        held = bool(panel.login and panel.login.held(self._sid()))
                        return self._send(200, render_setup(
                            base, panel.store, panel.token, (q.get("step") or [""])[0], held=held,
                            period=panel.settings.token_days,
                            github_source=settings_mod.token_source(panel.store.path),
                            error=err, bad=bad, saved="saved" in q))  # fmt: skip
                    if url.path == "/settings":
                        q = urllib.parse.parse_qs(url.query)
                        choices, _cerr = (panel.ai_choices() if panel.entities_fn is not None
                                          else (None, ""))  # fmt: skip
                        ext = (supervisor.external_url_set() if panel.installed_fn is not None
                               else None)  # fmt: skip
                        return self._send(200, render_settings(
                            base, panel.settings, panel.token, ai_entity=panel.ai_entity,
                            ai_mode=panel.ai_mode, ai_choices=choices, watcher=panel.watcher,
                            token_source=settings_mod.token_source(panel.store.path),
                            external=ext, saved="saved" in q,
                            bad=(q.get("bad") or [""])[0],
                            bad_detail=(self._session() or login.Session("", "", 0)).token_error,
                            mem=panel.memory_fn(),
                            defaults=panel.start_settings,
                            store_mb=panel.store.size_bytes() / (1024 * 1024),
                            ha_token_html=ha_token_block(base, panel.store,
                                                         panel.settings.token_days, panel.token)
                            if panel.standalone else ""))  # fmt: skip
                    if url.path == "/doctor":
                        # Never waits for the tools: the run goes on in its own thread.
                        doctor.memory_floor = panel.settings.memory_floor_mb * 1024 * 1024
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
                        rds = tuple(
                            (panel.shown_report(i) or {}).get("readings") for i in (old, new)
                        )
                        return self._send(
                            200,
                            render_diff(base, old, new, d, name, again, rds),  # type: ignore[arg-type]
                        )
                except StoreError as ex:
                    return self._text(HTTPStatus.NOT_FOUND, str(ex))
                except (KeyError, ValueError):
                    return self._text(HTTPStatus.BAD_REQUEST, BAD_REQUEST)
                self._text(HTTPStatus.NOT_FOUND, "nothing to sniff here")

            def do_POST(self) -> None:
                if not self._allowed():
                    return
                size = int(self.headers.get("Content-Length") or 0)
                if size > 4096:
                    return self._text(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "That form is too large."
                    )
                form = urllib.parse.parse_qs(self.rfile.read(size).decode("utf-8", "replace"))
                get = lambda k: (form.get(k) or [""])[0].strip()  # noqa: E731
                if not secrets.compare_digest(get("token"), panel.token):
                    return self._text(
                        HTTPStatus.FORBIDDEN, "This page is out of date. Reload it and try again."
                    )
                path = urllib.parse.urlsplit(self.path).path
                if path == "/logout" and panel.login is not None:
                    panel.login.logout(
                        login.read_cookie(self.headers.get("Cookie"), login.SESSION_COOKIE)
                    )
                    gone = panel.login.cookie(login.SESSION_COOKIE, "", 0)
                    return self._send(200, render_login("You're logged out."), cookies=(gone,))
                # Back to the same filter, view and page (rebuilt from known values only)
                v = ui.View.parse(urllib.parse.parse_qs(get("back")[:200]))
                home = f"{self._base()}/?{v.qs('&')}" if get("back") else f"{self._base()}/"
                if path in ("/auto-scan", "/notify-target", "/notify-test"):
                    w = panel.watcher
                    if w is None:
                        return self._text(
                            HTTPStatus.BAD_REQUEST,
                            "Auto-sniff only works when Barkley runs as a Home Assistant app.",
                        )
                    if path == "/auto-scan":
                        w.set_enabled(get("on") == "1")
                    elif path == "/notify-target":
                        if not w.set_target(get("target")[:100]):
                            return self._text(HTTPStatus.BAD_REQUEST,
                                              "not one of the notify targets Home Assistant "
                                              "offers")  # fmt: skip
                    else:
                        w.notify_test()
                    return self._redirect(f"{self._base()}/settings")
                if path == "/settings":
                    panel.save_settings({k: v[0] for k, v in form.items() if v})
                    return self._redirect(f"{self._base()}/settings?saved=1")
                if path == "/settings-reset":
                    panel.reset_settings(get("part"))
                    return self._redirect(f"{self._base()}/settings?saved=1")
                if path == "/setup/next":
                    # the end of the setup's Home Assistant step: let go of the first login
                    if panel.login is not None:
                        panel.login.release(self._sid())
                    return self._redirect(f"{self._base()}/setup?step=github")
                if path == "/github-token":
                    page = ("/setup?step=github&" if get("back") == "setup"
                            else "/settings?")  # fmt: skip
                    if get("remove") == "1":
                        settings_mod.remove_token(panel.store.path, panel.option_token)
                    elif not settings_mod.set_token(panel.store.path, get("value")):
                        return self._redirect(f"{self._base()}{page}bad=token")
                    return self._redirect(f"{self._base()}{page}saved=1")
                if path.startswith("/ha-token"):
                    if not panel.standalone:
                        return self._text(
                            HTTPStatus.BAD_REQUEST,
                            "This only works when Barkley runs on its own, outside Home Assistant.",
                        )
                    setup = get("back") == "setup"
                    page = "/setup?" if setup else "/settings?"
                    if path == "/ha-token/create":
                        if panel.login is None:
                            return self._redirect(f"{self._base()}{page}bad=nologin")
                        lg = panel.login
                        access = lg.held(self._sid()) if setup else ""
                        if access and lg.token_fn is not None:
                            # the first login, still held: no second login needed
                            try:
                                lg.token_fn(access)
                            except supervisor.SupervisorError as ex:
                                why = f"Barkley couldn't create its token ({ex})."
                                print(f"setup: {why}", file=sys.stderr)
                                panel.setup_errors[self._sid()] = why[:300]
                                return self._redirect(f"{self._base()}/setup?bad=create")
                            lg.release(self._sid())
                            print("setup: created Barkley's token", file=sys.stderr)
                            return self._redirect(f"{self._base()}/setup?saved=1")
                        return self._redirect(f"{self._base()}/login?for="
                                              + ("setup" if setup else "token"))  # fmt: skip
                    if path == "/ha-token/rotate":
                        why = ha_token.rotate(panel.store, panel.settings.token_days)
                        return self._redirect(f"{self._base()}/settings?"
                                              + ("bad=rotate" if why else "saved=1"))  # fmt: skip
                    if path == "/ha-token":
                        try:
                            ha_token.adopt(panel.store, get("value"), "pasted")
                        except supervisor.SupervisorError as ex:
                            print(f"pasted Home Assistant token refused: {ex}", file=sys.stderr)
                            return self._redirect(f"{self._base()}{page}bad=hatoken")
                        print("Home Assistant token: pasted in the panel", file=sys.stderr)
                        if panel.login is not None:
                            panel.login.release(self._sid())
                        return self._redirect(f"{self._base()}{page}saved=1")
                    return self._text(HTTPStatus.NOT_FOUND, "nothing here")
                if path == "/sniff-all-again":
                    st = panel.installed()
                    busy = panel.busy()
                    for it in st.items:
                        if it.repo.lower() not in busy:
                            panel.worker.submit("scan", it.repo, it.installed)
                    return self._redirect(home)
                if path == "/not-installed-again":
                    # the apps sniffed from search whose newest scan has earlier rules
                    here = {it.repo.lower() for it in panel.installed().items}
                    busy = panel.busy()
                    tv = panel.worker.tool_version
                    for repo, row in panel.not_installed_scans(here).items():
                        if row.tool_version != tv and repo not in busy and row.repo and row.ref:
                            panel.worker.submit("scan", row.repo, row.ref)
                    return self._redirect(f"{home}#not-installed")
                if path == "/recheck":
                    if not get("scan").isdigit():
                        return self._text(HTTPStatus.BAD_REQUEST, BAD_REQUEST)
                    sid = int(get("scan"))
                    row = panel.store.get(sid)
                    if row is None or not row.repo:
                        return self._text(HTTPStatus.NOT_FOUND, f"There's no stored scan @{sid}.")
                    panel.worker.submit("recheck", row.repo, row.ref, scan=sid)
                    return self._redirect(f"{self._base()}/scan/{sid}")
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
                        return self._text(HTTPStatus.BAD_REQUEST, BAD_REQUEST)
                    sid = int(get("scan"))
                    try:
                        if not panel.explain_item(sid, item):
                            return self._text(
                                HTTPStatus.BAD_REQUEST,
                                "Explain and read code is off, or Barkley has no code for "
                                "this item.",
                            )
                    except StoreError as ex:
                        return self._text(HTTPStatus.NOT_FOUND, str(ex))
                    return self._redirect(f"{self._base()}/scan/{sid}?open={item}#ai-{item}")
                if path == "/ai-stop":  # (0.15) Stop waiting for an AI answer
                    item = get("item")
                    if not get("scan").isdigit() or (
                        item and not re.fullmatch(r"[0-9a-f]{16}", item)
                    ):
                        return self._text(HTTPStatus.BAD_REQUEST, BAD_REQUEST)
                    sid = int(get("scan"))
                    panel.stop_ai(sid, item)
                    to = f"/scan/{sid}?open={item}#ai-{item}" if item else f"/scan/{sid}"
                    return self._redirect(f"{self._base()}{to}")
                if path == "/explain":
                    if not get("scan").isdigit() or not panel.ai_entity:
                        return self._text(
                            HTTPStatus.BAD_REQUEST, "No AI Task entity is chosen yet."
                        )
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
                              if r.tool_version == tv and r.complete}  # fmt: skip
                    busy = panel.busy()  # a second click queues nothing twice
                    for it in st.items:
                        if it.repo.lower() in busy:
                            continue
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
                    return self._text(
                        HTTPStatus.BAD_REQUEST, "Give the app as owner/repo, with a tag."
                    )
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
    allow: set[str] | None,
    *,
    exposure: str = "local",
    ha_fn: Callable[[], str | None] = lambda: None,
    installed_fn: InstalledFn | None = None,
    memory_fn: Callable[[], memory.Memory] = memory.check,
    budget_fn: Callable[[], RateLimit | None] = lambda: None,
    ai_entity: str = "",
    ai_fn: AiFn | None = None,
    ai_mode: str = AI_MODE_DEFAULT,
    parallel: int = 1,
    catalog_fn: CatalogFn | None = None,
    entities_fn: EntitiesFn | None = None,
    releases_fn: ReleasesFn | None = None,
    watcher: watch.Watcher | None = None,
    login_cfg: login.Login | None = None,
    tool_version: str = __version__,
) -> PanelServer:
    """Build the server (caller runs `serve_forever`); `.panel.worker` runs the scans.
    `tool_version`: the key a stored scan must have to be reused (logic.key(), 0.14.1).
    `watcher`: auto-sniff; built by the caller with the worker from `make_worker`.
    `allow`: client addresses let in (None: any). `login_cfg`: standalone, every page
    but the login needs a session."""
    global CURRENT_RULES
    CURRENT_RULES = tool_version
    worker = Worker(
        store, scan_fn, exposure=exposure, ha_fn=ha_fn, memory_fn=memory_fn,
        budget_fn=budget_fn, parallel=parallel, tool_version=tool_version,
    )  # fmt: skip
    panel = Panel(store, worker, allow, installed_fn, memory_fn)
    worker.memory_gb_fn = lambda: panel.settings.memory_gb
    worker.floor_fn = lambda: panel.settings.memory_floor_mb * 1024 * 1024
    panel.login = login_cfg
    # (0.15, #18) checked once: a VM's CPU type only changes with a full stop and start
    panel.cpu_gap = cpu.missing_v2()
    if panel.cpu_gap:
        print(f"CPU: missing {', '.join(panel.cpu_gap)}. {cpu.FIX}", file=sys.stderr)
    if login_cfg is not None:
        panel.csp = csp_with_login(login_cfg.ha_url)
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
    start_mode = ai_mode if ai_mode in AI_MODES else AI_MODE_DEFAULT
    panel.ai_mode = stored_mode if stored_mode in AI_MODES else start_mode
    panel.catalog_fn = catalog_fn
    panel.entities_fn = entities_fn
    panel.releases_fn = releases_fn
    if ai_fn is not None:
        panel.ai_fn = ai_fn
    if watcher is not None:
        panel.watcher = watcher
        watcher.worker = worker
        watcher.on_list = panel.set_installed
        watcher.view_fn = panel.view
        watcher.notify_when_fn = lambda: panel.settings.notify_when
        watcher.keep_versions_fn = lambda: panel.settings.keep_versions
        worker.on_done.append(watcher.on_job_done)
    httpd = PanelServer((host, port), panel.handler())
    httpd.panel = panel
    return httpd
