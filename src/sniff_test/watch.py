"""Auto-sniff: watch the Marketplace for installs and updates, scan what landed, notify.

How an install is noticed (verified in Core's source at HA 2026.11.0 and on the user's box):
the Marketplace sends `marketplace_repository_install_progress` events while it installs,
the last one `progress: false` when the install ended (success or failure). No event
carries the version, so the watcher then reads the installed list (one websocket round
trip) and compares it with the snapshot it keeps in the store: a repo that wasn't there
is an install, a changed version is an update. The same comparison runs at start (what
changed while Barkley was stopped) and every `POLL` seconds as a fallback, so a missed
event or an older HA without `marketplace/subscribe` still gets its scans.

What it scans: exactly the version that landed (`Installed.installed`), never the newest
release. A stored scan of that version (for example one sniffed from search before the
install) is reused. For an update the stored scan of the version before is the diff's
old side; it is scanned if there is none.

Timing, said plainly in the panel and DOCS: since HA 2026.11 a *new* integration runs as
soon as it's installed (the frontend opens its config flow at once, which imports its
code), so for a new install the auto-sniff comes after the code ran once; the protection
for a new install is sniffing it from search first. An update's code waits for a restart,
so its sniff and diff come before it runs. Barkley reports; it never moves, refuses or
blocks anything (user decision 2026-11-10).

Notifications go through HA's own services (persistent_notification always, an optional
notify.<target>). Their text is built from validated repo names and versions, scores,
verdicts and the fixed titles of rules: never from scanned text (README, code, evidence).

A restart in the middle of a sniff (an app rebuild, a host reboot) can't lose the change:
the snapshot is written as soon as the list is read, so the next start wouldn't see the
change again, and the worker's queue only lives in memory. Every change whose job hasn't
ended is also kept in the store (`PENDING_KEY`) and re-queued at start when the app is
still installed at that version (seen on the user's box 2026-11-11: an update was noticed
7 minutes before a rebuild, and nothing said whether its sniff had finished).

Age-out: scans of apps that aren't installed are deleted after `AGE_OUT_DAYS`; a scan of
anything installed (at any version) is never deleted, and nothing is deleted while the
installed list can't be read.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from sniff_test import supervisor
from sniff_test.diff import HEADLINE_RANK
from sniff_test.diff import diff as diff_reports
from sniff_test.report import explain
from sniff_test.scoring import VERDICTS
from sniff_test.store import Store, StoreError
from sniff_test.supervisor import Installed, SupervisorError

SNAPSHOT_KEY = "installed_snapshot"  # settings: the installed list as last seen
LOG_KEY = "auto_log"  # settings: recent auto-sniffs (bounded)
PENDING_KEY = "auto_pending"  # settings: changes whose auto job hasn't ended (survives a restart)
AGE_OUT_DAYS = 7
POLL = 600  # seconds between fallback reads of the installed list
SWEEP_EVERY = 24 * 3600
SETTLE = 3  # seconds after the Marketplace says an install ended, before the list is read
_LOG_KEPT = 20
_PENDING_KEPT = 20
_RECONNECT = 10  # seconds; doubles up to POLL while the subscription keeps failing

_VERDICT = {v.key: (v.label, v.emoji) for _, v in VERDICTS}
_KIND = {"integration": "Integration", "card": "Card", "plugin": "Card"}
_GROUP = {  # diff.py's summary buckets, in fixed plain words (singular, plural)
    "findings": ("finding", "findings"),
    "flows": ("data flow", "data flows"),
    "data": ("kind of private data read", "kinds of private data read"),
    "hosts": ("site", "sites"),
    "packages": ("package", "packages"),
    "hooks": ("hook into Home Assistant", "hooks into Home Assistant"),
    "repo": ("publisher or repository change", "publisher or repository changes"),
    "coverage": ("change in what could be checked", "changes in what could be checked"),
}
_NO_SIGN = {"repo", "coverage"}  # already say "change"
_SIGN = {"+": "new", "-": "removed", "~": "changed"}

InstalledFn = Callable[[], tuple[list[Installed], dict[str, int]]]


@dataclass(frozen=True, slots=True)
class Change:
    action: str  # install | update | available (an update the Marketplace offers)
    repo: str
    kind: str
    version: str  # what landed; for "available", the offered version
    previous: str | None = None  # the version before; for "available", the installed one


def _now_iso(now: float) -> str:
    return datetime.fromtimestamp(now, UTC).isoformat(timespec="seconds")


def _did(c: Change) -> str:
    if c.action == "available":
        return f"has an update waiting {c.previous} → {c.version}"
    return f"updated {c.previous} → {c.version}" if c.previous else f"installed {c.version}"


def snapshot_changes(old: dict[str, Any] | None, new: dict[str, Any]) -> list[Change]:
    """Installs, updates and newly offered updates between two snapshots
    ({lower repo: {repo, kind, version, available}}). An offered update ("available",
    user request 2026-11-12) is sniffed before it is installed, so the heads-up comes
    first; a snapshot from before 0.7.8 has no `available`, so every update waiting at that
    moment counts as newly offered once."""
    if old is None:
        return []
    out = []
    for key, cur in new.items():
        prev = old.get(key)
        if not isinstance(prev, dict):
            out.append(Change("install", cur["repo"], cur["kind"], cur["version"]))
            continue
        if prev.get("version") != cur["version"]:
            out.append(Change("update", cur["repo"], cur["kind"], cur["version"],
                              str(prev.get("version") or "")))  # fmt: skip
        offered = cur.get("available") or ""
        if offered and offered != cur["version"] and offered != (prev.get("available") or ""):
            out.append(Change("available", cur["repo"], cur["kind"], offered, cur["version"]))
    return out


def snapshot_of(items: Iterable[Installed]) -> dict[str, dict[str, str]]:
    return {
        it.repo.lower(): {"repo": it.repo, "kind": it.kind, "version": it.installed,
                          "available": it.available}
        for it in items
    }  # fmt: skip


def matters(signal: str, data: dict[str, Any]) -> bool:
    """Which events make the watcher read the list again: an install that ended (an
    update is an install too), or an uninstall. The Marketplace's own refreshes send
    `action: update` for every installed repo, so those are ignored."""
    if signal == supervisor.SIGNAL_INSTALL_PROGRESS:
        return data.get("progress") is False
    if signal == supervisor.SIGNAL_REPOSITORY:
        return data.get("action") == "uninstall"
    return False


def top_titles(report: dict[str, Any], limit: int = 3) -> list[str]:
    """Fixed rule titles of the most serious finding groups (never evidence text)."""
    order = {"critical": 0, "high": 1, "medium": 2}
    seen: list[tuple[int, str]] = []
    for f in report.get("findings", []):
        sev = str(f.get("severity"))
        if sev not in order:
            continue
        title = explain.explain(str(f.get("rule_id"))).title
        if (order[sev], title) not in seen:
            seen.append((order[sev], title))
    seen.sort(key=lambda s: s[0])
    return [t for _, t in seen[:limit]]


def change_summary(d: dict[str, Any]) -> str:
    """Headline changes of an update diff as counts per group, in fixed words."""
    counts: dict[tuple[str, str], int] = {}
    for c in d.get("changes", []):
        if c.get("rank", 0) < HEADLINE_RANK:
            continue
        group = str(c.get("group"))
        sign = "" if group in _NO_SIGN else _SIGN.get(str(c.get("sign")), "changed")
        counts[(sign, group)] = counts.get((sign, group), 0) + 1
    parts = []
    for (sign, group), n in counts.items():
        one, many = _GROUP.get(group, ("change", "changes"))
        parts.append(f"{n} {sign + ' ' if sign else ''}{one if n == 1 else many}")
    return ", ".join(parts)


def notification(
    entry: dict[str, Any], report: dict[str, Any], d: dict[str, Any] | None, panel: str
) -> tuple[str, str, str]:
    """(title, markdown message, plain message) for one auto-sniffed install or update.
    Every piece is validated or fixed text; nothing comes from the scanned repo."""
    repo, ver, prev = entry["repo"], entry["version"], entry.get("previous")
    kind = _KIND.get(str(entry.get("kind")), "App")
    label, emoji = _VERDICT.get(str(report.get("verdict", {}).get("key")), ("?", ""))
    score = int(report.get("score", 0))
    offered = entry.get("action") == "available"
    if offered:
        did = f"has an update waiting, {prev} → {ver}, sniffed before you install it"
    else:
        did = (
            f"was updated from {prev} to {ver} and sniffed"
            if prev
            else f"{ver} was installed and sniffed"
        )
    lines = [f"{kind} {repo} {did}: {emoji} {label}, {score}/100."]
    titles = top_titles(report)
    if titles:
        lines.append("Worth a look: " + "; ".join(titles) + ".")
    elif report.get("findings"):
        lines.append("Only minor things were found.")
    else:
        lines.append("No security concerns were found.")
    if d is not None:
        summary = change_summary(d)
        lines.append(
            f"What the update changes: {summary}." if summary
            else f"Nothing important changed since {prev}."
        )  # fmt: skip
    if not report.get("complete", True):
        lines.append("Part of the check didn't finish, so the score is capped at 89.")
    ids = entry.get("scan_ids") or []
    where = f"scan @{ids[-1]}" if ids else "the app's page"
    if len(ids) == 2:
        where += f", what the update changes @{ids[0]} → @{ids[1]}"
    link = f"[Open Barkley]({panel})" if panel else "Open Barkley from the sidebar"
    title = f"Barkley: {repo} {ver}" + (" (update waiting)" if offered else "")
    plain = " ".join(lines) + f" Open Barkley from the sidebar: {where}."
    return title, "\n\n".join(lines) + f"\n\n{link}: {where}.", plain


class Watcher:
    """The auto-sniff thread; also the panel's settings for it (store settings win over
    the app options, like the AI entity)."""

    def __init__(
        self,
        store: Store,
        worker: Any,
        installed_fn: InstalledFn,
        *,
        subscribe_fn: Callable[[], Any] | None = None,
        notify_fn: Callable[[str, str, str], None] | None = None,
        notify_service_fn: Callable[[str, str, str, str], None] | None = None,
        targets_fn: Callable[[], list[str]] | None = None,
        slug_fn: Callable[[], str] | None = None,
        enabled: bool = True,
        notify_target: str = "",
        sleep_fn: Callable[[float], None] = time.sleep,
        now_fn: Callable[[], float] = time.time,
        poll: float = POLL,
        settle: float = SETTLE,
        age_out_days: float = AGE_OUT_DAYS,
    ):
        self.store = store
        self.worker = worker
        self.installed_fn = installed_fn
        self.subscribe_fn = subscribe_fn
        self.notify_fn = notify_fn
        self.notify_service_fn = notify_service_fn
        self.targets_fn = targets_fn
        self.slug_fn = slug_fn
        self.sleep_fn = sleep_fn
        self.now_fn = now_fn
        self.poll = poll
        self.settle = settle
        self.age_out_days = age_out_days
        stored = store.setting("auto_scan")
        self.enabled = stored == "on" if stored in ("on", "off") else bool(enabled)
        stored_target = store.setting("notify_target")
        if stored_target is not None:  # "none" = bell only, chosen in the panel
            notify_target = "" if stored_target == "none" else stored_target
        self.notify_target = notify_target if supervisor.notify_target_ok(notify_target) else ""
        self.mode = "not started"
        self.error = ""
        self.since = 0.0
        self.last_check = 0.0
        self.last_sweep = 0.0
        self.last_event = ""
        self.events_seen = 0
        self.swept = 0
        self.last_test = ""
        self._slug: str | None = None
        self._targets: tuple[float, list[str], str] = (0.0, [], "")
        self._pending: dict[int, Change] = {}
        # The panel's copy of the installed list is refreshed from every read here, so a
        # just-installed app moves into the grid at once (set by `server.serve`).
        self.on_list: Callable[[list[Installed], dict[str, int]], None] | None = None
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.stop = threading.Event()  # tests and shutdown: end `run_forever`

    # --- settings (the panel) ----------------------------------------------------------

    def set_enabled(self, on: bool) -> None:
        self.enabled = on
        self.store.set_setting("auto_scan", "on" if on else "off")
        print(f"auto-sniff: {'on' if on else 'off'} (chosen in the panel)", file=sys.stderr,
              flush=True)  # fmt: skip

    def set_target(self, target: str) -> bool:
        """Only a target HA listed can be chosen ("" = bell only)."""
        if target and (not supervisor.notify_target_ok(target) or target not in self.targets()[0]):
            return False
        self.notify_target = target
        self.store.set_setting("notify_target", target or "none")
        print(f"auto-sniff notifications: bell{' + notify.' + target if target else ' only'} "
              "(chosen in the panel)", file=sys.stderr, flush=True)  # fmt: skip
        return True

    def targets(self, refresh: bool = False) -> tuple[list[str], str]:
        """notify.* targets HA offers, cached 5 minutes."""
        if self.targets_fn is None:
            return [], ""
        fetched, items, err = self._targets
        if refresh or not fetched or self.now_fn() - fetched > 300:
            try:
                items, err = self.targets_fn(), ""
            except SupervisorError as ex:
                items, err = [], str(ex)
            self._targets = (self.now_fn(), items, err)
        return items, err

    def panel_path(self) -> str:
        """`/app/<slug>`: HA's page for this app, "" when unknown. Verified in Core
        2026.11.0: the hassio integration registers a generic `app` panel at `/app`
        and one per app at `/<slug>` (only while "show in sidebar" is on), both rendered
        by the frontend's `ha-panel-app`; the old `/hassio/ingress/<slug>` route is gone
        (it fell through to the default dashboard on the user's box)."""
        if self._slug is None:
            try:
                self._slug = self.slug_fn() if self.slug_fn else ""
            except SupervisorError as ex:
                print(f"auto-sniff: no panel link in notifications: {ex}", file=sys.stderr)
                self._slug = ""
        return f"/app/{self._slug}" if self._slug else ""

    def log(self) -> list[dict[str, Any]]:
        raw = self.store.setting(LOG_KEY)
        try:
            data = json.loads(raw) if raw else []
        except ValueError:
            return []
        return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []

    def _log(self, entry: dict[str, Any]) -> None:
        with self._lock:
            data = [entry, *self.log()][:_LOG_KEPT]
            self.store.set_setting(LOG_KEY, json.dumps(data))

    def diagnostics(self) -> tuple[bool, str]:
        """(ok, one line) for the Diagnostics page and the panel."""
        head = "on" if self.enabled else "off (installs and updates are noticed, not sniffed)"
        how = self.mode
        if self.since:
            how += f" since {_now_iso(self.since)[11:16]} UTC"
        bits = [f"auto-sniff {head}", how]
        if self.last_event:
            bits.append(f"last event: {self.last_event}")
        if self.last_check:
            bits.append(f"list read {int(self.now_fn() - self.last_check) // 60} min ago")
        if self.error:
            bits.append(f"last error: {self.error[:200]}")
        bits.append(
            f"notifications: bell{' + notify.' + self.notify_target if self.notify_target else ''}"
        )
        return not self.error, "; ".join(bits)

    # --- the thread --------------------------------------------------------------------

    def start(self) -> threading.Thread:
        self._thread = threading.Thread(target=self.run_forever, name="auto-sniff", daemon=True)
        self._thread.start()
        return self._thread

    def run_forever(self) -> None:  # pragma: no cover - the loop; its parts are tested
        self.check()
        self.resume()
        self.sweep()
        wait = _RECONNECT
        while not self.stop.is_set():
            try:
                wait = self._round(wait)
            except Exception as ex:  # never let the thread die: say why and go on
                self.error = f"{type(ex).__name__}: {ex}"
                print(f"auto-sniff: {self.error}", file=sys.stderr, flush=True)
                self.sleep_fn(wait)
                wait = min(wait * 2, self.poll)

    def _round(self, wait: float) -> float:  # pragma: no cover - the loop; parts are tested
        """One subscription (or one polling wait); returns the next reconnect wait."""
        sub = None
        if self.subscribe_fn is not None:
            try:
                sub = self.subscribe_fn()
                self.mode, self.error, self.since, wait = "subscribed", "", self.now_fn(), 0.0
                wait = _RECONNECT
                print(
                    "auto-sniff: subscribed to the Marketplace's events "
                    f"({supervisor.SUBSCRIBE}: {', '.join(supervisor.WATCH_SIGNALS)}); the "
                    f"installed list is read again every {self.poll:.0f} s anyway",
                    file=sys.stderr,
                    flush=True,
                )
            except SupervisorError as ex:
                self.mode, self.error = "polling (no subscription)", str(ex)
                print(
                    f"auto-sniff: subscription failed, polling every {self.poll:.0f} s: {ex}",
                    file=sys.stderr,
                    flush=True,
                )
        else:
            self.mode = "polling"
        if sub is None:
            self.sleep_fn(min(wait, self.poll))
            self.tick()
            return min(wait * 2, self.poll)
        try:
            self.watch(sub.events())
        except SupervisorError as ex:
            self.error = str(ex)
            print(f"auto-sniff: subscription ended: {ex}", file=sys.stderr, flush=True)
        finally:
            sub.close()
        self.sleep_fn(wait)
        return min(wait * 2, self.poll)

    def watch(self, events: Iterable[tuple[str, dict[str, Any]] | None]) -> None:
        """Consume one subscription's events; idle ticks poll and sweep."""
        for ev in events:
            if ev is None:
                self.tick()
                continue
            signal, data = ev
            self.events_seen += 1
            repo = str(data.get("repository") or "")[:100]
            what = (
                data.get("progress")
                if signal == supervisor.SIGNAL_INSTALL_PROGRESS
                else (data.get("action"))
            )
            self.last_event = f"{signal.removeprefix('marketplace_')} {repo} {what!s:.20}".strip()
            if matters(signal, data):
                self.sleep_fn(self.settle)
                self.check()

    def tick(self) -> None:
        now = self.now_fn()
        if now - self.last_check >= self.poll:
            self.check()
        if now - self.last_sweep >= SWEEP_EVERY:
            self.sweep()

    # --- the work ----------------------------------------------------------------------

    def _snapshot(self) -> dict[str, Any] | None:
        raw = self.store.setting(SNAPSHOT_KEY)
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def check(self) -> list[Change]:
        """Read the installed list, compare with the snapshot, queue scans for what changed."""
        try:
            items, other = self.installed_fn()
        except SupervisorError as ex:
            self.error = str(ex)
            return []
        self.error = ""
        self.last_check = self.now_fn()
        if self.on_list is not None:
            self.on_list(items, other)
        new = snapshot_of(items)
        with self._lock:
            old = self._snapshot()
            self.store.set_setting(SNAPSHOT_KEY, json.dumps(new))
        if old is None:  # first run: remember what's there; the panel's button scans it
            print(f"auto-sniff: watching {len(new)} installed integration(s)/card(s)",
                  file=sys.stderr, flush=True)  # fmt: skip
            return []
        changes = snapshot_changes(old, new)
        for c in changes:
            self._handle(c)
        return changes

    def _active(self, repo: str, ref: str) -> bool:
        return any(
            j.repo.lower() == repo.lower() and j.ref == ref
            and j.state in ("queued", "running", "waiting")
            for j in list(self.worker.jobs)
        )  # fmt: skip

    def _handle(self, c: Change) -> None:
        did = _did(c)
        print(f"auto-sniff: {c.repo} {did}" + ("" if self.enabled else " (auto-sniff is off)"),
              file=sys.stderr, flush=True)  # fmt: skip
        if not self.enabled:
            self._log(self._entry(c, state="noticed", message="auto-sniff is off"))
            return
        self._queue(c)

    def _queue(self, c: Change) -> bool:
        """One auto job per change; the change is remembered until the job ends."""
        if self._active(c.repo, c.version):
            return False
        self._remember(c)
        job = self.worker.submit("auto", c.repo, c.version, prev=c.previous)
        with self._lock:
            self._pending[job.id] = c
        return True

    # --- changes whose job hasn't ended, kept across restarts ----------------------------

    def pending(self) -> list[Change]:
        raw = self.store.setting(PENDING_KEY)
        try:
            data = json.loads(raw) if raw else []
        except ValueError:
            return []
        out = []
        for x in data if isinstance(data, list) else []:
            if isinstance(x, dict) and all(isinstance(x.get(k), str) for k in ("repo", "version")):
                out.append(Change(str(x.get("action") or "install"), x["repo"],
                                  str(x.get("kind") or ""), x["version"],
                                  str(x["previous"]) if x.get("previous") else None))  # fmt: skip
        return out

    def _save_pending(self, items: list[Change]) -> None:
        self.store.set_setting(PENDING_KEY, json.dumps([asdict(c) for c in items[-_PENDING_KEPT:]]))

    def _remember(self, c: Change) -> None:
        with self._lock:
            self._save_pending([*self._without(c), c])

    def _forget(self, c: Change) -> None:
        with self._lock:
            self._save_pending(self._without(c))

    def _without(self, c: Change) -> list[Change]:
        return [
            x for x in self.pending()
            if not (x.repo.lower() == c.repo.lower() and x.version == c.version)
        ]  # fmt: skip

    def resume(self) -> list[Change]:
        """Re-queue the sniffs a restart interrupted (call after the first `check`, so the
        snapshot is fresh). A change is dropped when the app is no longer installed at that
        version (a newer version was found by `check`, or it was uninstalled) or when
        auto-sniff is off. A scan that did finish before the restart is reused by the job,
        so at worst the notification is repeated."""
        items = self.pending()
        if not items:
            return []
        snap = self._snapshot() or {}
        with self._lock:
            self._save_pending([])
        # Anything this process already queued (by `check`, a moment ago) is not a leftover,
        # even when its job has finished and its on-done hook hasn't cleared it yet.
        queued = {(j.repo.lower(), j.ref) for j in list(self.worker.jobs)}
        out = []
        for c in items:
            if (c.repo.lower(), c.version) in queued:
                continue
            cur = snap.get(c.repo.lower())
            still = isinstance(cur, dict) and (
                cur.get("available") == c.version and cur.get("version") == c.previous
                if c.action == "available"
                else cur.get("version") == c.version
            )
            if not self.enabled or not still:
                print(f"auto-sniff: dropping the sniff of {c.repo} {c.version} that a restart "
                      "interrupted: no longer installed at that version"
                      + ("" if self.enabled else " (auto-sniff is off)"),
                      file=sys.stderr, flush=True)  # fmt: skip
                continue
            print(f"auto-sniff: {c.repo} {c.version}: sniffing again, a restart interrupted it",
                  file=sys.stderr, flush=True)  # fmt: skip
            if self._queue(c):
                out.append(c)
        return out

    def _entry(self, c: Change, **extra: Any) -> dict[str, Any]:
        return {
            "when": _now_iso(self.now_fn()),
            "action": c.action,
            "repo": c.repo,
            "kind": c.kind,
            "version": c.version,
            "previous": c.previous,
            **extra,
        }

    def on_job_done(self, job: Any) -> None:
        """Worker hook: record the outcome of an auto job and notify."""
        with self._lock:
            c = self._pending.pop(job.id, None)
        if c is None:
            return
        self._forget(c)
        entry = self._entry(c, state=job.state, message=str(job.message)[:300],
                            scan_ids=list(job.scan_ids))  # fmt: skip
        report = d = None
        if job.state == "done" and job.scan_ids:
            try:
                report = self.store.report(job.scan_ids[-1])
                if len(job.scan_ids) == 2:
                    d = diff_reports(self.store.report(job.scan_ids[0]), report)
            except StoreError as ex:
                entry["state"], entry["message"] = "failed", str(ex)
                report = None
        if report is not None:
            entry["score"] = int(report.get("score", 0))
            entry["verdict"] = str(report.get("verdict", {}).get("key", ""))
            entry["complete"] = bool(report.get("complete", True))
            entry["changes"] = change_summary(d) if d is not None else ""
        self._log(entry)
        if report is not None:
            title, md, plain = notification(entry, report, d, self.panel_path())
        else:
            if c.action == "available":
                did = f"the offered update {c.version}"
            else:
                did = f"the update to {c.version}" if c.previous else f"version {c.version}"
            title = f"Barkley: {c.repo} {c.version}"
            md = plain = (
                f"Barkley couldn't sniff {did} of {c.repo} ({job.state}: "
                f"{str(job.message)[:200]}). Open Barkley from the sidebar to try again."
            )
        err = self._notify(title, md, plain, f"barkley_{c.repo.lower()}")
        # One line per outcome in the app's log (a finished job printed nothing before, so
        # the log on the user's box couldn't say whether a sniff ended before a rebuild).
        ver = f"{c.previous} → {c.version}" if c.previous else c.version
        if c.action == "available":
            ver += " (update waiting)"
        ids = " → ".join(f"@{i}" for i in job.scan_ids) or "no scan"
        if report is not None:
            label, emoji = _VERDICT.get(entry.get("verdict", ""), ("?", ""))
            what = f"sniffed: {emoji} {label} {entry['score']}/100"
            if entry.get("changes"):
                what += f", {entry['changes']}"
            if not entry.get("complete", True):
                what += " (incomplete)"
        else:
            what = f"{entry['state']}: {entry['message'][:200]}"
        sent = (
            f"notification failed: {err}" if err
            else "notified bell" + (f" + notify.{self.notify_target}" if self.notify_target else "")
        )  # fmt: skip
        print(f"auto-sniff: {c.repo} {ver} {what}; {ids}; {sent}", file=sys.stderr, flush=True)

    def _notify(self, title: str, md: str, plain: str, nid: str) -> str:
        """Both channels; errors are logged and returned, never raised into the worker."""
        errors = []
        nid = "".join(ch if ch.isalnum() else "_" for ch in nid)[:100]
        if self.notify_fn is not None:
            try:
                self.notify_fn(title, md, nid)
            except SupervisorError as ex:
                errors.append(str(ex))
        if self.notify_target and self.notify_service_fn is not None:
            try:
                self.notify_service_fn(self.notify_target, title, plain, self.panel_path())
            except SupervisorError as ex:
                errors.append(str(ex))
        for err in errors:
            print(f"auto-sniff: notification failed: {err}", file=sys.stderr, flush=True)
        return "; ".join(errors)

    def notify_test(self) -> str:
        """The panel's test button: a real notification through both channels."""
        md = (
            "This is how Barkley tells you about an auto-sniffed install or update: the app, "
            "its version, the verdict and score, what's worth a look, and for an update what "
            "changed. "
            + (f"[Open Barkley]({self.panel_path()})" if self.panel_path() else "Open Barkley")
        )
        plain = (
            "This is how Barkley tells you about an auto-sniffed install or update. "
            "Open Barkley from the sidebar."
        )
        err = self._notify("Barkley: test notification", md, plain, "barkley_test")
        self.last_test = err or f"sent at {_now_iso(self.now_fn())[11:16]} UTC"
        return err

    def sweep(self) -> int:
        """Delete scans of apps that aren't installed once they're `age_out_days` old."""
        try:
            items, _other = self.installed_fn()
        except SupervisorError:
            return 0  # the list is unknown: nothing is deleted
        self.last_sweep = self.now_fn()
        installed = {it.repo.lower() for it in items}
        busy = {
            j.repo.lower() for j in list(self.worker.jobs)
            if j.state in ("queued", "running", "waiting")
        }  # fmt: skip
        cutoff = self.now_fn() - self.age_out_days * 86400
        n = 0
        for r in self.store.history(limit=100000):
            if not r.repo or r.repo.lower() in installed or r.repo.lower() in busy:
                continue
            try:
                when = datetime.fromisoformat(r.scanned_at).timestamp()
            except ValueError:
                continue
            if when < cutoff and self.store.delete(r.id):
                n += 1
        if n:
            print(
                f"auto-sniff: deleted {n} scan(s) of apps that aren't installed "
                f"(older than {self.age_out_days:g} days)",
                file=sys.stderr,
                flush=True,
            )
        self.swept += n
        return n
