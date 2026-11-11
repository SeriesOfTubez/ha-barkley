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
from dataclasses import dataclass
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
AGE_OUT_DAYS = 7
POLL = 600  # seconds between fallback reads of the installed list
SWEEP_EVERY = 24 * 3600
SETTLE = 3  # seconds after the Marketplace says an install ended, before the list is read
_LOG_KEPT = 20
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
    action: str  # install | update
    repo: str
    kind: str
    version: str
    previous: str | None = None


def _now_iso(now: float) -> str:
    return datetime.fromtimestamp(now, UTC).isoformat(timespec="seconds")


def snapshot_changes(old: dict[str, Any] | None, new: dict[str, Any]) -> list[Change]:
    """Installs and updates between two snapshots ({lower repo: {repo, kind, version}})."""
    if old is None:
        return []
    out = []
    for key, cur in new.items():
        prev = old.get(key)
        if not isinstance(prev, dict):
            out.append(Change("install", cur["repo"], cur["kind"], cur["version"]))
        elif prev.get("version") != cur["version"]:
            out.append(Change("update", cur["repo"], cur["kind"], cur["version"],
                              str(prev.get("version") or "")))  # fmt: skip
    return out


def snapshot_of(items: Iterable[Installed]) -> dict[str, dict[str, str]]:
    return {
        it.repo.lower(): {"repo": it.repo, "kind": it.kind, "version": it.installed} for it in items
    }


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
    did = f"was updated from {prev} to {ver}" if prev else f"{ver} was installed"
    lines = [f"{kind} {repo} {did} and sniffed: {emoji} {label}, {score}/100."]
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
    title = f"Barkley: {repo} {ver}"
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
        """`/hassio/ingress/<slug>`: HA's own page for this app; "" when unknown."""
        if self._slug is None:
            try:
                self._slug = self.slug_fn() if self.slug_fn else ""
            except SupervisorError as ex:
                print(f"auto-sniff: no panel link in notifications: {ex}", file=sys.stderr)
                self._slug = ""
        return f"/hassio/ingress/{self._slug}" if self._slug else ""

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
        did = f"updated {c.previous} → {c.version}" if c.previous else f"installed {c.version}"
        print(f"auto-sniff: {c.repo} {did}" + ("" if self.enabled else " (auto-sniff is off)"),
              file=sys.stderr, flush=True)  # fmt: skip
        if not self.enabled:
            self._log(self._entry(c, state="noticed", message="auto-sniff is off"))
            return
        if self._active(c.repo, c.version):
            return
        job = self.worker.submit("auto", c.repo, c.version, prev=c.previous)
        with self._lock:
            self._pending[job.id] = c

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
            did = f"the update to {c.version}" if c.previous else f"version {c.version}"
            title = f"Barkley: {c.repo} {c.version}"
            md = plain = (
                f"Barkley couldn't sniff {did} of {c.repo} ({job.state}: "
                f"{str(job.message)[:200]}). Open Barkley from the sidebar to try again."
            )
        self._notify(title, md, plain, f"barkley_{c.repo.lower()}")

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
