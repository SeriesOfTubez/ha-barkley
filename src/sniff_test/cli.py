"""sniff-test command line."""

from __future__ import annotations

import argparse
import atexit
import contextlib
import json
import os
import signal
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape

from sniff_test import __version__, recheck, releases, sources
from sniff_test.deps import ha_env
from sniff_test.deps.ha_env import valid_version
from sniff_test.diff import diff as diff_reports
from sniff_test.fetch.github import GitHub, GitHubError
from sniff_test.fetch.hacs import FetchError
from sniff_test.models import TargetKind
from sniff_test.report import human
from sniff_test.report.json_report import to_dict
from sniff_test.scanner import scan
from sniff_test.scoring import Exposure
from sniff_test.store import Store, StoreError
from sniff_test.workspace import UnsafeArchiveError

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_BELOW_THRESHOLD = 3
STORE_ENV = "SNIFF_TEST_STORE"


def _add_store(p: argparse.ArgumentParser, help_text: str) -> None:
    p.add_argument(
        "--store",
        metavar="DB",
        default=os.environ.get(STORE_ENV) or None,
        help=f"{help_text} (default: ${STORE_ENV} if set)",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sniff-test",
        description="🐕 Sniff HA Marketplace (HACS) items before they get into the house.",
    )
    p.add_argument("--version", action="version", version=f"sniff-test {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="scan a GitHub repo or local directory")
    s.add_argument("source", help="GitHub URL, owner/repo, or local path")
    s.add_argument("--ref", help="tag to scan (default: latest release, as HACS would install)")
    s.add_argument(
        "--exposure",
        choices=[e.value for e in Exposure],
        default=Exposure.LOCAL.value,
        help="'public' if your HA is reachable from the internet (weights inbound findings up)",
    )
    s.add_argument(
        "--category",
        choices=[k.value for k in TargetKind],
        help="force integration/plugin instead of auto-detecting",
    )
    s.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    s.add_argument("-o", "--output", help="also write the JSON report to this file")
    s.add_argument("-v", "--verbose", action="store_true", help="show low/info findings too")
    s.add_argument("--fail-under", type=int, metavar="SCORE", help="exit 3 if score < SCORE")
    s.add_argument("--jobs", type=int, help="parallel jobs for semgrep (lower = less RAM)")
    s.add_argument("--keep-workspace", action="store_true", help="don't delete the temp dir")
    s.add_argument(
        "--ha-version",
        metavar="YYYY.M.P",
        help="resolve dependencies against this Home Assistant release (default: latest stable)",
    )
    s.add_argument(
        "--offline",
        action="store_true",
        help="skip checks that need PyPI/OSV (local scans only; the scan is marked incomplete)",
    )
    s.add_argument(
        "--no-library-lookup",
        action="store_true",
        help="read every JavaScript file as code; don't ask jsDelivr which published "
        "library a file is (sends the SHA-256 of larger JS files of an integration)",
    )
    _add_store(s, "also save the scan in this SQLite scan store")
    d = sub.add_parser(
        "diff",
        help="what an update changes: compare two reports, two sources, or two refs",
        description="Compare two scans. OLD and NEW are each a JSON report from "
        "`scan -o`, a stored scan (@ID, with --store), or anything `scan` accepts. With "
        "--from, OLD is one repo scanned at two refs; with --store, a matching stored scan "
        "is reused and new scans are saved. Shows the changes that matter first; never "
        "changes a score.",
    )
    d.add_argument("old", help="old report (.json), source, or the repo for --from/--to")
    d.add_argument("new", nargs="?", help="new report (.json) or source")
    d.add_argument("--from", dest="from_ref", metavar="TAG", help="old ref of the repo")
    d.add_argument(
        "--to", dest="to_ref", metavar="TAG", help="new ref (default: what HACS installs)"
    )
    d.add_argument("--exposure", choices=[e.value for e in Exposure], default=Exposure.LOCAL.value)
    d.add_argument("--category", choices=[k.value for k in TargetKind])
    d.add_argument(
        "--ha-version",
        metavar="YYYY.M.P|auto",
        help="resolve both sides against this HA release (default: the latest stable). "
        "With --from, 'auto' resolves the old side against the HA release that was current "
        "when the old tag came out, so its old pins resolve as they did then",
    )
    d.add_argument("--offline", action="store_true")
    d.add_argument("--jobs", type=int)
    d.add_argument("--json", action="store_true", help="print the diff as JSON")
    d.add_argument("-o", "--output", help="also write the diff JSON to this file")
    d.add_argument("-v", "--verbose", action="store_true", help="list every change")
    _add_store(d, "reuse and save scans in this SQLite scan store")

    h = sub.add_parser("history", help="list scans in the scan store")
    h.add_argument("repo", nargs="?", help="only this repo (owner/name)")
    h.add_argument("--limit", type=int, default=50)
    h.add_argument("--json", action="store_true")
    _add_store(h, "the SQLite scan store")

    env = os.environ.get
    v = sub.add_parser(
        "serve",
        help="run the web panel (the add-on's, or standalone next to Home Assistant)",
        description="Serve the scan store and run scans. As an add-on (SUPERVISOR_TOKEN "
        "set) only clients in --allow may connect (default: the Supervisor's ingress "
        "proxy, 172.30.32.2). Standalone (HA_URL and HA_TOKEN or HA_TOKEN_FILE set), "
        "every page asks for a login with Home Assistant (administrators only), which "
        "needs --public-url. Each option also reads the environment variable named in "
        "its help.",
    )
    _add_store(v, "the SQLite scan store")
    v.add_argument("--host", default="0.0.0.0")  # noqa: S104 - in a container
    v.add_argument("--port", type=int, default=env("BARKLEY_PORT", "8099"),
                   help="(BARKLEY_PORT)")  # fmt: skip
    v.add_argument(
        "--allow",
        action="append",
        metavar="IP",
        default=[a.strip() for a in env("BARKLEY_ALLOW", "").split(",") if a.strip()] or None,
        help="client address to accept; standalone, also needed when there is no login "
        "(BARKLEY_ALLOW, comma-separated)",
    )
    v.add_argument(
        "--public-url",
        default=env("BARKLEY_URL", ""),
        metavar="URL",
        help="standalone: Barkley's address as your browser reaches it, e.g. "
        "http://192.168.1.20:8099; the login and notification links use it (BARKLEY_URL)",
    )
    v.add_argument(
        "--ha-browser-url",
        default=env("HA_BROWSER_URL", ""),
        metavar="URL",
        help="standalone: Home Assistant's address as your browser reaches it, when it "
        "differs from HA_URL (HA_BROWSER_URL)",
    )
    v.add_argument("--exposure", choices=[e.value for e in Exposure],
                   default=env("BARKLEY_EXPOSURE", Exposure.LOCAL.value),
                   help="(BARKLEY_EXPOSURE)")  # fmt: skip
    v.add_argument("--jobs", type=int, default=env("BARKLEY_JOBS", "1"), help="(BARKLEY_JOBS)")
    v.add_argument(
        "--parallel",
        type=int,
        default=env("BARKLEY_PARALLEL", "1"),
        help="scans that may run at once, as memory allows (1-4) (BARKLEY_PARALLEL)",
    )
    v.add_argument(
        "--ai-entity",
        default=env("BARKLEY_AI_ENTITY", ""),
        metavar="ai_task.NAME",
        help="AI Task entity for 'Explain this app' (empty: off; the panel can pick one) "
        "(BARKLEY_AI_ENTITY)",
    )
    v.add_argument(
        "--ai-mode",
        choices=("summary", "deep"),
        default=env("BARKLEY_AI_MODE", "deep"),
        help="summary: explain the findings; deep: also 'Explain in context' (reads code) "
        "(BARKLEY_AI_MODE)",
    )
    v.add_argument(
        "--auto-scan",
        default=env("BARKLEY_AUTO_SCAN", "true"),
        metavar="true|false",
        help="sniff every Marketplace install and update and notify (needs Home "
        "Assistant) (BARKLEY_AUTO_SCAN)",
    )
    v.add_argument(
        "--notify-target",
        default=env("BARKLEY_NOTIFY_TARGET", ""),
        metavar="NAME",
        help="a notify service (notify.NAME) that also gets auto-sniff results "
        "(BARKLEY_NOTIFY_TARGET)",
    )
    v.add_argument(
        "--ha-version",
        metavar="YYYY.M.P",
        help="resolve against this HA release (default: the installed one, via the "
        "Supervisor; else the latest stable)",
    )

    dr = sub.add_parser("doctor", help="check that every scanner tool runs on this machine")
    dr.add_argument("--json", action="store_true")

    r = sub.add_parser("releases", help="list a repo's releases and who published them")
    r.add_argument("source", help="GitHub URL or owner/repo")
    r.add_argument("--all", action="store_true", help="list every release (default: newest 20)")
    r.add_argument("--json", action="store_true", help="print the timeline as JSON")
    return p


def _open_store(path: str | None, err: Console) -> Store | None:
    try:
        return Store(Path(path).expanduser()) if path else None
    except (StoreError, OSError) as e:
        err.print(f"[red]🐕 can't open the scan store {escape(str(path))}:[/] {e}")
        raise SystemExit(EXIT_ERROR) from e


def _requested_ha(args: argparse.Namespace) -> str | None:
    """The HA release a fresh scan would resolve against (for reusing stored scans)."""
    if args.ha_version or args.offline:
        return args.ha_version
    if not hasattr(args, "_latest_ha"):
        try:
            args._latest_ha = ha_env.load(None).version
        except ha_env.HAEnvError:
            args._latest_ha = None
    return args._latest_ha


def _repo_name(spec: str) -> str | None:
    s = spec.strip().removesuffix(".git").rstrip("/")
    s = s.removeprefix("https://").removeprefix("http://").removeprefix("github.com/")
    parts = s.split("/")
    return s if len(parts) == 2 and all(parts) and not Path(spec).exists() else None


def _load_or_scan(
    spec: str,
    ref: str | None,
    args: argparse.Namespace,
    err: Console,
    store: Store | None,
    ha: str | None = None,
) -> dict | None:
    """A report for one side: stored, from a file, or scanned. `ha` overrides the HA release."""
    if spec.startswith("@") and spec[1:].isdigit():
        if store is None:
            err.print(f"[red]🐕 {escape(spec)} is a stored scan: pass --store[/]")
            return None
        try:
            return store.report(int(spec[1:]))
        except StoreError as e:
            err.print(f"[red]🐕 {e}[/]")
            return None
    path = Path(spec).expanduser()
    if path.suffix == ".json" and not path.is_file():
        err.print(f"[red]🐕 no such report: {escape(spec)}[/]")
        return None
    if path.suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            err.print(f"[red]🐕 can't read report {escape(spec)}:[/] {e}")
            return None
        if not isinstance(data, dict) or "graph" not in data or "findings" not in data:
            err.print(f"[red]🐕 {escape(spec)} isn't a sniff-test report[/]")
            return None
        return data
    repo = _repo_name(spec)
    if store is not None and repo and ref:
        hit = store.find(
            repo,
            ref,
            exposure=args.exposure,
            tool_version=__version__,
            ha_version=ha or _requested_ha(args),
        )
        if hit is not None:
            if not args.json:
                err.print(f"🐕 using stored scan {escape(hit.label())} from {hit.scanned_at}")
            return store.report(hit.id)
    if not args.json:
        err.print(f"🐕 sniff sniff... {escape(spec)}{'@' + escape(ref) if ref else ''}")
    try:
        result = scan(
            spec,
            ref=ref,
            exposure=Exposure(args.exposure),
            kind=TargetKind(args.category) if args.category else None,
            jobs=args.jobs,
            ha_version=ha or args.ha_version,
            offline=args.offline,
            recognise_libraries=not getattr(args, "no_library_lookup", False),
        )
    except (FetchError, GitHubError, UnsafeArchiveError) as e:
        err.print(f"[red]🐕 couldn't get a sniff of {escape(spec)}:[/] {e}")
        return None
    report = to_dict(result)
    if store is not None:
        sid = store.save(report, inputs=result.inputs, source=result.source)
        if not args.json:
            err.print(f"🐕 stored as scan #{sid}")
    return report


def _ha_when_released(spec: str, ref: str, err: Console) -> str | None:
    """The HA stable release that was current when `ref` of repo `spec` came out."""
    repo = _repo_name(spec)
    if not repo:
        err.print("[red]🐕 --ha-version auto needs a GitHub repo (owner/name) with --from[/]")
        return None
    owner, name = repo.split("/", 1)
    try:
        when = GitHub.from_env().ref_date(owner, name, ref)
        return ha_env.version_at(when)
    except (GitHubError, ha_env.HAEnvError, KeyError, TypeError) as e:
        err.print(f"[red]🐕 couldn't date {escape(repo)}@{escape(ref)} to an HA release:[/] {e}")
        return None


def _diff(args: argparse.Namespace, out: Console, err: Console) -> int:
    if args.from_ref:
        if args.new:
            err.print("[red]🐕 use either OLD NEW or one repo with --from/--to[/]")
            return EXIT_ERROR
        sides = [(args.old, args.from_ref), (args.old, args.to_ref)]
    elif args.new:
        if args.to_ref:
            err.print("[red]🐕 --to needs --from[/]")
            return EXIT_ERROR
        sides = [(args.old, None), (args.new, None)]
    else:
        err.print("[red]🐕 diff needs OLD and NEW, or a repo with --from[/]")
        return EXIT_ERROR
    side_ha: list[str | None] = [None, None]
    if args.ha_version == "auto":
        if (old_ha := _ha_when_released(args.old, args.from_ref, err)) is None:
            return EXIT_ERROR
        side_ha[0] = old_ha
        args.ha_version = None  # the new side: the latest stable, as without the flag
        if not args.json:
            err.print(
                f"🐕 old side: HA {escape(old_ha)}, current when {escape(args.from_ref)} came "
                "out; new side: the latest stable HA"
            )
    store = _open_store(args.store, err)
    reports = []
    for (spec, ref), ha in zip(sides, side_ha, strict=True):
        if (rep := _load_or_scan(spec, ref, args, err, store, ha)) is None:
            return EXIT_ERROR
        reports.append(rep)
    d = diff_reports(*reports)
    if args.output:
        Path(args.output).write_text(json.dumps(d, indent=2), encoding="utf-8")
    if args.json:
        sys.stdout.write(json.dumps(d, indent=2) + "\n")
    else:
        human.render_diff(d, out, verbose=args.verbose)
    return EXIT_OK


def _history(args: argparse.Namespace, out: Console, err: Console) -> int:
    store = _open_store(args.store, err)
    if store is None:
        err.print(f"[red]🐕 history needs --store (or ${STORE_ENV})[/]")
        return EXIT_ERROR
    rows = store.history(args.repo, limit=args.limit)
    if args.json:
        sys.stdout.write(json.dumps([asdict(r) for r in rows], indent=2) + "\n")
    else:
        human.render_history(rows, out)
    return EXIT_OK


AI_MODES = ("summary", "deep")


def _loopback(host: str) -> bool:
    import ipaddress

    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _rotation_thread(store: Any, start: Any) -> None:
    """Standalone: once an hour, replace Barkley's own HA token when it's due (ha_token)."""
    import threading
    import time

    from sniff_test import ha_token, supervisor
    from sniff_test import settings as settings_mod

    def notify(title: str, message: str) -> None:
        with contextlib.suppress(supervisor.SupervisorError):
            supervisor.notify_persistent(title, message, "barkley_token")

    def run() -> None:
        while True:
            period = settings_mod.load(store, start).token_days
            if ha_token.due(store, period):
                why = ha_token.rotate(store, period, notify=notify)
                print(f"Home Assistant token: {why or 'rotated'}", file=sys.stderr, flush=True)
            time.sleep(3600)

    threading.Thread(target=run, name="token-rotation", daemon=True).start()


def _serve(args: argparse.Namespace, out: Console, err: Console) -> int:
    from sniff_test import server

    store = _open_store(args.store, err)
    if store is None:
        err.print(f"[red]🐕 serve needs --store (or ${STORE_ENV})[/]")
        return EXIT_ERROR

    from sniff_test import ha_token, login, supervisor, workspace

    # (0.14.0 part 4) standalone: Barkley's own token file next to the store, made or
    # pasted in the panel; HA_TOKEN / HA_TOKEN_FILE still win
    if not os.environ.get("SUPERVISOR_TOKEN") and os.environ.get(supervisor.HA_URL_ENV):
        supervisor.OWN_TOKEN_FILE = ha_token.path(store.path)
    if problem := supervisor.config_problem():
        err.print(f"[red]🐕 {escape(problem)}[/]")
        return EXIT_ERROR
    if args.exposure not in {x.value for x in Exposure} or args.ai_mode not in AI_MODES:
        err.print("[red]🐕 BARKLEY_EXPOSURE is local|public, BARKLEY_AI_MODE summary|deep[/]")
        return EXIT_ERROR
    conn = supervisor.connection()
    login_cfg = None
    if conn is None or conn.mode != "direct":
        standalone = False
        allow: set[str] | None = set(args.allow or [server.SUPERVISOR_IP])
    else:
        standalone = True
        allow = set(args.allow) if args.allow else None
        if args.public_url:
            try:
                login_cfg = login.Login(args.public_url, args.ha_browser_url or conn.base)
            except supervisor.SupervisorError as ex:
                err.print(f"[red]🐕 {escape(str(ex))}[/]")
                return EXIT_ERROR
        elif allow is None:
            err.print(
                "[red]🐕 Standalone, the panel is on the network: set BARKLEY_URL "
                "(--public-url) to log in with Home Assistant, or --allow (BARKLEY_ALLOW) for "
                "a proxy in front that does its own login.[/]"
            )
            return EXIT_ERROR
    from sniff_test import sandbox

    abi, sandbox_line = sandbox.status()
    if standalone and not abi and os.environ.get(sandbox.UNSANDBOXED_ENV) != "1":
        err.print(
            f"[red]🐕 {escape(sandbox_line)}. Standalone, Barkley has no AppArmor profile of "
            "its own, so it doesn't scan hostile code without Landlock (Linux 5.13 or later). "
            f"To run anyway, set {sandbox.UNSANDBOXED_ENV}=1.[/]"
        )
        return EXIT_ERROR
    # Standalone the image runs without the add-on's start script, which made these.
    for var in ("SNIFF_TEST_CACHE", "HOME", "TMPDIR"):
        if (d := os.environ.get(var)) and Path(d).is_absolute():
            with contextlib.suppress(OSError):
                Path(d).mkdir(parents=True, exist_ok=True)
    if swept := workspace.sweep_stale():
        out.print(f"🐕 Removed {swept} scan folder(s) an earlier run left behind")

    def ha_fn() -> str | None:
        return args.ha_version or supervisor.ha_version()

    from sniff_test import settings as settings_mod

    # (0.14.0) The add-on options / BARKLEY_* give the starting values; the Settings page
    # wins once saved. A GitHub token saved there wins over the option's.
    start = settings_mod.from_dict(
        {"exposure": args.exposure, "jobs": args.jobs, "parallel": args.parallel}
    )
    option_token = os.environ.get("GITHUB_TOKEN", "")
    settings_mod.apply_token(store.path)

    def scan_fn(repo: str, ref: str | None) -> dict:
        now = settings_mod.load(store, start)
        result = scan(repo, ref=ref, exposure=Exposure(now.exposure), jobs=now.jobs,
                      ha_version=ha_fn(), recognise_libraries=now.libraries)  # fmt: skip
        # the lockfiles for later advisory re-checks ride along; Store.save takes them out
        return {**to_dict(result), recheck.KEY: result.inputs, sources.KEY: result.source}

    # The installed list needs HA (the Supervisor, or HA_URL standalone).
    # standalone may start before it has a token (Create token in the panel): its HA
    # calls then say so, and work once the token is there
    have_ha = bool(supervisor.token()) or standalone
    installed_fn = supervisor.installed_hacs if have_ha else None
    watcher = None
    if installed_fn is not None:
        from sniff_test import watch

        target = args.notify_target.strip()
        watcher = watch.Watcher(
            store, None, installed_fn,
            subscribe_fn=lambda: supervisor.Subscription(supervisor.token() or ""),
            notify_fn=supervisor.notify_persistent,
            notify_service_fn=supervisor.notify_service,
            targets_fn=supervisor.notify_targets,
            slug_fn=None if standalone else supervisor.self_slug,
            panel_url=login_cfg.client_id if login_cfg else "",
            # bashio prints "null" for an option missing from an older options file
            enabled=str(args.auto_scan).strip().lower() in ("true", "1", "on", "yes", "null"),
            notify_target=target if target != "null" else "",
        )  # fmt: skip
    current = settings_mod.load(store, start)
    httpd = server.serve(
        store, scan_fn, args.host, args.port, allow,
        exposure=current.exposure, ha_fn=ha_fn, installed_fn=installed_fn,
        budget_fn=lambda: GitHub.from_env().rate_limit(),
        ai_entity=args.ai_entity.strip() if have_ha else "",
        ai_mode=args.ai_mode,
        parallel=current.parallel,
        catalog_fn=supervisor.catalog if have_ha else None,
        entities_fn=supervisor.ai_task_entities if have_ha else None,
        releases_fn=lambda repo: releases.recent(repo),
        watcher=watcher,
        login_cfg=login_cfg,
    )  # fmt: skip
    httpd.panel.start_settings = start
    httpd.panel.option_token = option_token
    httpd.panel.standalone = standalone
    if standalone:
        if login_cfg is not None:  # Create token: made with the login, before it's revoked

            def make_token(access: str) -> None:
                period = settings_mod.load(store, start).token_days
                tok, name = ha_token.create(access, period)
                ha_token.adopt(store, tok, "created", name)

            login_cfg.token_fn = make_token
            # A held first login is revoked on shutdown: docker stop sends SIGTERM, which
            # would end Python without running atexit.
            atexit.register(login_cfg.release_all)
            signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        _rotation_thread(store, start)
        out.print(f"🐕 Home Assistant token: {ha_token.source() or 'none yet (Settings)'}")
    if conn is not None:
        where = "via the Supervisor" if conn.mode == "addon" else f"at {conn.base} (standalone)"
        out.print(f"🐕 Home Assistant: {where}")
        if standalone and not conn.tls and not _loopback(conn.ws_host):
            out.print("🐕 [yellow]HA_URL is plain http: the token crosses your network "
                      "unencrypted. Use https if Home Assistant offers it.[/]")  # fmt: skip
    out.print(f"🐕 Tool sandbox: {sandbox_line}"
              + ("" if abi or not standalone else f" ({sandbox.UNSANDBOXED_ENV}=1)"))  # fmt: skip
    if login_cfg is not None:
        out.print(f"🐕 Login with Home Assistant ({login_cfg.ha_url}), administrators only; "
                  f"Barkley's address: {login_cfg.public_url}")  # fmt: skip
    if watcher is not None:
        watcher.start()
        out.print(
            f"🐕 Auto-sniff: {'on' if watcher.enabled else 'off'}; notifications: bell"
            + (f" + notify.{watcher.notify_target}" if watcher.notify_target else "")
        )
    ai = httpd.panel.ai_entity
    if args.ai_entity.strip() and not ai:
        out.print(
            f"🐕 AI explanations: off ({args.ai_entity.strip()!r} is not an ai_task.* entity)"
        )
    else:
        out.print(f"🐕 AI explanations: {'on, via ' + ai if ai else 'off (no ai_entity set)'}"
                  f"{', mode ' + httpd.panel.ai_mode if ai else ''}")  # fmt: skip
    clients = ", ".join(sorted(allow)) if allow is not None else "any, after the login"
    out.print(
        f"🐕 Barkley {__version__} panel on {args.host}:{args.port} "
        f"(clients: {clients}; store: {store.path})"
    )
    with contextlib.suppress(KeyboardInterrupt):
        httpd.serve_forever()
    return EXIT_OK


def _doctor(args: argparse.Namespace, out: Console) -> int:
    from sniff_test import doctor

    checks = doctor.run_checks()
    if args.json:
        sys.stdout.write(json.dumps(doctor.to_dicts(checks), indent=2) + "\n")
    else:
        for c in checks:
            mark = "[green]ok[/]  " if c.ok else "[red]FAIL[/]"
            out.print(f"{mark} [bold]{escape(c.name)}[/] {escape(c.summary)}", soft_wrap=True)
            if not c.ok:
                for label, text in (("stderr", c.stderr), ("stdout", c.stdout)):
                    if text:
                        out.print(f"      {label}: {escape(text)}", soft_wrap=True)
    return EXIT_OK if all(c.ok for c in checks) else EXIT_ERROR


def _releases(args: argparse.Namespace, out: Console, err: Console) -> int:
    try:
        t = releases.build(args.source)
    except (releases.ReleasesError, GitHubError) as e:
        err.print(f"[red]🐕 couldn't get a sniff:[/] {e}")
        return EXIT_ERROR
    if args.json:
        sys.stdout.write(json.dumps(releases.to_dict(t), indent=2) + "\n")
    else:
        human.render_releases(t, out, limit=None if args.all else 20)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ha = getattr(args, "ha_version", None)
    if ha == "auto" and args.command == "diff":
        if not args.from_ref:
            parser.error("--ha-version auto needs --from (it dates the old side)")
        if args.offline:
            parser.error("--ha-version auto needs the network (GitHub release dates)")
    elif ha and not valid_version(ha):
        parser.error(f"--ha-version: expected YYYY.M.P, got {ha!r}")
    out = Console()
    err = Console(stderr=True)
    if args.command == "releases":
        return _releases(args, out, err)
    if args.command == "diff":
        return _diff(args, out, err)
    if args.command == "history":
        return _history(args, out, err)
    if args.command == "serve":
        return _serve(args, out, err)
    if args.command == "doctor":
        return _doctor(args, out)
    store = _open_store(args.store, err)
    if not args.json:
        human.sniffing(out, args.source)
    try:
        result = scan(
            args.source,
            ref=args.ref,
            exposure=Exposure(args.exposure),
            kind=TargetKind(args.category) if args.category else None,
            keep_workspace=args.keep_workspace,
            jobs=args.jobs,
            ha_version=args.ha_version,
            offline=args.offline,
            recognise_libraries=not args.no_library_lookup,
        )
    except (FetchError, GitHubError, UnsafeArchiveError) as e:
        err.print(f"[red]🐕 couldn't get a sniff:[/] {e}")
        return EXIT_ERROR

    report = to_dict(result)
    if store is not None:
        sid = store.save(report, inputs=result.inputs, source=result.source)
        if not args.json:
            err.print(f"🐕 stored as scan #{sid} in {escape(str(store.path))}")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:  # noqa: PTH123
            json.dump(report, fh, indent=2)
    if args.json:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        human.render(result, out, verbose=args.verbose)
    if args.fail_under is not None and result.score.score < args.fail_under:
        return EXIT_BELOW_THRESHOLD
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
