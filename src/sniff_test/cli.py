"""sniff-test command line."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from sniff_test import __version__, releases
from sniff_test.deps.ha_env import valid_version
from sniff_test.diff import diff as diff_reports
from sniff_test.fetch.github import GitHubError
from sniff_test.fetch.hacs import FetchError
from sniff_test.models import TargetKind
from sniff_test.report import human
from sniff_test.report.json_report import to_dict
from sniff_test.scanner import scan
from sniff_test.scoring import Exposure
from sniff_test.workspace import UnsafeArchiveError

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_BELOW_THRESHOLD = 3


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
    d = sub.add_parser(
        "diff",
        help="what an update changes: compare two reports, two sources, or two refs",
        description="Compare two scans. OLD and NEW are each a JSON report from "
        "`scan -o`, or anything `scan` accepts. With --from, OLD is one repo scanned at "
        "two refs. Shows the changes that matter first; never changes a score.",
    )
    d.add_argument("old", help="old report (.json), source, or the repo for --from/--to")
    d.add_argument("new", nargs="?", help="new report (.json) or source")
    d.add_argument("--from", dest="from_ref", metavar="TAG", help="old ref of the repo")
    d.add_argument(
        "--to", dest="to_ref", metavar="TAG", help="new ref (default: what HACS installs)"
    )
    d.add_argument("--exposure", choices=[e.value for e in Exposure], default=Exposure.LOCAL.value)
    d.add_argument("--category", choices=[k.value for k in TargetKind])
    d.add_argument("--ha-version", metavar="YYYY.M.P")
    d.add_argument("--offline", action="store_true")
    d.add_argument("--jobs", type=int)
    d.add_argument("--json", action="store_true", help="print the diff as JSON")
    d.add_argument("-o", "--output", help="also write the diff JSON to this file")
    d.add_argument("-v", "--verbose", action="store_true", help="list every change")

    r = sub.add_parser("releases", help="list a repo's releases and who published them")
    r.add_argument("source", help="GitHub URL or owner/repo")
    r.add_argument("--all", action="store_true", help="list every release (default: newest 20)")
    r.add_argument("--json", action="store_true", help="print the timeline as JSON")
    return p


def _load_or_scan(
    spec: str, ref: str | None, args: argparse.Namespace, err: Console
) -> dict | None:
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
    if not args.json:
        err.print(f"🐕 sniff sniff... {escape(spec)}{'@' + escape(ref) if ref else ''}")
    try:
        result = scan(
            spec,
            ref=ref,
            exposure=Exposure(args.exposure),
            kind=TargetKind(args.category) if args.category else None,
            jobs=args.jobs,
            ha_version=args.ha_version,
            offline=args.offline,
        )
    except (FetchError, GitHubError, UnsafeArchiveError) as e:
        err.print(f"[red]🐕 couldn't get a sniff of {escape(spec)}:[/] {e}")
        return None
    return to_dict(result)


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
    reports = []
    for spec, ref in sides:
        if (rep := _load_or_scan(spec, ref, args, err)) is None:
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
    if getattr(args, "ha_version", None) and not valid_version(args.ha_version):
        parser.error(f"--ha-version: expected YYYY.M.P, got {args.ha_version!r}")
    out = Console()
    err = Console(stderr=True)
    if args.command == "releases":
        return _releases(args, out, err)
    if args.command == "diff":
        return _diff(args, out, err)
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
        )
    except (FetchError, GitHubError, UnsafeArchiveError) as e:
        err.print(f"[red]🐕 couldn't get a sniff:[/] {e}")
        return EXIT_ERROR

    report = to_dict(result)
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
