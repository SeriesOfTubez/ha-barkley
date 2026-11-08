"""sniff-test command line."""

from __future__ import annotations

import argparse
import json
import sys

from rich.console import Console

from sniff_test import __version__
from sniff_test.deps.ha_env import valid_version
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
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.ha_version and not valid_version(args.ha_version):
        parser.error(f"--ha-version: expected YYYY.M.P, got {args.ha_version!r}")
    out = Console()
    err = Console(stderr=True)
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
