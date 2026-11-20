"""(0.14.1) The scan-logic key: whether a stored scan still says what a new one would.

A stored scan is reused while its key is the current one, so a Barkley release that
only changes the panel, the settings or the docs no longer sniffs every app again. The
key is worked out from the files themselves when Barkley starts, so a change to what a
scan finds can't ship without changing it: every file of the package except the ones
listed in PANEL_ONLY (tests/test_scan_logic.py checks that none of those is used by a
scan), the Semgrep rules, and the versions of the scanner tools. It is stored where the
tool version used to be (`tool_version` in the store; "rules …" in the panel).
"""

from __future__ import annotations

import hashlib
import shutil
from functools import cache
from pathlib import Path

# Files that never change what a scan finds or stores: the panel, the store, settings,
# notifications, the AI (asked on a click, never during a scan), the CLI's text output.
# A scan never imports them (tests/test_scan_logic.py). Anything not listed counts.
PANEL_ONLY = frozenset(
    {
        "__init__.py",  # __version__: a release alone mustn't re-sniff
        "logic.py",
        "cli.py",
        "server.py",
        "ui.py",
        "store.py",
        "settings.py",
        "watch.py",
        "supervisor.py",
        "login.py",
        "ha_token.py",
        "memory.py",
        "doctor.py",
        "review.py",
        "readings.py",  # (preview) the proposed readings, worked out when a page is shown
        "devnote.py",  # (preview) the developer's note, read from stored snippets
        "diff.py",
        "releases.py",
        "report/ai.py",
        "report/ai_context.py",
        "report/human.py",
        "report/explain.py",
        "report/privacy.py",
    }
)
_SUFFIXES = (".py", ".txt", ".yaml", ".yml", ".json")


def _files(root: Path, base: Path) -> list[tuple[str, Path]]:
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix not in _SUFFIXES or "__pycache__" in p.parts:
            continue
        out.append((p.relative_to(base).as_posix(), p))
    return out


def fingerprint(package: Path, rules: Path, tools: dict[str, str | None]) -> str:
    h = hashlib.sha256()
    for rel, p in _files(package, package):
        if rel in PANEL_ONLY or rel.startswith("assets/"):
            continue
        h.update(f"pkg/{rel}\0".encode())
        h.update(p.read_bytes())
        h.update(b"\0")
    for rel, p in _files(rules, rules):
        h.update(f"rules/{rel}\0".encode())
        h.update(p.read_bytes())
        h.update(b"\0")
    for name in sorted(tools):
        h.update(f"tool/{name}={tools[name] or 'missing'}\0".encode())
    return "logic-" + h.hexdigest()[:12]


def tool_versions() -> dict[str, str | None]:
    """Each scanner tool's --version, through the same helpers the scan and Diagnostics
    use (sandboxed; GuardDog with its own environment)."""
    from sniff_test.analyzers import guarddog, osv, python_deps, semgrep

    exe = shutil.which("semgrep")
    return {
        "semgrep": semgrep._version(exe) if exe else None,
        "osv-scanner": osv.osv_version(),
        "guarddog": guarddog.guarddog_version(),
        "uv": python_deps.uv_version(),
    }


@cache
def key() -> str:
    """This Barkley's scan-logic key (worked out once per process)."""
    from sniff_test.analyzers import semgrep

    return fingerprint(Path(__file__).resolve().parent, semgrep.rules_dir(), tool_versions())
