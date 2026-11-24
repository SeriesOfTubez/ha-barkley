"""(0.14.0 part 3) Barkley's Settings page: what a user can change, with Barkley's
defaults (the standing rule: where a user should have control over a behaviour or a
score, Barkley ships a default plus a setting). Stored by Barkley in its own store, the
same in the add-on and standalone.

The add-on's options (and standalone's BARKLEY_* variables) are where the values start:
each one counts until the user saves the Settings page, which then stores every value and
wins from then on (the same rule the AI and auto-sniff choices already followed).

The GitHub token never goes in the database: it's written to its own file next to it,
mode 600, read once into the process environment, and never shown again. The page only
says whether one is set.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path
from typing import Any

KEY = "settings"
TOKEN_FILE = "github-token"  # noqa: S105 - a file name, not a secret
_TOKEN = re.compile(r"[A-Za-z0-9_]{20,255}")


@dataclass(frozen=True)
class Settings:
    # Scoring
    exposure: str = "local"  # local | public
    # (0.15) minor items (kinds.MINOR) on an app's page: hidden with a "Show them" link
    # unless this is on (Paranoid mode before; with no score it only decides what's shown)
    show_minor: bool = False
    # Checking (parallel and jobs: the add-on's defaults)
    parallel: int = 2
    jobs: int = 1
    # (0.14.0) memory Barkley may give scans, in GB; 0 is Auto (what's free, less a reserve)
    memory_gb: int = 0
    # (0.15, #20) scans don't start with less free than this, in MB; 0: never refused
    memory_floor_mb: int = 1024
    # (0.14.1) analyzers/libraries.py: unchanged published npm files aren't read as code
    libraries: bool = True
    # (0.14.1) disk for answers about code already read (scancache), in MB; 0: off
    cache_mb: int = 1024
    # Standalone: how often Barkley replaces its own Home Assistant token (ha_token.py)
    token_days: int = 60
    # (preview 2026-11-19, the default in 0.15) where Home Assistant runs, for the Exposure
    # reading. The page shows it with `exposure` as one choice: home, shared or work
    # network, or reachable from the internet (exposure "public")
    network: str = "home"  # home | shared
    # (0.15, his report) months without a push after which an app's page and card say the
    # project has gone quiet; 0: never say it. Context only, never a reading.
    quiet_months: int = 12
    # (0.15, #29) which auto-sniff results notify: all | medium | high | threat (Exposure
    # at or above that level, or any sign of malicious behavior). A sniff that didn't
    # finish or couldn't run always notifies.
    notify_when: str = "all"
    # (0.15, his decision 2026-11-22) Threat points for a build tool known to be malware
    # (it runs on the developer's machine while building and could change what ships):
    # 2.5 is "possible", like any high sign
    build_tool_points: str = "2.5"
    # (0.15, his design 2026-11-23) AI answers: how much of the developer's text one request
    # may carry (ai_words.SIZES; docstrings and sentences follow), and how long Barkley
    # waits for an answer: ai_minutes when ai_limit is on, as long as the model takes when
    # it's off. Picking a size fills in its paired minutes (3, 6, 9); the minutes stay the
    # user's to edit.
    ai_size: int = 12000
    ai_limit: bool = True
    ai_minutes: int = 6

    @property
    def where(self) -> str:
        return "internet" if self.exposure == "public" else self.network


WHERE = ("home", "shared", "internet")


def where_values(where: str) -> dict[str, str]:
    """The one "Where Home Assistant runs" choice as the two stored values."""
    if where == "internet":
        return {"exposure": "public"}
    return {"exposure": "local", "network": where} if where in WHERE else {}


DEFAULTS = Settings()
# "Reset to defaults" per section of the page
PARTS = {
    "readings": (
        "exposure",
        "network",
        "show_minor",
        "quiet_months",
        "build_tool_points",
    ),
    "checking": (
        "parallel",
        "jobs",
        "memory_gb",
        "memory_floor_mb",
        "libraries",
        "cache_mb",
        "token_days",
        "ai_size",
        "ai_limit",
        "ai_minutes",
    ),
}
# the minutes that go with each size (his design: 6,000 / 3 min, 12,000 / 6, 18,000 / 9)
AI_PAIRED_MINUTES = {6000: 3, 12000: 6, 18000: 9}


def describe(s: Settings) -> str:
    """One log line: the values that differ from Barkley's defaults."""
    diff = [f"{k}={v}" for k, v in asdict(s).items() if getattr(DEFAULTS, k) != v]
    return ", ".join(diff) or "Barkley's defaults"


CHOICES: dict[str, tuple[Any, ...]] = {
    "exposure": ("local", "public"),
    "network": ("home", "shared"),
    "parallel": (1, 2, 3, 4),
    "jobs": (1, 2, 3, 4),
    "memory_gb": (0, 2, 3, 4, 6, 8, 12, 16),
    "memory_floor_mb": (1024, 512, 0),
    "cache_mb": (0, 512, 1024, 2048, 4096),
    "token_days": (30, 60, 90, 180),
    "quiet_months": (0, 6, 12, 24, 36),
    "notify_when": ("all", "medium", "high", "threat"),
    "build_tool_points": ("2", "2.5", "3"),
    "ai_size": (6000, 12000, 18000),
    "ai_minutes": tuple(range(1, 61)),
}


def _coerce(name: str, value: Any, default: Any) -> Any:
    if isinstance(default, bool):
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "on", "yes")
    if isinstance(default, int):
        try:
            v = int(value)
        except (TypeError, ValueError):
            return default
        return v if v in CHOICES.get(name, (v,)) else default
    v = str(value)
    return v if v in CHOICES.get(name, (v,)) else default


def from_dict(raw: dict[str, Any], base: Settings = DEFAULTS) -> Settings:
    """Known keys only, each checked; anything else keeps `base`'s value."""
    if "where" in raw:  # the page's one choice for where Home Assistant runs
        raw = {**raw, **where_values(str(raw["where"]))}
    vals = {}
    for f in fields(Settings):
        if f.name in raw:
            vals[f.name] = _coerce(f.name, raw[f.name], getattr(base, f.name))
    return replace(base, **vals)


def load(store: Any, start: Settings = DEFAULTS) -> Settings:
    """`start`: the values from the add-on options or the BARKLEY_* variables."""
    text = store.setting(KEY)
    if not text:
        return start
    try:
        raw = json.loads(text)
    except ValueError:
        return start
    return from_dict(raw, start) if isinstance(raw, dict) else start


def save(store: Any, s: Settings) -> None:
    store.set_setting(KEY, json.dumps(asdict(s), sort_keys=True))


def saved(store: Any) -> bool:
    return bool(store.setting(KEY))


# --- the GitHub token (never in the database) ---------------------------------------------


def token_path(store_path: Path) -> Path:
    return Path(store_path).parent / TOKEN_FILE


def valid_token(token: str) -> bool:
    """GitHub's token shapes (ghp_/github_pat_/gho_… and the old 40-hex), nothing else."""
    return bool(_TOKEN.fullmatch(token))


def set_token(store_path: Path, token: str) -> bool:
    token = token.strip()
    if not valid_token(token):
        return False
    path = token_path(store_path)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token)
    tmp.replace(path)
    os.environ["GITHUB_TOKEN"] = token
    return True


def remove_token(store_path: Path, option_token: str = "") -> None:
    """Back to the add-on option's token, if there is one, else none."""
    with contextlib.suppress(FileNotFoundError):
        token_path(store_path).unlink()
    if option_token:
        os.environ["GITHUB_TOKEN"] = option_token
    else:
        os.environ.pop("GITHUB_TOKEN", None)


def apply_token(store_path: Path) -> bool:
    """At start: a token saved on the Settings page wins over the add-on option."""
    try:
        token = token_path(store_path).read_text(encoding="utf-8")[:512].strip()
    except OSError:
        return False
    if valid_token(token):
        os.environ["GITHUB_TOKEN"] = token
        return True
    return False


def token_source(store_path: Path) -> str:
    """ "settings", "option" (the add-on's own field or GITHUB_TOKEN), "file"
    (GITHUB_TOKEN_FILE) or "" (none)."""
    if token_path(store_path).exists():
        return "settings"
    if os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"):
        return "option"
    return "file" if os.environ.get("GITHUB_TOKEN_FILE") else ""
