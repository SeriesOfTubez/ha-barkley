"""(0.14.0) Retrying one failed request, and saying in plain English why it still failed.

A dropped connection used to leave a scan unfinished with "download/extract failed".
Now only the failed request is repeated, with growing waits plus jitter, and only for
errors that can pass: timeouts, dropped or refused connections, a cut-off file, HTTP 5xx,
408 and 429 (a `Retry-After` is honoured up to a cap), and a checksum mismatch once.
Never a 404, another 4xx, a file over the size limit, or a host off the allowlist.

When it still fails, the error carries a `Failure`: which file, from where, how many tries
over how long, the actual error, and `plain()` says what that means. A failure is never a
scan result: the scan stays unfinished, as before. GitHub's rate limit is not handled
here (the worker waits for its reset; fetch/github.RateLimitError is never retried).
"""

from __future__ import annotations

import contextlib
import http.client
import random
import socket
import ssl
import time
import urllib.error
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

TRIES = 3  # the first request and two retries
BASE_WAIT = 2.0  # seconds: 2, 6, 18 … (times 3), plus up to 50% jitter
MAX_WAIT = 120.0  # a Retry-After longer than this is not waited for

# Test hooks: the waits and the clock.
sleep: Callable[[float], None] = time.sleep
clock: Callable[[], float] = time.monotonic


@dataclass(frozen=True)
class Failure:
    """What went wrong with one file, kept in the report as data (never from the code)."""

    file: str
    source: str  # the host it came from
    tries: int
    seconds: float
    # timeout | network | server | busy | not_found | checksum | too_big | unsafe |
    # refused | other
    kind: str
    error: str  # the actual error, short

    def as_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "source": self.source,
            "tries": self.tries,
            "seconds": round(self.seconds, 1),
            "kind": self.kind,
            "error": self.error[:300],
        }

    def plain(self) -> str:
        return plain(self.as_dict())


_WHAT = {
    "timeout": "the server didn't answer in time",
    "network": "the connection failed",
    "server": "the server had an error",
    "busy": "the server asked us to slow down",
    "not_found": "the file isn't there any more (it may have been removed from the registry)",
    "checksum": "the file we received didn't match the checksum the registry publishes for "
    "it, so nothing from it was used",
    "too_big": "it's bigger than the size limit for one file",
    "unsafe": "the archive holds entries Barkley won't unpack (links, or paths that would "
    "land outside its folder)",
    "refused": "its address isn't one of the package hosts Barkley fetches from",
}
_NEXT = {
    "timeout": "This is usually temporary: sniff it again later.",
    "network": "This is usually temporary: sniff it again later.",
    "server": "This is usually temporary: sniff it again later.",
    "busy": "Sniff it again in a while.",
    "not_found": "If it keeps happening, the app asks for a version that's gone; only its "
    "developer can fix that.",
    "checksum": "Sniff it again later. If it keeps happening, the file on the registry may "
    "have been changed after it was published.",
    "too_big": "Sniffing again won't change this.",
    "unsafe": "Sniffing again won't change this.",
    "refused": "Sniffing again won't change this.",
}


def _duration(seconds: float) -> str:
    s = round(seconds)
    if s < 2:
        return "about a second"
    if s < 90:
        return f"{s} seconds"
    return f"{round(s / 60)} minutes"


def plain(d: dict[str, Any]) -> str:
    """A stored failure (Failure.as_dict) in plain English: which file, from where, how
    many tries over how long, the actual error, and what that means for the scan."""
    kind = str(d.get("kind", "other"))
    what = _WHAT.get(kind, "it couldn't be fetched")
    tries = int(d.get("tries") or 1)
    when = (
        f"Tried {tries} times over {_duration(float(d.get('seconds') or 0))}"
        if tries > 1
        else "Tried once (retrying wouldn't help)"
    )
    return (
        f"{d.get('file')} from {d.get('source')}: {what} ({d.get('error')}). {when}. "
        "Its code wasn't checked, so this scan is unfinished and its score is capped at 89. "
        + _NEXT.get(kind, "Sniff it again later.")
    )


_NETWORK = (
    ConnectionError,
    http.client.IncompleteRead,
    http.client.RemoteDisconnected,
    ssl.SSLError,
    socket.gaierror,
    urllib.error.URLError,
)


def classify(exc: BaseException) -> tuple[str, bool, float | None]:
    """(kind, worth retrying, Retry-After seconds)."""
    status = getattr(exc, "status", None)
    kind = getattr(exc, "kind", None)
    if kind in ("not_found", "too_big", "refused", "unsafe"):
        return kind, False, None
    if kind == "checksum":
        return kind, True, None
    if isinstance(status, int):
        after = getattr(exc, "retry_after", None)
        if status == 429 or (status == 503 and after is not None):
            return "busy", True, after
        if status >= 500 or status == 408:
            return "server", True, after
        return "other", False, None
    cause = exc.__cause__ or exc.__context__ or exc
    for e in (exc, cause, getattr(cause, "reason", None)):
        if isinstance(e, (TimeoutError, socket.timeout)):
            return "timeout", True, None
    for e in (exc, cause, getattr(cause, "reason", None)):
        if isinstance(e, _NETWORK):
            return "network", True, None
    return "other", False, None


def attempt[T](
    fn: Callable[[], T],
    *,
    file: str,
    source: str,
    tries: int = TRIES,
    retry: tuple[type[BaseException], ...] = (Exception,),
    never: tuple[type[BaseException], ...] = (),
) -> T:
    """`fn()`, repeated on transient errors. The last error is re-raised with a `failure`
    attribute (a Failure). `never` errors pass straight through, untouched."""
    start = clock()
    checksum_seen = False
    n = 0
    while True:
        n += 1
        try:
            return fn()
        except never:
            raise
        except retry as exc:
            kind, transient, after = classify(exc)
            if kind == "checksum":
                transient = not checksum_seen  # a mismatch is retried once
                checksum_seen = True
            wait = BASE_WAIT * (3 ** (n - 1)) * (1 + random.random() / 2)  # noqa: S311 - jitter
            if after is not None:
                wait = max(wait, after)
            if not transient or n >= tries or wait > MAX_WAIT:
                error = str(exc) or type(exc).__name__
                if after is not None and wait > MAX_WAIT:
                    error += f" (asked to wait {round(after)} s)"
                with contextlib.suppress(AttributeError):
                    exc.failure = Failure(file, source, n, clock() - start, kind, error)  # type: ignore[attr-defined]
                raise
            sleep(wait)
