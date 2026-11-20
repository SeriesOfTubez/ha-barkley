"""(0.14.0) Item 13: only the failed file is retried, with growing waits, and a failure
that remains is said in plain English. Offline: every response here is a fake."""

from __future__ import annotations

import io
import urllib.error
from email.message import Message

import pytest

from sniff_test.analyzers import guarddog, python_deps
from sniff_test.analyzers.python_deps import Resolution, ResolvedPackage
from sniff_test.deps.uv import Artifact
from sniff_test.fetch import github, http, retry


@pytest.fixture
def waits(monkeypatch):
    got: list[float] = []
    now = [0.0]

    def sleep(s: float) -> None:
        got.append(s)
        now[0] += s

    monkeypatch.setattr(retry, "sleep", sleep)
    monkeypatch.setattr(retry, "clock", lambda: now[0])
    return got


def _http_error(code: int, after: str | None = None) -> http.HttpError:
    err = http.HttpError(f"HTTP {code} for https://pypi.org/x")
    err.status = code
    err.retry_after = float(after) if after else None
    return err


def test_a_timeout_is_retried_with_growing_waits(waits):
    calls = []

    def fn():
        calls.append(1)
        if len(calls) < 3:
            raise http.HttpError("timed out") from TimeoutError()
        return "ok"

    assert retry.attempt(fn, file="a.whl", source="files.pythonhosted.org") == "ok"
    assert len(calls) == 3
    assert 2 <= waits[0] <= 3 and 6 <= waits[1] <= 9  # 2 s then 6 s, plus jitter


@pytest.mark.parametrize("code", [404, 403, 410])
def test_a_missing_or_refused_file_is_never_retried(waits, code):
    def fn():
        raise http.NotFoundError("HTTP 404 for x") if code == 404 else _http_error(code)

    with pytest.raises(http.HttpError) as exc:
        retry.attempt(fn, file="a.whl", source="pypi.org")
    assert waits == [] and exc.value.failure.tries == 1
    assert exc.value.failure.kind == ("not_found" if code == 404 else "other")


def test_retry_after_is_honoured_and_a_long_one_gives_up(waits):
    n = []

    def busy():
        n.append(1)
        if len(n) == 1:
            raise _http_error(429, "30")
        return "ok"

    assert retry.attempt(busy, file="x", source="pypi.org") == "ok"
    assert waits == [30.0]

    def very_busy():
        raise _http_error(503, "3600")

    with pytest.raises(http.HttpError) as exc:
        retry.attempt(very_busy, file="x", source="pypi.org")
    assert exc.value.failure.kind == "busy" and "asked to wait 3600 s" in exc.value.failure.error


def test_a_checksum_mismatch_is_retried_once(waits):
    def bad():
        err = http.HttpError("sha256 mismatch")
        err.kind = "checksum"
        raise err

    with pytest.raises(http.HttpError) as exc:
        retry.attempt(bad, file="a.whl", source="files.pythonhosted.org")
    assert exc.value.failure.tries == 2 and len(waits) == 1


def test_the_plain_reason_says_what_where_how_often_and_what_it_means():
    f = retry.Failure("multidict-6.7.0-cp314.whl", "files.pythonhosted.org", 3, 27.4,
                      "timeout", "timed out after 60 s")  # fmt: skip
    text = f.plain()
    for part in ("multidict-6.7.0-cp314.whl", "files.pythonhosted.org", "didn't answer in time",
                 "timed out after 60 s", "Tried 3 times over 27 seconds", "unfinished",
                 "capped at 89", "sniff it again later"):  # fmt: skip
        assert part in text
    once = retry.plain({"file": "a", "source": "b", "tries": 1, "kind": "too_big", "error": "e"})
    assert "Tried once" in once and "won't change" in once


# --- the real download path, with a fake connection ----------------------------------


class _Resp(io.BytesIO):
    def __init__(self, data: bytes, cut: bool = False):
        super().__init__(data)
        self.cut = cut

    def read(self, n=-1):
        chunk = super().read(n)
        if self.cut and self.tell() >= len(self.getvalue()):
            raise ConnectionResetError("Connection reset by peer")
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_a_dropped_download_retries_only_that_file(tmp_path, monkeypatch, waits):
    import hashlib

    data = b"wheel bytes" * 100
    digest = hashlib.sha256(data).hexdigest()
    opened = []

    def fake_open(url):
        opened.append(url)
        return _Resp(data, cut=len(opened) == 1)

    monkeypatch.setattr(http, "_open", fake_open)
    dest = tmp_path / "a.whl"
    assert http.download("https://files.pythonhosted.org/p/a.whl", dest, digest) == digest
    assert dest.read_bytes() == data and len(opened) == 2 and len(waits) == 1


def test_fetch_artifact_keeps_the_reason(tmp_path, monkeypatch, waits):
    def fake_open(url):
        raise http.HttpError(f"network error for {url}: [Errno 61] Connection refused") from (
            urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))
        )

    monkeypatch.setattr(http, "_open", fake_open)
    art = Artifact("https://files.pythonhosted.org/p/a-1.0-py3-none-any.whl",
                   "a-1.0-py3-none-any.whl", "0" * 64, "wheel")  # fmt: skip
    assert python_deps.fetch_artifact(art, tmp_path) is None
    assert art.failure["kind"] == "network" and art.failure["tries"] == retry.TRIES
    assert art.failure["source"] == "files.pythonhosted.org"
    assert "Connection refused" in retry.plain(art.failure)
    assert not list((tmp_path / "dists").glob("*.whl"))  # no partial file left


def test_guarddog_makes_a_last_pass_and_reports_what_still_failed(tmp_path, monkeypatch):
    flaky = Artifact("https://files.pythonhosted.org/f.whl", "f.whl", "1" * 64, "wheel")
    dead = Artifact("https://files.pythonhosted.org/d.whl", "d.whl", "2" * 64, "wheel")
    tries = {"f.whl": 0, "d.whl": 0}

    def fake_fetch(art, work):
        tries[art.filename] += 1
        if art.filename == "f.whl" and tries["f.whl"] > 1:
            return tmp_path
        art.failure = {"file": art.filename, "source": "files.pythonhosted.org", "tries": 3,
                       "seconds": 9.0, "kind": "timeout", "error": "timed out"}  # fmt: skip
        return None

    monkeypatch.setattr(guarddog, "fetch_artifact", fake_fetch)
    monkeypatch.setattr(guarddog.shutil, "which", lambda _x: "/bin/guarddog")
    monkeypatch.setattr(guarddog, "tool_env", lambda _exe: {})
    monkeypatch.setattr(guarddog, "guarddog_version", lambda: "test")
    monkeypatch.setattr(guarddog, "neutralize_ignores", lambda _p: None)
    monkeypatch.setattr(guarddog, "_scan", lambda *a, **k: ({"results": {}}, "", True))
    res = Resolution()
    for name, art in (("f", flaky), ("d", dead)):
        res.packages[(name, "1")] = ResolvedPackage(name, "1", artifacts={art.filename: art})
    out = guarddog.run(res, tmp_path)
    assert tries == {"f.whl": 2, "d.whl": 2}  # the last pass reached both
    assert [p["file"] for p in out.problems] == ["d.whl"]
    assert str(out.state) == "error"


# --- GitHub: transient errors retried, never the rate limit --------------------------


def _gh_http(code: int, headers: dict[str, str] | None = None) -> urllib.error.HTTPError:
    msg = Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError("https://api.github.com/x", code, "err", msg, None)


def test_github_retries_a_502_but_never_the_rate_limit(monkeypatch, waits):
    seq = [_gh_http(502), "ok"]

    class Opener:
        def open(self, req, timeout):
            item = seq.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

    gh = github.GitHub(token="t")
    monkeypatch.setattr(gh, "_opener", lambda: Opener())
    assert gh._request("https://api.github.com/x") == "ok" and len(waits) == 1

    seq[:] = [_gh_http(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "99"}), "ok"]
    with pytest.raises(github.RateLimitError):
        gh._request("https://api.github.com/x")
    assert len(waits) == 1 and seq == ["ok"]  # not retried


def test_the_panel_says_why_in_plain_english():
    from sniff_test import ui

    a = {"name": "guarddog", "state": "error", "detail": "d.whl: timeout: <b>",
         "problems": [{"file": "d<x>.whl", "source": "files.pythonhosted.org", "tries": 3,
                       "seconds": 40, "kind": "timeout", "error": "timed out"}]}  # fmt: skip
    html = ui._missing_html(a)
    assert "It couldn't fetch 1 file" in html and "Tried 3 times over 40 seconds" in html
    assert "d&lt;x&gt;.whl" in html and "<b>" not in html.split("</b>", 1)[1]
