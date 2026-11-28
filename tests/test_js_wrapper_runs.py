"""(0.14.1) js_wrapper asks Semgrep for a file's function list once per scan, and answers a
repeated run (same rules, same files) from the first. Findings must not change: the
end-to-end cases in test_js_wrapper.py run through the same cache.

A fake runner stands in for Semgrep; nothing is parsed or run.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sniff_test.analyzers import js_wrapper


class _Fake:
    """Answers one result per file per rule id in the rules text."""

    def __init__(self, fail: bool = False):
        self.calls: list[tuple[str, tuple[Path, ...]]] = []
        self.fail = fail

    def __call__(self, rules: str, files: list[Path]) -> list[dict]:
        self.calls.append((rules, tuple(files)))
        if self.fail:
            raise subprocess.SubprocessError("boom")
        ids = [
            line.split("- id: ", 1)[1].strip() for line in rules.splitlines() if "- id: " in line
        ]
        return [{"check_id": rid, "path": str(f)} for rid in ids for f in files]


def _with_fns(rules: str) -> bool:
    return "- id: fns" in rules


def test_the_function_list_rides_along_once_per_file(tmp_path):
    a, b = tmp_path / "a.js", tmp_path / "b.js"
    fake = _Fake()
    runs = js_wrapper._Runs(fake)
    first = runs("rules:\n- id: one\n", [a])
    runs("rules:\n- id: two\n", [a])
    third = runs("rules:\n- id: three\n", [a, b])
    # first run: the rules plus `fns`, in one Semgrep run (as before 0.14.1)
    assert fake.calls[0] == ("rules:\n- id: one\n" + js_wrapper._FNS, (a,))
    # a's function list is known after that: no `fns` in the second run
    assert not _with_fns(fake.calls[1][0])
    # b is new, so the third run carries `fns` again
    assert _with_fns(fake.calls[2][0])
    # every answer carries each of its files' function list exactly once
    assert [r["path"] for r in first if r["check_id"] == "fns"] == [str(a)]
    assert [r["path"] for r in third if r["check_id"] == "fns"] == [str(a), str(b)]
    assert [r["check_id"] for r in first if r["check_id"] != "fns"] == ["one"]


def test_the_same_run_twice_is_answered_from_the_first(tmp_path):
    a = tmp_path / "a.js"
    fake = _Fake()
    runs = js_wrapper._Runs(fake)
    one = runs("rules:\n- id: c-O\n", [a])
    two = runs("rules:\n- id: c-O\n", [a])
    assert one == two
    assert len(fake.calls) == 1


def test_an_error_is_raised_and_not_remembered(tmp_path):
    a = tmp_path / "a.js"
    fake = _Fake(fail=True)
    runs = js_wrapper._Runs(fake)
    with pytest.raises(subprocess.SubprocessError):
        runs("rules:\n- id: one\n", [a])
    fake.fail = False
    out = runs("rules:\n- id: one\n", [a])
    assert {r["check_id"] for r in out} == {"one", "fns"}  # asked again, in full


SAMPLE = """\
const C = "/api/x";
function a(u, {C}) { return fetch(C + u); }
const b = (u) => { let C = "https://x.invalid"; return fetch(C, u); };
class K { m(u) { return fetch(`${C}/y`, u); } }
const e = ({C}) => fetch(C);
O(function (u) { return function (v) { fetch(u + v); }; });
"""


def test_a_cached_view_is_the_same_as_a_fresh_one(tmp_path):
    p = tmp_path / "a.js"
    p.write_text(SAMPLE)
    index = js_wrapper._Index(tmp_path)
    path = p.resolve()
    for at in range(len(SAMPLE)):
        text, names = index._view(path, at)
        fresh = js_wrapper.visible(SAMPLE, at)
        assert text == fresh, at
        assert names == js_wrapper.destructured(fresh), at
    assert len(index._views) <= js_wrapper._MAX_VIEWS
