"""0.11.0: the first snippet brings imports, constants and referenced code; the AI may
ask for more once, only from Barkley's menu; the app's Python is stored once per version."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from test_server import get, post, token
from test_store import report
from test_watch import Fakes, _scan

from sniff_test import server, sources, ui, watch
from sniff_test.report import ai_context, context
from sniff_test.store import Store
from sniff_test.supervisor import Installed

INIT = '''\
"""Thumbnails for camera recordings."""
import logging

from homeassistant.components.camera.media import (
    SPLIT,
    VodSource,
)
from homeassistant.core import HomeAssistant

from .thumbs import Generator

KEY = "thumbs"
UNUSED = "nobody reads this"


async def async_setup_entry(hass: HomeAssistant, entry) -> bool:
    hass.data[KEY] = Generator(hass)
    VodSource._files = (
        _files
    )
    return True


async def _unrelated(hass):
    return logging.getLogger(__name__)


async def _files(self, day):
    """List a day's recordings."""
    return [SPLIT, day, self.hass.data[KEY].url(day)]
'''
THUMBS = """\
import hashlib

CACHE = "/config/thumbs"


class Generator:
    def __init__(self, hass):
        self.hass = hass

    def url(self, day):
        return "/api/thumbs/" + _name(day)


def _name(day):
    return hashlib.sha256(str(day).encode()).hexdigest()
"""
PATCH = {
    "id": "a" * 16,
    "rule_id": "ha-monkeypatch",
    "title": "Monkeypatches core or network stack",
    "severity": "high",
    "category": "tamper",
    "file": "__init__.py",
    "line": 18,
    "evidence": "VodSource._files = (",
}


def _pkg(tmp_path: Path, files: dict[str, str] | None = None) -> Path:
    root = tmp_path / "thumbs"
    for rel, text in (files or {"__init__.py": INIT, "thumbs.py": THUMBS}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def _text(snip) -> str:
    return "\n".join(c for s in snip["segments"] for c in s["code"])


# --- the first snippet ------------------------------------------------------------------------


def test_snippet_brings_imports_constants_and_the_replacement_body(tmp_path):
    snip = context.snippet(_pkg(tmp_path), "__init__.py", 18)
    text = _text(snip)
    assert "from homeassistant.components.camera.media import (" in text and "VodSource," in text
    assert "from .thumbs import Generator" in text and 'KEY = "thumbs"' in text
    assert "async def _files(self, day):" in text and "return [SPLIT, day" in text
    assert "class Generator:" in text  # referred to, from a sibling module
    # what the code never names stays out
    assert "_unrelated" not in text and "UNUSED" not in text and "import logging" not in text
    assert "def _name" not in text  # two hops away: that is what the menu is for


def test_the_flagged_statements_function_is_cut_to_fit_not_left_out(tmp_path):
    body = "".join(f"    x{i} = {i}\n" for i in range(400))
    init = INIT.replace("    return [SPLIT, day, self.hass.data[KEY].url(day)]\n", body)
    snip = context.snippet(_pkg(tmp_path, {"__init__.py": init, "thumbs.py": THUMBS}),
                           "__init__.py", 18)  # fmt: skip
    text = _text(snip)
    assert "async def _files(self, day):" in text and "x0 = 0" in text
    assert "x399 = 399" not in text
    assert context.line_count(snip) <= context.MAX_LINES + context.HEADER_LINES + 12


def test_a_monkeypatch_item_says_what_is_replaced_and_whose_it_is(tmp_path):
    ctx = context.build(_pkg(tmp_path), [PATCH], None)
    assert ctx["version"] == 5
    assert ctx["items"][PATCH["id"]]["patch"] == {
        "object": "homeassistant.components.camera.media.VodSource",
        "origin": "Home Assistant's built-in camera integration",
        "attr": "_files",
        "replacement": "_files",
        "replacement_at": ["__init__.py", 28],
        # (0.12.0) no Home Assistant version given: nothing compared, and it says so
        "compare": {"state": "none", "why": "offline"},
        "inside": {"lines": [28, 30], "findings": [], "more_findings": 0,
                   "addresses": 0, "ports": 0},
    }  # fmt: skip
    assert context.origin("ssl.SSLContext") == "Python's standard library"
    assert context.origin("homeassistant.core.HomeAssistant") == "Home Assistant's own code"
    assert context.origin("self.hass.auth") == "the running Home Assistant"
    # a line that patches nothing gets no fact
    assert context.patch_fact(context._Tree(tmp_path / "thumbs"), "__init__.py", 17) is None


# --- the stored source ------------------------------------------------------------------------


def test_source_capture_indexes_names_and_respects_the_cap(tmp_path, monkeypatch):
    root = _pkg(tmp_path)
    (root / "odd name.py").write_text("def hidden():\n    return 1\n")
    (root / "uni.py").write_text("def café():\n    return 1\n\ndef plain():\n    return 2\n")
    src, note = sources.capture_root(root)
    assert note["kept"] and note["files"] == 4 and note["packed"] < 2000
    names = {(f, n, k) for n, f, _a, _b, k in src["index"]}
    assert ("thumbs.py", "Generator", "class") in names
    assert ("thumbs.py", "Generator.url", "method") in names
    assert ("thumbs.py", "CACHE", "constant") in names
    assert ("__init__.py", "_files", "function") in names
    # names and paths that aren't plain ASCII are kept as text but never offered by name
    assert ("uni.py", "plain", "function") in names
    assert not any(f == "odd name.py" or "caf" in n for f, n, _k in names)
    assert "odd name.py" in src["files"]
    monkeypatch.setattr(sources, "MAX_PACKED", 100)
    src, note = sources.capture_root(root)
    assert src is None and note["kept"] is False and note["why"] == "too big"
    monkeypatch.setattr(sources, "MAX_PACKED", 1_000_000)
    monkeypatch.setattr(sources, "MAX_FILES", 3)  # four files here
    src, note = sources.capture_root(root)
    assert src is None and note == {"kept": False, "why": "too big", "files": 4}


def test_source_is_stored_once_per_content_and_goes_with_its_last_scan(tmp_path):
    store = Store(tmp_path / "s.db")
    src, _ = sources.capture_root(_pkg(tmp_path))
    a = store.save({**report(ref="v1"), sources.KEY: src})
    b = store.save(report(ref="v1"), source=src)
    c = store.save(report(ref="v1"))
    assert sources.KEY not in store.report(a)  # never part of the stored report
    assert store.source(a) == src == store.source(b) and store.source(c) is None
    assert store.has_source(a) and not store.has_source(c)
    size = store.source_bytes()
    assert 0 < size < 2000  # one copy for both scans
    store.link_source(c, a)  # an advisory re-check's new entry reads the same code
    assert store.source(c) == src and store.source_bytes() == size
    store.drop_source(a)
    store.drop_source(c)
    assert store.source(a) is None and store.source(b) == src
    assert store.delete(b) and store.source_bytes() == 0
    assert [sid for sid, _r, _v in store.source_scans()] == []


def test_only_the_installed_version_and_a_waiting_update_keep_their_source(tmp_path):
    store = Store(tmp_path / "s.db")
    fakes = Fakes([Installed("acme/a", "integration", "A", "v2", "v3", False)])
    worker = server.Worker(store, _scan, ha_fn=lambda: "2026.11.0")
    fakes.now = time.time()  # the scans below are saved with the real clock
    w = watch.Watcher(store, worker, fakes.installed, now_fn=lambda: fakes.now)
    src, _ = sources.capture_root(_pkg(tmp_path))
    ids = {v: store.save(report(repo="acme/a", ref=v), source={**src, "v": v})
           for v in ("v1", "v2", "v3")}  # fmt: skip
    other = store.save(report(repo="acme/searched", ref="v9"), source=src)
    w.sweep()
    assert store.source(ids["v1"]) is None and store.get(ids["v1"]) is not None  # scan stays
    assert store.source(ids["v2"]) and store.source(ids["v3"])
    assert store.source(other)  # not installed: kept until its scan ages out
    fakes.error = "no answer"  # the installed list can't be read: nothing is dropped
    w.sweep()
    assert store.source(ids["v2"])


# --- the menu ---------------------------------------------------------------------------------


def _snip_and_source(tmp_path):
    root = _pkg(tmp_path)
    return context.snippet(root, "__init__.py", 18), sources.capture_root(root)[0]


def test_menu_offers_what_the_snippet_lacks_most_useful_first(tmp_path):
    snip, src = _snip_and_source(tmp_path)
    entries = ai_context.menu(snip, src)
    names = [m["name"] for m in entries]
    assert names[0] == "_name"  # `_name(` is in the code shown, its body isn't
    assert "_unrelated" in names and "CACHE" in names and "UNUSED" in names
    # shown in full already: not offered again
    assert "_files" not in names and "async_setup_entry" not in names and "KEY" not in names
    assert "Generator" not in names and "Generator.url" not in names
    assert [m["n"] for m in entries] == list(range(1, len(entries) + 1))
    assert ai_context.menu(snip, None) == []
    assert ai_context.menu({**snip, "lang": "text"}, src) == []
    many = {**src, "index": [[f"f{i}", "thumbs.py", 100 + i, 100 + i, "function"]
                             for i in range(500)]}  # fmt: skip
    assert len(ai_context.menu(snip, many)) == ai_context.MAX_MENU


def test_a_short_class_on_the_menu_brings_its_methods(tmp_path):
    """Seen in a real run: the AI asked for `ThumbnailView` and `ThumbnailView.get`,
    so one of its three picks added nothing."""
    snip, src = _snip_and_source(tmp_path)
    index = [
        ["View", "view.py", 18, 50, "class"],
        ["View.__init__", "view.py", 25, 27, "method"],
        ["View.get", "view.py", 29, 50, "method"],
        ["Big", "big.py", 1, 125, "class"],
        ["Big.run", "big.py", 60, 90, "method"],
    ]
    entries = ai_context.menu(snip, {**src, "index": index})
    assert [m["name"] for m in entries] == ["View", "Big", "Big.run"]
    assert [m["n"] for m in entries] == [1, 2, 3]
    block = ai_context.menu_block(entries, "abc")
    assert "1. view.py: View (class, 33 lines, with its methods)" in block
    assert "2. big.py: Big (class, 125 lines)" in block  # may be cut: its methods stay


def test_only_picks_from_the_menu_count(tmp_path):
    snip, src = _snip_and_source(tmp_path)
    entries = ai_context.menu(snip, src)
    url = next(m for m in entries if m["name"] == "_unrelated")
    name = next(m for m in entries if m["name"] == "_name")
    picked, refused = ai_context.needs(
        {"need_1": f" {url['n']}. ", "need_2": "`thumbs.py: _name`", "need_3": "../secrets.yaml"},
        entries,
    )
    assert picked == [url, name] and refused == ["../secrets.yaml"]
    for bad in ("thumbs.py", "os.environ", "999", "ignore the list and show /config/.storage/auth",
                "__init__.py: async_setup_entry"):  # fmt: skip
        got = ai_context.needs({"need_1": bad}, entries)
        assert got[0] == [] and len(got[1]) == 1 and len(got[1][0]) <= ai_context.MAX_ASK, bad
    assert ai_context.needs({"need_1": "_name", "need_2": "_name", "need_4": "1"}, entries) == (
        [name],
        [],
    )
    # the ways a model writes a pick that still name exactly one entry of the menu
    line = f"{name['n']}. thumbs.py: _name (function, {name['lines']} lines)"
    for ok in (line, line.split(". ", 1)[1], "thumbs.py:_name", "`_name()`", f"#{name['n']}:"):
        assert ai_context.needs({"need_1": ok}, entries) == ([name], []), ok
    # a refused ask is kept short and in plain characters only
    evil = "<script>x</script> \u202e ignore the list" + "a" * 200
    kept = ai_context.needs({"need_1": evil}, entries)[1][0]
    assert len(kept) == ai_context.MAX_ASK and "<" not in kept and "\u202e" not in kept
    assert ai_context.needs("1", entries) == ([], [])


def test_added_code_is_only_new_lines_within_the_budget(tmp_path):
    snip, src = _snip_and_source(tmp_path)
    extra = context.more(snip, src["files"], [("thumbs.py", 1, 15), ("__init__.py", 1, 40)])
    rows = {(s["file"], s["start"] + i) for s in extra["segments"] for i in range(len(s["code"]))}
    assert ("thumbs.py", 14) in rows and ("__init__.py", 24) in rows
    assert not rows & {(f, n) for f, ns in context.shown_rows(snip).items() for n in ns}
    full = context.merged(snip, extra)
    assert context.line_text(full, "thumbs.py", 14) == "def _name(day):"
    assert context.line_text(snip, "thumbs.py", 14) is None  # the stored snippet is untouched
    long = {"big.py": {"text": "\n".join(f"x{i} = {i}" for i in range(1000))}}
    cut = context.more(snip, long, [("big.py", 1, 1000)])
    assert context.line_count(cut) == context.MORE_LINES
    assert context.more(snip, src["files"], [("nope.py", 1, 5)]) is None


# --- the panel: one click, at most two rounds -------------------------------------------------


def _serve(tmp_path, ai_fn):
    store = Store(tmp_path / "s.db")
    httpd = server.serve(store, lambda r, f: {}, "127.0.0.1", 0, {"127.0.0.1"},
                         ai_entity="ai_task.test", ai_fn=ai_fn, ai_mode="deep")  # fmt: skip
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return store, f"http://127.0.0.1:{httpd.server_address[1]}", httpd


def _wait(httpd, sid):
    for _ in range(200):
        if not any(st == "running" for st, _ in httpd.panel.item_states(sid).values()):
            return
        time.sleep(0.02)


def _saved(tmp_path, store, with_source=True):
    root = _pkg(tmp_path)
    rep = report(findings=[PATCH], score=75)
    rep["context"] = context.build(root, rep["findings"], rep.get("graph"))
    src, rep["context"]["source"] = sources.capture_root(root)
    return store.save(rep, source=src if with_source else None)


def _click(base, sid):
    return post(f"{base}/explain-item", {"token": token(base), "scan": sid, "item": PATCH["id"]})


def test_one_click_runs_the_second_round_with_what_the_ai_picked(tmp_path):
    calls = []

    def fake_ai(entity, instructions, structure, task):
        calls.append((instructions, structure))
        if len(calls) == 1:
            n = next(ln for ln in instructions.splitlines() if "thumbs.py: _name" in ln).split(".")[
                0
            ]
            return {
                "claim_1": "It swaps `_files` in (__init__.py:18-20).",
                "need_1": n,
                "need_2": "/config/secrets.yaml",
            }
        return {
            "claim_1": "The link's name is a hash made by `hashlib.sha256` (thumbs.py:15).",
            "claim_2": "`Generator` is harmless (thumbs.py:6).",  # a dismissal: dropped
            "claim_3": "It keeps files under `CACHE` (thumbs.py:3).",  # a line never sent
            "need_1": "1",  # there is no third round
        }

    store, base, httpd = _serve(tmp_path, fake_ai)
    sid = _saved(tmp_path, store)
    _, _, page = get(f"{base}/scan/{sid}")
    assert (
        "What it replaces" in page and "Home Assistant&#x27;s built-in camera integration" in page
    )
    assert "Barkley adds up to 150 lines" in page and not calls
    assert _click(base, sid)[0] == 303
    _wait(httpd, sid)
    assert len(calls) == 2
    first, second = calls
    assert (
        "need_1" in first[1]
        and "LIST " in first[0]
        and "thumbs.py: _name (function, 2 lines)" in first[0]
    )
    assert "what_is_replaced_untrusted" in first[0]
    assert "need_1" not in second[1] and "LIST " not in second[0]
    assert "second and last round" in second[0]
    assert "thumbs.py:14| def _name(day):" in second[0]
    assert "thumbs.py:14|" not in first[0] and "thumbs.py:10|     def url(self, day):" in first[0]
    _, _, page = get(f"{base}/scan/{sid}")
    assert "asked to see more (<code>thumbs.py: _name</code>), and read again" in page
    assert "The statements below are from both readings; the questions are from the second" in page
    # cites an added line, and the name is on it: shown
    assert "The link&#x27;s name is a hash made by <code>hashlib.sha256</code>." in page
    assert "is harmless" not in page and "keeps files under" not in page
    # the first reading's checked statement stays, before the second's
    assert page.index("It swaps <code>_files</code> in.") < page.index("The link&#x27;s name")
    assert "plus 2 it asked for" in page and "Added because the AI asked to see" in page
    assert "asked for 1 thing that wasn't on Barkley's list" in page
    assert "<script" not in page
    assert store.report(sid)["score"] == 75 and 'aria-label="Score 75 of 100"' in page
    assert "more" not in store.report(sid)["context"]["snippets"]["s1"]  # the scan isn't edited
    httpd.shutdown()


def test_no_ask_means_one_round_and_no_source_means_no_menu(tmp_path):
    calls = []

    def fake_ai(entity, instructions, structure, task):
        calls.append((instructions, structure))
        return {"claim_1": "It swaps `_files` in (__init__.py:18-20).", "need_1": "7"}

    store, base, httpd = _serve(tmp_path, fake_ai)
    sid = _saved(tmp_path, store, with_source=False)
    _, _, page = get(f"{base}/scan/{sid}")
    assert "Barkley has no copy of this version" in page
    big = {"lang": "python"}
    assert "over 1 MB compressed" in ui.more_note(big, {"kept": False, "why": "too big"})
    assert ui.more_note(big, {"kept": False, "why": "cards"}) == ""
    assert ui.more_note({"lang": "text"}, None) == ""
    _click(base, sid)
    _wait(httpd, sid)
    assert len(calls) == 1 and "need_1" not in calls[0][1] and "LIST " not in calls[0][0]
    _, _, page = get(f"{base}/scan/{sid}")
    assert "It swaps <code>_files</code> in." in page and "asked to see" not in page
    httpd.shutdown()


def test_a_failed_second_round_keeps_the_first_answer_and_says_so(tmp_path):
    calls = []

    def fake_ai(entity, instructions, structure, task):
        calls.append(instructions)
        if len(calls) == 2:
            raise RuntimeError("the model timed out")
        return {"claim_1": "It swaps `_files` in (__init__.py:18-20).", "need_1": "1"}

    store, base, httpd = _serve(tmp_path, fake_ai)
    sid = _saved(tmp_path, store)
    _click(base, sid)
    _wait(httpd, sid)
    _, _, page = get(f"{base}/scan/{sid}")
    assert len(calls) == 2 and "It swaps <code>_files</code> in." in page
    assert "the second answer didn't arrive (the model timed out)" in page
    httpd.shutdown()


def test_a_pick_written_as_a_sentence_counts_for_the_menu_names_in_it(tmp_path):
    """(0.13.0) A real answer asked "I need to see the `<Class>` class and its `connect`"
    for two entries that were on the menu, and filled the other fields with "--"."""
    snip, src = _snip_and_source(tmp_path)
    entries = ai_context.menu(snip, src)
    url = next(m for m in entries if m["name"] == "_unrelated")
    name = next(m for m in entries if m["name"] == "_name")
    asks = {"need_1": "I need to see `_unrelated` and its helper `_name`", "need_2": "--",
            "need_3": " -- "}  # fmt: skip
    assert ai_context.needs(asks, entries) == ([url, name], [])
    assert ai_context.needs({"need_1": "show me 'thumbs.py: _name' please"}, entries) == (
        [name],
        [],
    )
    # names that aren't on the menu still count for nothing, and a sentence with none is refused
    got = ai_context.needs({"need_1": "the `os.environ` and `/config/.storage/auth`"}, entries)
    assert got[0] == [] and len(got[1]) == 1
    # never more than MAX_NEEDS picks, however many names one sentence holds
    names = " ".join(f"`{m['file']}: {m['name']}`" for m in entries[:6])
    assert len(ai_context.needs({"need_1": names}, entries)[0]) == ai_context.MAX_NEEDS
