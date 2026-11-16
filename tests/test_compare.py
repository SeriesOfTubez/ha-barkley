"""0.12.0: a replaced Home Assistant function is compared with its replacement by Barkley;
the README is read as what the app says it does; the AI may only say that the code is
consistent with the README, as a labelled opinion, and never for data leaving the box."""

from __future__ import annotations

import pytest
from test_more_code import INIT, PATCH, THUMBS, _click, _pkg, _serve, _wait
from test_server import get
from test_store import report

from sniff_test import sources, ui
from sniff_test.deps import ha_env
from sniff_test.fetch.github import GitHubError, RateLimitError
from sniff_test.report import ai_context, compare, context, explain

HA_PATH = "homeassistant/components/camera/media.py"
# Home Assistant's side: a method, indented, written for Python 3.14 (`except A, B:`).
HA_FILE = '''\
"""Camera media."""

SPLIT = "|"


class VodSource:
    """Recordings of a camera."""

    def other(self):
        try:
            return 1
        except KeyError, ValueError:
            return 0

    async def _files(self, day):
        """List a day's recordings."""
        # the plain list
        return [SPLIT, day]
'''
README = """\
# Thumbs

Shows a thumbnail for each camera recording in the media browser.

![shot](https://example.invalid/shot.png)

## Install

Add it through the Marketplace.
"""
LIMIT = RateLimitError("https://api.github.com/x", 0.0, authenticated=False)


def _fetch(files=None, calls=None):
    files = {HA_PATH: HA_FILE} if files is None else files

    def fetch(path):
        if calls is not None:
            calls.append(path)
        return files.get(path)

    return fetch


def _built(tmp_path, fetch=None, version="2026.11.1", findings=None, places=None, readme=README):
    root = _pkg(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    if readme is not None:
        (repo / "README.md").write_text(readme)
    return context.build(
        root, findings or [PATCH], None, source_root=repo,
        places=places, ha_version=version, ha_source=fetch if fetch is not None else _fetch(),
    )  # fmt: skip


# --- where the original is, and reading it ----------------------------------------------------


def test_the_import_path_names_the_file_and_the_name_inside_it():
    assert compare.locate("homeassistant.components.camera.media_source.Vod", "_gen") == (
        ["homeassistant/components/camera/media_source.py",
         "homeassistant/components/camera/media_source/__init__.py"],
        ["Vod", "_gen"],
    )  # fmt: skip
    assert compare.locate("homeassistant.helpers.aiohttp_client", "async_get_clientsession") == (
        ["homeassistant/helpers/aiohttp_client.py",
         "homeassistant/helpers/aiohttp_client/__init__.py"],
        ["async_get_clientsession"],
    )  # fmt: skip
    assert compare.locate("homeassistant.core.HomeAssistant", "x")[1] == ["HomeAssistant", "x"]
    # not Home Assistant's source, or nothing that names a module
    for obj in ("ssl.SSLContext", "aiohttp.ClientSession", "self.hass.auth", "homeassistant",
                "homeassistant.HomeAssistant", "homeassistant.core/../x"):  # fmt: skip
        assert compare.locate(obj, "x") is None


def test_home_assistants_python_314_except_form_is_read():
    with pytest.raises(SyntaxError):
        compile(HA_FILE, "media.py", "exec", flags=0x400)  # ast.PyCF_ONLY_AST: parse, never run
    tree = compare.parse(HA_FILE)
    node = compare.find_function(tree, ["VodSource", "_files"])
    assert compare.span(node) == (15, 18)  # the file's own line numbers
    assert compare.find_function(tree, ["VodSource", "nope"]) is None
    assert compare.find_function(tree, ["SPLIT"]) is None  # not a function
    assert compare.parse("def broken(:\n") is None


def test_ha_source_is_cached_and_a_miss_too(tmp_path, monkeypatch):
    monkeypatch.setenv("SNIFF_TEST_CACHE", str(tmp_path))
    calls = []

    class G:
        def file_at(self, owner, name, path, ref):
            calls.append((owner, name, path, ref))
            return HA_FILE if path == HA_PATH else None

    for _ in range(2):
        assert ha_env.source_file("2026.11.1", HA_PATH, G()) == HA_FILE
        assert ha_env.source_file("2026.11.1", "homeassistant/nope.py", G()) is None
    assert calls == [
        ("home-assistant", "core", HA_PATH, "2026.11.1"),
        ("home-assistant", "core", "homeassistant/nope.py", "2026.11.1"),
    ]
    for bad in ("../etc/passwd", "homeassistant/../x.py", "custom_components/x.py",
                "homeassistant/a.py?ref=main", "homeassistant/A.py"):  # fmt: skip
        with pytest.raises(ha_env.HAEnvError):
            ha_env.source_file("2026.11.1", bad, G())
    with pytest.raises(ha_env.HAEnvError):
        ha_env.source_file("main", HA_PATH, G())


def test_ha_source_never_turns_a_failure_into_a_cached_answer(tmp_path, monkeypatch):
    monkeypatch.setenv("SNIFF_TEST_CACHE", str(tmp_path))

    class G:
        def __init__(self, error):
            self.error = error

        def file_at(self, *a):
            raise self.error

    with pytest.raises(RateLimitError):
        ha_env.source_file("2026.11.1", HA_PATH, G(LIMIT))
    with pytest.raises(ha_env.HAEnvError):
        ha_env.source_file("2026.11.1", HA_PATH, G(GitHubError("GitHub 502")))
    assert not list((tmp_path / "ha").rglob("*")) if (tmp_path / "ha").exists() else True


# --- the comparison ---------------------------------------------------------------------------


def test_the_replacement_is_compared_with_the_original_line_by_line(tmp_path):
    calls = []
    ctx = _built(tmp_path, _fetch(calls=calls))
    assert ctx["version"] == 5
    patch = ctx["items"][PATCH["id"]]["patch"]
    cmp = patch["compare"]
    assert calls == [HA_PATH]
    assert {k: cmp[k] for k in ("state", "ha_version", "file", "name", "original", "replacement",
                                "added", "removed", "cut")} == {
        "state": "ok", "ha_version": "2026.11.1", "file": HA_PATH, "name": "VodSource._files",
        "original": [15, 18], "replacement": ["__init__.py", 28, 30],
        "added": 1, "removed": 2, "cut": False,
    }  # fmt: skip
    # a method and a module-level function: the shared indentation is not a difference
    assert cmp["hunks"] == [
        [
            [" ", 15, 28, "async def _files(self, day):"],
            [" ", 16, 29, '    """List a day\'s recordings."""'],
            ["-", 17, 0, "    # the plain list"],
            ["-", 18, 0, "    return [SPLIT, day]"],
            ["+", 0, 30, "    return [SPLIT, day, self.hass.data[KEY].url(day)]"],
        ]
    ]
    assert cmp["noncode"] == [16, 17]  # the docstring and the comment of the original
    assert compare.original_segments(cmp) == [
        {"file": HA_PATH, "start": 15, "code": [r[3] for r in cmp["hunks"][0][:4]]}
    ]


@pytest.mark.parametrize(
    ("fetch", "version", "why"),
    [
        (_fetch({}), "2026.11.1", "not-found"),  # that release has no such file
        (_fetch({HA_PATH: "class VodSource:\n    _files = None\n"}), "2026.11.1", "not-found"),
        (_fetch({HA_PATH: "def broken(:\n"}), "2026.11.1", "unreadable"),
        (_fetch(), None, "offline"),
    ],
)
def test_no_comparison_is_a_stated_reason_never_a_result(tmp_path, fetch, version, why):
    ctx = _built(tmp_path, fetch, version)
    patch = ctx["items"][PATCH["id"]]["patch"]
    assert patch["compare"]["state"] == "none" and patch["compare"]["why"] == why
    assert why in compare.WHY and "hunks" not in patch["compare"]
    assert patch["replacement"] == "_files"  # the 0.11.0 fact is still there
    html = ui.patch_html(patch)
    assert (
        "Barkley has no comparison with Home Assistant" in html and ui.e(compare.WHY[why]) in html
    )


def test_github_not_answering_is_said_and_a_rate_limit_goes_through(tmp_path):
    def down(path):
        raise ha_env.HAEnvError("could not fetch")

    patch = _built(tmp_path, down)["items"][PATCH["id"]]["patch"]
    assert patch["compare"] == {"state": "none", "why": "unreachable", "ha_version": "2026.11.1"}
    assert "Sniffing this version again tries once more." in ui.patch_html(patch)

    def limited(path):
        raise LIMIT

    with pytest.raises(RateLimitError):  # the job waits and scans again
        _built(tmp_path, limited)


def test_at_most_two_files_are_asked_for_per_scan(tmp_path):
    calls = []
    second = {**PATCH, "id": "b" * 16, "rule_id": "ha-monkeypatch-2"}
    ctx = _built(tmp_path, _fetch({}, calls), findings=[PATCH, second])
    assert len(calls) == compare.MAX_FETCH == 2  # `media.py`, then `media/__init__.py`
    assert ctx["items"][PATCH["id"]]["patch"]["compare"]["why"] == "not-found"
    fact = {"object": "homeassistant.components.camera.media.VodSource", "attr": "_files"}
    assert compare.compare(fact, ("x.py", [], None), "2026.11.1", _fetch(), [0]) == {
        "state": "none", "why": "limit",
    }  # fmt: skip


def test_only_a_function_of_the_app_replacing_ha_source_is_compared(tmp_path):
    fetch = _fetch()
    # a network library, the running hass: no comparison entry at all
    for obj in ("aiohttp.ClientSession", "self.hass.auth"):
        assert compare.compare({"object": obj, "attr": "x"}, None, "2026.11.1", fetch, [2]) is None
    # replaced by something that isn't a function defined in the app
    init = INIT.replace("    VodSource._files = (\n        _files\n    )\n",
                        "    VodSource._files = Generator\n")  # fmt: skip
    root = _pkg(tmp_path, {"__init__.py": init, "thumbs.py": THUMBS})
    finding = {**PATCH, "line": 18}
    ctx = context.build(root, [finding], None, ha_version="2026.11.1", ha_source=fetch)
    patch = ctx["items"][PATCH["id"]]["patch"]
    assert patch["compare"] == {"state": "none", "why": "not-a-function"}
    assert "inside" not in patch


def test_a_long_comparison_keeps_its_counts_and_says_it_is_cut():
    old = [f"    a{i} = {i}" for i in range(400)]
    new = [f"    b{i} = {i}" for i in range(400)]
    hunks, added, removed, cut = compare.diff(["def f():", *old], 10, ["def f():", *new], 50)
    assert (added, removed, cut) == (400, 400, True) and hunks == []
    hunks, added, removed, cut = compare.diff(["x = 1"], 3, ["x = 1"], 9)
    assert (hunks, added, removed, cut) == ([], 0, 0, False)


# --- Barkley's own sentence about the replacement ---------------------------------------------


def test_the_calm_line_counts_what_else_the_scan_has_on_the_replacements_lines(tmp_path):
    patch = _built(tmp_path)["items"][PATCH["id"]]["patch"]
    assert patch["inside"] == {
        "lines": [28, 30], "findings": [], "more_findings": 0, "addresses": 0, "ports": 0,
    }  # fmt: skip
    html = ui.patch_html(patch)
    assert "The replacement is lines 28–30 of <code>__init__.py</code>" in html  # noqa: RUF001
    assert "Barkley&#x27;s other checks found nothing there" in html or (
        "Barkley's other checks found nothing there" in html
    )
    assert "isn't a statement that the code is safe" in html

    other = {**PATCH, "id": "c" * 16, "rule_id": "py-eval-exec", "line": 30}
    outside = {**PATCH, "id": "d" * 16, "rule_id": "py-runtime-pip", "line": 12}
    places = [("host", "__init__.py", 29), ("port", "__init__.py", 30), ("host", "thumbs.py", 29)]
    patch = _built(tmp_path, findings=[PATCH, other, outside], places=places)["items"][PATCH["id"]][
        "patch"
    ]
    assert patch["inside"] == {
        "lines": [28, 30], "findings": ["py-eval-exec"], "more_findings": 0,
        "addresses": 1, "ports": 1,
    }  # fmt: skip
    html = ui.patch_html(patch)
    assert "This scan also has there: 1 other finding (" in html and "1 address, 1 port" in html
    assert "found nothing there" not in html


def test_what_it_means_names_what_is_replaced_only_for_home_assistants_source():
    built_in = explain.patch_means(
        {"object": "homeassistant.components.camera.media.VodSource", "attr": "_files",
         "origin": "Home Assistant's built-in camera integration"}
    )  # fmt: skip
    assert (
        "swaps _files of VodSource" in built_in and "the camera integration can reach" in built_in
    )
    core = explain.patch_means({"object": "homeassistant.core.HomeAssistant", "attr": "x",
                                "origin": "Home Assistant's own code"})  # fmt: skip
    assert "a part of Home Assistant's own code" in core and "grab passwords" in core
    no_attr = {"object": "homeassistant.core", "origin": "Home Assistant's own code"}
    for patch in (None, {}, {"object": "ssl.SSLContext", "attr": "x", "origin": "Python"}, no_attr):
        assert explain.patch_means(patch) is None
    for text in (built_in, core):
        assert not ai_context.dismisses(text)


# --- the README -------------------------------------------------------------------------------


def test_the_readme_head_is_kept_with_its_line_numbers(tmp_path):
    ctx = _built(tmp_path)
    assert ctx["readme"] == {
        "file": "README.md", "start": 1, "total": 9,
        "code": README.splitlines(),
    }  # fmt: skip
    repo = tmp_path / "caps"
    repo.mkdir()
    (repo / "ReadMe.MD").write_text("x" * 1000 + "\n" + "\n".join(f"line {i}" for i in range(500)))
    doc = context.readme(repo)
    assert doc["file"] == "ReadMe.MD" and doc["total"] == 501
    assert len(doc["code"]) == context.README_LINES and doc["code"][0] == "x" * 300 + " …"
    assert context.readme(tmp_path / "missing") is None and context.readme(None) is None
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "notes.md").write_text("not a readme")
    assert context.readme(empty) is None
    (empty / "README.md").symlink_to(repo / "ReadMe.MD")  # never followed
    assert context.readme(empty) is None
    assert "readme" not in _built(tmp_path / "bare", readme=None)


# --- the AI: the comparison as citable lines, the README opinion ------------------------------


def _report(tmp_path, **finding):
    rep = report(findings=[{**PATCH, **finding}], score=75)
    rep["context"] = _built(tmp_path, findings=rep["findings"])
    return rep


def test_the_request_carries_the_comparison_and_the_readme_in_their_own_fences(tmp_path):
    rep = _report(tmp_path)
    text, structure = ai_context.build_request(rep, PATCH["id"])
    nonce = text.split("<<<CODE ")[1].split(" ")[0]
    assert f"<<<DIFF {nonce} " in text and f"DIFF {nonce}>>>" in text
    assert f"- {HA_PATH}:18|     return [SPLIT, day]" in text
    assert "+ __init__.py:30|     return [SPLIT, day, self.hass.data[KEY].url(day)]" in text
    assert f"  {HA_PATH}:15 = __init__.py:28| async def _files(self, day):" in text
    assert f"<<<README {nonce} " in text and "README.md:3| Shows a thumbnail" in text
    assert "comparison_by_barkley" in text and '"lines_only_in_the_original": 2' in text
    assert "What does the replacement do differently from the original" in text
    assert "swaps _files of VodSource" in text  # the specific meaning, not the general one
    assert "grab passwords" not in text
    assert ai_context.ALIGN_FIELD in structure
    # the second round carries them too
    again, structure = ai_context.build_request(rep, PATCH["id"], snip=ai_context.snippet_of(
        rep, PATCH["id"]))  # fmt: skip
    assert "<<<DIFF " in again and "<<<README " in again and ai_context.ALIGN_FIELD in structure


@pytest.mark.parametrize(
    "finding",
    [{"category": "exfil"}, {"category": "endpoint"}, {"tags": ["exfil"]}, {"tags": ["malware"]}],
)
def test_no_readme_opinion_for_findings_about_data_leaving_the_box(tmp_path, finding):
    rep = _report(tmp_path, **finding)
    text, structure = ai_context.build_request(rep, PATCH["id"])
    assert ai_context.ALIGN_FIELD not in structure and "<<<README" not in text
    assert "consistent_with_readme" not in text
    # and one that turns up anyway is not shown
    got = ai_context.accept(rep, PATCH["id"], {
        ai_context.ALIGN_FIELD: "The README says thumbnails (README.md:3) and the code adds "
        "`url` (__init__.py:30)."})  # fmt: skip
    assert "alignment" not in got and got["dropped"] == []


def test_only_the_replaced_home_assistant_code_finding_gets_the_readme_opinion(tmp_path):
    other = {**PATCH, "id": "e" * 16, "rule_id": "py-eval-exec", "category": "code_exec",
             "line": 30}  # fmt: skip
    rep = report(findings=[PATCH, other], score=50)
    rep["context"] = _built(tmp_path, findings=rep["findings"])
    assert ai_context.readme_of(rep, PATCH["id"]) and ai_context.readme_of(rep, other["id"]) is None
    text, structure = ai_context.build_request(rep, other["id"])
    assert ai_context.ALIGN_FIELD not in structure and "<<<README" not in text


def test_no_readme_no_opinion(tmp_path):
    rep = report(findings=[PATCH], score=75)
    rep["context"] = _built(tmp_path / "bare", readme=None)
    text, structure = ai_context.build_request(rep, PATCH["id"])
    assert ai_context.ALIGN_FIELD not in structure and "<<<README" not in text
    assert "<<<DIFF" in text  # the comparison doesn't depend on a README


GOOD = ("The README says it shows a thumbnail for each recording (README.md:3), and the "
        "replacement adds `url` to the list (__init__.py:30).")  # fmt: skip


@pytest.mark.parametrize(
    ("text", "why"),
    [
        (GOOD, ""),
        (GOOD + " So it is safe.", "README opinion gives a verdict"),
        (GOOD + " This is fine.", "README opinion gives a verdict"),
        (GOOD + " That is expected behaviour.", "README opinion gives a verdict"),
        (GOOD + " It is a false positive.", "README opinion gives a verdict"),
        ("The README describes thumbnails (README.md:3).",
         "README opinion cites no line of the app's code"),
        ("The code adds `url` (__init__.py:30).", "README opinion cites no README line"),
        ("The README (README.md:2) matches `url` (__init__.py:30).",
         "README opinion cites no README line"),  # a blank line
        (f"The README (README.md:3) matches the original ({HA_PATH}:18).",
         "README opinion cites no line of the app's code"),
        ("The README (README.md:3) matches `requests.post` (__init__.py:30).",
         "README opinion names code that isn't on the cited lines"),
        ("The README (README.md:300) matches `url` (__init__.py:30).",
         "README opinion cites a line we didn't send"),
        ("It matches the README.", "README opinion cites no README line"),
    ],
)  # fmt: skip
def test_the_readme_opinion_must_cite_both_sides_and_give_no_verdict(tmp_path, text, why):
    rep = _report(tmp_path)
    got = ai_context.accept(rep, PATCH["id"], {ai_context.ALIGN_FIELD: text})
    if why:
        assert "alignment" not in got and got["dropped"] == [why]
    else:
        assert got["dropped"] == []
        assert got["alignment"]["text"].startswith("The README says it shows a thumbnail")
        assert ["README.md", 3, 3] in got["alignment"]["cites"]
        assert ["__init__.py", 30, 30] in got["alignment"]["cites"]


def test_claims_may_cite_the_original_but_never_rest_on_the_readme(tmp_path):
    rep = _report(tmp_path)
    got = ai_context.accept(rep, PATCH["id"], {
        "claim_1": f"The original returned only `SPLIT` and `day` ({HA_PATH}:18).",
        "claim_2": "The replacement also adds `url` (__init__.py:30).",
        "claim_3": "It shows a thumbnail for each recording (README.md:3).",
        "claim_4": f"The original is the plain list ({HA_PATH}:17).",  # a comment
        "claim_5": f"The original is harmless ({HA_PATH}:18).",
    })  # fmt: skip
    assert [c["text"] for c in got["claims"]] == [
        "The original returned only `SPLIT` and `day`.",
        "The replacement also adds `url`.",
    ]
    assert sorted(got["dropped"]) == ["cites only comments", "cites only comments",
                                      "dismisses something"]  # fmt: skip


# --- the panel --------------------------------------------------------------------------------


def test_the_page_shows_the_comparison_and_the_sheet_the_labelled_opinion(tmp_path):
    calls = []

    def fake_ai(entity, instructions, structure, task):
        calls.append((instructions, structure))
        return {
            "claim_1": "The replacement also adds `url` to the list (__init__.py:30).",
            ai_context.ALIGN_FIELD: GOOD,
        }

    store, base, httpd = _serve(tmp_path, fake_ai)
    rep = _report(tmp_path)
    src, rep["context"]["source"] = sources.capture_root(tmp_path / "thumbs")
    sid = store.save(rep, source=src)
    _, _, page = get(f"{base}/scan/{sid}")
    assert "How it differs from the original" in page
    assert "<code>VodSource._files</code> in Home Assistant 2026.11.1" in page
    assert "1 line only in the replacement, 2 lines only in the original" in page
    assert '<span class="del">   18       - ' in page and '<span class="add">         30 + ' in page
    assert "Compared by Barkley, not by AI." in page
    assert "The rest of the replacement" in page
    assert "While it runs, the app swaps _files of VodSource" in page
    assert "grab passwords" not in page  # the general text gave way to the specific one
    assert "Also sent: Barkley's comparison with the original in Home Assistant 2026.11.1" in page
    assert "the first 9 lines of the app's <code>README.md</code>" in page
    assert "The AI's opinion" not in page and not calls
    assert _click(base, sid)[0] == 303
    _wait(httpd, sid)
    _, _, page = get(f"{base}/scan/{sid}")
    assert "<h3>The AI's opinion: consistent with the README</h3>" in page
    assert "The README says it shows a thumbnail for each recording" in page
    assert "This is the AI's opinion, not one of Barkley's checks." in page
    assert "which is not the same as safe" in page
    assert "<script" not in page
    assert store.report(sid)["score"] == 75 and 'aria-label="Score 75 of 100"' in page
    assert store.report(sid)["findings"] == rep["findings"]  # nothing cleared or changed
    httpd.shutdown()


def test_fixes_from_the_first_real_run(tmp_path):
    """Three things the first real run on 0.12.0 showed."""
    rep = _report(tmp_path)
    # 1. the model was told only the changes, and asked what the rest of the original does
    text, _ = ai_context.build_request(rep, PATCH["id"])
    assert "every line of the two functions that is not listed is the same in both" in text
    # 2. picks written as ": 4" were refused although 4 is a number on the menu
    menu = [{"n": n, "name": f"f{n}", "file": "a.py"} for n in range(1, 7)]
    picked, refused = ai_context.needs(
        {"need_1": ": 4", "need_2": "(5)", "need_3": "a.py line 4"}, menu
    )
    assert [m["n"] for m in picked] == [4, 5] and refused == ["a.py line 4"]
    # 3. a statement longer than 400 characters lost half a citation to the cut
    long = (
        "The replacement also adds `url` to the list, "
        + "and that is all it adds, " * 16
        + f"which the original does not have (__init__.py:30, {HA_PATH}:18)."
    )
    assert len(long) > ai_context.MAX_CLAIM
    got = ai_context.accept(rep, PATCH["id"], {"claim_1": long})
    assert got["dropped"] == [] and got["claims"][0]["cites"] == [
        ["__init__.py", 30, 30],
        [HA_PATH, 18, 18],
    ]
    shown = got["claims"][0]["text"]
    assert len(shown) <= ai_context.MAX_CLAIM + 2 and shown.endswith(" …")
    assert "homeassistant" not in shown  # no half citation left in the text
