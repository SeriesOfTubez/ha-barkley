"""(0.15, his decision 2026-11-21) A card that copies the page address into its settings and
runs a setting as code: a link can make it run code (card-eval-address, Exposure 5, not
Threat). Shapes from a real card, made-up names; the text is read in time proportional
to its size."""

import time

import pytest

from sniff_test import readings
from sniff_test.analyzers import js_address
from sniff_test.models import Category, Finding, Severity

COPIES = [
    # the real card's shape, readable and minified
    """function updateConfig() {
  const params = new URLSearchParams(window.location.search);
  const paramConfig = {};
  for (let [key, value] of params) { if (key.startsWith("wp_")) paramConfig[key.slice(3)] = value; }
  mergeConfig(config, paramConfig);
}""",
    "function Gd(){const e=new URLSearchParams(window.location.search),t={};for(let[n,o]of e)"
    "n.startsWith('wp_')&&(t[n.substring(3)]=o);return t}",
    "const p = new URLSearchParams(location.hash.slice(1)); p.forEach((v, k) => (cfg[k] = v));",
    "const all = Object.fromEntries(new URLSearchParams(document.location.search));",
    "for (const [k, v] of new URLSearchParams(location.search)) opts[k] = v;",
]
READS_ONE = [
    "const n=new URLSearchParams(window.location.search);return a.some(a=>n.has(a))},"
    "Qe=(a,...n)=>{n.forEach(n=>store.save(Ke(n),a))}",
    'const mode = new URLSearchParams(window.location.search).get("mode");',
    "const q = new URLSearchParams(location.search); if (q.get('edit') == '1') return;",
    "items.forEach((x) => f(x));",
]


@pytest.mark.parametrize("text", COPIES)
def test_copying_every_parameter_of_the_address(text):
    assert js_address.copies_address(text)


@pytest.mark.parametrize("text", READS_ONE)
def test_reading_named_parameters_is_not_a_copy(text):
    assert not js_address.copies_address(text)


def _eval(rule="card-eval", file="card.js", line=9):
    return Finding(rule, "t", Severity.MEDIUM, Category.CODE_EXEC, "m", file=file, line=line)


def test_the_first_place_that_runs_code_in_such_a_file_becomes_card_eval_address(tmp_path):
    (tmp_path / "card.js").write_text(COPIES[0] + "\nnew Function('bmp', config.popup_func);")
    (tmp_path / "other.js").write_text("eval(x);")
    got = js_address.add([_eval(), _eval(line=20), _eval(file="other.js")], tmp_path)
    assert [(f.rule_id, f.file, f.line) for f in got] == [
        ("card-eval-address", "card.js", 9),
        ("card-eval", "card.js", 20),
        ("card-eval", "other.js", 9),
    ]
    assert got[0].severity is Severity.HIGH


def test_a_file_that_copies_the_address_but_runs_no_code_is_left_alone(tmp_path):
    (tmp_path / "card.js").write_text(COPIES[0])
    assert js_address.add([], tmp_path) == []


def test_exposure_5_not_threat():
    fs = [{"rule_id": "card-eval-address", "severity": "high", "file": "card.js"}]
    rd = readings.compute({"findings": fs, "complete": True})
    assert rd.threat_level == "none"
    assert rd.exposure == 5.0 and rd.exposure_level == "high"
    assert any("A link can make it run code" in x for x in rd.exposure_reasons)


@pytest.mark.parametrize(
    "text",
    [
        "p=new URLSearchParams(location.search);" * 60_000,
        "p=new URLSearchParams(location.search);" + "{" * 2_000_000,
        "new URLSearchParams(location.search" + ")" * 1_000_000,
        "of new URLSearchParams(" * 100_000,
        "a" * 41 + "=new URLSearchParams(location.search);" + "x" * 2_000_000,
    ],
)
def test_hostile_text_is_read_in_time_proportional_to_its_size(text):
    start = time.monotonic()
    js_address.copies_address(text)
    assert time.monotonic() - start < 5
