"""The card-token guard's patterns stay linear on hostile input (no semgrep needed)."""

from sniff_test.analyzers import js_wrapper as w

# --- (0.14.0) hostile input can't stall a scan -----------------------------------------------
# A real card's bundle, blanked by `visible`, left `function` followed by 100 000+ spaces,
# and `function\s*\*?\s*[\w$]*\s*\(` took 123 s per call while holding the interpreter:
# the panel stopped answering. Every pattern here must stay linear on such input.

_N = 30_000
_RUNS = [
    "function" + " " * _N,
    "function*" + " " * _N + "x",
    "function" + "\x01" * _N,
    "(" + " " * _N,
    "{" + " " * _N,
    "[" + " " * _N,
    "const" + " " * _N + "{",
    "const {" + " " * _N,
    "catch" + " " * _N + "(",
    "x" + " " * _N + "=",
    " \n" * _N,
    "`${" + " " * _N,
    "import" + " " * _N + "{",
    "export" + " " * _N,
    "a" * _N,
    "a=" * _N,
    "({" * _N,
    "static " * _N,
]


def _patterns():
    import re

    found = {}
    for k, v in vars(w).items():
        if isinstance(v, re.Pattern):
            found[k] = v
        elif isinstance(v, tuple) and v and all(isinstance(x, re.Pattern) for x in v):
            found.update({f"{k}[{i}]": x for i, x in enumerate(v)})
    return found


def test_no_pattern_backtracks_on_long_runs():
    import time

    slow = []
    for name, rx in _patterns().items():
        for run in _RUNS:
            t = time.perf_counter()
            for _ in rx.finditer(run):
                pass
            if time.perf_counter() - t > 0.5:
                slow.append((name, run[:10]))
    assert slow == []


def test_blanked_code_is_not_whitespace():
    text = "function a(){ " + "x;" * 50 + "}\nfetch(u)"
    v = w.visible(text, len(text) - 3)
    assert len(v) == len(text) and " " * 20 not in v and w._FILL * 20 in v


def test_destructured_is_fast_on_a_big_blanked_bundle():
    import time

    body = "function f(a){" + "a.b;" * 40_000 + "}\n"
    text = body * 3 + "fetch(u)"
    t = time.perf_counter()
    w.destructured(w.visible(text, len(text) - 3))
    assert time.perf_counter() - t < 2


def test_property_assignment_is_not_destructuring():
    """`n[e] = o` in a real card's bundle kept a same-origin call flagged."""
    assert "e" not in w.destructured("n[e]=o;a.b[e] = 1;f()[e]=2;x[0][e]=3")
    assert {"e", "f"} <= w.destructured("[e] = arr;({f} = obj);")
