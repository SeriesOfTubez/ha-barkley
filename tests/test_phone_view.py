"""(his call 2026-11-25) On a phone the app page is short: the readings, Threat, Exposure,
In short and every item that counts toward a reading. The rest (context items, the
picture, the sites, the packages, the AI buttons) is under Show details (?all=1), and
Hide details goes back. A wider screen always shows everything. An item that counts
toward a reading is never hidden. Made-up reports; hosts use .invalid."""

from __future__ import annotations

import re

from test_server import get, panel  # noqa: F401  (the fixture)
from test_sniff_report import f, report
from test_store import report as stored_report

from sniff_test import kinds, readings, ui

RULES = ("card-token-exfil", "ha-unauth-view", "ha-auth-internals", "ha-read-secrets",
         "ha-service-register")  # fmt: skip


def _blocks(out: str) -> list[str]:
    return [b for b in re.split(r'(?=<div class="(?:ph-hide )?finding)', out)
            if b.startswith('<div class="') and "finding" in b[:30]]  # fmt: skip


def _check_items(out: str, rules: tuple[str, ...]) -> None:
    seen = set()
    for b in _blocks(out):
        rule = next((r for r in rules if f"{r} · " in b or f">{r}<" in b), None)
        if rule is None:
            continue
        seen.add(rule)
        counts = kinds.is_threat(rule) or readings.counts_in_exposure(
            {"rule_id": rule, "severity": "high", "file": "a.py", "line": 1}
        )
        assert ("ph-hide" in b[:40]) is (not counts), rule
    assert seen == set(rules), seen


def test_items_that_count_are_never_hidden_on_a_phone() -> None:
    # with a found threat (no Exposure chips drawn) and without one
    every = tuple(f(r, n=i) for i, r in enumerate(RULES))
    _check_items(ui.render_app("", 1, report(*every), []).decode(), RULES)
    calm = RULES[1:]
    _check_items(ui.render_app("", 1, report(*every[1:]), []).decode(), calm)


def test_the_short_view_ends_with_show_details() -> None:
    out = ui.render_app("", 4, report(f("ha-unauth-view"), f("ha-read-secrets", n=1)), [])
    out = out.decode()
    assert '<div class="short">' in out and "Hide details" not in out
    more = out[out.index("<h2>More about this app</h2>") :]
    assert 'class="box phone"' in out
    assert "What it touches" in more and "Where it connects" in more
    assert 'href="/scan/4?all=1#found">Show details</a>' in out
    assert "1 more item is context." in out  # inside What Barkley found
    # the picture and the sections after it sit in the hidden part
    touches = out.index("<h2>What it touches")
    assert out.rfind('<div class="ph-hide"', 0, touches) > out.index("What Barkley found")


def test_the_full_view_shows_everything_and_offers_hide_details() -> None:
    r = report(f("ha-unauth-view"), f("ha-read-secrets", n=1))
    out = ui.render_app("", 4, r, [], full=True).decode()
    assert '<div class="short">' not in out and "More about this app" not in out
    assert '<a class="phone hidedet" href="/scan/4">Hide details</a>' in out
    assert ">Show details</a>" not in out


def test_only_a_phone_width_hides_anything() -> None:
    css = re.sub(r"/\*.*?\*/", "", ui.CSS, flags=re.S)
    assert ".phone { display:none; }" in css and ".short { display:contents; }" in css
    i = css.index(".short .ph-hide")
    m = css.rfind("@media (max-width:600px)", 0, i)
    assert m != -1 and "}" not in css[m:i]  # inside the phone rule
    assert css.count(".ph-hide") == 1  # nowhere outside the phone rule


def test_all_1_reaches_the_page(panel) -> None:  # noqa: F811
    store, _scan_fn, base, _httpd = panel
    sid = store.save(stored_report(repo="acme/acme", ref="v1"))
    _s, _h, short = get(f"{base}/scan/{sid}")
    _s, _h, full = get(f"{base}/scan/{sid}?all=1")
    assert '<div class="short">' in short and '<div class="short">' not in full
    assert "Hide details" in full
