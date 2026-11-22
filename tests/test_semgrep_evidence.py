"""(0.15, batch 2026-11-21) The snippet shown for a match on a long minified line is cut
around Semgrep's column, which counts bytes: characters of more than one byte before the
match must not push the window past it."""

from sniff_test.analyzers import semgrep


def test_the_window_is_around_the_match_after_multibyte_characters(tmp_path):
    before = "°" * 3000 + "x" * 50  # 6,000 bytes but 3,000 characters before the match
    line = before + "eval(action.eval)" + ";y" * 2000
    p = tmp_path / "card.min.js"
    p.write_text(line + "\n", encoding="utf-8")
    col = len(before.encode()) + 1  # Semgrep's 1-based byte column
    got = semgrep._evidence_at(p, 1, col)
    assert "eval(action.eval)" in got
    assert got.startswith("…")


def test_plain_ascii_is_unchanged(tmp_path):
    p = tmp_path / "a.js"
    p.write_text("a" * 500 + "eval(x)" + "b" * 500 + "\n", encoding="utf-8")
    got = semgrep._evidence_at(p, 1, 501)
    assert got.startswith("…") and "eval(x)" in got
