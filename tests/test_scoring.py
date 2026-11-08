from sniff_test.models import Category, Finding, Severity, Tag
from sniff_test.scoring import Exposure, apply_exposure, score, verdict_for


def f(rule="r", sev=Severity.MEDIUM, line=1, tags=(), cat=Category.CODE_EXEC):
    return Finding(rule, "t", sev, cat, "m", file="x.py", line=line, tags=frozenset(tags))


def test_verdict_tiers():
    assert verdict_for(100).key == "good_boy"
    assert verdict_for(90).key == "good_boy"
    assert verdict_for(89).key == "kinda_sus"
    assert verdict_for(70).key == "kinda_sus"
    assert verdict_for(69).key == "very_sus"
    assert verdict_for(40).key == "very_sus"
    assert verdict_for(39).key == "bork"
    assert verdict_for(0).key == "bork"


def test_clean_complete_scan_is_good_boy():
    s = score([], complete=True)
    assert s.score == 100
    assert s.verdict.key == "good_boy"


def test_incomplete_scan_cannot_be_good_boy():
    s = score([], complete=False)
    assert s.score == 89
    assert s.verdict.key == "kinda_sus"


def test_any_critical_is_bork():
    s = score([f(sev=Severity.CRITICAL, tags=[Tag.EXFIL])], complete=True)
    assert s.score <= 39
    assert s.verdict.key == "bork"


def test_single_high_caps_at_kinda_sus():
    s = score([f(sev=Severity.HIGH)], complete=True)
    assert s.score == 75
    assert s.verdict.key == "kinda_sus"


def test_repeats_have_diminishing_cost_and_cap():
    many = [f(rule="noisy", sev=Severity.MEDIUM, line=i) for i in range(50)]
    s = score(many, complete=True)
    # one rule can never cost more than 2x its base (8 * 2 = 16)
    assert s.raw_score == 84


def test_score_is_deterministic():
    fs = [f(rule=str(i % 3), sev=Severity(i % 5), line=i) for i in range(20)]
    assert score(fs, True).score == score(list(reversed(fs)), True).score


def test_public_exposure_raises_inbound_only():
    inbound = f(
        rule="ha-unauth-view", sev=Severity.MEDIUM, tags=[Tag.INBOUND], cat=Category.INBOUND
    )
    other = f(rule="py-shell-exec", sev=Severity.MEDIUM, line=2)
    out = apply_exposure([inbound, other], Exposure.PUBLIC)
    assert out[0].severity == Severity.HIGH
    assert out[0].base_severity == Severity.MEDIUM
    assert out[1].severity == Severity.MEDIUM
    assert apply_exposure([inbound], Exposure.LOCAL)[0].severity == Severity.MEDIUM


def test_exposure_never_lowers_exfil():
    exfil = f(rule="ha-exfil-taint", sev=Severity.CRITICAL, tags=[Tag.EXFIL], cat=Category.EXFIL)
    for exposure in Exposure:
        assert apply_exposure([exfil], exposure)[0].severity == Severity.CRITICAL


def test_supersedes_replaces_generic_rule_on_same_line():
    from dataclasses import replace

    from sniff_test.scanner import _dedupe

    generic = f(rule="card-eval", sev=Severity.HIGH, line=5)
    specific = replace(
        f(rule="card-eval-config", sev=Severity.MEDIUM, line=5),
        supersedes=frozenset({"card-eval"}),
    )
    elsewhere = f(rule="card-eval", sev=Severity.HIGH, line=9)
    kept = {(x.rule_id, x.line) for x in _dedupe([generic, specific, elsewhere])}
    assert kept == {("card-eval-config", 5), ("card-eval", 9)}
