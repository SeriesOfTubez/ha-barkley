"""What 0.15 kept of trust.py: the scanner's own score for stored findings, and the
shape of an address a finding may carry."""

from sniff_test import scoring, trust
from sniff_test.models import Category, Finding, Severity


def test_rescore_is_the_scanners_own_score():
    fs = [
        Finding(f"r{i % 3}", "t", sev, Category.DEPENDENCY, "m", file=f"f{i}.py")
        for i, sev in enumerate(
            [
                Severity.HIGH,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.LOW,
                Severity.INFO,
            ]
        )
    ]
    for complete in (True, False):
        own = scoring.score(fs, complete)
        again = trust.rescore([(f.id, f.rule_id, str(f.severity)) for f in fs], complete)
        assert (again.score, again.raw_score, again.verdict_key, again.caps) == (
            own.score, own.raw_score, own.verdict.key, own.caps,
        )  # fmt: skip
        assert sum(d["points"] for d in again.breakdown) == sum(d.points for d in own.deductions)


def test_only_plain_hosts_and_ips_are_addresses():
    assert trust.valid_address("api.together.xyz") and trust.valid_address("203.0.113.9")
    for bad in ("https://a.example/", "a.example:443", "A.EXAMPLE", "a b", "", "a/b", "x@y"):
        assert not trust.valid_address(bad)
