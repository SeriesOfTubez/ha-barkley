"""Addresses the user marks trusted (user decisions 2026-11-12): which findings a mark
can reach, what it does to the shown score, and that the stored scan never changes."""

import json

from test_store import FINDING, report

from sniff_test import scoring, trust
from sniff_test.models import Category, Finding, Severity

# A real integration as scanned: two GuardDog highs on one dependency, score 50
ADDR = {
    "id": "a" * 16,
    "rule_id": "dep-guarddog-network-exfiltration",
    "title": "Suspicious code in dependency vector-client",
    "severity": "high",
    "category": "dependency",
    "file": "manifest.json",
    "line": None,
    "evidence": "vector-client==1.5.3 remote_embedding.py:13: https://api.together.xyz/",
    "message": "GuardDog heuristic matched",
    "addresses": ["api.together.xyz"],
}
PIP = {
    "id": "b" * 16,
    "rule_id": "dep-guarddog-process-download-exec",
    "title": "Suspicious code in dependency vector-client",
    "severity": "high",
    "category": "dependency",
    "file": "manifest.json",
    "line": None,
    "evidence": "vector-client==1.5.3 vectors/__init__.py:143: check_call(",
    "message": "GuardDog heuristic matched",
}
REPO = "acme/agent"


def _report(findings=(ADDR, PIP), repo=REPO, score=50):
    r = report(repo=repo, ref="v0.9.5", findings=findings, score=score)
    r["score_breakdown"] = [
        {"finding_id": f["id"], "rule_id": f["rule_id"], "severity": "high", "points": 25}
        for f in findings
    ]
    return r


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


def test_the_list_takes_only_plain_addresses_and_survives_bad_settings():
    t = trust.Trusted()
    assert t.add("api.together.xyz", REPO) and t.add("203.0.113.9", None)
    for bad in ("https://api.together.xyz", "API.Together.xyz", "a b", "*.together.xyz", "",
                "x/y", "evil.tk?x", "<script>"):  # fmt: skip
        assert not t.add(bad, None), bad
    assert not t.add("ok.example.org", "not a repo")
    again = trust.Trusted.loads(t.dumps())
    assert again.scope(REPO.upper(), "api.together.xyz") == "app"
    assert again.scope("other/app", "api.together.xyz") == ""
    assert again.scope("other/app", "203.0.113.9") == "all"
    for junk in (
        None,
        "",
        "nope",
        "[]",
        '{"all": "x", "apps": {"a/b": [1, "<x>"], "bad": ["a.b"]}}',
    ):
        assert not trust.Trusted.loads(junk)


def test_view_sets_the_trusted_finding_aside_and_never_changes_the_report():
    rep = _report()
    before = json.dumps(rep, sort_keys=True)
    t = trust.Trusted()
    assert trust.view(rep, t) is rep  # nothing trusted: the very same report
    t.add("api.together.xyz", REPO)
    v = trust.view(rep, t)
    assert json.dumps(rep, sort_keys=True) == before
    assert v["score"] == 75 and v["verdict"]["key"] == "kinda_sus"  # 100 - 25, capped at 89
    assert [f["id"] for f in v["findings"]] == [PIP["id"]]
    assert [f["id"] for f in v["trusted_findings"]] == [ADDR["id"]]
    assert v["trusted_findings"][0]["trusted"] == "app"
    assert v["trust"]["own_score"] == 50 and v["trust"]["addresses"] == ["api.together.xyz"]
    assert v["score_breakdown"] == [
        {"finding_id": PIP["id"], "rule_id": PIP["rule_id"], "severity": "high", "points": 25.0}
    ]


def test_every_address_must_be_trusted_exactly_and_app_trust_stays_with_its_app():
    two = {**ADDR, "addresses": ["api.together.xyz", "cdn-update.top"]}
    t = trust.Trusted()
    t.add("api.together.xyz", REPO)
    assert trust.view(_report((two, PIP)), t)["score"] == 50  # one of two: still flagged
    assert trust.view(_report((ADDR, PIP), repo="other/app"), t)["score"] == 50
    sub = {**ADDR, "addresses": ["eu.api.together.xyz"]}
    assert trust.view(_report((sub, PIP)), t)["score"] == 50  # no subdomains
    t.add("cdn-update.top", None)
    v = trust.view(_report((two, PIP)), t)
    assert v["score"] == 75 and v["trusted_findings"][0]["trusted"] == "mixed"
    # the update names a new address: flagged again
    changed = {**ADDR, "addresses": ["api.together.ai"]}
    assert trust.view(_report((changed, PIP)), t)["score"] == 50


def test_a_finding_without_addresses_can_never_be_switched_off():
    """Proven flows, possible exfil, paste sites and webhooks carry no addresses; trusting
    every host in sight changes nothing about them."""
    t = trust.Trusted()
    for a in ("x.invalid", "api.together.xyz", "webhook.site", "203.0.113.9"):
        t.add(a, None)
    rep = _report((FINDING, PIP))
    assert trust.view(rep, t) is rep
    odd = {**ADDR, "addresses": "api.together.xyz"}  # not a list: ignored, not trusted
    assert "trust" not in trust.view(_report((odd, PIP)), t)
