"""Addresses the user marks trusted (user decisions 2026-11-12): which findings a mark
can reach, what it does to the shown score, and that the stored scan never changes."""

import json
import re

from test_server import addon, get, panel, post, token  # noqa: F401 (fixtures)
from test_store import FINDING, report

from sniff_test import scoring, trust, ui, watch
from sniff_test.models import Category, Finding, Severity
from sniff_test.store import Store

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


def test_rows_show_the_score_only_through_the_panels_overlay(tmp_path):
    store = Store(tmp_path / "s.db")
    sid = store.save(_report())
    other = store.save(_report(repo="other/app"))
    t = store.trusted()
    t.add("api.together.xyz", REPO)
    store.set_trusted(t)
    assert store.get(sid).score == 50 and store.get(sid).own_score is None  # the CLI's view
    store.trust_overlay = True
    row = store.get(sid)
    assert (row.score, row.verdict, row.own_score) == (75, "kinda_sus", 50)
    assert store.get(other).score == 50  # trusted for one app only
    assert [r.score for r in store.history(REPO)] == [75]
    assert store.report(sid)["score"] == 50  # the stored report is never rewritten
    t.remove("api.together.xyz", REPO)
    store.set_trusted(t)
    assert store.get(sid).score == 50  # undone at once, no rescan


def test_trust_button_flow_in_the_panel(panel):  # noqa: F811
    store, _scan, base, _httpd = panel
    sid = store.save(_report())
    _, _, page = get(f"{base}/scan/{sid}")
    assert "Trust api.together.xyz?" in page and "Trust for this app" in page
    assert "Barkley knows this as Together AI, AI model API." in page
    assert page.count("Trust for every app") == 1  # only the address finding offers it
    tok = token(base)
    # a finding with no addresses, a stranger's id and a missing token are all refused
    assert post(f"{base}/trust", {"token": tok, "scan": sid, "finding": PIP["id"],
                                  "scope": "app"})[0] == 400  # fmt: skip
    assert post(f"{base}/trust", {"token": tok, "scan": sid, "finding": "c" * 16,
                                  "scope": "all"})[0] == 400  # fmt: skip
    assert post(f"{base}/trust", {"token": "x", "scan": sid, "finding": ADDR["id"],
                                  "scope": "app"})[0] == 403  # fmt: skip
    assert not store.trusted()
    status, headers = post(f"{base}/trust", {"token": tok, "scan": sid, "finding": ADDR["id"],
                                             "scope": "app"})  # fmt: skip
    assert status == 303 and headers["Location"].endswith(f"/scan/{sid}")
    assert store.trusted().scope(REPO, "api.together.xyz") == "app"
    _, _, page = get(f"{base}/scan/{sid}")
    # (0.14.0) a trusted address counts as reviewed: the ring shows 75, the split pill
    # Barkley's own 50 and what the review added
    assert 'aria-label="Score 75 of 100"' in page and ">Reviewed<" in page
    assert "Barkley's score 50" in page.replace("&#x27;", "'") and "+25 <small>" in page
    assert "Barkley's own score for this scan is 50." in page.replace("&#x27;", "'")
    assert "Findings about addresses you trust (1)" in page and "You trust this address" in page
    assert "What Barkley found (1)" in page and "Stop trusting api.together.xyz" in page
    # the raw report is untouched
    _, _, raw = get(f"{base}/scan/{sid}.json")
    assert json.loads(raw)["score"] == 50 and "trusted_findings" not in raw
    # the list page shows it, and its undo puts everything back
    _, _, listed = get(f"{base}/trusted")
    assert "api.together.xyz" in listed and "Only for" in listed
    status, headers = post(f"{base}/untrust", {"token": tok, "address": "api.together.xyz",
                                               "repo": REPO})  # fmt: skip
    assert status == 303 and headers["Location"].endswith("/trusted")
    assert not store.trusted()
    _, _, page = get(f"{base}/scan/{sid}")
    assert "you trust" not in page.lower().replace("trust api.together.xyz?", "")
    assert post(f"{base}/untrust", {"token": tok, "address": "https://x", "repo": ""})[0] == 400


def test_the_card_and_the_notification_say_the_score_counts_trusted_addresses(panel):  # noqa: F811
    store, _scan, base, _httpd = panel
    sid = store.save(_report())
    t = store.trusted()
    t.add("api.together.xyz", None)
    store.set_trusted(t)
    _, _, index = get(base + "/")
    assert "<b>75</b>" in index and "<b>50</b>" not in index  # the stored-scans table
    shown_row = store.get(sid)
    c = ui.Card(repo=REPO, name="Agent", kind="integration", installed="v0.9.5",
                available=None, scan=shown_row,
                report=trust.view(store.report(sid), store.trusted()))  # fmt: skip
    assert "The score treats 1 address you trust as fine. Barkley's own score is 50." in (
        ui.card_sentence(c)
    )
    assert ">75<" in ui.card_html("", c)
    shown = trust.view(store.report(sid), store.trusted())
    entry = {"repo": REPO, "version": "v0.9.5", "kind": "integration", "scan_ids": [sid]}
    _title, md, plain = watch.notification(entry, shown, None, "/app/x")
    for text in (md, plain):
        assert "75/100" in text and "Barkley's own score is 50" in text
        assert "api.together.xyz" not in text  # never an address from scanned code
    assert re.search(r"doesn't count 1 address you trust", md)
