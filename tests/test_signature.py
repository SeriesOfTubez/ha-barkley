"""(0.15) The scanned commit's signature, as GitHub verified it (fetch/github.py)."""

import pytest

from sniff_test.fetch.github import signature_state


def _c(verified, reason, email="dev@example.invalid", signature="-----BEGIN"):
    return {"sha": "a" * 40, "commit": {"committer": {"email": email}, "verification": {
        "verified": verified, "reason": reason, "signature": signature}}}  # fmt: skip


@pytest.mark.parametrize(
    ("data", "want"),
    [
        (_c(True, "valid", "noreply@github.com"), {"state": "github"}),
        (_c(True, "valid"), {"state": "developer"}),
        (_c(False, "unsigned", signature=None), {"state": "unsigned"}),
        (_c(False, "unknown_key"), {"state": "unverified", "reason": "unknown_key"}),
        (_c(False, "<script>"), {"state": "unverified", "reason": "unknown"}),
        ({"sha": "a" * 40}, {"state": "unsigned"}),
    ],
)
def test_four_states_from_github_s_verdict(data, want):
    assert signature_state(data) == want


def _rep(state):
    t = {"repo": "acme/acme", "ref": "v1"}
    if state:
        t["signature"] = {"state": state}
    return {"target": t}


@pytest.mark.parametrize(
    ("a", "b", "kind", "rank"),
    [
        ("github", "unsigned", "signature_stopped", 60),
        ("developer", "unverified", "signature_stopped", 60),
        ("github", "developer", "signature_changed", 45),
        ("unsigned", "github", "signature_started", 10),
    ],
)
def test_a_change_in_signing_is_a_change_in_the_comparison(a, b, kind, rank):
    from sniff_test import diff

    (c,) = diff.signature_changes(_rep(a), _rep(b))
    assert (c.kind, c.rank, c.group) == (kind, rank, "repo")
    assert (c.rank >= diff.HEADLINE_RANK) == (kind != "signature_started")


def test_no_change_and_scans_from_before_say_nothing():
    from sniff_test import diff

    assert diff.signature_changes(_rep("github"), _rep("github")) == []
    assert diff.signature_changes(_rep(None), _rep("unsigned")) == []


def test_the_habits_box_says_how_the_commit_is_signed():
    from sniff_test import ui

    rep = {"hygiene": {"scanners": [], "errors": []}, "target": {"signature": {"state": "github"}}}
    assert "made on github.com, and GitHub signed it" in ui.hygiene_html(rep)
    rep["target"]["signature"] = {"state": "unsigned"}
    assert "says nothing bad on its own" in ui.hygiene_html(rep)
