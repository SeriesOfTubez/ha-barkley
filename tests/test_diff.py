"""`sniff-test diff`: matching, folding, publishers, and the fixture pair end to end."""

import copy
import json

import pytest
from conftest import requires_semgrep
from real_cases import case

from sniff_test import cli
from sniff_test.diff import diff, match_findings, publisher_changes
from sniff_test.report.json_report import to_dict
from sniff_test.scanner import scan


def _f(rule, file=None, line=None, evidence="", severity="low", fid=None):
    return {
        "id": fid or f"{rule}:{file}:{line}:{evidence}",
        "rule_id": rule,
        "title": rule,
        "severity": severity,
        "file": file,
        "line": line,
        "evidence": evidence,
    }


def _report(findings=(), edges=(), nodes=(), ref="v1", provenance=None, score=100):
    subject = {"id": "integration:acme", "kind": "integration", "label": "acme", "attrs": {}}
    return {
        "schema_version": 1,
        "target": {"repo": "acme/acme", "ref": ref, "kind": "integration"},
        "exposure": "local",
        "complete": True,
        "score": score,
        "verdict": {"key": "good_boy", "label": "Good Boy"},
        "analyzers": [],
        "findings": list(findings),
        "graph": {"subject": "integration:acme", "nodes": [subject, *nodes], "edges": list(edges)},
        "provenance": provenance,
    }


def test_findings_match_across_moved_lines_and_rebuilt_chunks():
    old = [
        _f("card-eval", "a.js", 10, "eval(x)"),
        _f("scan-parse-error", "front/2831.f1b6e847444f5d27.js"),
        _f("dep-vuln", "package-lock.json", None, "js-yaml@4.1.0 (npm): GHSA-1"),
    ]
    new = [
        _f("card-eval", "a.js", 42, "eval(x)"),
        _f("scan-parse-error", "front/2831.38221ccba3bbdab2.js"),
        _f("dep-vuln", "package-lock.json", None, "js-yaml@4.1.1 (npm): GHSA-2"),
    ]
    pairs, added, removed = match_findings(old, new)
    assert len(pairs) == 3
    assert added == removed == []


def test_identical_reports_have_no_changes():
    r = _report([_f("card-eval", "a.js", 1, "eval(x)")])
    assert diff(r, copy.deepcopy(r))["changes"] == []


def test_severity_change_is_one_change_not_new_and_resolved():
    old = _report([_f("repo-transferred", evidence="a/b (redirect)", severity="low")])
    new = _report([_f("repo-transferred", evidence="a/b (redirect)", severity="high", fid="x")])
    kinds = [c["kind"] for c in diff(old, new)["changes"]]
    assert kinds == ["severity_up"]


def test_evidence_upgrade_possible_to_proven():
    nodes = [
        {"id": "data:secrets.yaml", "kind": "data", "label": "secrets.yaml", "attrs": {}},
        {"id": "host:x.invalid", "kind": "host", "label": "x.invalid", "attrs": {}},
    ]

    def edge(ev):
        return {
            "id": "e1",
            "source": "data:secrets.yaml",
            "target": "host:x.invalid",
            "relation": "flows_to",
            "evidence": ev,
            "count": 1,
            "samples": [],
            "finding_ids": [],
            "attrs": {},
        }

    d = diff(
        _report(edges=[edge("possible")], nodes=nodes), _report(edges=[edge("proven")], nodes=nodes)
    )
    [c] = d["changes"]
    assert (c["kind"], c["text"]) == ("evidence_up", "secrets.yaml → x.invalid: possible → proven")
    assert c["rank"] >= d["headline_rank"]


def _prov(*releases):
    rel = [
        {"tag": t, "published_at": f"{d}T00:00:00Z", "publisher": p, "asset_uploaders": []}
        for t, d, p in releases
    ]
    return {"repo_id": 1, "full_name": "acme/acme", "releases": rel}


def test_new_publisher_from_provenance():
    prov = _prov(
        ("v4.0.0-beta.1", "2025-10-12", "bob"),
        ("v3.4.5", "2025-07-02", "alice"),
        ("v3.4.4", "2025-01-06", "alice"),
    )
    old = _report(ref="v3.4.5", provenance=prov)
    new = _report(ref="v4.0.0-beta.1", provenance=prov)
    [c] = publisher_changes(old, new)
    assert c.kind == "new_publisher"
    assert "bob" in c.text and "none of the 2 release(s) up to v3.4.5" in c.text
    # A later release by the same new maintainer is not "new" again.
    later = _prov(
        ("v4.2.1", "2026-02-08", "bob"),
        *[(r["tag"], r["published_at"][:10], r["publisher"]) for r in prov["releases"]],
    )
    assert (
        publisher_changes(
            _report(ref="v4.0.0-beta.1", provenance=later), _report(ref="v4.2.1", provenance=later)
        )
        == []
    )


def test_repo_findings_fold_into_the_publisher_line():
    prov = _prov(("v2", "2025-10-12", "newbie"), ("v1", "2025-07-02", "owner"))
    f = _f("repo-new-maintainer-release", evidence="v2 by newbie", severity="medium")
    d = diff(_report(ref="v1", provenance=prov), _report([f], ref="v2", provenance=prov))
    [c] = d["changes"]
    assert c["kind"] == "new_publisher"
    assert c["severity"] == "medium"
    assert c["finding_ids"] == [f["id"]]


@requires_semgrep
def test_fixture_pair_surfaces_exactly_the_new_host_and_secrets_read(fixtures):
    old = to_dict(scan(str(fixtures / "clean_integration"), offline=True))
    new = to_dict(scan(str(fixtures / "clean_integration_v2"), offline=True))
    d = diff(old, new)
    assert d["warnings"] == []
    got = sorted((c["kind"], c["text"]) for c in d["changes"])
    assert got == [
        ("new_flow", "possible: secrets.yaml → status.weather-mirror.invalid · possible-exfil"),
        ("new_host", "undeclared: status.weather-mirror.invalid (const.py:4)"),
        ("new_read", "secrets.yaml (diagnostics.py:6) · ha-read-secrets"),
    ]
    # Every new finding is carried by one of those lines, none listed twice.
    carried = {i for c in d["changes"] for i in c["finding_ids"]}
    assert carried == {f["id"] for f in new["findings"]}
    assert all(c["rank"] >= d["headline_rank"] for c in d["changes"])


@requires_semgrep
def test_diff_does_not_change_scores(tmp_path, fixtures):
    old = to_dict(scan(str(fixtures / "clean_integration"), offline=True))
    new = to_dict(scan(str(fixtures / "clean_integration_v2"), offline=True))
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(old))
    b.write_text(json.dumps(new))
    out = tmp_path / "d.json"
    assert cli.main(["diff", str(a), str(b), "--json", "-o", str(out)]) == 0
    d = json.loads(out.read_text())
    assert d["score"] == {
        "from": old["score"],
        "to": new["score"],
        "delta": new["score"] - old["score"],
    }
    assert json.loads(a.read_text()) == old  # inputs untouched


def test_cli_rejects_missing_report(tmp_path):
    assert cli.main(["diff", str(tmp_path / "nope.json"), str(tmp_path / "x.json")]) == 1


@pytest.mark.network
@requires_semgrep
def test_a_real_handover_surfaces_the_new_publisher(tmp_path):
    repo, old_tag, new_tag, publisher, before = case("BARKLEY_TEST_HANDOVER", 5)
    out = tmp_path / "d.json"
    rc = cli.main(["diff", repo, "--from", old_tag, "--to", new_tag, "--json", "-o", str(out)])
    assert rc == 0
    d = json.loads(out.read_text())
    top = d["changes"][0]
    assert top["kind"] == "new_publisher"
    assert publisher in top["text"] and before in top["text"]
