"""(0.15, his decision 2026-11-21) Test scripts Home Assistant never loads: what Barkley saw
in them doesn't count toward Threat or Exposure and isn't listed under "What it can do",
the list's readings agree with the page's, they get their own fold in the scan details
(never under what Barkley couldn't check), an update that changes one is never a headline,
and a computed import in the app's own code keeps them in the normal list."""

import dataclasses
import sqlite3
from types import SimpleNamespace

from test_shown import fnd, rep

from sniff_test import diff, readings, scanner, shown, ui
from sniff_test.models import Category, Finding, Severity, Tag, TargetKind
from sniff_test.report import graph
from sniff_test.store import Store


def tfind(i, rule, sev="critical", file="tests/test_api.py", line=9):
    return {**fnd(i, rule, sev, file=file, line=line), "tags": ["test-code"]}


def _report():
    return rep([
        tfind(1, "ha-exfil-taint"),
        tfind(2, "ha-unauth-view", "medium", line=30),
        fnd(3, "ha-http-client", "low", file="custom_components/acme/api.py"),
    ])  # fmt: skip


def test_a_test_script_counts_toward_neither_reading():
    r = _report()
    rd = readings.compute(r)
    assert rd.threat == 0 and rd.threat_level == "none"
    assert rd.exposure == 0 and rd.exposure_level == "low"
    # the same finding outside a test script is a found threat
    r2 = rep([fnd(1, "ha-exfil-taint", "critical")])
    assert readings.compute(r2).threat_level == "found"


def test_the_panel_lists_them_apart_and_nowhere_else():
    v = shown.view(_report())
    assert [f["rule_id"] for f in v["findings"]] == ["ha-http-client"]
    assert {f["rule_id"] for f in v["test_scripts"]} == {"ha-exfil-taint", "ha-unauth-view"}
    html = ui.test_scripts_html(v)
    assert "Ignored test scripts that aren't loaded (1 file)" in html
    assert "<code>tests/test_api.py</code>" in html
    assert "line 9" in html and "line 30" in html
    assert "doesn't count toward Threat or Exposure" in html
    assert "couldn" not in html  # Barkley read them: never "couldn't check"
    assert ui.test_scripts_html(shown.view(rep([fnd(3, "ha-http-client", "low")]))) == ""


def test_the_fold_sits_in_the_scan_details_not_under_what_it_can_do():
    v = shown.view(_report())
    page = ui.render_app("", 1, v, [], name="acme").decode()
    head, _, rest = page.partition("In short")
    assert "Ignored test scripts" in head and "Ignored test scripts" not in rest
    can_do = rest.split("What it can do")[1].split("</section>")[0]
    assert "tests/test_api.py" not in can_do


def test_many_files_and_items_are_capped():
    fs = [tfind(i, f"r{i % 9}", "low", file=f"tests/t{i // 9}.py", line=i)
          for i in range(1, 300)]  # fmt: skip
    html = ui.test_scripts_html(shown.view(rep(fs)))
    assert html.count("<li>") == ui.TEST_FILES_SHOWN + 1
    assert "more files" in html and "and 3 more." in html


def test_the_list_index_carries_the_tag(tmp_path):
    st = Store(tmp_path / "s.db")
    sid = st.save(_report())
    idx = st.findings_index([sid])[sid]
    assert sorted(bool(f.get("tags")) for f in idx) == [False, True, True]
    got = readings.compute({"findings": idx, "complete": True, "exposure": "local"})
    assert got.threat_level == "none" and got.exposure == 0


def test_scans_stored_before_are_indexed_once_from_their_reports(tmp_path):
    path = tmp_path / "s.db"
    sid = Store(path).save(_report())
    with sqlite3.connect(path) as db:  # a store from before the table existed
        db.execute("DROP TABLE test_findings")
    report_before = Store(path).report(sid)
    st = Store(path)
    assert len([f for f in st.findings_index([sid])[sid] if f.get("tags")]) == 2
    assert st.report(sid) == report_before  # the stored report is only read


def test_an_update_that_changes_a_test_script_is_never_a_headline():
    old = rep([fnd(3, "ha-http-client", "low", file="custom_components/acme/api.py")])
    new = _report()
    d = diff.diff(old, new)
    tests = [c for c in d["changes"] if "test script" in c["text"]]
    assert len(tests) == 2
    assert all(c["rank"] < diff.HEADLINE_RANK for c in tests)


def _f(rule, file):
    return Finding(rule, "t", Severity.MEDIUM, Category.CODE_EXEC, "m", file=file, line=1)


def test_a_computed_import_keeps_test_scripts_in_the_normal_list():
    tests = frozenset({"tests/test_a.py"})
    assert scanner.loadable_tests([_f("ha-http-client", "x.py")], tests) == tests
    # a computed import in a test file itself changes nothing
    assert scanner.loadable_tests([_f("py-dynamic-import", "tests/test_a.py")], tests) == tests
    assert scanner.loadable_tests([_f("py-dynamic-import", "__init__.py")], tests) == frozenset()


def test_the_graph_draws_no_line_from_a_test_script(tmp_path):
    assert Tag.TEST_CODE == readings.TEST_CODE
    (tmp_path / "manifest.json").write_text("{}")
    target = SimpleNamespace(
        kind=TargetKind.INTEGRATION,
        domain="acme",
        repo="acme/acme",
        source="acme/acme",
        ref="v1",
        commit_sha=None,
        root=tmp_path,
    )
    read = Finding(
        "ha-read-secrets", "t", Severity.HIGH, Category.SENSITIVE_ACCESS, "m", file="a.py", line=1
    )
    in_test = dataclasses.replace(read, file="tests/test_a.py", tags=frozenset({Tag.TEST_CODE}))

    def reads(findings):
        g = graph.build(
            SimpleNamespace(
                target=target, facts=[], findings=findings, packages=[], resolution=None
            )
        )
        return [e for e in g["edges"] if e["relation"] == "reads"]

    assert len(reads([read])) == 1
    assert reads([in_test]) == []
