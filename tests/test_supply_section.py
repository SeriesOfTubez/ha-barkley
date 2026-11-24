"""(0.15) "Where its code comes from": the project and this release, every package, the
published libraries copied in, and code that arrives while the app runs. Facts the scan
already keeps, in plain sentences; names from the scanned repo are escaped; nothing here
is scored."""

from __future__ import annotations

from sniff_test import readings, ui


def _edge(rel, target, **attrs):
    return {"id": target, "source": "integration:acme", "target": target, "relation": rel,
            "attrs": attrs, "finding_ids": attrs.pop("finding_ids", [])}  # fmt: skip


def _report(packages=(), kind="integration", findings=(), **target):
    nodes = [{"id": f"package:{label}", "label": label} for label, _rel, _a in packages]
    edges = [_edge(rel, f"package:{label}", **dict(a)) for label, rel, a in packages]
    return {
        "complete": True,
        "ha_version": "2026.11.2",
        "target": {"kind": kind, "ref": "v1.2.0", "install_source": "tag_source", **target},
        "graph": {"subject": "integration:acme", "nodes": nodes, "edges": edges},
        "findings": list(findings),
    }


PROVENANCE = {
    "full_name": "acme/widget",
    "owner_type": "User",
    "created_at": "2024-03-02T10:00:00Z",
    "former_names": [{"name": "olduser/widget", "how": "redirect"}],
    "publishers": [
        {"login": "release-bot[bot]", "bot": True, "releases": 12,
         "first": "2024-04-01T00:00:00+00:00", "last": "2026-10-30T00:00:00+00:00"},
        {"login": "acme", "bot": False, "releases": 1,
         "first": "2024-03-03T00:00:00+00:00", "last": "2024-03-03T00:00:00+00:00"},
    ],
    "releases": [
        {"tag": "v1.2.0", "published_at": "2026-10-30T08:00:00Z", "publisher": "release-bot[bot]",
         "bot": True, "asset_uploaders": ["acme"], "installed": True},
    ],
}  # fmt: skip


def test_the_project_and_the_release_in_plain_sentences():
    rep = _report(signature={"state": "developer"})
    rep["provenance"] = PROVENANCE
    html = ui.supply_html(rep)
    assert "<h2>Where its code comes from</h2>" in html
    assert "The Marketplace installs the code as it is at <code>v1.2.0</code>." in html
    assert ("The project is <code>acme/widget</code> on GitHub, under one person's account. "
            "It was created on 2024-03-02.") in html.replace("&#x27;", "'")  # fmt: skip
    assert "It used to be at <code>olduser/widget</code>." in html
    assert ("This release was published by <code>release-bot[bot]</code>, an automated "
            "workflow, on 2026-10-30.") in html  # fmt: skip
    assert "Its files were uploaded by <code>acme</code>." in html
    assert "The project has 13 releases, from 2 publishers." in html
    assert "<code>acme</code>: one release, 2024-03-03</li>" in html
    assert "12 releases, 2024-04-01 to 2026-10-30" in html
    assert "signed with the developer" in html


def test_a_release_file_and_a_project_without_releases_say_what_was_read():
    html = ui.supply_html(_report(install_source="release_asset"))
    assert "installs a file attached to release <code>v1.2.0</code>. Barkley read that file" in html
    html = ui.supply_html(_report(install_source="default_branch"))
    assert "has no release the Marketplace can use" in html


def test_every_python_package_is_listed_the_apps_own_first():
    pk = [
        ("pypi/zlib-extra", "depends_on", {"version": "1.0", "direct": False,
                                           "ha_provided": True}),
        ("pypi/acme-client", "depends_on", {"version": "2.1.0", "direct": True,
                                            "ha_provided": False, "finding_ids": ["f1"]}),
        ("pypi/anyio", "depends_on", {"version": "4.0", "direct": False, "ha_provided": False}),
    ]  # fmt: skip
    rep = _report(pk, findings=[
        {"id": "f1", "rule_id": "dep-vuln", "dependency": {
            "package": "acme-client", "ecosystem": "PyPI", "version": "2.1.0",
            "advisories": [{"id": "GHSA-a"}, {"id": "GHSA-b"}]}},
        {"id": "f2", "rule_id": "dep-malicious",
         "evidence": "zlib-extra@1.0 (PyPI): MAL-2026-1"},
    ])  # fmt: skip
    html = ui.supply_html(rep)
    assert "Python packages (3)" in html
    assert ("Home Assistant installs 3 Python packages for this app. The app asks for one of "
            "them itself, and the other 2 come along with it. Home Assistant 2026.11.2 already "
            "ships 1 of them at the same version.") in html  # fmt: skip
    # (0.15, his report) affected packages come first: malware, then known vulnerabilities,
    # each with an icon; then the app's own, then the rest
    assert html.index("<code>zlib-extra") < html.index("<code>acme-client") < html.index(
        "<code>anyio")  # fmt: skip
    assert "the app asks for it" in html and "comes along" in html
    assert "Home Assistant already ships it" in html
    assert 'class="pk bug">' in html and "2 known vulnerabilities</span>" in html
    assert 'class="pk bad">' in html and "malware warning</span>" in html


def test_a_cards_lock_file_packages_with_a_known_bug_are_listed():
    pk = [("npm/lit", "bundles", {"spec": "^3.0.0"})]
    rep = _report(pk, findings=[
        {"id": "f1", "rule_id": "dep-vuln", "dependency": {
            "package": "semver", "ecosystem": "npm", "version": "5.7.1",
            "advisories": [{"id": "GHSA-a"}]}},
        {"id": "f2", "rule_id": "dep-vuln", "dependency": {
            "package": "semver", "ecosystem": "npm", "version": "6.3.0",
            "advisories": [{"id": "GHSA-a"}]}},
        {"id": "f3", "rule_id": "dep-build-tool-vuln",
         "evidence": "<img/src=x>@1.0 (npm): GHSA-b, GHSA-c"},
    ])  # fmt: skip
    html = ui.supply_html(rep)
    assert (
        "Its lock file brings along 2 more packages with a known vulnerability or a malware"
    ) in html
    assert "<code>semver</code>" in html and "5.7.1, 6.3.0 · comes along through the lock" in html
    assert "only used to build it" in html and "<img" not in html
    assert "one known vulnerability</span>" in html  # an advisory once
    assert "2 known vulnerabilities</span>" in html
    assert html.index("<code>lit</code>") < html.index("<code>semver</code>")


def test_a_long_package_list_folds_and_names_are_escaped():
    pk = [(f"pypi/p{i:03d}", "depends_on", {"version": "1", "direct": False}) for i in range(80)]
    pk.append(("pypi/<img src=x>", "depends_on", {"version": "<b>", "direct": True}))
    html = ui.supply_html(_report(pk))
    assert "Python packages (81)" in html and "76 more</summary>" in html
    assert "<img" not in html and "&lt;img src=x&gt;" in html and "· &lt;b&gt;" in html


def test_a_scan_without_the_resolved_list_says_so():
    pk = [("pypi/acme-client", "depends_on", {"requirement": "acme-client>=2", "direct": True})]
    html = ui.supply_html(_report(pk))
    assert "The app asks for one Python package." in html
    assert "didn't work out what those bring along" in html.replace("&#x27;", "'")


def test_a_card_lists_the_npm_packages_it_is_built_from():
    pk = [("npm/lit", "bundles", {"spec": "^3.0.0"}), ("npm/@acme/chart", "bundles", {})]
    html = ui.supply_html(_report(pk, kind="plugin"))
    assert "npm packages it is built from (2)" in html and "<code>lit</code>" in html
    assert "nothing that loads code from a website while the card runs" in html


def test_code_that_arrives_while_running_is_listed_from_the_scans_items():
    fs = [
        {"id": "a", "rule_id": "py-runtime-pip", "file": "setup.py", "line": 9},
        {"id": "b", "rule_id": "dep-vcs-or-url-requirement", "file": "manifest.json"},
        {"id": "c", "rule_id": "ha-unauth-view", "file": "views.py", "line": 3},
    ]
    html = ui.supply_html(_report(findings=fs))
    assert "<b>Installs extra software while running.</b>" in html
    assert "<code>setup.py, line 9</code>" in html
    assert "Installs a code library straight from a web address" in html
    assert "views.py" not in html
    assert "never sees code that arrives later" in html
    none = ui.supply_html(_report())
    assert "Barkley found nothing that installs packages while the app runs." in none
    part = _report()
    part["complete"] = False
    assert "In the part Barkley could check, it found nothing" in ui.supply_html(part)


def test_what_the_scan_noted_about_the_project_points_at_its_item():
    fs = [{"id": "a", "rule_id": "repo-transferred"}, {"id": "b", "rule_id": "repo-transferred"}]
    html = ui.supply_html(_report(findings=fs)).replace("&#x27;", "'")
    assert html.count("<b>The project changed owners.</b>") == 1
    assert "under How it's made" in html


def test_the_published_libraries_sit_inside_it_and_an_empty_report_shows_nothing():
    rep = _report()
    rep["libraries"] = [{"name": "chart-lib", "version": "4.4.1", "files": ["www/chart.js"]}]
    html = ui.supply_html(rep)
    assert '<h3 class="kindh">Published libraries it ships (1)</h3>' in html
    assert html.count("<section") == 1  # one box, the libraries are a part of it
    assert ui.supply_html({}) == "" and ui.supply_html({"target": {"kind": "integration"}}) == ""


def test_nothing_in_the_section_moves_a_reading():
    """Listing where the code comes from never changes Threat or Exposure."""
    rep = _report([("pypi/x", "depends_on", {"version": "1", "direct": True})])
    before = readings.compute(rep).to_dict()
    rep["provenance"] = PROVENANCE
    ui.supply_html(rep)
    assert readings.compute(rep).to_dict() == before


def test_a_quiet_or_archived_project_is_said_on_the_page_and_the_card():
    """(0.15, his report) nothing pushed for as long as the Quiet projects setting says."""
    from datetime import date

    rep = _report(findings=[{"id": "f1", "rule_id": "dep-vuln",
                             "evidence": "semver@5.7.1 (npm): GHSA-a"}])  # fmt: skip
    rep["provenance"] = {**PROVENANCE, "pushed_at": "2024-08-24T15:15:10Z", "archived": False}
    today = date(2026, 11, 21)
    assert ui.quiet(rep, today) == (
        "No changes in over 2 years",
        "The project has gone quiet: when Barkley sniffed it, the last push to it on GitHub "
        "was on 2024-08-24, over 2 years ago.",
    )
    assert ui.quiet(rep, date(2025, 8, 24))[0] == "No changes in a year"
    assert ui.quiet(rep, date(2025, 8, 23)) == ("", "")  # a day short of the 12 months
    assert ui.quiet({**rep, "shown": {"quiet_months": 6}}, date(2025, 4, 24))[0] == (
        "No changes in 8 months")  # fmt: skip
    assert ui.quiet({**rep, "shown": {"quiet_months": 0}}, today) == ("", "")  # never say it
    html = ui.supply_html(rep)
    assert "<b>The project has gone quiet:" in html
    assert "The known vulnerabilities in its packages are unlikely to be fixed." in html
    fresh = {**rep, "provenance": {**PROVENANCE, "pushed_at": "2999-01-01T00:00:00Z"}}
    assert ("When Barkley sniffed it, the last push to the project on GitHub was on "
            "2999-01-01.") in ui.supply_html(fresh)  # fmt: skip
    old = {**rep, "provenance": {**PROVENANCE, "pushed_at": "2999-01-01T00:00:00Z",
                                 "archived": True}}  # fmt: skip
    assert ui.quiet(old)[0] == "Archived project"
    assert "The owner has archived the project on GitHub" in ui.supply_html(old)
    assert ui.quiet({"provenance": {"pushed_at": "<script>"}}) == ("", "")
    assert ui.quiet({}) == ("", "")  # a scan from before 0.15

    # (his ask) the same in the facts under the app's name: release day, last push, a chip
    rep["target"]["repo"] = "acme/widget"
    facts = ui.facts_line(rep)
    assert "v1.2.0, released 2026-10-30</span>" in facts and "Last push 2024-08-24</span>" in facts
    assert '<span class="chip" title="The project has gone quiet' in facts
    assert "No changes in" in facts
    assert "chip" not in ui.facts_line(fresh) and "Last push 2999-01-01" in ui.facts_line(fresh)
    assert "Archived project</span>" in ui.facts_line(old)
    assert "Last push" not in ui.facts_line({"target": {"ref": "v1"}})  # before 0.15
