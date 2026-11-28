"""(0.15) The panel's words for three facts a scan records: how the code sends requests
to each site, the environment variables it uses, and the libraries it found but read as
code. Plain sentences, everything from the scanned code escaped, nothing scored."""

from __future__ import annotations

from test_zone_layout import _graph_report

from sniff_test import ui

SHAPES = [
    {"method": "POST", "body": ["user", "password"], "headers": ["Authorization", "X-Key"],
     "query": None, "address": [], "auth": False, "more": False, "count": 3,
     "at": ["api.py:18", "api.py:40", "api.py:61"]},
    {"method": "GET", "body": None, "headers": None, "query": ["full"],
     "address": ["device_id"], "auth": True, "more": True, "count": 1, "at": ["api.py:25"]},
]  # fmt: skip


def _report(sites=None, elsewhere=()):
    rep = _graph_report([("api.acme.invalid", "undeclared", ["https"], [], [])])
    rep["requests"] = {"version": 1, "sites": sites or {}, "elsewhere": list(elsewhere),
                       "total": 4}  # fmt: skip
    return rep


def test_a_site_says_how_the_code_sends_requests_to_it():
    html = ui.zones_html(_report({"api.acme.invalid": SHAPES}))
    assert "Sends <b>POST</b> requests here from 3 places in the code." in html
    assert "The body carries <code>user</code>, <code>password</code>." in html
    assert "It sets the headers <code>Authorization</code>, <code>X-Key</code>." in html
    assert "Sends <b>GET</b> requests here from one place in the code." in html
    assert "After the <code>?</code> in the address it adds <code>full</code>." in html
    assert "Into the address itself it puts <code>device_id</code>." in html
    assert "It passes a login for the site" in html and "can add more." in html
    assert "api.py:18, api.py:40, api.py:61" in html


def test_a_get_is_never_called_safe():
    """His rule: a GET never makes anything safe by itself."""
    rep = _report({"api.acme.invalid": SHAPES})
    note = ui.requests_note(rep)
    assert "GET or POST alone doesn't tell you what is sent" in note
    html = ui.zones_html(rep).lower()
    for word in ("safe", "harmless", "only reads", "read-only"):
        assert word not in html
    assert ui.requests_note({}) == ""  # a card, or a scan from before 0.15: no sentence


def test_what_is_built_elsewhere_is_said_plainly():
    shape = {"method": "", "body": [], "headers": [], "query": [], "address": [],
             "auth": False, "more": False, "count": 2, "at": ["a.py:3"]}  # fmt: skip
    line = ui.request_line(shape, here=False)
    assert line.startswith("Sends requests from 2 places in the code. The code picks the method")
    assert "It has a body that is put together elsewhere in the code." in line
    assert "It sets headers that are put together elsewhere." in line
    assert "a.py:3 and 1 more" in line


def test_requests_without_a_site_are_listed_apart():
    html = ui.zones_html(_report(elsewhere=[SHAPES[1]]))
    assert "Requests to addresses that aren&#x27;t in the code" in html or (
        "Requests to addresses it works out while it runs" in html
    )
    assert "Sends <b>GET</b> requests from one place in the code." in html
    # no site, no port: the box still shows them
    rep = {"graph": {"subject": "s", "nodes": [], "edges": []},
           "requests": {"sites": {}, "elsewhere": [SHAPES[0]]}}  # fmt: skip
    assert "Sends <b>POST</b> requests from 3 places" in ui.zones_html(rep)


def test_many_kinds_of_request_are_cut_and_names_escaped():
    many = [dict(SHAPES[0], body=[f"f{i}"], count=1, at=[]) for i in range(7)]
    many[0]["body"] = ["<script>x</script>", *[f"n{i}" for i in range(9)]]
    html = ui.zones_html(_report({"api.acme.invalid": many}))
    shown, folded = html.split("3 more kinds of request to this site</summary>")
    assert shown.count("Sends <b>POST</b>") == ui.REQUESTS_SHOWN  # the rest fold open
    assert folded.count("Sends <b>POST</b>") == 3
    assert "<script>x" not in html and "&lt;script&gt;" in html and "and 4 more" in html
    junk = {"api.acme.invalid": ["x", None, {"method": "<b>", "count": "many", "at": [3]}]}
    assert "<b>&lt;" not in ui.zones_html(_report(junk))  # an unknown method isn't printed


ENV = {
    "version": 1,
    "reads": [
        {"name": "ACME_HOME", "count": 2, "at": ["a.py:3", "b.py:9"], "own": True},
        {"name": "TZ", "count": 1, "at": ["a.py:7"], "own": False},
    ],
    "writes": [{"name": "ACME_HOME", "count": 1, "at": ["a.py:2"]}],
    "unnamed_reads": 1,
    "unnamed_writes": 0,
    "whole": {"count": 2, "at": ["run.py:5", "run.py:9"]},
}


def test_environment_variables_are_listed_by_name():
    html = ui.environment_html({"environment": ENV})
    assert "<h2>Environment variables it uses</h2>" in html
    assert "Reads <code>ACME_HOME</code>. The app sets this one itself." in html
    assert "Reads <code>TZ</code>. <span" in html and "a.py:7" in html
    assert "Sets or removes <code>ACME_HOME</code>." in html
    assert "Reads one more whose name is put together while the app runs." in html
    assert "Also takes all of them at once in 2 places" in html
    assert "Where: <code>run.py</code> lines 5 and 9" in html


def test_an_app_that_only_copies_the_whole_environment_says_so_plainly():
    """(0.15, his report on a real integration) It names no variable; it copies them all in
    three places to start git, a shell and ssh."""
    only = dict(ENV, reads=[], writes=[], unnamed_reads=0,
                whole={"count": 3, "at": ["backend/git.py:56", "backend/term.py:277",
                                          "backend/term.py:596"]})  # fmt: skip
    html = ui.environment_html({"environment": only})
    assert "It doesn't read or set any environment variable by name." in html
    assert "In 3 places it takes all of them at once." in html
    assert "such as git or a shell" in html and "Supervisor" in html
    assert ("Where: <code>backend/git.py</code> line 56; <code>backend/term.py</code> lines "
            "277 and 596") in html  # fmt: skip
    assert "Most are harmless" not in html  # the intro about named variables doesn't apply
    assert ui.environment_html({}) == "" and ui.environment_html({"environment": "x"}) == ""
    empty = dict(ENV, reads=[], writes=[], unnamed_reads=0, whole={"count": 0, "at": []})
    none = ui.environment_html({"environment": empty})  # checked, none used: said plainly
    assert "This app neither reads nor sets any environment variables." in none
    bad = dict(ENV, reads=[{"name": "<img src=x>", "count": 1, "at": ["<i>"]}])
    out = ui.environment_html({"environment": bad})
    assert "<img" not in out and "<i>" not in out


def test_libraries_that_were_read_are_listed_with_the_reason():
    rep = {
        "libraries": [{"name": "docview-dist", "version": "4.10.38", "files": ["www/v.js"],
                       "published": "2025-01-02", "weekly_downloads": 60000000,
                       "advisories": 0}],
        "library_lookups": {
            "looked_up": 6, "unanswered": 1, "no_match": 3, "not_npm": 0,
            "read": [{"name": "tiny-lib", "version": "0.0.1", "files": ["www/t.js"],
                      "published": "2026-11-10", "weekly_downloads": 12, "advisories": 2,
                      "why": "new"}],
        },
    }  # fmt: skip
    html = ui.libraries_html(rep)
    assert "· 1 file · not read</span>" in html and "· 1 file · read as code</span>" in html
    assert ("Barkley read this as code, because this version was published less than a month "
            "ago.") in html  # fmt: skip
    assert "No known security problems are listed for this version." in html
    assert "2 known security problems are listed for this version." in html
    assert "3 large JavaScript files matched no published file. One lookup got no answer." in html
    assert "Barkley read all of those as code." in html
    only_read = {"library_lookups": rep["library_lookups"]}
    assert "tiny-lib" in ui.libraries_html(only_read)
    assert ui.libraries_html({"library_lookups": {"read": [], "no_match": 4}}) == ""


def test_each_request_is_a_block_with_one_fact_per_line():
    html = ui.zones_html(_report({"api.acme.invalid": SHAPES}))
    assert html.count('<div class="req">') == 2
    assert ('<div>Sends <b>POST</b> requests here from 3 places in the code.</div>'
            '<span class="u">The body carries') in html  # fmt: skip


def test_a_site_without_a_request_says_so_once_the_scan_read_requests():
    rep = _report({})
    html = ui.zones_html(rep)
    assert "Barkley saw no request in the code that names this address." in html
    assert "may only mention it" in html
    rep["requests"]["elsewhere"] = [SHAPES[1]]
    html = ui.zones_html(rep)
    assert "so it may still reach it" in html and "may only mention it" not in html
    del rep["requests"]  # a card, or a scan from before 0.15: nothing is claimed
    assert "saw no request" not in ui.zones_html(rep)


def test_requests_without_a_site_are_one_sentence_with_the_detail_folded():
    html = ui.zones_html(_report(elsewhere=[SHAPES[0], SHAPES[1]]))
    assert "4 requests go to an address the code only works out while the app runs" in html
    assert "(3 POST, 1 GET)" in html and "<summary>Where in the code</summary>" in html


def test_more_addresses_fold_open():
    urls = [f"https://api.acme.invalid/v{i}" for i in range(6)]
    rep = _graph_report([("api.acme.invalid", "undeclared", ["https"], [], urls)])
    html = ui.zones_html(rep)
    assert "<summary>3 more addresses</summary>" in html and "/v5</code>" in html


def test_packages_say_what_was_checked_and_what_came_back():
    rep = {"target": {"kind": "integration"}, "analyzers": [{"name": "osv-python", "state": "ok"}],
           "findings": [],
           "graph": {"subject": "s", "nodes": [{"id": "package:pypi/x", "label": "pypi/x"}],
                     "edges": [{"source": "s", "target": "package:pypi/x",
                                "relation": "depends_on", "attrs": {"version": "1"}}]}}  # fmt: skip
    html = ui.supply_html(rep)
    assert "<b>0</b> malware warnings" in html and "<b>0</b> with known vulnerabilities" in html
    bug = {"rule_id": "dep-vuln", "dependency": {"package": "x"}}
    rep["findings"] = [{"id": "a", **bug}, {"id": "b", **bug}]
    assert "<b>1</b> with known vulnerabilities" in ui.supply_html(rep)
    rep["analyzers"][0]["state"] = "error"
    assert "check these packages" in ui.supply_html(rep) and "<b>0</b>" not in ui.supply_html(rep)


def test_a_login_free_page_shows_its_own_description_as_the_developers_words():
    f = {"id": "a", "rule_id": "ha-unauth-view", "file": "views.py", "line": 3,
         "evidence": "class PanelView(HomeAssistantView):", "page": "/acme/panel",
         "page_note": "Serve the <b>panel</b> page."}  # fmt: skip
    html = ui.login_free_pages({"findings": [f]})
    assert "Serve the &lt;b&gt;panel&lt;/b&gt; page." in html and 'class="src dev"' in html
    threat = {"findings": [f], "readings": {"threat_level": "found"}}
    assert "Serve the" not in ui.login_free_pages(threat)  # never beside a found threat


def test_sites_with_a_request_and_sites_only_mentioned_are_listed_apart():
    rep = _graph_report([("api.acme.invalid", "undeclared", ["https"], [], []),
                         ("docs.acme.invalid", "undeclared", ["https"], [], []),
                         ("bad.acme.invalid", "undeclared", ["https"], [], [])])  # fmt: skip
    rep["graph"]["edges"][2]["finding_ids"] = ["t1"]  # a site with a threat item
    rep["requests"] = {"sites": {"api.acme.invalid": [SHAPES[0]]}, "elsewhere": []}
    proven = ui.zones_html(rep, part="connects")
    other = ui.zones_html(rep, part="mentioned")
    assert "api.acme.invalid" in proven and "docs.acme.invalid" not in proven
    assert "docs.acme.invalid" in other and "api.acme.invalid" not in other
    # a site with a threat item is never moved to the quieter list
    assert "bad.acme.invalid" in proven and "bad.acme.invalid" not in other
    assert "saw no request" not in other  # the box's own text says it once
    rep["requests"]["sites"] = {}
    rep["graph"]["edges"][2]["finding_ids"] = []
    assert "Barkley read no request to a site named in the code." in ui.zones_html(
        rep, part="connects")  # fmt: skip


def test_sites_picked_from_a_list_count_as_sites_it_connects_to():
    """Seen on his box 2026-11-23: a real cloud integration picks one of two cloud sites
    written in its code for nearly every request. The scan kept them under requests whose
    address it works out while it runs, and neither the picture nor "Where it connects"
    showed them."""
    from sniff_test import does, ui

    shape = {"method": "POST", "body": [], "headers": [], "query": None, "address": [],
             "count": 3, "at": ["cloud.py:9"],
             "from": [{"kind": "list", "detail": "a.cloud.invalid,b.cloud.invalid"}]}  # fmt: skip
    odd = {**shape, "from": [{"kind": "list", "detail": "<b>x</b>,ok.invalid"}]}
    rep = {"target": {"kind": "integration"}, "findings": [],
           "graph": {"subject": "integration:x", "nodes": [], "edges": []},
           "requests": {"sites": {}, "elsewhere": [shape, odd], "total": 6}}  # fmt: skip
    assert sorted(ui.picked_sites(rep)) == ["a.cloud.invalid", "b.cloud.invalid", "ok.invalid"]
    html = ui.zones_html(rep, None, "", True, "connects")
    assert "<code>a.cloud.invalid</code>" in html and "<b>x" not in html
    assert html.count("picks this site or another one") == 2  # once per site
    assert "builds the address for this site while it runs" in html  # ok.invalid alone
    assert "Requests to addresses it works out while it runs" in html
    m = does.build(rep, "X")
    assert ("a.cloud.invalid", ["one of 2 sites it picks from", "POST"], "") in m.sites
