"""(0.15) The update comparison for the facts a scan keeps since 0.15: how the code sends
requests, the environment variables it uses and the published libraries copied into it.
Facts, not warnings: they are listed below the headline and never notify on their own."""

from __future__ import annotations

from sniff_test import diff, ui


def _shape(method, **parts):
    return {"method": method, "body": None, "headers": None, "query": None, "address": [],
            "count": 1, "at": ["api.py:3"], **parts}  # fmt: skip


def _texts(changes):
    return [c.text for c in changes]


def test_a_new_kind_of_request_to_a_site_is_said_with_what_it_carries():
    old = {"requests": {"sites": {"api.acme.invalid": [_shape("GET")]}, "elsewhere": []}}
    new = {"requests": {"sites": {"api.acme.invalid": [
        _shape("GET"), _shape("POST", body=["user", "password"], headers=["X-Key"])]},
        "elsewhere": [_shape("")]}}  # fmt: skip
    out = diff.request_changes(old, new)
    assert _texts(out) == [
        "It now sends POST requests to api.acme.invalid, with password, user in the body; "
        "X-Key as headers",
        "It now sends requests with a method picked while it runs to an address that isn't in "
        "the code",
    ]
    assert all(c.rank < diff.HEADLINE_RANK and c.kind == "new_request" for c in out)


def test_new_names_in_a_request_it_already_sent():
    old = {"requests": {"sites": {"a.invalid": [_shape("POST", body=["user"])]}}}
    new = {"requests": {"sites": {"a.invalid": [_shape("POST", body=["user", "token"],
                                                       query=["full"])]}}}  # fmt: skip
    assert _texts(diff.request_changes(old, new)) == [
        "Its POST requests to a.invalid now carry token in the body",
        "Its POST requests to a.invalid now carry full after the ? in the address",
    ]
    assert diff.request_changes(new, new) == []


def test_a_scan_from_before_these_facts_says_nothing():
    new = {"requests": {"sites": {"a.invalid": [_shape("POST")]}},
           "environment": {"reads": [{"name": "TZ"}]},
           "library_lookups": {"read": [{"name": "x", "version": "1"}]}}  # fmt: skip
    assert diff.request_changes({}, new) == [] == diff.request_changes(new, {})
    assert diff.environment_changes({}, new) == [] == diff.library_changes({}, new)


def test_new_environment_variables_by_name():
    old = {"environment": {"reads": [{"name": "TZ"}], "writes": []}}
    new = {"environment": {"reads": [{"name": "TZ"}, {"name": "SUPERVISOR_TOKEN"},
                                     {"name": "HOME"}],
                           "writes": [{"name": "PATH"}], "whole": {"count": 1}}}  # fmt: skip
    assert _texts(diff.environment_changes(old, new)) == [
        "It now reads the environment variables HOME, SUPERVISOR_TOKEN",
        "It now sets or removes the environment variable PATH",
        "It now uses all environment variables at once, for example to copy them or hand them "
        "to another program",
    ]


def test_libraries_new_changed_read_and_gone():
    was = [("chart-lib", "4.3.0"), ("pdf-lib", "1.0"), ("old-lib", "2")]
    old = {"libraries": [{"name": n, "version": v} for n, v in was],
           "library_lookups": {"read": []}}  # fmt: skip
    read = [{"name": "pdf-lib", "version": "1.0", "why": "new"},
            {"name": "tiny", "version": "0.1", "why": "new"}]  # fmt: skip
    new = {"libraries": [{"name": "chart-lib", "version": "4.4.1"}],
           "library_lookups": {"read": read}}  # fmt: skip
    out = diff.library_changes(old, new)
    assert _texts(out) == [
        "The copied-in library chart-lib is now 4.4.1 (was 4.3.0)",
        "Barkley recognized the copied-in library pdf-lib before and reads it as code now",
        "A new published library is copied in: tiny 0.1. Barkley read it as code",
        "The published library old-lib is no longer copied in",
    ]
    assert [c.sign for c in out] == ["~", "~", "+", "-"]


def test_the_whole_comparison_carries_them_and_the_panel_escapes_names():
    def rep(extra):
        graph = {"subject": "integration:x", "nodes": [], "edges": []}
        return {"schema_version": 1, "exposure": "local", "score": 100, "complete": True,
                "verdict": "Good Boy", "tool": {"version": "0"}, "findings": [],
                "target": {"repo": "acme/x", "ref": "v1", "kind": "integration"},
                "analyzers": [], "graph": graph, **extra}  # fmt: skip

    old = rep({"requests": {"sites": {}}, "environment": {"reads": []}})
    new = rep({"requests": {"sites": {"a.invalid": [_shape("POST", body=["<b>x</b>"])]}},
               "environment": {"reads": [{"name": "TZ"}]}})  # fmt: skip
    d = diff.diff(old, new)
    kinds = {c["kind"] for c in d["changes"]}
    assert {"new_request", "new_env"} <= kinds
    assert not [c for c in d["changes"] if c["rank"] >= diff.HEADLINE_RANK]
    for c in d["changes"]:
        lead, html, _raw = ui.change_line(c)
        assert lead == "New" and "<b>x" not in html
    assert any("&lt;b&gt;x&lt;/b&gt; in the body" in ui.change_line(c)[1] for c in d["changes"])


def _app(services=(), packages=(), carried=(), platforms=None, sites=None, env=None):
    nodes = [{"id": "integration:x", "kind": "integration", "label": "x"}]
    edges = []
    for s in services:
        nodes.append({"id": f"service:{s}", "kind": "service", "label": s})
        edges.append(
            {
                "source": "integration:x",
                "target": f"service:{s}",
                "relation": "registers",
                "finding_ids": [],
            }
        )
    for p, direct in [(p, True) for p in packages] + [(p, False) for p in carried]:
        nodes.append({"id": f"package:pypi/{p}", "kind": "package", "label": f"pypi/{p}"})
        edges.append(
            {
                "source": "integration:x",
                "target": f"package:pypi/{p}",
                "relation": "depends_on",
                "attrs": {"direct": direct, "version": "1"},
                "finding_ids": [],
            }
        )
    rep = {"graph": {"subject": "integration:x", "nodes": nodes, "edges": edges}}
    if platforms is not None:
        rep["platforms"] = list(platforms)
    if sites is not None:
        rep["requests"] = {"sites": {h: [_shape("GET")] for h in sites}, "elsewhere": []}
    if env is not None:
        rep["environment"] = {"reads": [{"name": n} for n in env]}
    return rep  # fmt: skip


def test_what_the_update_changes_counts_added_and_removed_by_name():
    """(0.15, his ask 2026-11-23) Beyond security: actions, kinds of entity, packages,
    sites, environment variables, added and removed; a version bump of a package is no
    change; kinds of entity, not a count of entities."""
    old = _app(["x.refresh", "x.reset"], ["aiohttp"], ["yarl"], ["sensor"], ["api.x.invalid"],
               [])  # fmt: skip
    new = _app(["x.refresh", "x.a", "x.b", "x.c"], ["aiohttp", "pyx", "qy"], ["yarl"],
               ["sensor", "switch", "binary_sensor"], ["api.x.invalid", "eu.x.invalid"],
               ["X_KEY"])  # fmt: skip
    what = diff.what_changes(old, new)
    by = {w["kind"]: w for w in what}
    assert by["actions"]["added"] == ["x.a", "x.b", "x.c"] and by["actions"]["removed"] == [
        "x.reset"
    ]
    assert by["entities"]["added"] == ["binary sensor", "switch"]
    assert by["packages"]["added"] == ["pyx", "qy"] and "carried" not in by
    assert diff.what_sentence(what) == (
        "Adds 3 actions you can use in automations, adds 2 kinds of entity, adds 2 packages it "
        "requires, sends requests to 1 new site, reads 1 more environment variable, no longer "
        "adds 1 action you can use in automations."
    )
    assert diff.what_sentence([]) == ""
    # a scan that doesn't keep a fact never reads as "all removed"
    assert "entities" not in {w["kind"] for w in diff.what_changes(_app(), new)}
    from test_store import report

    # the full comparison carries it; an older scan without the facts says it can't tell
    d = diff.diff(report(repo="acme/x", ref="v1"), report(repo="acme/x", ref="v2"))
    assert d["what"] == [] and d["what_known"] is False


def test_the_comparison_page_names_them_escaped_and_says_when_it_cant_tell():
    from sniff_test import server

    what = [{"kind": "actions", "added": ["x.<b>"], "removed": [], "n_added": 1,
             "n_removed": 0}]  # fmt: skip
    html = server.what_html({"what": what, "what_known": True})
    assert "Adds 1 action you can use in automations." in html
    assert "<code>x.&lt;b&gt;</code>" in html and "<b>x" not in html
    assert "0.15 or later" in server.what_html({"what": [], "what_known": False})
    assert "adds and removes no actions" in server.what_html({"what": [], "what_known": True})
