"""(0.15, his question) Sites the README or .github/FUNDING.yml name: noted as the
developer's words inside the site's fold, never changing its group or what's scored, and
never beside a threat. Hosts are .invalid."""

from pathlib import Path

from sniff_test import ui
from sniff_test.analyzers import endpoints
from sniff_test.models import Target, TargetKind


def _run(tmp_path: Path) -> dict[str, dict]:
    src = tmp_path / "repo"
    pkg = src / "custom_components" / "acme"
    pkg.mkdir(parents=True)
    (pkg / "manifest.json").write_text('{"domain": "acme"}')
    (pkg / "const.py").write_text(
        'NEWS = "https://news.example.invalid/letter"\n'
        'API = "https://api.other.invalid/v1"\n'
        'TIP = "https://ko-fi.com/acme"\n'
    )
    (src / "README.md").write_text(
        "# Acme\n\nSign up at <https://www.news.example.invalid/>.\n"
        "Docs: https://api.other.invalid/docs\n"
    )
    (src / ".github").mkdir()
    (src / ".github" / "funding.yaml").write_text(
        "ko_fi: acme\n# patreon: acme\ncustom: ['https://news.example.invalid/support']\n"
    )
    t = Target(source=str(src), kind=TargetKind.INTEGRATION, root=pkg, source_root=src,
               domain="acme")  # fmt: skip
    return {f.key: f.attrs for f in endpoints.run(t).facts if f.kind == "host"}


def test_readme_and_funding_mentions_are_recorded(tmp_path):
    got = _run(tmp_path)
    assert got["news.example.invalid"]["readme_line"] == 3  # www. counts as the same site
    assert got["news.example.invalid"]["funding"] is True
    assert (
        got["api.other.invalid"]["readme_line"] == 4 and "funding" not in got["api.other.invalid"]
    )
    assert got["ko-fi.com"]["funding"] is True  # a platform key
    assert "patreon.com" not in got  # commented out, and not in the code anyway
    assert got["news.example.invalid"]["class"] == "undeclared"  # the group never changes


def _report(attrs, findings=()):
    edge = {"id": "h" * 16, "source": "s", "relation": "connects_to",
            "target": "host:news.example.invalid", "samples": [], "attrs": attrs}  # fmt: skip
    nodes = [{"id": "host:news.example.invalid", "label": "news.example.invalid"}]
    return {"graph": {"subject": "s", "nodes": nodes, "edges": [edge]},
            "findings": list(findings)}  # fmt: skip


def test_the_fold_says_so_in_barkleys_words_with_a_link_to_the_line():
    """(2026-11-23, his report) the tag promised a quote that wasn't there: Barkley's own
    sentence now, linking to that README line of the scanned release."""
    rep = _report({"class": "undeclared", "readme_line": 3, "funding": True})
    html = ui.zones_html(rep)
    assert "developer&#x27;s words" not in html and "developer's words" not in html
    assert "The README names this site too, on line 3." in html  # no repository: no link
    assert "lists it as a way to support the developer" in html
    rep["target"] = {"repo": "someone/thing", "ref": "v1.2.0"}
    rep["context"] = {"readme": {"file": "README.md"}}
    html = ui.zones_html(rep)
    assert (
        '<a href="https://github.com/someone/thing/blob/v1.2.0/README.md?plain=1#L3" '
        'target="_blank" rel="noopener noreferrer">line 3</a>'
    ) in html


def test_no_link_from_an_odd_repository_or_readme_name():
    rep = _report({"class": "undeclared", "readme_line": 3})
    for target, name in (({"repo": "a/b/c", "ref": "v1"}, "README.md"),
                         ({"repo": "a/b", "ref": ""}, "README.md"),
                         ({"repo": "a/b", "ref": "v1"}, "../../x.md")):  # fmt: skip
        rep["target"], rep["context"] = target, {"readme": {"file": name}}
        assert "<a href" not in ui.zones_html(rep)


def test_never_beside_a_threat():
    attrs = {"class": "undeclared", "readme_line": 3}
    assert "README" not in ui.zones_html(_report(attrs), dev_words=False)  # a found threat
    ev = "sources: a.py:1; destinations: news.example.invalid, b.invalid"
    near = {"rule_id": "possible-exfil", "evidence": ev}
    assert "README" not in ui.zones_html(_report(attrs, [near]))
