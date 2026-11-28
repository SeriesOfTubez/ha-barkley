"""(0.14.1) A dependency's known vulnerability by exposure, with CISA's SSVC assessment
from the CVE record (user decision 2026-11-18). The CVE records here are faked: no test
reaches a real server, and the package names are made up."""

from __future__ import annotations

import pytest

from sniff_test.analyzers import osv
from sniff_test.fetch import http
from sniff_test.models import Advisory, Category, DepFacts, Finding, Severity, Tag
from sniff_test.scoring import Exposure, apply_exposure


def _record(options: list[dict], kev: bool = False) -> dict:
    metrics = [{"other": {"type": "ssvc", "content": {"options": options}}}]
    if kev:
        metrics.append({"other": {"type": "kev", "content": {"dateAdded": "2026-01-01"}}})
    return {"containers": {"adp": [{"metrics": metrics}]}}


WORST = [{"Exploitation": "active"}, {"Automatable": "yes"}, {"Technical Impact": "total"}]


@pytest.fixture
def cve(monkeypatch, tmp_path):
    monkeypatch.setenv("SNIFF_TEST_CACHE", str(tmp_path / "cache"))
    records: dict[str, object] = {}
    asked: list[str] = []

    def fake(url: str, timeout: float, max_bytes: int = 0):
        asked.append(url)
        rec = records.get(url.rsplit("/", 1)[-1])
        if isinstance(rec, Exception):
            raise rec
        return rec

    monkeypatch.setattr(http, "lookup_json", fake)
    return records, asked


def test_the_ssvc_decision_is_read_from_the_cve_record(cve):
    records, asked = cve
    records["CVE-2026-0001"] = _record(WORST)
    records["CVE-2026-0002"] = _record(
        [{"Exploitation": "poc"}, {"Automatable": "no"}, {"Technical Impact": "partial"}],
        kev=True,
    )
    assert osv.ssvc("CVE-2026-0001") == ("active", "yes", "total", False)
    assert osv.ssvc("CVE-2026-0002") == ("poc", "no", "partial", True)
    assert osv.ssvc("CVE-2026-0001") == ("active", "yes", "total", False)
    assert len(asked) == 2  # the second answer came from the cache


def test_odd_words_bad_ids_and_errors_give_nothing(cve):
    records, asked = cve
    records["CVE-2026-0003"] = _record([{"Exploitation": "<b>yes</b>"}, {"Automatable": "maybe"}])
    records["CVE-2026-0004"] = http.HttpError("HTTP 429")
    assert osv.ssvc("CVE-2026-0003") is None
    assert osv.ssvc("CVE-2026-0004") is None
    assert osv.ssvc("../../etc/passwd") is None and osv.ssvc("GHSA-xxxx") is None
    assert all("passwd" not in u for u in asked)


def test_offline_asks_nothing(cve):
    _records, asked = cve
    p = osv._Pkg("acme-lib", "1.0.0", "PyPI")
    p.vulns["GHSA-a"] = {"aliases": ["CVE-2026-0001"], "database_specific": {"severity": "HIGH"}}
    p.groups = [{"ids": ["GHSA-a"]}]
    osv.to_findings([p], None, set(), osv.PYTHON_POLICY, lookup=None)
    assert asked == []


def _dep(sev: Severity, *, worst: bool = False, inbound: bool = False) -> Finding:
    adv = Advisory("GHSA-a", aliases=("CVE-2026-0001",))
    if worst:
        adv = Advisory("GHSA-a", aliases=("CVE-2026-0001",), exploitation="active",
                       automatable="yes", impact="total")  # fmt: skip
    return Finding(
        rule_id="dep-vuln",
        title="Dependency with known vulnerabilities",
        severity=sev,
        category=Category.DEPENDENCY,
        message="acme-lib 1.0.0 has 1 known vulnerability.",
        evidence="acme-lib@1.0.0 (PyPI): GHSA-a",
        tags=frozenset({Tag.INBOUND}) if inbound else frozenset(),
        analyzer="osv",
        dependency=DepFacts("acme-lib", "PyPI", "1.0.0", (adv,)),
    )


@pytest.mark.parametrize(
    "sev, worst, inbound, exposure, want, says",
    [
        # local only: at most medium, and the finding says why
        (Severity.HIGH, False, True, Exposure.LOCAL, Severity.MEDIUM, "It is rated high"),
        (Severity.HIGH, True, False, Exposure.LOCAL, Severity.MEDIUM, "would make it critical"),
        (Severity.MEDIUM, False, False, Exposure.LOCAL, Severity.MEDIUM, None),
        # the worst case rated low stays low locally (never raised), but is explained
        (Severity.LOW, True, False, Exposure.LOCAL, Severity.LOW, "would make it critical"),
        # public: the rating, inbound raised a level as before, the worst case critical
        (Severity.HIGH, False, False, Exposure.PUBLIC, Severity.HIGH, None),
        (Severity.HIGH, False, True, Exposure.PUBLIC, Severity.CRITICAL, None),
        (Severity.MEDIUM, True, False, Exposure.PUBLIC, Severity.CRITICAL, "exposed to the"),
    ],
)
def test_a_dependency_vulnerability_by_exposure(sev, worst, inbound, exposure, want, says):
    [f] = apply_exposure([_dep(sev, worst=worst, inbound=inbound)], exposure)
    assert f.severity is want
    if says:
        assert says in f.message
    else:
        assert f.message == "acme-lib 1.0.0 has 1 known vulnerability."


def test_kev_counts_as_exploited():
    adv = Advisory("GHSA-a", exploitation="poc", automatable="yes", impact="total", kev=True)
    assert adv.worst_case
    assert not Advisory("GHSA-a", exploitation="poc", automatable="yes", impact="total").worst_case


@pytest.mark.parametrize("exposure", [Exposure.LOCAL, Exposure.PUBLIC])
def test_malware_and_exfiltration_are_never_lowered(exposure):
    mal = Finding(
        rule_id="dep-malicious",
        title="t",
        severity=Severity.CRITICAL,
        category=Category.DEPENDENCY,
        message="m",
        tags=frozenset({Tag.MALWARE}),
    )
    exfil = Finding(rule_id="card-token-exfil", title="t", severity=Severity.CRITICAL,
                    category=Category.EXFIL, message="m",
                    tags=frozenset({Tag.EXFIL, Tag.INBOUND}))  # fmt: skip
    out = apply_exposure([mal, exfil], exposure)
    assert [f.severity for f in out] == [Severity.CRITICAL, Severity.CRITICAL]


def test_the_panel_says_cisas_assessment_in_plain_words():
    from sniff_test import ui

    assert (
        ui.ssvc_phrase(
            {"exploitation": "poc", "automatable": "yes", "impact": "total", "kev": False}
        )
        == "CISA says: public code to exploit it exists, attacks can be automated, and it can "
        "give an attacker full control or all of its data"
    )
    assert ui.ssvc_phrase({"exploitation": "poc", "kev": True}) == (
        "CISA says: it's on CISA's Known Exploited Vulnerabilities list"
    )
    assert ui.ssvc_phrase({"exploitation": "<script>", "automatable": "x"}) == ""
    assert ui.ssvc_phrase(None) == ""
