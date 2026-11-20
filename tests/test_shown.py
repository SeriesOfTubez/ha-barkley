"""(0.15) The report as the panel shows it (shown.py), the kinds and scoring settings, and
the removal of reviews, Malware check only and trusted addresses (his decision 2026-11-20:
with the Threat and Exposure readings a review changed nothing; Report a false positive
stays)."""

import os
import re
import sqlite3
import stat

import pytest
from test_server import addon, get, panel, post, token  # noqa: F401 (fixtures)
from test_store import report

from sniff_test import kinds, scoring, server, shown, trust, ui, watch
from sniff_test import settings as settings_mod
from sniff_test.models import Category, Finding, Severity
from sniff_test.report import explain
from sniff_test.store import Store

REPO = "acme/acme"


def fnd(i, rule, sev="high", fp=None, file="a.py", line=3):
    return {
        "id": f"{i:x}".rjust(16, "0"),
        "rule_id": rule,
        "title": rule,
        "severity": sev,
        "category": "ha",
        "file": file,
        "line": line,
        "evidence": f"code {i}",
        "message": "m",
        "fingerprint": fp or f"fp{i}",
    }


def rep(findings, ref="v1", exposure="local", complete=True):
    """A report whose stored score is the scanner's own (default policy)."""
    r = report(repo=REPO, ref=ref, findings=findings, exposure=exposure)
    s = trust.rescore([(f["id"], f["rule_id"], f["severity"]) for f in findings], complete,
                      scoring.Policy(exposure=exposure))  # fmt: skip
    r.update(score=s.score, complete=complete, score_breakdown=s.breakdown, caps_applied=s.caps)
    r["verdict"] = {"key": s.verdict_key, "label": s.verdict_label}
    return r


# --- kinds --------------------------------------------------------------------------------


def test_every_rule_has_a_kind_and_the_threat_set_is_the_agreed_one():
    for rule in explain.RULES:
        assert kinds.kind(rule) in kinds.ORDER
    assert kinds.kind("ha-monkeypatch") == kinds.CAPABILITY  # decided 2026-11-17
    assert kinds.kind("dep-guarddog-process-download-exec") == kinds.CAPABILITY
    for rule in ("ha-exfil-taint", "card-token-exfil", "dep-malicious", "card-hidden-name"):
        assert kinds.is_threat(rule)
    assert kinds.kind("dep-vuln") == kinds.VULNERABILITY
    assert kinds.kind("repo-young") == kinds.PRACTICE
    assert kinds.kind("scan-file-not-checked") == kinds.COVERAGE
    assert set(explain.RULES) >= kinds.MINOR
    assert not kinds.MINOR & kinds.THREAT_RULES
    assert "ha-auth-change-users" not in kinds.MINOR  # changing who can log in isn't minor


def test_high_privilege_actions_are_the_agreed_list():
    for x in ("hassio.addon_stop", "shell_command.x", "homeassistant.restart", "lock.unlock",
              "DOMAIN.SERVICE_HOMEASSISTANT_RESTART", "recorder.purge",
              "backup.create"):  # fmt: skip
        assert kinds.high_privilege(x), x
    for x in ("light.turn_on", "*.SERVICE_TURN_ON", "notify.mobile_app", "cover.open_cover",
              "homeassistant.reload_all", "person.remove_device_tracker"):  # fmt: skip
        assert not kinds.high_privilege(x), x


# --- scoring policy -------------------------------------------------------------------------


def F(rule, sev):
    return Finding(rule, "t", sev, Category.DEPENDENCY, "m", file=f"{rule}.py")


def test_minor_findings_count_only_in_paranoid_mode():
    fs = [F("ha-auth-list-users", Severity.MEDIUM), F("ha-foreign-entry-options", Severity.MEDIUM)]
    assert scoring.score(fs, True).score == 100
    assert scoring.score(fs, True, scoring.Policy(paranoid=True)).score < 100


def test_no_threat_floor_keeps_capabilities_at_very_sus():
    caps = [F(f"cap-{i}", Severity.HIGH) for i in range(4)]  # 4 x 25 = 100 points
    assert scoring.score(caps, True).score == scoring.FLOOR_NO_THREAT
    assert scoring.score(caps, True, scoring.Policy(floor=False)).score == 0
    assert scoring.score(caps, False).score == 0  # unfinished: a Threat may be unseen
    threat = [*caps, F("py-obfuscation", Severity.HIGH)]
    assert scoring.score(threat, True).score == 0
    crit = [*caps, F("dep-vuln", Severity.CRITICAL)]
    assert scoring.score(crit, True).score < scoring.FLOOR_NO_THREAT


def test_pages_without_login_and_hidden_usage_reporting_settings():
    view = [F("ha-unauth-view", Severity.LOW)]
    assert scoring.score(view, True).score == 100
    assert scoring.score(view, True, scoring.Policy(unauth_views=True)).score == 98
    assert scoring.score(view, True, scoring.Policy(exposure="public")).score == 98
    tele = [F("telemetry-shadow", Severity.MEDIUM)]
    assert scoring.score(tele, True).score == 92
    assert scoring.score(tele, True, scoring.Policy(shadow_telemetry=False)).score == 100


# --- the shown report ------------------------------------------------------------------------


def test_paranoid_off_hides_minor_findings_and_show_them_keeps_them_unscored():
    minor, cap = fnd(1, "ha-auth-list-users", "medium"), fnd(2, "py-shell-exec")
    r = rep([minor, cap])
    v = shown.view(r)
    assert [f["rule_id"] for f in v["findings"]] == ["py-shell-exec"]
    assert v["shown"]["minor"] == ["ha-auth-list-users"] and v["score"] == r["score"]
    every = shown.view(r, show_minor=True)
    assert len(every["findings"]) == 2 and every["score"] == r["score"]
    p = shown.view(r, settings=shown.Settings(paranoid=True))
    assert len(p["findings"]) == 2 and p["score"] < r["score"] and not p["shown"]["minor"]
    assert r["score"] == rep([minor, cap])["score"] and "shown" not in r  # never edited


def test_nothing_in_the_view_comes_from_a_user_review():
    v = shown.view(rep([fnd(1, "py-shell-exec")]))
    assert not {"review", "trust", "trusted_findings"} & set(v)
    assert all("review" not in f for f in v["findings"])


def test_settings_are_checked_and_fall_back(tmp_path):
    store = Store(tmp_path / "s.db")
    start = settings_mod.from_dict({"exposure": "public", "parallel": "1", "jobs": 9})
    assert (start.exposure, start.parallel, start.jobs) == ("public", 1, 1)
    assert settings_mod.load(store, start) == start
    settings_mod.save(store, settings_mod.from_dict({"paranoid": "1", "reconfirm_months": "6",
                                                     "exposure": "evil"}, start))  # fmt: skip
    s = settings_mod.load(store, start)
    assert s.paranoid and s.exposure == "public"
    assert not hasattr(s, "reconfirm_months") and not hasattr(s, "notify_reopen")  # 0.15


def test_the_github_token_lives_in_its_own_private_file(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    db = tmp_path / "s.db"
    assert not settings_mod.set_token(db, "not a token!")
    tok = "github_pat_" + "A1" * 20
    assert settings_mod.set_token(db, tok)
    path = settings_mod.token_path(db)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and os.environ["GITHUB_TOKEN"] == tok
    assert settings_mod.token_source(db) == "settings"
    settings_mod.remove_token(db, option_token="")
    assert not path.exists() and "GITHUB_TOKEN" not in os.environ


def test_what_014_stored_for_reviews_is_deleted_once_at_start(tmp_path, capsys):
    """0.14's reviews table, trusted addresses and Malware check only list go on the first
    start of 0.15 (his decision 2026-11-20); the scans stay."""
    db = tmp_path / "s.db"
    sid = Store(db).save(rep([fnd(1, "py-shell-exec")]))
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE reviews (repo TEXT, fingerprint TEXT)")
        c.executemany("INSERT INTO reviews VALUES (?, ?)", [(REPO, "a"), (REPO, "b")])
        c.execute("INSERT INTO settings VALUES ('trusted_addresses', '{}')")
        c.execute("INSERT INTO settings VALUES ('malware_only', '[\"acme/acme\"]')")
        c.execute("INSERT INTO settings VALUES ('ai_mode', 'deep')")
    store = Store(db)
    err = capsys.readouterr().err
    assert "2 accepted findings, trusted addresses, Malware check only" in err
    with sqlite3.connect(db) as c:
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "reviews" not in tables
    assert store.setting("trusted_addresses") is None and store.setting("malware_only") is None
    assert store.setting("ai_mode") == "deep" and store.report(sid)["findings"]
    Store(db)
    assert "removed" not in capsys.readouterr().err  # once


# --- the panel ------------------------------------------------------------------------------


def _saved(store, findings, ref="v1"):
    return store.save(rep(findings, ref=ref))


def test_an_app_page_offers_report_a_false_positive_and_nothing_to_accept(panel):  # noqa: F811
    store, _scan, base, _httpd = panel
    a, b = fnd(1, "ha-auth-change-users"), fnd(2, "py-shell-exec")
    sid = _saved(store, [a, b])
    _, _, page = get(f"{base}/scan/{sid}")
    assert page.count(">Report a false positive<") == 2 and "template=2-scan-result.yml" in page
    for gone in (
        "Accept all",
        "Mark reviewed",
        "Malware check only",
        "Trust for this app",
        "Addresses you trust",
        "Reviewed",
        "from your review",
        "/accept",
    ):
        assert gone not in page, gone
    _, _, home = get(f"{base}/")
    assert "Addresses you trust" not in home


@pytest.mark.parametrize("path", ["/accept", "/accept-all", "/unaccept", "/malware-only",
                                  "/trust", "/untrust"])  # fmt: skip
def test_the_review_routes_are_gone(panel, path):  # noqa: F811
    store, _scan, base, _httpd = panel
    sid = _saved(store, [fnd(1, "py-shell-exec")])
    st, _ = post(f"{base}{path}", {"token": token(base), "scan": sid, "finding": "1",
                                   "repo": REPO, "on": "1", "address": "a.example"})  # fmt: skip
    assert st == 404, path
    for page in ("/trusted", f"/changed?scan={sid}&finding={'0' * 16}"):
        assert get(base + page)[0] == 404


def test_an_item_about_an_address_lists_it_without_a_trust_button(panel):  # noqa: F811
    store, _scan, base, _httpd = panel
    f = {**fnd(1, "dep-guarddog-network-exfiltration", "medium"), "addresses": ["api.example"]}
    sid = _saved(store, [f])
    _, _, page = get(f"{base}/scan/{sid}")
    assert "api.example" in page and "Trust " not in page


def test_settings_page_saves_and_changes_scores(panel):  # noqa: F811
    store, _scan, base, httpd = panel
    minor = fnd(1, "ha-auth-list-users", "medium")
    sid = _saved(store, [minor])
    _, _, page = get(f"{base}/settings")
    for text in ("Paranoid mode", "Powerful, no threat", "Pages without a login",
                 "Hidden usage reporting", "GitHub token", "it needs no permissions",
                 "Reset to defaults"):  # fmt: skip
        assert text in ui.e(text) and ui.e(text) in page, text
    assert "write-only" not in page.lower()
    assert "Ask again" not in page and "accepted finding" not in page  # 0.15
    _, _, app = get(f"{base}/scan/{sid}")
    assert "1 minor thing isn't shown or counted" in app
    tok = token(base)
    assert post(f"{base}/settings", {"token": tok, "paranoid": "1", "parallel": "3"})[0] == 303
    assert httpd.panel.settings.paranoid and httpd.panel.worker.parallel == 3
    _, _, app = get(f"{base}/scan/{sid}")
    assert "minor finding not shown" not in app and "Score 100 of 100" not in app
    post(f"{base}/settings-reset", {"token": tok, "part": "scoring"})
    assert not httpd.panel.settings.paranoid and httpd.panel.worker.parallel == 3


def test_the_token_form_never_shows_the_token(panel, monkeypatch, tmp_path):  # noqa: F811
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    _store, _scan, base, _httpd = panel
    tok = "ghp_" + "Z9" * 18
    assert post(f"{base}/github-token", {"token": token(base), "value": tok})[0] == 303
    _, _, page = get(f"{base}/settings")
    assert tok not in page and "Set here" in page
    _st, hd = post(f"{base}/github-token", {"token": token(base), "value": "nope"})
    assert hd["Location"].endswith("bad=token")
    post(f"{base}/github-token", {"token": token(base), "remove": "1"})
    assert "GITHUB_TOKEN" not in os.environ


def test_installed_cards_offer_sniff_again_and_the_list_sniff_all(addon):  # noqa: F811
    store, scan_fn, base, httpd, _state = addon
    from test_server import INSTALLED

    for it in INSTALLED:
        store.save(report(repo=it.repo, ref=it.installed, kind=it.kind))
    _, _, page = get(base + "/?refresh=1")
    assert "Sniff again" in page and f"Sniff all {len(INSTALLED)} again" in page
    assert "Report an issue" in page and "template=1-bug.yml" in page
    post(f"{base}/sniff-all-again", {"token": token(base)})
    httpd.panel.worker.wait()
    assert sorted(r for r, _ in scan_fn.calls) == sorted(it.repo for it in INSTALLED)


def test_report_links_carry_versions_not_secrets():
    r = rep([fnd(1, "py-shell-exec", file="custom_components/acme/x.py", line=7)])
    r["ha_version"] = "2026.11.1"
    url = server.report_fp_url(r, r["findings"][0])
    q = dict(re.findall(r"[?&]([^=&]+)=([^&]*)", url))
    assert q["template"] == "2-scan-result.yml" and q["rule"] == "py-shell-exec"
    assert q["ha-version"] == "2026.11.1" and "x.py%3A7" in q["location"]
    assert "token" not in url.lower()


# --- page wording ---------------------------------------------------------------------------


def test_in_short_says_what_it_can_do():
    r = rep([fnd(1, "ha-auth-change-users"), fnd(2, "ha-foreign-entry-data")])
    text = ui.in_short(r)
    assert "It can change who can log in" in text and "It can read" in text


def test_a_plus_star_with_seven_days_grace():
    h = {"scanners": [{"name": "CodeQL", "kind": "code"}], "dependabot": ["pip"],
         "security_policy": "SECURITY.md", "update_prs": {"open": 1, "oldest_days": 2},
         "security_issues": {"open": 0, "of": 3}, "errors": []}  # fmt: skip
    assert ui.all_green(h)
    assert "A+ security habits" in ui.hygiene_html({"hygiene": h, "target": {}})
    assert not ui.all_green({**h, "update_prs": {"open": 1, "oldest_days": 7}})
    assert not ui.all_green({**h, "security_policy": None})


def test_stars_and_downloads_are_facts_never_scores():
    r = rep([])
    assert ui.facts_line(r) == ""  # scans from before 0.14.0
    r["popularity"] = {"stars": 1234, "downloads": None}
    line = ui.facts_line(r)
    assert "1,234 stars" in line and "Downloads aren't counted" in line and "scored" not in line
    r["popularity"] = {"stars": 1, "downloads": 0}
    assert "0 downloads" in ui.facts_line(r)


@pytest.mark.parametrize(("title", "phrase"), [
    ("Changes who can log in to Home Assistant", "change who can log in to Home Assistant"),
    ("Reads other apps' settings", "read other apps' settings"),
    ("Runs other programs", "run other programs"),
    ("Has a page", "have a page"),
    ("Fetches x", "fetch x"),
])  # fmt: skip
def test_can_phrase(title, phrase):
    assert ui._can_phrase(title) == phrase


def test_notifications_say_nothing_about_reviews_or_trust():
    v = shown.view(rep([fnd(2, "py-shell-exec", fp="new", file="x.py")]))
    entry = {"repo": REPO, "version": "v2", "previous": "v1", "kind": "integration",
             "scan_ids": [1, 2]}  # fmt: skip
    _t, _md, plain = watch.notification(entry, v, None, "")
    assert "accepted" not in plain and "you trust" not in plain and "review" not in plain


def test_a_page_reads_the_settings_once_not_per_row(addon, monkeypatch):  # noqa: F811
    """0.14.0.1 on a real box: the list took 3-4 s because every row read the settings,
    trusted addresses and reviews again (about 1,500 database opens per render)."""
    store, _scan, base, _httpd, _state = addon
    from test_server import INSTALLED

    for it in INSTALLED:
        for v in range(6):
            store.save(report(repo=it.repo, ref=f"v{v}", kind=it.kind))
    settings_mod.save(store, settings_mod.from_dict({"paranoid": "1"}))
    get(base + "/?refresh=1")  # warm
    opened = []
    real = Store._connect

    def counting(self):
        opened.append(1)
        return real(self)

    monkeypatch.setattr(Store, "_connect", counting)
    get(base + "/?refresh=1")
    assert len(opened) < 60, len(opened)
