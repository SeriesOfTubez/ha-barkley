"""(0.14.0 part 3) Kinds, the scoring settings, reviews and the reviewed score (user
decisions 2026-11-17/18). Barkley's own score never changes; a stored scan is never
edited; known malware can never be accepted."""

import contextlib
import os
import re
import stat
from datetime import UTC, datetime, timedelta

import pytest
from test_server import addon, get, panel, post, token  # noqa: F401 (fixtures)
from test_store import report

from sniff_test import kinds, review, scoring, server, trust, ui, watch
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


def acc(f, ref="v1", sid=1, at=None, note="", who="Pat"):
    when = at or datetime.now(UTC).isoformat()
    return review.Accept(REPO, f["fingerprint"], f["rule_id"], note, who, when, sid, f["id"],
                         ref, f["file"])  # fmt: skip


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


# --- the review view ------------------------------------------------------------------------


def test_accepting_raises_the_reviewed_score_and_never_barkleys():
    a, b = fnd(1, "ha-auth-change-users"), fnd(2, "py-shell-exec")
    r = rep([a, b])
    own = r["score"]
    v = review.view(r, accepts=[acc(a)])
    assert v["review"]["reviewed"] and v["review"]["own_score"] == own
    assert v["score"] == v["review"]["own_score"] + v["review"]["delta"] > own
    assert not v["review"]["all_accepted"]
    v2 = review.view(r, accepts=[acc(a), acc(b)])
    assert v2["score"] == 100 and v2["review"]["all_accepted"]
    assert r["score"] == own and "review" not in r  # the stored report is never edited
    assert ui.verdict_text(v2) == "All findings accepted"


def test_known_malware_is_never_accepted_and_blocks_a_reviewed_score():
    mal = fnd(1, "dep-malicious", "critical")
    cap = fnd(2, "py-shell-exec")
    assert not review.can_accept(mal)
    v = review.view(rep([mal, cap]), accepts=[acc(cap), acc(mal)])
    assert not v["review"]["reviewed"] and v["review"]["malware"]
    assert "accepted" not in {(f.get("review") or {}).get("state") for f in v["findings"]
                              if f["rule_id"] == "dep-malicious"}  # fmt: skip


def test_changed_code_reopens_and_the_same_code_stays_accepted():
    a = fnd(1, "py-shell-exec", fp="old", file="x.py")
    b = fnd(2, "ha-auth-change-users", fp="same", file="y.py")
    accepts = [acc(a), acc(b)]
    nxt = [fnd(3, "py-shell-exec", fp="new", file="x.py", line=40),
           fnd(4, "ha-auth-change-users", fp="same", file="y.py", line=99)]  # fmt: skip
    v = review.view(rep(nxt, ref="v2"), accepts=accepts)
    st = {f["rule_id"]: f["review"]["state"] for f in v["findings"]}
    assert st == {"py-shell-exec": "reopened", "ha-auth-change-users": "accepted"}
    assert review.due(v) == 1
    assert ui.verdict_text(v) == "1 finding to look at again"
    # a new finding of the same rule in another file is new, not "changed"
    other = review.view(rep([fnd(5, "py-shell-exec", fp="z", file="other.py")]), accepts=[acc(a)])
    assert "review" not in other["findings"][0]


def test_re_confirm_reopens_old_acceptances():
    a = fnd(1, "py-shell-exec")
    old = (datetime.now(UTC) - timedelta(days=200)).isoformat()
    v = review.view(rep([a]), accepts=[acc(a, at=old)],
                    settings=review.Settings(reconfirm_months=6))  # fmt: skip
    assert v["findings"][0]["review"]["state"] == "reconfirm" and not v["review"]["reviewed"]
    v = review.view(rep([a]), accepts=[acc(a, at=old)])  # never (the default)
    assert v["findings"][0]["review"]["state"] == "accepted"


def test_paranoid_off_hides_minor_findings_and_show_them_keeps_them_unscored():
    minor, cap = fnd(1, "ha-auth-list-users", "medium"), fnd(2, "py-shell-exec")
    r = rep([minor, cap])
    v = review.view(r)
    assert [f["rule_id"] for f in v["findings"]] == ["py-shell-exec"]
    assert v["review"]["minor"] == ["ha-auth-list-users"] and v["score"] == r["score"]
    shown = review.view(r, show_minor=True)
    assert len(shown["findings"]) == 2 and shown["score"] == r["score"]
    p = review.view(r, settings=review.Settings(paranoid=True))
    assert len(p["findings"]) == 2 and p["score"] < r["score"] and not p["review"]["minor"]
    assert p["review"]["own_score"] == p["score"]  # Barkley's score under his settings


def test_malware_check_only_shows_threats_alone():
    cap, thr = fnd(1, "py-shell-exec"), fnd(2, "py-obfuscation")
    v = review.view(rep([cap]), malware_only=True)
    assert v["findings"] == [] and v["score"] == 100
    v = review.view(rep([cap, thr]), malware_only=True)
    assert [f["rule_id"] for f in v["findings"]] == ["py-obfuscation"] and v["score"] < 100
    assert ui.verdict_text(v).startswith("Malware check only")


def test_notes_and_names_are_cleaned():
    assert review.clean_note("ok\x00\nfine " + "x" * 400) == ("ok fine " + "x" * 400)[:300]
    assert review.clean_who("<b>Pat</b>") == ""
    assert review.clean_who("  Pat   Smith ") == "Pat Smith"


# --- store and settings ---------------------------------------------------------------------


def test_store_keeps_acceptances_per_app(tmp_path):
    store = Store(tmp_path / "s.db")
    a = fnd(1, "py-shell-exec")
    store.accept([acc(a, note="its own entries")])
    got = store.accepts(REPO.upper())
    assert len(got) == 1 and got[0].note == "its own entries" and got[0].who == "Pat"
    store.accept([acc(fnd(2, "py-shell-exec", fp="new"))], replaces=["fp1"])
    assert [x.fingerprint for x in store.accepts(REPO)] == ["new"]
    store.unaccept(REPO, ["new"])
    assert store.accepts(REPO) == []


def test_settings_are_checked_and_fall_back(tmp_path):
    store = Store(tmp_path / "s.db")
    start = settings_mod.from_dict({"exposure": "public", "parallel": "1", "jobs": 9})
    assert (start.exposure, start.parallel, start.jobs) == ("public", 1, 1)
    assert settings_mod.load(store, start) == start
    settings_mod.save(store, settings_mod.from_dict({"paranoid": "1", "reconfirm_months": "7",
                                                     "exposure": "evil"}, start))  # fmt: skip
    s = settings_mod.load(store, start)
    assert s.paranoid and s.reconfirm_months == 0 and s.exposure == "public"
    assert settings_mod.set_malware_only(store, "Acme/App", True)
    assert not settings_mod.set_malware_only(store, "../x", True)
    assert settings_mod.malware_only(store) == {"acme/app"}


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


# --- the panel ------------------------------------------------------------------------------


def _saved(store, findings, ref="v1"):
    return store.save(rep(findings, ref=ref))


def test_mark_reviewed_and_undo_in_the_panel(panel):  # noqa: F811
    store, _scan, base, _httpd = panel
    a, b = fnd(1, "ha-auth-change-users"), fnd(2, "py-shell-exec")
    sid = _saved(store, [a, b])
    _, _, page = get(f"{base}/scan/{sid}")
    assert "Accept all" in page and page.count(">Mark reviewed<") == 2
    assert "Report a false positive" in page and "template=2-scan-result.yml" in page
    assert "Threats (0)" in page and "No signs of malicious behavior" in page
    tok = token(base)
    st, hd = post(f"{base}/accept", {"token": tok, "scan": sid, "finding": a["id"],
                                     "note": "checked it"})  # fmt: skip
    assert st == 303 and hd["Location"].endswith(f"/scan/{sid}")
    _, _, page = get(f"{base}/scan/{sid}", {"X-Remote-User-Display-Name": "Pat"})
    assert "Accepted" in page and "checked it" in page and ">Reviewed<" in page
    assert "from your review" in page
    assert store.report(sid)["score"] == rep([a, b])["score"]  # stored scan unchanged
    assert post(f"{base}/unaccept", {"token": tok, "scan": sid, "finding": a["id"]})[0] == 303
    _, _, page = get(f"{base}/scan/{sid}")
    assert ">Reviewed<" not in page
    assert post(f"{base}/accept", {"token": "x", "scan": sid, "finding": a["id"]})[0] == 403


def test_undo_on_a_finding_shown_for_several_places_undoes_them_all(panel):  # noqa: F811
    """His report 2026-11-19: one finding shown for two places, Mark reviewed accepted both,
    Undo removed only the first, and "+8 from your review" stayed."""
    store, _scan, base, _httpd = panel
    a, b = fnd(1, "card-eval", "medium", line=3), fnd(2, "card-eval", "medium", line=9)
    sid = _saved(store, [a, b])
    tok = token(base)
    _, _, page = get(f"{base}/scan/{sid}")
    assert page.count(">Mark reviewed<") == 1 and f'name=also value="{b["id"]}"' in page
    post(f"{base}/accept", {"token": tok, "scan": sid, "finding": a["id"], "also": b["id"]})
    assert {x.fingerprint for x in store.accepts(REPO)} == {"fp1", "fp2"}
    _, _, page = get(f"{base}/scan/{sid}")
    assert "Undo" in page and f'name=also value="{b["id"]}"' in page  # Undo carries both
    post(f"{base}/unaccept", {"token": tok, "scan": sid, "finding": a["id"], "also": b["id"]})
    assert store.accepts(REPO) == []
    _, _, page = get(f"{base}/scan/{sid}")
    assert ">Reviewed<" not in page and "from your review" not in page


def test_accept_all_needs_a_tick_per_threat(panel):  # noqa: F811
    store, _scan, base, _httpd = panel
    t1, t2, cap = fnd(1, "py-obfuscation"), fnd(2, "card-hidden-name"), fnd(3, "py-shell-exec")
    sid = _saved(store, [t1, t2, cap])
    _, _, page = get(f"{base}/scan/{sid}")
    assert "Threats need their own tick" in page and "Accept the rest" in page
    tok = token(base)
    post(f"{base}/accept-all", {"token": tok, "scan": sid, "threat": t1["id"]})
    got = {a.rule_id for a in store.accepts(REPO)}
    assert got == {"py-obfuscation", "py-shell-exec"}  # the unticked Threat stays open


def test_who_accepted_comes_from_ingress(panel):  # noqa: F811
    store, _scan, base, _httpd = panel
    a = fnd(1, "py-shell-exec")
    sid = _saved(store, [a])
    tok = token(base)
    import urllib.request

    req = urllib.request.Request(  # noqa: S310 - local server
        f"{base}/accept",
        data=f"token={tok}&scan={sid}&finding={a['id']}".encode(),
        headers={"X-Remote-User-Display-Name": "Pat Smith"},
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    with contextlib.suppress(urllib.error.HTTPError):
        urllib.request.build_opener(NoRedirect).open(req)
    assert store.accepts(REPO)[0].who == "Pat Smith"


def test_what_changed_shows_the_old_and_new_code(panel):  # noqa: F811
    store, _scan, base, _httpd = panel
    a = fnd(1, "py-shell-exec", fp="old", file="x.py")
    old_sid = _saved(store, [a])
    store.accept([acc(a, sid=old_sid)])
    b = {**fnd(2, "py-shell-exec", fp="new", file="x.py"), "evidence": "subprocess.run(evil)"}
    sid = _saved(store, [b], ref="v2")
    _, _, page = get(f"{base}/scan/{sid}")
    assert "Changed since you accepted it in v1" in page and "What changed?" in page
    _, _, diff = get(f"{base}/changed?scan={sid}&finding={b['id']}")
    assert "What changed?" in diff and "subprocess.run(evil)" in diff and 'class="add"' in diff
    post(f"{base}/accept", {"token": token(base), "scan": sid, "finding": b["id"]})
    assert [x.fingerprint for x in store.accepts(REPO)] == ["new"]  # replaced, not added


def test_settings_page_saves_and_changes_scores(panel):  # noqa: F811
    store, _scan, base, httpd = panel
    minor = fnd(1, "ha-auth-list-users", "medium")
    sid = _saved(store, [minor])
    _, _, page = get(f"{base}/settings")
    for text in ("Paranoid mode", "Powerful, no threat", "Pages without a login",
                 "Hidden usage reporting", "Ask again", "GitHub token", "It needs no permissions",
                 "Reset to defaults"):  # fmt: skip
        assert text in ui.e(text) and ui.e(text) in page, text
    assert "write-only" not in page.lower()
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


def test_malware_check_only_per_app(panel):  # noqa: F811
    store, _scan, base, _httpd = panel
    sid = _saved(store, [fnd(1, "py-shell-exec")])
    tok = token(base)
    assert post(f"{base}/malware-only", {"token": tok, "repo": REPO, "on": "1",
                                         "scan": sid})[0] == 303  # fmt: skip
    _, _, page = get(f"{base}/scan/{sid}")
    assert "Malware check only" in page and "Show everything again" in page
    assert "Score 100 of 100" in page and "Accept all" not in page
    assert post(f"{base}/malware-only", {"token": tok, "repo": "../x", "on": "1"})[0] == 400


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


def test_notification_says_reviewed_and_reopened():
    a = fnd(1, "py-shell-exec", fp="old", file="x.py")
    v = review.view(rep([fnd(2, "py-shell-exec", fp="new", file="x.py")]), accepts=[acc(a)])
    entry = {"repo": REPO, "version": "v2", "previous": "v1", "kind": "integration",
             "scan_ids": [1, 2]}  # fmt: skip
    _t, _md, plain = watch.notification(entry, v, None, "")
    assert "1 finding you accepted changed in this version and is open again." in plain
    _t, _md, plain = watch.notification(entry, v, None, "", notify_reopen=False)
    assert "open again" not in plain


def test_a_page_reads_the_settings_and_reviews_once_not_per_row(addon, monkeypatch):  # noqa: F811
    """0.14.0.1 on a real box: the list took 3-4 s because every row read the settings,
    trusted addresses and reviews again (about 1,500 database opens per render)."""
    store, _scan, base, _httpd, _state = addon
    from test_server import INSTALLED

    for it in INSTALLED:
        for v in range(6):
            store.save(report(repo=it.repo, ref=f"v{v}", kind=it.kind))
    store.accept([acc(fnd(1, "py-shell-exec"))])
    get(base + "/?refresh=1")  # warm
    opened = []
    real = Store._connect

    def counting(self):
        opened.append(1)
        return real(self)

    monkeypatch.setattr(Store, "_connect", counting)
    get(base + "/?refresh=1")
    assert len(opened) < 60, len(opened)
    # and a change shows at once
    settings_mod.set_malware_only(store, INSTALLED[0].repo, True)
    _, _, page = get(base + "/?refresh=1")
    assert "Malware check only" in page
