"""(0.15, his yes 2026-11-22) "Where your logins go", the key line on the picture, the site
chips and the list of where run-time addresses come from (report/logins.py, does.py, ui.py).

The report sections are written by hand in the shapes py_requests.summary makes; every host
is .invalid and every name is made up. Context only: nothing here touches a reading.
"""

from __future__ import annotations

import re

from sniff_test import does, ui
from sniff_test.report import logins


def _report(requests: dict) -> dict:
    return {
        "target": {"kind": "integration", "repo": "someone/solar", "domain": "solar"},
        "findings": [],
        "requests": {"version": 3, "sites": {}, "elsewhere": [], "total": 0, **requests},
    }


HANDED = {
    "library": "vendor_api",
    "call": "VendorClient",
    "logins": ["username", "password"],
    "addresses": [{"arg": "base_url",
                   "from": [{"kind": "setup", "detail": "base_url"},
                            {"kind": "site", "detail": "monitor.vendor.invalid"}]}],
    "at": "coordinator.py:167",
}  # fmt: skip
INSIDE = {
    "package": "vendor-api",
    "version": "1.2",
    "state": "followed",
    "sends": [
        {"from": [{"kind": "setup", "detail": "base_url"},
                  {"kind": "site", "detail": "monitor.vendor.invalid"}],
         "logins": ["username", "password"], "at": "client.py:765"},
    ],
}  # fmt: skip


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def test_the_case_he_reported_a_login_and_a_site_handed_to_a_library():
    rep = _report({"handoffs": [{**HANDED, "inside": INSIDE}]})
    box = _text(logins.html(rep, "Solar monitor"))
    assert "The login you gave this app ( username , password )" in box
    assert "vendor_api library Barkley read inside the library (version 1.2)." in box
    # the site first, then what you entered (his pick, 2026-11-22)
    assert ("monitor.vendor.invalid , or the address you entered when you set it up "
            "( base_url ) inside the library at client.py:765") in box  # fmt: skip
    # the site: "through a library" and "your login", in the picture and the fold
    m = logins.marks(rep)["monitor.vendor.invalid"]
    assert (m.library, m.login) == ("vendor_api", True)
    assert _text(logins.chips(m)) == "through a library the login you gave this app"
    assert "with this site as its address ( base_url )" in _text(logins.fold_lines(m))


def test_the_picture_draws_the_library_site_with_the_key_line():
    rep = _report({"handoffs": [{**HANDED, "inside": INSIDE}]})
    m = does.build(rep, "Solar monitor")
    (site,) = [s for s in m.sites if s[0] == "monitor.vendor.invalid"]
    assert site[1] == [
        "through the vendor_api library",
        does.KEY + "gets the login you gave this app",
    ]
    svg = does.wide(m)
    assert 'class="pv"' in svg and "gets the login you gave this app" in svg
    assert "holds the login you gave it" in svg and 'class="kp"' in svg  # the purple line
    assert "holds the login you gave it" in does.narrow(m)


def test_a_scan_from_before_library_reading_says_so():
    rep = _report({"handoffs": [HANDED]})
    box = _text(logins.html(rep, "Solar monitor"))
    assert "Barkley doesn't read inside libraries" in box
    assert "Where it goes from there isn't in the app's code." in box


def test_a_library_barkley_couldnt_read_says_why():
    inside = {"state": "unread", "why": "not one of its requirements"}
    box = _text(logins.html(_report({"handoffs": [{**HANDED, "inside": inside}]}), "X"))
    assert "isn't one of the app's own requirements (it comes with Home Assistant" in box


def test_a_library_with_no_web_requests_says_how_it_connects():
    inside = {"package": "vendor-api", "version": "1.2", "state": "no_requests",
              "other": ["MQTT"], "uses": []}  # fmt: skip
    box = _text(logins.html(_report({"handoffs": [{**HANDED, "inside": inside}]}), "X"))
    assert "There are no web requests in it. It connects by MQTT." in box


def test_the_apps_own_login_and_a_token_get_a_group_each():
    sites = {
        "login.vendor.invalid": [{"method": "POST", "count": 1, "logins": ["email", "password"]}],
        "api.vendor.invalid": [{"method": "GET", "count": 9, "tokens": ["login.vendor.invalid"]}],
    }
    two = "eu.vendor.invalid,us.vendor.invalid"
    elsewhere = [{"method": "POST", "count": 2, "logins": ["password"],
                  "from": [{"kind": "list", "detail": two}]}]  # fmt: skip
    gs = logins.groups(_report({"sites": sites, "elsewhere": elsewhere}), "Printer")
    assert [_text(g.what) for g in gs] == [
        "The login you gave this app ( email , password )",
        "The token from login.vendor.invalid 's answer",
    ]
    assert [(_text(d.name), d.note, d.fixed) for d in gs[0].dests] == [
        ("login.vendor.invalid", "POST", True),
        ("One of 2 sites in its code ( eu.vendor.invalid , us.vendor.invalid )",
         "POST · 2 requests", False),
    ]  # fmt: skip
    assert [(_text(d.name), d.note) for d in gs[1].dests] == [("api.vendor.invalid",
                                                                "GET · 9 requests")]  # fmt: skip


def test_more_than_six_places_fold_away():
    elsewhere = [{"method": "GET", "count": 1, "logins": ["password"],
                  "from": [{"kind": "site", "detail": f"s{i}.vendor.invalid"}]}
                 for i in range(9)]  # fmt: skip
    box = logins.html(_report({"elsewhere": elsewhere}), "Car")
    assert box.count('class="lg-dest"') == 9
    assert "and 3 more places</summary>" in box


def test_no_box_when_no_login_was_followed():
    sites = {"api.vendor.invalid": [{"method": "GET", "count": 1}]}
    assert logins.html(_report({"sites": sites}), "X") == ""
    # an address alone, handed to a library: listed under "Where it connects", no login box
    only = {**HANDED, "logins": []}
    rep = _report({"handoffs": [only]})
    assert logins.html(rep, "X") == ""
    assert logins.marks(rep)["monitor.vendor.invalid"].login is False


def test_where_run_time_addresses_come_from_is_counted():
    elsewhere = [
        {"method": "GET", "count": 12, "from": [{"kind": "setup", "detail": "host"}],
         "logins": ["password"]},
        {"method": "GET", "count": 2,
         "from": [{"kind": "answer", "detail": "url", "site": "api.vendor.invalid"}]},
        {"method": "GET", "count": 1, "from": [{"kind": "ha"}]},
        {"method": "GET", "count": 3},
    ]  # fmt: skip
    got = _text(logins.origins_html(elsewhere))
    assert got == (
        "The address you entered when you set it up ( host ): 12 requests. The login you gave "
        "this app ( password ) goes there too. An address from api.vendor.invalid 's answer: 2 "
        "requests. Your Home Assistant's own address: 1 request. Barkley couldn't trace "
        "where the address comes from: 3 requests."
    )
    # nothing traced: the old sentence stays
    assert logins.origins_html([{"method": "GET", "count": 3}]) == ""
    page = ui.requests_elsewhere_html(_report({"elsewhere": elsewhere}))
    assert "Where the addresses come from:" in page


def test_names_from_the_scanned_code_are_escaped():
    evil = '<img src=x onerror="alert(1)">'
    rep = _report({"handoffs": [{**HANDED, "library": evil, "logins": [evil],
                                 "inside": {**INSIDE, "version": evil}}]})  # fmt: skip
    out = logins.html(rep, evil) + "".join(
        logins.fold_lines(m) + logins.chips(m) for m in logins.marks(rep).values()
    )
    assert "<img" not in out and "&lt;img" in out


def test_the_new_styles_keep_to_the_tokens():
    css = ui.CSS[ui.CSS.index(".lg {") : ui.CSS.index("ul.from")]
    # sizes come from the tokens; only 1px borders and the 24px arrow column are literal
    assert not re.search(r"\b(?!0)\d+px", css.replace("24px", "").replace("1px", ""))


# --- what the app does for itself (his ask, 2026-11-22) -------------------------------------


def test_own_devices_are_said_without_lighting_the_room(tmp_path):
    from sniff_test.analyzers import platforms

    root = tmp_path / "acme"
    root.mkdir()
    for f in ("__init__.py", "climate.py", "sensor.py", "select.py", "api.py", "const.py"):
        (root / f).write_text("")
    (root / "number").mkdir()
    (root / "number" / "__init__.py").write_text("")
    assert platforms.platforms_in(root) == ["climate", "number", "select", "sensor"]
    rep = {**_report({}), "platforms": ["climate", "number", "select", "sensor"]}
    m = does.build(rep, "Thermostat")
    assert m.own == {"devices": ["adds its own thermostats, sensors, number settings and "
                                 "option lists"]}  # fmt: skip
    assert "devices" not in m.use  # the room stays dashed: its own devices aren't reach
    svg = does.wide(m)
    assert 'class="ro"' in svg and "adds its own thermostats" in svg
    assert 'class="room idle"' in svg and 'class="room on"' not in svg
    assert "beyond its own devices" in does.legend(m)


def test_no_entity_files_no_line():
    m = does.build({**_report({}), "platforms": []}, "X")
    assert m.own == {} and not m.holds_login
    assert "holds the login" not in does.wide(m)


def test_the_held_login_and_its_line_without_a_named_site():
    # the login goes to an address worked out while it runs: the app still says it holds it
    elsewhere = [{"method": "POST", "count": 1, "logins": ["email", "password"],
                  "from": [{"kind": "setup", "detail": "host"}]}]  # fmt: skip
    m = does.build(_report({"elsewhere": elsewhere}), "Cloud app")
    assert m.holds_login
    assert "holds the login you gave it" in does.wide(m)
    assert "Purple: the login you gave this app" in does.legend(m)
