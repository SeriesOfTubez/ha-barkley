"""(0.15, his decision 2026-11-21: mock-up v5) "What it does": rooms, paths and ways in,
drawn from a stored scan. Made-up apps; every host is .invalid. The picture is script
free, keeps the design tokens and escapes what comes from the scanned code."""

import re

from test_shown import fnd, rep

from sniff_test import does, shown, ui


def _graph(r, flows=(), hosts=()):
    subject = {"id": "integration:acme", "kind": "integration", "label": "acme", "attrs": {}}
    nodes, edges = [subject], []
    for name, cls in hosts:
        nodes.append({"id": f"host:{name}", "kind": "host", "label": name, "attrs": {"class": cls}})
        edges.append({"id": f"c-{name}", "source": subject["id"], "target": f"host:{name}",
                      "relation": "connects_to", "evidence": "possible",
                      "attrs": {"class": cls}})  # fmt: skip
    for src, dst in flows:
        edges.append({"id": f"f-{dst}", "source": src, "target": dst, "relation": "flows_to",
                      "evidence": "proven", "attrs": {}})  # fmt: skip
    r["graph"] = {"subject": subject["id"], "nodes": nodes, "edges": edges}
    return r


def test_rooms_light_up_from_what_the_code_does():
    r = rep([fnd(1, "ha-read-secrets"), fnd(2, "ha-auth-change-users"),
             fnd(3, "py-shell-exec")])  # fmt: skip
    m = does.build(shown.view(r), "Acme")
    assert m.use["files"] == [("eye", "reads your secrets file")]
    assert m.use["users"] == [("pencil", "changes who can log in")]
    assert "programs" in m.use and "browser" not in m.use and not m.bad_rooms


def test_a_found_path_runs_red_to_a_site_that_isnt_the_apps_own():
    r = rep([fnd(1, "ha-read-secrets"), fnd(2, "ha-exfil-taint", "critical")])
    r = _graph(
        r,
        flows=[("data:secrets.yaml", "host:drop.evil.invalid")],
        hosts=[("drop.evil.invalid", "unknown"), ("api.acme.invalid", "declared")],
    )
    r["requests"] = {"sites": {"api.acme.invalid": [{"method": "GET"}]}}
    m = does.build(shown.view(r), "Acme")
    assert m.sites[0][0] == "drop.evil.invalid" and m.sites[0][2] == "bad"
    assert ("files", 0, "bad") in m.paths and "files" in m.bad_rooms
    assert ("api.acme.invalid", ["GET"], "own") in m.sites
    svg = does.wide(m)
    assert 'class="path bad"' in svg and "leaves your home" in svg


def test_an_unknown_destination_is_said_plainly():
    r = rep([fnd(1, "ha-read-secrets")])
    r = _graph(r, flows=[("data:secrets.yaml", "network:off-box")])
    r["graph"]["nodes"].append(
        {
            "id": "network:off-box",
            "kind": "network",
            "label": "off-box (destination not visible statically)",
        }
    )
    m = does.build(shown.view(r), "Acme")
    assert m.sites[0][0] == does.OFF_BOX
    html = does.wide(m) + does.narrow(m)
    assert "statically" not in html and "the code doesn" in html


def test_ways_in_are_orange_doors_and_a_bug_strip():
    r = rep([fnd(1, "ha-unauth-view", "medium"), fnd(2, "dep-vuln", "high", file="manifest.json")])
    m = does.build(shown.view(r), "Acme")
    assert (
        m.doors
        == [("Anyone on your home network", "can open one of its pages without logging in", True)]
        and m.bugs == 1
    )
    svg = does.wide(m)
    assert 'class="door"' in svg and "comes in" in svg
    assert "vulnerabilities</text>" in svg  # the strip wraps at 20 characters


def test_a_door_is_drawn_where_the_people_who_can_use_it_are():
    """(his rule 2026-11-22: it has to be accurate) A login-free page or a webhook can be
    used by whoever can reach Home Assistant: inside your home on a home or work network,
    outside only when it's reachable from the internet. A site you visit or a link someone
    sends you is always someone outside."""
    rules = [fnd(1, "ha-unauth-view", "medium"), fnd(2, "ha-webhook-remote", "low"),
             fnd(3, "ha-cors-allowed", "low")]  # fmt: skip
    home = does.build(shown.view(rep(rules)), "Acme").doors
    assert [(who, inside) for who, _w, inside in home] == [
        ("Anyone on your home network", True), ("Anyone on your home network", True),
        ("Other websites you visit", False)]  # fmt: skip
    work = does.build(shown.view(rep(rules), network="shared"), "Acme").doors
    assert work[0][:1] == ("Anyone on your shared or work network",) and work[0][2]
    public = does.build(shown.view(rep(rules, exposure="public")), "Acme").doors
    assert public[0][0] == "Anyone on the internet" and not public[0][2]
    # inside: drawn in the house, no arrow across the wall; outside: in the yard
    m = does.build(shown.view(rep(rules[:1])), "Acme")
    svg = does.wide(m)
    x = re.search(r'<g class="door"><rect x="(\d+)"', svg)
    assert int(x[1]) < does.WALL
    m = does.build(shown.view(rep(rules[:1], exposure="public")), "Acme")
    x = re.search(r'<g class="door"><rect x="(\d+)"', does.wide(m))
    assert int(x[1]) > does.WALL


def test_a_card_runs_in_your_browser_session():
    r = rep([fnd(1, "card-read-tokens", file="card.js")])
    r["target"]["kind"] = "plugin"
    m = does.build(shown.view(r), "Card")
    assert m.browser and m.use["browser"] == [("eye", "reads your saved login")]
    assert "runs in your browser session" in does.wide(m)


def test_the_exposure_bar_follows_the_setting():
    medium = {"exposure": 2.5, "exposure_level": "medium", "exposure_reasons": ["A reason."]}
    high = {"exposure": 6.0, "exposure_level": "high", "exposure_reasons": ["A reason."]}
    low = {"exposure": 0.0, "exposure_level": "low", "exposure_reasons": []}
    assert "Exposure 2.5 of 10" in does.bar_html(medium, "medium")
    assert does.bar_html(medium, "high") == ""
    assert "Exposure 6 of 10" in does.bar_html(high, "high")
    assert does.bar_html(low, "medium") == ""
    assert "found no way in" in does.bar_html(low, "always")
    assert does.bar_html({**high, "threat_level": "found"}, "always") == ""


def test_names_from_the_code_are_escaped_and_the_picture_is_script_free():
    r = rep([fnd(1, "ha-read-secrets")])
    r["requests"] = {"sites": {"<script>x</script>.invalid": [{"method": "<b>GET</b>"}]}}
    page = ui.render_app("", 1, shown.view(r), [], name="<img src=x>").decode()
    part = page.split("<h2>What it touches")[1].split("</section>")[0]
    assert "<script>" not in part and "<img" not in part and "&lt;script&gt;" in part


def test_the_picture_keeps_the_design_tokens():
    text = (ui.Path if hasattr(ui, "Path") else __import__("pathlib").Path)(
        does.__file__).read_text()  # fmt: skip
    for m in re.finditer(r' rx="(\d+)"', text):
        assert int(m[1]) in (0, 4, 6, 8, 12), m[0]
    assert not re.search(r"font-size:\s*(?:[0-9]|1[01])(?:\.\d+)?px", text)
