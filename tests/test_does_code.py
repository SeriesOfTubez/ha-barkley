"""(0.15, his ask 2026-11-23) On the "What it does" picture, code from outside that runs
here: a dotted orange arrow from where it comes from into the room where it runs. Made-up
reports; every site is .invalid."""

from __future__ import annotations

from sniff_test import does


def _card() -> dict:
    return {"target": {"kind": "plugin"}, "findings": [
        {"rule_id": "card-remote-script", "severity": "medium", "file": "c.js", "line": 3,
         "evidence": "https://cdn.example.invalid/npm/thing@latest/x.js"},
        {"rule_id": "card-remote-pinned", "severity": "low", "file": "c.js", "line": 9,
         "evidence": "import('https://pinned.example.invalid/x@1.2.3/x.js')"},
    ]}  # fmt: skip


def _lua(origin: dict) -> dict:
    run = {"file": "runtime.py", "line": 15, "source": "downloaded", "from": [origin]}
    return {"target": {"kind": "integration"},
            "findings": [{"rule_id": "py-lua-download", "severity": "medium",
                          "file": "runtime.py", "line": 15}],
            "lua": {"runtimes": [], "runs": [run]}}  # fmt: skip


def test_a_cards_code_sites_are_drawn_first_with_an_arrow_into_the_browser() -> None:
    m = does.build(_card(), "Card")
    assert [h for h, _l, _w in m.sites][:2] == ["cdn.example.invalid", "pinned.example.invalid"]
    assert m.code_paths == [(0, "browser"), (1, "browser")]
    assert m.sites[0][1][0] == does.CODE + "sends code that runs here"
    assert m.sites[1][1][0] == does.CODE + "sends a fixed version of code"
    svg = does.wide(m)
    assert svg.count('class="codein"') == 2 and "url(#o-d)" in svg
    assert "sends code that runs here" in svg
    phone = does.narrow(m)
    assert "sends code that runs in your browser" in phone
    assert "Dotted orange arrow: code from outside that runs here." in does.legend(m)


def test_code_only_sites_get_no_grey_request_line() -> None:
    m = does.build(_card(), "Card")
    assert m.code_only == {0, 1}
    assert f'd="M{does.APP_X + does.APP_W} ' not in does.wide(m)  # no app-to-site line


def test_lua_from_a_site_in_the_code_points_into_programs() -> None:
    m = does.build(_lua({"kind": "site", "detail": "lua.example.invalid"}), "App")
    assert m.code_paths == [(0, "programs")] and m.sites[0][0] == "lua.example.invalid"
    assert "sends code that runs in Home Assistant" in does.narrow(m)


def test_lua_from_an_answer_is_a_dashed_box_linked_to_the_answering_sites() -> None:
    o = {"kind": "answer", "detail": "url", "site": "a.example.invalid,b.example.invalid"}
    m = does.build(_lua(o), "App")
    assert m.code_paths == []  # Barkley doesn't know the host the code comes from
    assert m.code_boxes == [("Code from an address one of these sites gives it", "programs",
                             ["a.example.invalid", "b.example.invalid"])]  # fmt: skip
    svg = does.wide(m)
    assert 'class="codein"' in svg and "runs in Home Assistant" in svg
    one = does.build(_lua({"kind": "answer", "detail": "url", "site": "a.example.invalid"}), "A")
    assert one.code_boxes[0][0] == "Code from an address a.example.invalid gives it"


def test_untraceable_and_odd_hosts_are_said_plainly() -> None:
    m = does.build(_lua({"kind": "unknown"}), "App")
    assert m.code_boxes == [("Code from an address Barkley couldn't trace", "programs", [])]
    bad = does.build(_lua({"kind": "site", "detail": "<script>"}), "App")
    assert bad.code_paths == [] and "<script>" not in does.wide(bad)
