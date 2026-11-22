"""(0.15) What a dashboard card's built JavaScript asks other sites for. Every name is made
up; nothing is run: the reader scans text."""

from __future__ import annotations

import time

import pytest

from sniff_test import ui
from sniff_test.analyzers import js_requests

CARD = (
    'const a=await fetch("https://api.radar.example.org/maps.json",{signal:e});'
    "await fetch(`https://wms.acme-maps.io/${i}/ows?service=WMS&version=1.3.0`);"
    'fetch("https://api.acme-maps.io/alerts?status=actual",'
    '{method:"post",headers:{Accept:"application/json","X-Key":k},body:JSON.stringify(d)});'
    "fetch(u,{signal:t});fetch(base+e,opts);fetch(`https://${host}/x`);"
    'this._fetch();x.fetch("https://not.acme-maps.io/");prefetch("https://no.acme-maps.io/");'
    'window.fetch("/api/hassio/x");fetch("https://up.acme-maps.io/"+id,{method:m,...rest});'
    'r.open("GET","https://xhr.acme-maps.io/a");window.open("https://link.acme-maps.io/");'
    'navigator.sendBeacon("https://beacon.acme-maps.io/hit",data);'
    'L.tileLayer("https://{s}.tiles.acme-maps.io/{z}/{x}/{y}.png");'
    'const t="https://tile.acme-maps.io/v1/{z}/{x}/{y}.pbf",'
    'doc="https://tiles.example.com/{z}/{x}/{y}.png";'
)


def _by_host(reqs):
    return {r.host: r for r in reqs if r.host}


def test_fetch_calls_with_a_written_out_site_are_read():
    reqs, tiles = js_requests.read(CARD, "card.js")
    by = _by_host(reqs)
    assert sorted(by) == ["api.acme-maps.io", "api.radar.example.org", "beacon.acme-maps.io",
                          "up.acme-maps.io", "wms.acme-maps.io", "xhr.acme-maps.io"]  # fmt: skip
    plain = by["api.radar.example.org"]
    assert (plain.method, plain.body, plain.headers) == ("GET", None, None)  # fetch's default
    assert by["wms.acme-maps.io"].query == ("service", "version")
    post = by["api.acme-maps.io"]
    assert (post.method, post.body, post.headers) == ("POST", (), ("Accept", "X-Key"))
    assert post.query == ("status",)
    up = by["up.acme-maps.io"]
    assert (up.method, up.more) == ("", True)  # the method is a name, and `...rest` adds more
    assert by["xhr.acme-maps.io"].method == "GET"
    assert (by["beacon.acme-maps.io"].method, by["beacon.acme-maps.io"].body) == ("POST", ())
    # an address in a name, one added to a name, and a site with a `${…}` piece: no site
    nowhere = [r for r in reqs if r.host is None]
    assert len(nowhere) == 3 and nowhere[1].more and nowhere[1].method == ""
    # a method of the card's own, another object's fetch, a longer name, a page-relative
    # address and window.open are not requests to a site
    assert not {"not.acme-maps.io", "no.acme-maps.io", "link.acme-maps.io"} & set(by)
    # map-tile patterns, `{s}.` dropped; a name kept for examples is never a site
    assert sorted(tiles) == ["tile.acme-maps.io", "tiles.acme-maps.io"]


def test_a_site_must_be_written_out_in_full():
    assert js_requests.site_of("https://api.acme-maps.io/x") == ("api.acme-maps.io", "https", None)
    assert js_requests.site_of("http://api.acme-maps.io:8080/x") == (
        "api.acme-maps.io", "http", 8080)  # fmt: skip
    for bad in ("https://api.acme\x00.io/x", "https://\x00/x", "/api/x", "//cdn.acme-maps.io/x",
                "https://api.acme-maps.io:\x00/x", "https://user@evil.acme-maps.io/x",
                "https://a"):  # fmt: skip
        assert js_requests.site_of(bad) is None, bad


def test_the_report_section_and_the_page(tmp_path):
    (tmp_path / "card.js").write_text(CARD)
    (tmp_path / "notes.txt").write_text('fetch("https://ignored.acme-maps.io/")')
    section = js_requests.summary(*js_requests.requests_in(tmp_path))
    assert section["code"] == "card" and section["total"] == 9
    assert section["images"]["tile.acme-maps.io"] == {"count": 1, "at": ["card.js:1"]}
    assert "ignored.acme-maps.io" not in section["sites"]
    assert js_requests.summary([], {}) is None
    host = {"id": "host:api.acme-maps.io", "kind": "host", "label": "api.acme-maps.io",
            "ring": "network", "attrs": {"class": "undeclared"}}  # fmt: skip
    report = {
        "requests": section, "findings": [],
        "graph": {"subject": "card:x", "nodes": [host], "edges": [
            {"id": "e1", "source": "card:x", "target": host["id"], "relation": "connects_to",
             "attrs": {"schemes": ["https"]}, "finding_ids": []}]},
    }  # fmt: skip
    html = ui.zones_html(report, part="connects")
    assert "Sends <b>POST</b> requests here from one place in the code." in html
    assert "Sites named by an address pattern" in html and "<b>Loads map images</b>" in html
    assert "One address in the code is a map-tile pattern" in html
    assert "from the card's settings" in html and "entered during setup" not in html
    assert "tiles.example.com" not in html


@pytest.mark.parametrize(
    "text",
    [
        "fetch(" * 200_000,
        'fetch("' + "a" * 400_000,
        "fetch(`" + "${" * 200_000,
        'fetch("https://a.acme-maps.io/",{' + "{" * 300_000,
        'fetch("https://a.acme-maps.io/",{headers:{' + '"a":1,' * 100_000,
        "fetch((" * 150_000,
        '.open("GET",' * 100_000,
        "https://" * 100_000 + "{z}" * 100_000,
        "{z}" * 300_000,
        'x.open("' + "\\" * 400_000,
    ],
)
def test_hostile_text_is_read_in_time_proportional_to_its_size(text):
    start = time.monotonic()
    js_requests.read(text, "card.js")
    assert time.monotonic() - start < 5
