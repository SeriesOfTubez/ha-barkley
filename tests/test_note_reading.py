"""(0.13.0) A privacy note opens the AI's reading of the address or port behind it: the
same item, answer and sheet as under "Where it connects", never a second reading."""

import re

from test_deep import _serve, _wait
from test_server import get, post, token
from test_store import report

from sniff_test.report import context, privacy

SUBJECT = "integration:acme"
TELE, MQTT, API = "a1" * 8, "b2" * 8, "c3" * 8
FILES = {
    "tele.py": "import aiohttp\n\nURL = 'https://telemetry.acme.invalid/ping'\n",
    "mqtt.py": "PORT = 1883\n",
    "api.py": "BASE = 'http://api.acme.invalid/v1'\n",
}


def _edge(eid, target, relation, attrs, file, line):
    return {
        "id": eid,
        "source": SUBJECT,
        "relation": relation,
        "target": target,
        "evidence": f"{file}:{line}",
        "attrs": attrs,
        "samples": [{"file": file, "line": line}],
    }


def _report(tmp_path, hosts=(), declared=True):
    root = tmp_path / "pkg"
    root.mkdir(exist_ok=True)
    for name, text in FILES.items():
        (root / name).write_text(text)
    rep = report()
    g = rep["graph"]
    edges = [
        _edge(TELE, "host:telemetry.acme.invalid", "connects_to",
              {"class": "developer_hosted", "schemes": ["https"]}, "tele.py", 3),
        _edge(MQTT, "port:1883", "uses_port", {"names": ["PORT"]}, "mqtt.py", 1),
    ]  # fmt: skip
    nodes = [
        {"id": "host:telemetry.acme.invalid", "kind": "host", "label": "telemetry.acme.invalid"},
        {"id": "port:1883", "kind": "port", "label": "1883"},
    ]
    if declared:
        edges.append(_edge(API, "host:api.acme.invalid", "connects_to",
                           {"class": "declared", "schemes": ["http"]}, "api.py", 1))  # fmt: skip
        nodes.append({"id": "host:api.acme.invalid", "kind": "host", "label": "api.acme.invalid"})
    dev = {"class": "developer_hosted", "schemes": ["https"]}
    for eid, host in hosts:
        edges.append(_edge(eid, f"host:{host}", "connects_to", dev, "tele.py", 3))
        nodes.append({"id": f"host:{host}", "kind": "host", "label": host})
    g["nodes"] += nodes
    g["edges"] += edges
    rep["context"] = context.build(root, rep["findings"], g)
    return rep


def _note(page, title):
    """The HTML of one privacy note (from its title to the next note or the box's end)."""
    start = page.index(f"<h3>{title}</h3>")
    end = page.find('<div class="finding">', start)
    box_end = page.index("</section>", start)
    return page[start : end if 0 < end < box_end else box_end]


def test_notes_carry_their_edges_lined_up_with_their_hosts(tmp_path):
    notes = {n.kind: n for n in privacy.notes(_report(tmp_path))}
    assert notes["telemetry"].edges == [TELE] and notes["telemetry"].hosts == [
        "telemetry.acme.invalid"
    ]
    assert notes["mqtt"].edges == [MQTT] and notes["mqtt"].classes == [""]
    assert notes["unencrypted"].edges == [API] and notes["unencrypted"].classes == ["declared"]


def test_a_note_opens_the_same_reading_as_its_address(tmp_path):
    calls = []

    def fake_ai(entity, instructions, structure, task):
        calls.append(instructions)
        return {"claim_1": "It sends a ping to `URL` (tele.py:3)."}

    store, base, httpd = _serve(tmp_path, fake_ai)
    sid = store.save(_report(tmp_path))
    _, _, page = get(f"{base}/scan/{sid}")
    tele = _note(page, "Can send usage statistics to the developer")
    assert f'name=item value="{TELE}"' in tele and "Explain in context</button>" in tele
    assert "same one as under “Where it connects”" in tele
    assert f'name=item value="{MQTT}"' in _note(page, "May use unencrypted MQTT")
    # one sheet and one anchor per item: the note links to the sheet, it doesn't copy it
    for eid in (TELE, MQTT):
        assert page.count(f'id="ai-{eid}"') == 1 and page.count(f'id="item-{eid}"') == 1
        assert page.count(f'name=item value="{eid}"') >= 2  # the note's button and the zone's
    assert not calls  # nothing is sent before the click

    ask = {"token": token(base), "scan": sid, "item": TELE}
    status, headers = post(f"{base}/explain-item", ask)
    assert status == 303 and headers["Location"].endswith(f"#ai-{TELE}")
    _wait(httpd, sid)
    assert len(calls) == 1 and "tele.py:3| " in calls[0]
    _, _, page = get(f"{base}/scan/{sid}")
    tele = _note(page, "Can send usage statistics to the developer")
    assert f'class="aichip" href="#ai-{TELE}"' in tele
    assert "reading of the code (1 statement" in tele
    assert page.count(f'id="ai-{TELE}"') == 1
    assert page.count("It sends a ping to") == 1  # the answer is in the one sheet
    assert store.report(sid)["score"] == 100  # untouched
    httpd.shutdown()


def test_a_note_without_a_reading_says_why(tmp_path):
    store, base, httpd = _serve(tmp_path, lambda *a: {})
    sid = store.save(_report(tmp_path))
    _, _, page = get(f"{base}/scan/{sid}")
    plain = _note(page, "Uses unencrypted web addresses on the internet")
    assert "Explain in context</button>" not in plain
    assert (
        "This note has no “Explain in context”. Its addresses are named in the app's "
        "documentation or manifest" in plain
    )
    httpd.shutdown()


def test_summary_mode_and_old_reports_show_nothing_on_notes(tmp_path):
    store, base, httpd = _serve(tmp_path, lambda *a: {}, mode="summary")
    sid = store.save(_report(tmp_path))
    _, _, page = get(f"{base}/scan/{sid}")
    assert "<h3>May use unencrypted MQTT</h3>" in page
    assert "noteai" not in page.split("</style>", 1)[1]
    httpd.shutdown()
    store, base, httpd = _serve(tmp_path, lambda *a: {})
    rep = _report(tmp_path)
    del rep["context"]
    sid = store.save(rep)
    _, _, page = get(f"{base}/scan/{sid}")
    assert "<h3>May use unencrypted MQTT</h3>" in page
    assert "noteai" not in page.split("</style>", 1)[1]
    httpd.shutdown()


def test_an_address_past_the_twelve_shown_still_has_its_sheet(tmp_path):
    hosts = [(f"{i:02x}" * 8, f"telemetry-{i:02d}.acme.invalid") for i in range(16, 30)]
    store, base, httpd = _serve(tmp_path, lambda *a: {})
    sid = store.save(_report(tmp_path, hosts=hosts, declared=False))
    _, _, page = get(f"{base}/scan/{sid}")
    assert "and 3 more" in page  # 15 developer hosts, 12 shown in their zone
    tele = _note(page, "Can send usage statistics to the developer")
    linked = re.findall(r'name=item value="([0-9a-f]{16})"', tele)
    assert len(linked) == 4  # the note links the first four, as it lists four addresses
    for eid in [TELE, *(h for h, _ in hosts)]:
        assert page.count(f'id="ai-{eid}"') == 1
    httpd.shutdown()


def test_the_sheet_says_how_many_restatements_it_left_out():
    from sniff_test import ui

    snip = {"file": "a.py", "lang": "python", "segments": [{"file": "a.py", "start": 1,
            "code": ["x = 1"]}]}  # fmt: skip
    claim = {"text": "`x` is one.", "cites": [["a.py", 1, 1]]}
    ans = {"claims": [claim], "questions": [], "dropped": [], "both": True, "repeats": 4,
           "entity_id": "ai_task.t", "created": "2026-11-17T00:50"}  # fmt: skip
    html = ui.deep_html("<form>{label}</form>", item_id="d4" * 8, title="t", answer=ans,
                        state="", error="", snip=snip, entity="ai_task.t")  # fmt: skip
    assert "4 statements in the second reading said the same as ones above" in html
    assert "so they aren't shown again" in html
    ans["repeats"] = 1
    html = ui.deep_html("<form>{label}</form>", item_id="d4" * 8, title="t", answer=ans,
                        state="", error="", snip=snip, entity="ai_task.t")  # fmt: skip
    assert "1 statement in the second reading said the same as one above" in html
    assert "so it isn't shown again" in html
    ans["repeats"] = 0
    html = ui.deep_html("<form>{label}</form>", item_id="d4" * 8, title="t", answer=ans,
                        state="", error="", snip=snip, entity="ai_task.t")  # fmt: skip
    assert "said the same as" not in html
