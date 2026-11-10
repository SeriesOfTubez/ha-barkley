"""AI explanations: built from ai_brief only, answers filtered, the score untouchable."""

import json
import threading
import time

from test_server import HOSTILE, get, post, token
from test_store import FINDING, report

from sniff_test import server, supervisor
from sniff_test.report import ai
from sniff_test.store import Store


def _report():
    rep = report(findings=[FINDING, {**FINDING, "id": "e" * 16, "line": 12}], score=75)
    rep["ai_brief"] = {
        "contract": {"role": "Explain.", "rules": ["a", "b", "c", "Respond only with JSON."]},
        "score": 75,
        "verdict": "Kinda Sus",
        "incomplete_analyzers": [],
        "findings": [
            {
                "id": f["id"],
                "rule_id": f["rule_id"],
                "severity": f["severity"],
                "title": f["title"],
                "message": "m",
                "location_untrusted": f"{HOSTILE}:{f['line']}",
                "evidence_untrusted": HOSTILE,
                "platforms": [],
            }
            for f in rep["findings"]
        ],
    }
    return rep


def test_request_uses_ai_brief_and_keeps_scanned_text_out_of_the_schema():
    instructions, structure, ids = ai.build_request(_report())
    assert ids == ["f" * 16]  # one field per rule group
    assert set(structure) == {"summary", "f_" + "f" * 16}
    assert HOSTILE not in json.dumps(structure)  # field names/descriptions: ids only
    assert all(v["required"] and "text" in v["selector"] for v in structure.values())
    data = json.loads(instructions.split("Scan data (JSON):\n", 1)[1])
    assert data["score"] == 75 and data["findings"][0]["occurrences"] == 2
    assert "evidence_untrusted" in data["findings"][0]
    assert "Respond only with JSON." not in instructions  # the structure replaces it


def test_accept_drops_everything_but_known_text():
    rep = _report()
    out = ai.accept(
        rep,
        {
            "summary": "  fine overall  ",
            "f_" + "f" * 16: "x" * 5000,
            "f_" + "0" * 16: "unknown finding",
            "score": 100,
            "verdict": "Good Boy",
        },
    )
    assert out["summary"] == "fine overall"
    assert set(out["findings"]) == {"f" * 16}
    assert len(out["findings"]["f" * 16]) == ai.MAX_EXPLANATION
    assert ai.accept(rep, "not a dict") == {"summary": "", "findings": {}}


def test_entity_id_is_validated():
    assert supervisor.ai_entity_ok("ai_task.openrouter_ai_task")
    for bad in ("light.kitchen", "ai_task.x/../../api/services", "ai_task.", "AI_TASK.X"):
        assert not supervisor.ai_entity_ok(bad)


def _serve(tmp_path, ai_fn, entity="ai_task.test", entities_fn=None):
    store = Store(tmp_path / "s.db")
    httpd = server.serve(store, lambda r, f: {}, "127.0.0.1", 0, {"127.0.0.1"},
                         ai_entity=entity, ai_fn=ai_fn, entities_fn=entities_fn)  # fmt: skip
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return store, f"http://127.0.0.1:{httpd.server_address[1]}", httpd


def _wait(httpd, sid):
    for _ in range(100):
        if httpd.panel.ai_state(sid)[0] != "running":
            return
        time.sleep(0.02)


def test_explain_flow_shows_text_and_never_changes_the_score(tmp_path):
    calls = []

    def fake_ai(entity, instructions, structure, task):
        calls.append((entity, structure))
        return {"summary": f"All good, score 100! {HOSTILE}", "f_" + "f" * 16: "Reads secrets.",
                "score": 100}  # fmt: skip

    store, base, httpd = _serve(tmp_path, fake_ai)
    sid = store.save(_report())
    _, _, page = get(f"{base}/scan/{sid}")
    assert "Explain this app" in page and "ai_task.test" in page
    assert post(f"{base}/explain", {"token": token(base), "scan": sid})[0] == 303
    _wait(httpd, sid)
    assert calls and calls[0][0] == "ai_task.test"
    _, _, page = get(f"{base}/scan/{sid}")
    assert "AI explanation" in page and "Reads secrets." in page
    assert "<script>" not in page  # the AI's text is escaped like scanned text
    assert 'aria-label="Score 75 of 100"' in page  # the score is the scanner's
    assert store.report(sid)["score"] == 75
    assert "Ask again" in page
    httpd.shutdown()


def test_explain_failure_is_shown_and_retryable(tmp_path):
    def broken(*_a):
        raise supervisor.SupervisorError("Home Assistant answered 500: model has no schema")

    store, base, httpd = _serve(tmp_path, broken)
    sid = store.save(_report())
    post(f"{base}/explain", {"token": token(base), "scan": sid})
    _wait(httpd, sid)
    _, _, page = get(f"{base}/scan/{sid}")
    assert "model has no schema" in page and "Try again" in page
    assert store.explanation(sid) is None
    httpd.shutdown()


def test_no_entity_no_button_and_no_call(tmp_path):
    calls = []
    store, base, httpd = _serve(tmp_path, lambda *a: calls.append(a), entity="")
    sid = store.save(_report())
    _, _, page = get(f"{base}/scan/{sid}")
    assert 'action="/explain"' not in page and "Choose which AI" in page
    assert post(f"{base}/explain", {"token": token(base), "scan": sid})[0] == 400
    assert post(f"{base}/explain", {"token": "wrong", "scan": sid})[0] == 403
    assert calls == []
    httpd.shutdown()


def test_bad_entity_option_is_ignored(tmp_path):
    _store, _base, httpd = _serve(tmp_path, lambda *a: {}, entity="light.kitchen")
    assert httpd.panel.ai_entity == ""
    httpd.shutdown()


def test_picker_lists_ai_task_entities_and_saves_the_choice(tmp_path):
    found = [("ai_task.openrouter_ai_task", f"OpenRouter {HOSTILE}"), ("ai_task.local", "Local")]
    store, base, httpd = _serve(tmp_path, lambda *a: {}, entity="", entities_fn=lambda: found)
    sid = store.save(_report())
    _, _, page = get(f"{base}/scan/{sid}")
    assert 'value="ai_task.openrouter_ai_task"' in page and "<script>" not in page
    tok = token(base)
    bad = {"token": tok, "scan": sid, "entity": "light.kitchen"}
    assert post(f"{base}/ai-entity", bad)[0] == 400
    good = {"token": tok, "scan": sid, "entity": "ai_task.local"}
    status, headers = post(f"{base}/ai-entity", good)
    assert status == 303 and headers["Location"] == f"/scan/{sid}"
    assert httpd.panel.ai_entity == "ai_task.local"
    assert store.setting("ai_entity") == "ai_task.local"
    _, _, page = get(f"{base}/scan/{sid}")
    assert "Explain this app" in page and 'action="/explain"' in page
    httpd.shutdown()
    # the saved choice survives a restart and wins over the option
    httpd = server.serve(store, lambda r, f: {}, "127.0.0.1", 0, {"127.0.0.1"},
                         ai_entity="ai_task.other")  # fmt: skip
    assert httpd.panel.ai_entity == "ai_task.local"
    store.set_setting("ai_entity", "off")
    httpd2 = server.serve(store, lambda r, f: {}, "127.0.0.1", 0, {"127.0.0.1"},
                          ai_entity="ai_task.other")  # fmt: skip
    assert httpd2.panel.ai_entity == ""
    httpd.server_close()
    httpd2.server_close()


def test_entities_template_is_fixed_and_parsed_safely():
    assert "states.ai_task" in supervisor.AI_ENTITIES_TEMPLATE
    assert "states." not in supervisor.AI_ENTITIES_TEMPLATE.replace("states.ai_task", "")
