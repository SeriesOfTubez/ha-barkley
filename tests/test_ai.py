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
    assert data["items"][0]["occurrences"] == 2 and "evidence_untrusted" in data["items"][0]
    # (0.15) the two readings, never the 0-100 score, the verdict word or a grade for context
    assert "score" not in data and "verdict" not in data and "Kinda Sus" not in instructions
    assert data["threat"] in ("none", "possible", "found") and data["exposure"] in (
        "low", "medium", "high")  # fmt: skip
    assert "two readings and they are final" in instructions
    assert "The score and verdict are final" not in instructions
    assert ("severity" in data["items"][0]) == (
        "Threat" in data["items"][0]["kind"] or "bug" in data["items"][0]["kind"])  # fmt: skip
    shown = {"threat_level": "none", "exposure_level": "low", "exposure": 1.69,
             "exposure_reasons": ["4 pages open without logging in"]}  # fmt: skip
    text = ai.build_request(_report(), None, shown)[0]
    assert '"exposure_out_of_10": 1.69' in text and "4 pages open without logging in" in text
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
    assert ai.accept(rep, "not a dict") == {
        "summary": "",
        "findings": {},
        "readings": [],
        "dropped": 0,
    }


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
    assert 'aria-label="Threat 0 of 10"' in page and "of 100" not in page  # readings, not the AI's
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


def test_every_ai_call_logs_its_time_and_size(tmp_path, capfd):
    """One log line per AI call: seconds and characters sent, answered or not. The
    error's text stays out of it (only its type)."""

    def fake_ai(entity, instructions, structure, task):
        return {"summary": "Fine.", "f_" + "f" * 16: "Reads secrets."}

    store, base, httpd = _serve(tmp_path, fake_ai)
    sid = store.save(_report())
    post(f"{base}/explain", {"token": token(base), "scan": sid})
    _wait(httpd, sid)
    err = capfd.readouterr().err
    line = next(x for x in err.splitlines() if x.startswith(f"ai call @{sid} explain this app"))
    assert "answered in" in line and line.endswith("chars sent")

    def broken(*_a):
        raise supervisor.SupervisorError("secret-looking text that must not be logged")

    httpd.panel.ai_fn = broken
    post(f"{base}/explain", {"token": token(base), "scan": sid})
    _wait(httpd, sid)
    err = capfd.readouterr().err
    line = next(x for x in err.splitlines() if x.startswith(f"ai call @{sid} explain this app"))
    assert "failed after" in line and line.endswith("SupervisorError")
    assert "secret-looking" not in line
    httpd.shutdown()


def test_a_running_explanation_shows_a_box_in_the_ai_colour_with_the_wait(tmp_path):
    """(0.15) While the AI answers, the app page shows a box with a moving sparkle and how
    long it has waited; the list's status strip names the app."""
    release = threading.Event()

    def slow(*_a):
        release.wait(5)
        return {"summary": "Fine."}

    store, base, httpd = _serve(tmp_path, slow)
    sid = store.save(_report())
    post(f"{base}/explain", {"token": token(base), "scan": sid})
    _, _, page = get(f"{base}/scan/{sid}")
    assert 'class="aibox' in page and "Your AI is answering…" in page and "It has been" in page
    assert 'class="thinking"' in page and '<meta http-equiv="refresh"' in page
    assert [(r.sid, r.item) for r in httpd.panel.ai_running()] == [(sid, "")]
    release.set()
    _wait(httpd, sid)
    assert httpd.panel.ai_running() == []
    httpd.shutdown()


def test_ai_answers_settings_pair_minutes_with_the_size_and_reach_the_call(tmp_path,
                                                                          monkeypatch):  # fmt: skip
    """(0.15, his design 2026-11-23) A new size fills in its minutes unless they were edited;
    the limit (or none) and the Stop waiting flag reach the websocket call."""
    store, base, httpd = _serve(tmp_path, None)
    panel = httpd.panel
    assert (panel.settings.ai_size, panel.settings.ai_minutes, panel.ai_timeout()) == (
        12000, 6, 360.0)  # fmt: skip
    panel.save_settings({"ai_size": "18000", "ai_minutes": "6"})
    assert (panel.settings.ai_size, panel.settings.ai_minutes) == (18000, 9)
    panel.save_settings({"ai_size": "6000", "ai_minutes": "20"})  # edited: kept
    assert (panel.settings.ai_size, panel.settings.ai_minutes) == (6000, 20)
    panel.save_settings({"ai_limit": "0"})
    assert panel.ai_timeout() is None
    seen = {}

    def fake(entity, instructions, structure, task, timeout=None, cancel=None, **_kw):
        seen.update(timeout=timeout, cancel=cancel)
        panel.stop_ai(sid)  # the user clicks Stop waiting while it runs
        assert cancel is not None and cancel.is_set()
        raise supervisor.AiStopped()

    monkeypatch.setattr(supervisor, "ai_generate_data", fake)
    sid = store.save(_report())
    panel.explain(sid)
    _wait(httpd, sid)
    assert seen["timeout"] is None
    state, err = panel.ai_state(sid)
    assert state == "failed" and err.startswith("You stopped waiting.")
    _, _, page = get(f"{base}/scan/{sid}")
    assert "You stopped waiting." in page and "The AI didn't answer: You" not in page
    assert panel.ai_running() == []
    httpd.shutdown()


def test_a_time_out_says_how_long_it_waited_and_the_ways_out():
    txt = server.ai_why(supervisor.AiTimeout(360))
    assert txt.startswith("Your AI didn't answer within 6 minutes.")
    assert "Settings → AI answers" in txt and "changes the readings" in txt
    assert server.ai_why(RuntimeError("boom")) == "The AI didn't answer: boom"
    assert server.ai_reason(supervisor.AiTimeout(60)) == "no answer within 1 minute"
