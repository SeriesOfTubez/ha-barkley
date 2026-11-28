"""(his report 2026-11-25) The Settings page has no script: its controls sit in the rows
and reach the one form (id="settings") through a form="settings" attribute. A control
outside every form without that attribute is never sent, so its change is lost on Save
(the AI answers slider and the minutes box were). Every named control must be inside a
form or point at one that exists."""

from __future__ import annotations

from html.parser import HTMLParser

from test_watch import ctx  # noqa: F401  (the fixture)

from sniff_test import server, settings

CONTROLS = ("input", "select", "textarea", "button")


class _Forms(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.depth = 0
        self.ids: set[str] = set()
        self.loose: list[tuple[str, str]] = []  # (name, form attr) outside every form
        self.names: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "form":
            self.depth += 1
            if a.get("id"):
                self.ids.add(str(a["id"]))
        elif tag in CONTROLS and a.get("name"):
            self.names.add(str(a["name"]))
            if self.depth == 0:
                self.loose.append((str(a["name"]), str(a.get("form") or "")))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.depth -= 1


def test_every_setting_reaches_the_form_it_is_saved_with(ctx):  # noqa: F811
    _store, _worker, _fakes, w = ctx
    out = server.render_settings(
        "", settings.DEFAULTS, "t", ai_entity="ai_task.x", watcher=w,
        ai_choices=[("ai_task.x", "X")], store_mb=1.0, ha_token_html="<p>token</p>",
    ).decode()  # fmt: skip
    p = _Forms()
    p.feed(out)
    assert p.depth == 0
    bad = [(n, f) for n, f in p.loose if f not in p.ids]
    assert bad == [], bad
    # the settings this report was about are among them
    assert {"ai_size", "ai_minutes", "ai_limit", "keep_versions"} <= p.names
