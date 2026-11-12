"""The installed list: clickable summary filters, cards or table, paging, the status strip."""

import re
import time

from test_server import INSTALLED, _seed, addon, get, post, token  # noqa: F401
from test_store import report

from sniff_test import server, ui
from sniff_test.store import Store


def test_summary_items_are_filter_links(addon):  # noqa: F811
    store, _, base, _, _ = addon
    _seed(store)
    _, _, page = get(base + "/")
    summary = page[page.index('class="box summary"') : page.index("</nav>")]
    assert 'href="/?f=look&amp;view=cards"' in summary  # 1 worth a look
    assert 'href="/?f=fine&amp;view=cards"' in summary
    assert 'href="/?f=updates&amp;view=cards"' in summary
    _, _, fine = get(base + "/?f=fine")
    assert 'class="sum on"' in fine and "Showing" in fine and "show all" in fine
    cards = re.findall(r'class="app-name"[^>]*>([^<]+)<', fine)
    assert cards and "Moved" not in cards and "Never" not in cards


def test_table_view_is_remembered_and_shows_the_same_apps(addon):  # noqa: F811
    store, _, base, _, _ = addon
    _seed(store)
    _, _, table = get(base + "/?view=table")
    assert '<table class="apps">' in table and 'class="grid"' not in table.split("Sniffed")[0]
    for it in INSTALLED:
        assert f"<b>{it.name}</b>" in table
    assert store.setting("view") == "table"
    _, _, again = get(base + "/")  # no view in the URL: the remembered one
    assert '<table class="apps">' in again
    _, _, cards = get(base + "/?view=cards")
    assert '<table class="apps">' not in cards


def test_paging_splits_long_lists():
    cards = [
        ui.Card(repo=f"a/r{i}", name=f"App {i:02}", kind="integration", installed="v1",
                available=None, scan=None, report=None)
        for i in range(30)
    ]  # fmt: skip
    one = ui.render_grid("", cards, ui.View())
    assert one.count('class="app ') == ui.PER_PAGE["cards"]
    assert "Page 1 of 3" in one and 'href="/?view=cards&amp;page=2"' in one
    three = ui.render_grid("", cards, ui.View(pg=3))
    assert three.count('class="app ') == 30 - 2 * ui.PER_PAGE["cards"] and "Next" not in three
    assert ui.render_grid("", cards, ui.View(pg=99)).count('class="app ') == 6  # clamped
    table = ui.render_grid("", cards, ui.View(view="table"))
    assert table.count("<tr><td>") == ui.PER_PAGE["table"] and "Page 1 of 2" in table


def test_view_parse_accepts_only_known_values():
    v = ui.View.parse({"f": ["<x>"], "view": ["evil"], "page": ["-3"]})
    assert v == ui.View()
    assert ui.View.parse({"page": ["abc"]}).pg == 1
    assert ui.View(f="look", view="table", pg=2).qs("&") == "f=look&view=table&page=2"


def test_a_button_brings_you_back_to_the_same_view(addon):  # noqa: F811
    store, _, base, _, _ = addon
    _seed(store)
    _, _, page = get(base + "/?f=updates&view=table")
    assert 'name=back value="f=updates&amp;view=table"' in page
    status, headers = post(base + "/installed", {"repo": "acme/never", "ref": "v3",
                                                 "back": "f=updates&view=table&x=<y>",
                                                 "token": token(base)})  # fmt: skip
    assert status == 303 and headers["Location"] == "/?f=updates&view=table"


def test_status_strip_shows_running_and_just_finished(tmp_path):
    jobs = [
        server.Job(1, "installed", "acme/one", "v1", state="running"),
        server.Job(2, "installed", "acme/two", "v1"),
        server.Job(3, "installed", "acme/three", "v1", state="done", scan_ids=[7],
                   finished=time.time() - 5),
        server.Job(4, "installed", "acme/old", "v1", state="done", scan_ids=[8], finished=1.0),
    ]  # fmt: skip
    names = {"acme/one": "One <b>", "acme/three": "Three"}
    html = server.status_html("", jobs, names, "view=cards")
    assert "Sniffing One &lt;b&gt;…" in html  # names are untrusted
    assert "1 waiting their turn: acme/two" in html
    assert 'Three is done: <a href="/scan/7">' in html
    assert "acme/old" not in html  # finished long ago
    assert "refreshes by itself" in html
    assert server.status_html("", jobs[3:], names, "") == ""
    page = server.render_index("", Store(tmp_path / "s.db"), jobs, "t", status=html).decode()
    assert '<meta http-equiv="refresh" content="5">' in page
    assert page.index('class="box status"') < page.index("Check any repository")
    quiet = server.render_index("", Store(tmp_path / "s.db"), jobs[3:], "t").decode()
    assert "http-equiv" not in quiet and "Refresh</a>" in quiet


def test_finished_time_is_set(tmp_path):
    w = server.Worker(Store(tmp_path / "s.db"), lambda repo, ref: report(repo=repo, ref="v1"))
    w.submit("scan", "acme/x", "v1")
    w.wait()
    assert w.jobs[0].finished > 0
