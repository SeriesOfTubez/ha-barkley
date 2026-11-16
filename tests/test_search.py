"""Marketplace search: sniff an app before installing it."""

import threading

from test_server import HOSTILE, Calls, get, post, token
from test_store import report

from sniff_test import server, supervisor
from sniff_test.store import Store

RAW = [
    {"full_name": "acme/printer-hub", "category": "integration", "name": "Printer Hub",
     "description": "A hub for printers", "stars": 900, "downloads": 50000, "installed": True},
    {"full_name": "acme/printer-card", "category": "plugin", "name": "Printer Card",
     "description": f"Shows a printer {HOSTILE}", "stars": 5, "downloads": 10, "installed": False},
    {"full_name": "acme/hub-extras", "category": "integration", "name": "Extras",
     "description": "Hub add-ons", "stars": 1, "downloads": 1, "topics": ["hub"]},
    {"full_name": "acme/theme", "category": "theme", "name": "Hub Theme"},  # not scannable
    {"full_name": "../../etc", "category": "integration", "name": "Bad"},  # invalid repo
]  # fmt: skip


def test_catalog_keeps_only_scannable_valid_repos():
    items = supervisor.parse_catalog(RAW)
    assert [i.repo for i in items] == [
        "acme/printer-hub", "acme/printer-card", "acme/hub-extras"
    ]  # fmt: skip
    assert items[1].kind == "card" and not items[1].installed


def test_search_ranks_name_over_description():
    items = supervisor.parse_catalog(RAW)
    assert [i.repo for i in supervisor.search(items, "hub")] == [
        "acme/printer-hub", "acme/hub-extras"
    ]  # fmt: skip
    assert [i.repo for i in supervisor.search(items, "printer", kind="card")] == [
        "acme/printer-card"
    ]
    assert supervisor.search(items, "hub nothing") == []
    assert supervisor.search(items, "   ") == []


def _serve(tmp_path):
    store = Store(tmp_path / "s.db")
    scan_fn = Calls()
    httpd = server.serve(
        store, scan_fn, "127.0.0.1", 0, {"127.0.0.1"},
        installed_fn=lambda: supervisor.parse_installed(
            [{**RAW[0], "installed_version": "v2.3.0", "available_version": "v2.3.0"}]
        ),
        catalog_fn=lambda: supervisor.parse_catalog(RAW),
    )  # fmt: skip
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return store, scan_fn, f"http://127.0.0.1:{httpd.server_address[1]}", httpd


def test_search_page_sniff_and_not_installed_cards(tmp_path):
    _store, scan_fn, base, httpd = _serve(tmp_path)
    _, _, index = get(base + "/")
    assert 'action="/search"' in index
    _, _, page = get(base + "/search?q=printer")
    assert "Printer Card" in page and "Sniff it" in page
    assert "<script>" not in page and "&lt;script&gt;" in page  # catalog text is untrusted
    status, headers = post(base + "/scan", {"repo": "acme/printer-card", "q": "printer",
                                            "token": token(base)})  # fmt: skip
    assert status == 303 and headers["Location"] == "/search?q=printer&kind="
    httpd.panel.worker.wait()
    assert scan_fn.calls == [("acme/printer-card", None)]  # what the Marketplace installs
    _, _, page = get(base + "/search?q=printer")
    row = page[page.index("Printer Card") :]
    row = row[: row.index("</tr>")]
    assert 'href="/scan/' in row and "Sniff it" not in row  # now shows its score
    _, _, index = get(base + "/")
    assert "Sniffed, not installed (1)" in index and "Printer Card" in index
    httpd.shutdown()


def test_no_search_outside_an_addon(tmp_path):
    store = Store(tmp_path / "s.db")
    httpd = server.serve(store, Calls(), "127.0.0.1", 0, {"127.0.0.1"})
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    _, _, index = get(base + "/")
    assert 'action="/search"' not in index
    assert get(base + "/search?q=x")[0] == 404
    store.save(report())
    httpd.shutdown()
