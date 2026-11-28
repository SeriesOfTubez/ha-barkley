"""(0.15) The Marketplace's removed list: a plain line and a chip, never a reading. The
real address is never fetched here: `fetch` is a stand-in."""

import json

from sniff_test import listings, ui

LIST = [
    {"repository": "acme/bad", "removal_type": "critical",
     "reason": "Security issues, <b>known</b> to steal auth tokens."},
    {"repository": "acme/old", "removal_type": "blacklist", "reason": "Repository is archived"},
    {"repository": "not a repo", "removal_type": "critical"},
]  # fmt: skip


def test_the_list_is_read_and_shown_as_the_marketplaces_word(tmp_path):
    li = listings.Listings(tmp_path, fetch=lambda: json.dumps(LIST).encode())
    li.refresh()
    assert li.get("ACME/bad")["type"] == "critical"
    assert li.get("acme/old") == {"type": "removed", "reason": "Repository is archived"}
    assert li.get("not a repo") is None and li.get("acme/fine") is None
    note = listings.note_html(li.get("acme/bad"))
    assert "removed this app as critical" in note and "<b>known</b>" not in note
    assert listings.chip(li.get("acme/old")) == ("", "Removed from the Marketplace")
    card = ui.Card("acme/bad", "Bad", "card", "v1", None, None, None,
                   listing=li.get("acme/bad"))  # fmt: skip
    assert ("bad", "Removed as critical") in ui.card_chips(card)


def test_kept_a_day_and_a_failed_fetch_shows_nothing(tmp_path):
    calls = []

    def fetch():
        calls.append(1)
        return json.dumps(LIST).encode()

    li = listings.Listings(tmp_path, fetch=fetch)
    li.refresh()
    again = listings.Listings(tmp_path, fetch=fetch)  # a restart reads the cached copy
    again._load_cached()
    again.refresh_soon()
    assert calls == [1] and again.get("acme/bad")

    def broken():
        raise OSError("unreachable")

    fresh = listings.Listings(tmp_path / "other", fetch=broken)
    fresh.refresh()
    assert fresh.get("acme/bad") is None
