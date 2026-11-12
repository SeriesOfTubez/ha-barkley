"""Geist and Geist Mono are served by the panel itself (assets/fonts, vendored with
provenance), never fetched from a CDN, and the CSP grew exactly one directive for them."""

from __future__ import annotations

import hashlib
from importlib import resources

from sniff_test import server, ui

FILES = {
    "Geist-Variable.woff2": "3626eba547294501c8a4d662c7d9ea3b49734409a4c5a1ccf12fa86429b1687e",
    "GeistMono-Variable.woff2": "5d93ee62680bbec1abc5405c2658311f9396f6f9a821ef8551ec463887e600d4",
}


def test_font_files_are_the_vendored_bytes():
    folder = resources.files("sniff_test") / "assets" / "fonts"
    for name, sha in FILES.items():
        data = (folder / name).read_bytes()
        assert data[:4] == b"wOF2", name
        assert hashlib.sha256(data).hexdigest() == sha, name  # README.md's table
    assert (folder / "LICENSE-OFL.txt").read_text().startswith("Copyright")
    assert "SHA-256" in (folder / "README.md").read_text()


def test_css_references_only_the_served_files_and_no_cdn():
    assert ui.CSS.count("@font-face") == 2
    for name in FILES:
        assert f'url("__BASE__/fonts/{name}")' in ui.CSS
    assert "http" not in ui.CSS.lower()
    page = ui.page("t", "", base="/api/hassio_ingress/abc").decode()
    assert 'url("/api/hassio_ingress/abc/fonts/Geist-Variable.woff2")' in page
    assert 'rel="preload" href="/api/hassio_ingress/abc/fonts/Geist-Variable.woff2"' in page


def test_csp_grew_only_font_src_self():
    assert server._CSP == (
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
        "font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'self'"
    )
    assert server._font_bytes("Geist-Variable.woff2")[:4] == b"wOF2"
    assert server._font_bytes("../../etc/passwd") is None
    assert server._font_bytes("Other.woff2") is None
