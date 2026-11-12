"""The panel's design tokens (vault: UI Design Guidelines, Sniff Test — Design Decisions
"The panel against the UI Design Guidelines", decided 2026-11-12): four text sizes 12 / 13 /
15 / 20 px plus 24 for the score ring, nothing under 12; spacing on the 4/8 scale; four
radii 4 / 6 / 8 / 12. This fails on any size or gap off the scale, in the stylesheet or in
an inline style, so the next "a bit smaller" never creeps back in."""

from __future__ import annotations

import re
from pathlib import Path

from sniff_test import server, ui

SRC = Path(server.__file__).parent
TEXT_PX = {12, 13, 15, 20, 24}
SPACE_PX = {0, 4, 8, 12, 16, 24, 32, 48}
RADIUS_PX = {0, 4, 6, 8, 12}
_VAR = re.compile(r"--([\w-]+):\s*([^;{}]+);")
_DECL = re.compile(r"([\w-]+)\s*:\s*([^;{}]+)")
_LEN = re.compile(r"(-?\d*\.?\d+)(px|rem|em|%|ch|vw|vh)?")


def tokens() -> dict[str, str]:
    root = ui.CSS.split("}", 1)[0]  # the :root block (light); dark only recolours
    light = ui.CSS[: ui.CSS.index("@media (prefers-color-scheme: dark)")]
    return dict(_VAR.findall(light)) | dict(_VAR.findall(root))


def resolve(value: str, toks: dict[str, str]) -> str:
    """Replace var(--x) with the token's value (one level is enough here)."""
    return re.sub(r"var\(--([\w-]+)\)", lambda m: toks.get(m[1], m[0]), value)


def declarations(css: str):
    body = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    for block in body.split("}"):
        if "{" not in block:
            continue
        selector, decls = block.rsplit("{", 1)
        if selector.strip().startswith((":root", "@font-face")):
            continue  # tokens and the font files themselves
        for prop, val in _DECL.findall(decls):
            yield selector.strip(), prop.strip(), val.strip()


def px_values(value: str) -> list[float]:
    out = []
    for num, unit in _LEN.findall(value):
        if unit == "px":
            out.append(float(num))
        elif unit in ("rem", "em") and float(num) != 0:
            raise AssertionError(f"{value!r}: sizes are px tokens, not {unit}")
    return out


def test_text_sizes_are_the_four_tokens_plus_the_ring():
    toks = tokens()
    seen = set()
    for sel, prop, val in declarations(ui.CSS):
        if prop in ("font-size", "font"):
            v = resolve(val, toks)
            sizes = [p for p in px_values(v) if prop == "font-size" or p >= 10]
            if prop == "font":  # shorthand: the size is the first px length ≥ 10 (not weight)
                sizes = sizes[:1]
            for px in sizes:
                assert px in TEXT_PX, f"{sel} {{ {prop}: {val} }} → {px}px is off the scale"
                seen.add(px)
    assert seen >= {12, 13, 15, 20, 24}


def test_inline_styles_and_svg_never_go_under_12px():
    for name in ("ui.py", "server.py"):
        text = (SRC / name).read_text()
        for m in re.finditer(r"font-size:\s*([\d.]+)px", text):
            assert float(m[1]) >= 12, f"{name}: inline font-size {m[0]}"
        assert "font-size:{" not in text, f"{name}: a computed inline font size"
        for m in re.finditer(r'style="([^"]*)"', text):
            for prop, val in _DECL.findall(m[1]):
                if prop in ("margin", "margin-top", "padding", "gap"):
                    for px in px_values(val):
                        assert px in SPACE_PX, f"{name}: inline {prop}:{val}"


def test_spacing_is_on_the_4_8_scale():
    toks = tokens()
    props = ("padding", "margin", "gap", "padding-top", "padding-left", "padding-right",
             "padding-bottom", "margin-top", "margin-bottom", "margin-left", "margin-right",
             "row-gap", "column-gap")  # fmt: skip
    for sel, prop, val in declarations(ui.CSS):
        if prop in props:
            v = resolve(val, toks)
            if "auto" in v or ("em" in v and "px" not in v):
                continue
            for px in px_values(v):
                assert px in SPACE_PX, f"{sel} {{ {prop}: {val} }} → {px}px is off the scale"


def test_radii_are_the_four_tokens():
    toks = tokens()
    for sel, prop, val in declarations(ui.CSS):
        if prop == "border-radius":
            for px in px_values(resolve(val, toks)):
                assert px in RADIUS_PX, f"{sel} {{ border-radius: {val} }} → {px}px"
    for name in ("ui.py", "server.py"):
        text = (SRC / name).read_text()
        if "_ICONS = {" in text:  # icon paths live in a 24-unit box; not UI radii
            a = text.index("_ICONS = {")
            text = text[:a] + text[text.index("\n}\n", a) :]
        for m in re.finditer(r' rx="(\d+)"', text):
            assert int(m[1]) in RADIUS_PX, f"{name}: svg rx={m[1]}"


def test_borders_are_one_pixel_except_the_two_accents():
    toks = tokens()
    for sel, prop, val in declarations(ui.CSS):
        if prop.startswith("border") and "radius" not in prop and "color" not in prop:
            for px in px_values(resolve(val, toks)):
                ok = px <= 1 or (px == 2 and ("a.sum" in sel or ".ai" in sel or ".aibox" in sel))
                ok = ok or (px == 3 and ".sheet" in sel)
                assert ok, f"{sel} {{ {prop}: {val} }}"
