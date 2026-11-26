"""ha-monkeypatch forms Semgrep misses, found with ast (parsed, never run)."""

import ast
import textwrap

import pytest
import yaml
from conftest import requires_semgrep

from sniff_test.analyzers import py_tamper, semgrep
from sniff_test.models import Target, TargetKind

FORMS = """\
import homeassistant
import aiohttp
import ssl
from homeassistant import core
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client


def f(hass, w, v):
    homeassistant.a = w
    x = homeassistant.b = w
    homeassistant.c = y = w
    homeassistant.d, z = w, v
    homeassistant.e += w
    homeassistant.f2: int = w
    for homeassistant.g in [w]:
        pass
    with w as homeassistant.h:
        pass
    core.i = w
    a = core.j = w
    HomeAssistant.k = w
    b = HomeAssistant.l = w
    aiohttp.ClientSession.m = w
    c = aiohttp.ClientSession.n = w
    hass.auth.o = w
    d = hass.auth.p = w
    [homeassistant.q] = [w]
    ssl._create_default_https_context = w
    e = ssl._create_default_https_context = w
    aiohttp_client.async_get_clientsession = w
    setattr(core, "r", w)
    setattr(aiohttp_client, "s", w)
"""
PATCH_LINES = [10, 11, 12, 13, 14, 15, 16, 18, *range(20, 34)]


def _lines(src: str) -> list[int]:
    return sorted(line for line, _ in py_tamper.check_tree(ast.parse(textwrap.dedent(src))))


def test_every_patch_form_is_found():
    assert _lines(FORMS) == PATCH_LINES


def test_aliases_resolve_to_the_module():
    hits = dict(py_tamper.check_tree(ast.parse(FORMS)))
    assert hits[20] == "homeassistant.core"
    assert hits[31] == "homeassistant.helpers.aiohttp_client"


def test_a_local_that_shadows_the_import_is_not_the_module():
    src = """
    from homeassistant import config_entries, core

    async def flow(self, core):
        config_entries = self.hass.config_entries.async_entries("x")
        config_entries.extra = 1
        core.thing = 2
        x = config_entries.more = 3

    def g(items):
        for config_entries in items:
            config_entries.y = 1
        try:
            pass
        except Exception as core:
            core.z = 1
    """
    assert _lines(src) == []


def test_tricks_that_only_look_like_shadowing_are_still_found():
    src = """
    from homeassistant import core
    import homeassistant

    def comprehension(r, w):
        [0 for core in r]           # its own scope: core is still the module below
        core.a = w

    def declared_global(w):
        global core
        core = core
        core.b = w

    def later_inner_function(w):
        def inner(core):
            return core
        core.c = w

    def function_level_import(w):
        import homeassistant.helpers
        homeassistant.helpers.d = w

    def walrus_in_comprehension(r, w):
        [(core := 1) for _ in r]    # walrus binds in the function: this core is local
        core.e = w
    """
    assert _lines(src) == [7, 12, 17, 21]


def test_unrelated_attribute_stores_are_quiet():
    src = """
    import aiohttp
    from homeassistant.core import callback

    class C:
        def __init__(self, hass):
            self.hass = hass
            self.session = aiohttp.ClientSession()
            self._hass_data = {}
            hass.data["x"] = 1
            self.socket = None

    def f(entry, w):
        entry.runtime_data = w
        callback_fn = callback
        setattr(entry, "x", w)
        setattr(*w)
    """
    assert _lines(src) == []


def test_constants_match_the_semgrep_rule():
    rule = yaml.safe_load((semgrep.rules_dir() / "python" / "tamper.yaml").read_text())
    (mp,) = [r for r in rule["rules"] if r["id"] == py_tamper.RULE_ID]
    assert " ".join(mp["message"].split()) == py_tamper.MESSAGE
    assert mp["metadata"]["sniff"]["title"] == py_tamper.TITLE
    assert mp["metadata"]["sniff"]["severity"] == "high"
    regexes = [
        p["metavariable-regex"]["regex"]
        for alt in mp["pattern-either"]
        for p in alt.get("patterns", [])
        if "metavariable-regex" in p
    ]
    assert regexes == [py_tamper.OBJ_REGEX]


def test_find_skips_lines_already_flagged_and_unparseable_files(tmp_path):
    (tmp_path / "a.py").write_text(FORMS)
    (tmp_path / "bad.py").write_text("homeassistant.x = (\n")
    found = py_tamper.find(tmp_path, {("a.py", 10)}, {})
    assert sorted(f.line for f in found) == PATCH_LINES[1:]
    assert {f.file for f in found} == {"a.py"}
    f = next(f for f in found if f.line == 31)
    assert f.evidence == "aiohttp_client.async_get_clientsession = w"
    assert f.message.endswith("Patched object: homeassistant.helpers.aiohttp_client.")


@requires_semgrep
def test_semgrep_and_ast_together_flag_each_form_once(tmp_path):
    root = tmp_path / "custom_components" / "x"
    root.mkdir(parents=True)
    (root / "forms.py").write_text(FORMS)
    t = Target(source=str(root), kind=TargetKind.INTEGRATION, root=root, domain="x")
    work = tmp_path / "work"
    work.mkdir()
    res = semgrep.run(t, work)
    lines = sorted(f.line for f in res.findings if f.rule_id == "ha-monkeypatch")
    assert lines == PATCH_LINES


# (0.15, #32) A real integration forces IPv4 for one request and puts the original back.
PUT_BACK = """\
import socket
import urllib3.util.connection as conn


def ipv4_only():
    original = getattr(conn, "allowed_gai_family", None)
    try:
        conn.allowed_gai_family = lambda: socket.AF_INET
        yield
    finally:
        if original is not None:
            conn.allowed_gai_family = original
"""


def test_putting_the_original_back_is_not_a_second_patch():
    tree = ast.parse(PUT_BACK)
    assert sorted(line for line, _ in py_tamper.check_tree(tree)) == [8, 12]
    assert py_tamper.temporary(tree) == ({12}, {8})


def test_the_patch_that_is_put_back_says_so(tmp_path):
    (tmp_path / "a.py").write_text(PUT_BACK)
    found = py_tamper.find(tmp_path, set(), {})
    assert [f.line for f in found] == [8]
    assert found[0].message.endswith(py_tamper.PUT_BACK)
    assert "all of Home Assistant" in found[0].message


@pytest.mark.parametrize(
    "src",
    [
        # the saved name is bound twice: it may hold anything by then
        PUT_BACK.replace("        yield\n", "        yield\n        original = evil\n"),
        # another attribute is written with the saved original
        PUT_BACK.replace("conn.allowed_gai_family = original", "conn.create_connection = original"),
        # the restore comes before the save
        "import urllib3.util.connection as conn\n\ndef f(orig, w):\n"
        "    conn.x = orig\n    conn.x = w\n",
        # the object's first name is rebound in the function
        PUT_BACK.replace("    try:\n", "    conn = other\n    try:\n"),
    ],
)
def test_anything_short_of_a_clean_put_back_keeps_every_line(src):
    tree = ast.parse(src)
    restores, _undone = py_tamper.temporary(tree)
    assert restores == set()


def test_setattr_put_back_counts_too():
    src = (
        "import ssl\n\ndef f(w):\n"
        "    saved = ssl.SSLContext.wrap_socket\n"
        "    setattr(ssl.SSLContext, 'wrap_socket', w)\n"
        "    setattr(ssl.SSLContext, 'wrap_socket', saved)\n"
    )
    assert py_tamper.temporary(ast.parse(src)) == ({6}, {5})


@requires_semgrep
def test_semgrep_lines_follow_the_same_put_back_rule(tmp_path):
    root = tmp_path / "custom_components" / "x"
    root.mkdir(parents=True)
    (root / "net.py").write_text(
        "import socket\n\ndef f(w):\n"
        "    orig = socket.socket\n"
        "    socket.socket = w\n"
        "    try:\n        pass\n    finally:\n"
        "        socket.socket = orig\n"
    )
    t = Target(source=str(root), kind=TargetKind.INTEGRATION, root=root, domain="x")
    work = tmp_path / "work"
    work.mkdir()
    res = semgrep.run(t, work)
    hits = [f for f in res.findings if f.rule_id == "ha-monkeypatch"]
    assert [f.line for f in hits] == [5]
    assert hits[0].message.endswith(py_tamper.PUT_BACK)
