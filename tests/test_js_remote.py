"""(0.15, batch 2026-11-21) Code a card loads from a code CDN while it runs: found however
it is loaded (a loader of its own, an address put together while it runs, a Web Worker),
the version read as decided at run time (Exposure 5) or fixed (Exposure 2), and the text
read in time proportional to its size. Made-up package names; never fetched."""

import time

import pytest

from sniff_test import readings
from sniff_test.analyzers import js_remote
from sniff_test.models import Category, Finding, Severity


def loads(text):
    return [(x.pinned, x.address) for x in js_remote.read(text, "card.js")]


@pytest.mark.parametrize(
    ("text", "pinned"),
    [
        # a module of another package, no version: the newest each time
        ('import("https://unpkg.com/@acme/text-input/text-input.js?module")', False),
        # a generic loader: the address is a prefix, the version comes from the registry
        (
            'kc="https://cdn.jsdelivr.net/npm/acme-map-card@",Lc="/dist/b.js";zc(`${kc}${v}${Lc}`)',
            False,
        ),
        ('a="https://cdn.jsdelivr.net/npm/acme@" + latest + "/d.js"; latest = await ask();', False),
        ('a="https://cdn.jsdelivr.net/npm/acme@2/index.js"', False),  # a range
        ('a="https://cdn.jsdelivr.net/npm/acme@latest/index.js"', False),
        ('a="https://raw.githubusercontent.com/acme/card/main/x.js"', False),
        ("a=`https://esm.sh/${name}`", False),
        # one exact version, in the address or in a constant it uses
        ('const lit = await import("https://esm.sh/acme-lit@3.2.1")', True),
        ('const V = "4.7.1"; s.src = `https://unpkg.com/acme-gl@${V}/dist/acme-gl.js`;', True),
        ('DZ="6.7.0";kZ=`https://unpkg.com/acme-gl@${DZ}/dist/acme-gl-worker.mjs`', True),
        ('a="https://cdn.jsdelivr.net/npm/acme@" + V + "/d.js"; var V="1.2.3";', True),
        ('a="https://cdnjs.cloudflare.com/ajax/libs/acme/3.7.1/acme.min.js"', True),
        ('a="https://cdn.jsdelivr.net/gh/acme/card@v1.2.3/x.js"', True),
        ('a="https://esm.sh/v135/acme@10.19.2/es2022/acme.mjs"', True),
    ],
)
def test_code_addresses_and_their_versions(text, pinned):
    got = loads(text)
    assert len(got) == 1, got
    assert got[0][0] is pinned


@pytest.mark.parametrize(
    "text",
    [
        '<link rel="stylesheet" href="https://unpkg.com/acme/css/acme.min.css" />',
        'fetch("https://cdn.jsdelivr.net/npm/@acme/font@7.4.47/css/icons.min.css")',
        """t.replace(/x/g,'url("https://cdn.jsdelivr.net/npm/@acme/font@7.4.47/fonts/')""",
        'a="see https://unpkg.com/ for more"',
        'a="https://unpkg.com/"',
        'a="https://unpkg.com/acme@1.0.0/logo.png"',
        'a="https://cdn.acme.invalid/x.js"',  # not a code CDN: the Semgrep rule's case
    ],
)
def test_other_addresses_are_not_code_loads(text):
    assert loads(text) == []


def test_files_of_one_package_are_one_load():
    text = "\n".join([
        'a="https://unpkg.com/acme-html@1/directives/unsafe-svg.js?module"',
        'b="https://unpkg.com/acme-html@1/directives/if-defined?module"',
        'c="https://unpkg.com/@acme/utils@3.8.4/lib/index.js?module"',
    ])  # fmt: skip
    got = js_remote.merge([], js_remote.read(text, "card.js"))
    assert [(f.rule_id, f.line) for f in got] == [
        ("card-remote-script", 1),
        ("card-remote-pinned", 3),
    ]


def _semgrep(line, evidence):
    return Finding("card-remote-script", "t", Severity.MEDIUM, Category.CODE_EXEC, "m",
                   file="card.js", line=line, evidence=evidence)  # fmt: skip


def test_a_semgrep_match_takes_the_version_reading_of_its_address():
    text = 'x;\nconst lit = await import("https://esm.sh/acme-lit@3.2.1");'
    sem = _semgrep(2, 'const lit = await import("https://esm.sh/acme-lit@3.2.1");')
    got = js_remote.merge([sem], js_remote.read(text, "card.js"))
    assert [(f.rule_id, f.severity) for f in got] == [("card-remote-pinned", Severity.LOW)]
    other = _semgrep(5, 'import("https://cdn.acme.invalid/mod.js")')  # no CDN address there
    assert js_remote.merge([other], []) == [other]


def test_the_exposure_reading():
    def rd(*rules):
        fs = [{"rule_id": r, "severity": "medium", "file": "c.js"} for r in rules]
        return readings.compute({"findings": fs, "complete": True})

    assert rd("card-remote-script").exposure == 5.0
    assert rd("card-remote-script").exposure_level == "high"
    assert rd("card-remote-pinned").exposure == 2.0
    assert rd("card-remote-pinned").exposure_level == "medium"
    assert rd("card-remote-script", "card-remote-pinned").exposure == 5.5
    assert any(x.startswith("It loads unpinned code from another site while it runs. Which "
                            "version runs is decided when it loads.")
               for x in rd("card-remote-script").exposure_reasons)  # fmt: skip
    # the network setting doesn't raise it: who can reach HA doesn't change who publishes
    shared = readings.compute({"findings": [{"rule_id": "card-remote-script"}]}, "shared")
    assert shared.exposure == 5.0


def test_decoys_never_hide_a_load():
    decoys = 'a="https://unpkg.com/acme@1.0.0/x.js";' * (js_remote._MAX_HITS + 10)
    got = js_remote.read(decoys + 'b="https://unpkg.com/evil/x.js"', "card.js")
    assert any(not x.pinned for x in got)


@pytest.mark.parametrize(
    "text",
    [
        '"https://unpkg.com/' * 200_000,
        ('"https://unpkg.com/a@1.0.0/' + "b" * 1900 + '.js";') * 6000,
        "`https://unpkg.com/a@${" * 100_000,
        '"https://cdn.jsdelivr.net/npm/a@" + ' * 100_000,
        "//esm.sh/" * 300_000,
        '"https://unpkg.com/a@' + "\\" * 400_000,
        "\n".join(f"`https://unpkg.com/a@${{V{i}}}/x.js`" for i in range(50_000)),
        "x" * 3_000_000 + '"https://unpkg.com/a/x.js"',
    ],
)
def test_hostile_text_is_read_in_time_proportional_to_its_size(text):
    start = time.monotonic()
    js_remote.read(text, "card.js")
    assert time.monotonic() - start < 5


def test_an_address_in_a_comment_is_not_loaded():
    """(full Marketplace run 2026-11-22) A real card kept a debugging console's loader
    inside `/* ... */`."""
    text = """
    /*
    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/acme-console';
    */
    // import("https://unpkg.com/acme-old/x.js")
    const r = /["']/g; // a regex with quotes doesn't start a string
    s.src = 'https://cdn.jsdelivr.net/npm/acme-live';
    t = `${"https://esm.sh/acme-inner@1.2.3"}`;
    """
    assert [a for _p, a in loads(text)] == [
        "https://cdn.jsdelivr.net/npm/acme-live",
        "https://esm.sh/acme-inner@1.2.3",
    ]
