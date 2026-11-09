"""Post-filters on Semgrep results (parsed with ast, never run)."""

from conftest import requires_semgrep

from sniff_test.analyzers import semgrep
from sniff_test.models import Category, Finding, Severity

SRC = """from homeassistant import config_entries
import homeassistant


async def flow(self, wrapper):
    config_entries = self.hass.config_entries.async_entries("x")
    a, *rest = config_entries
    x = homeassistant.helpers = wrapper
    setattr(homeassistant, "helpers", wrapper)
    homeassistant.core = wrapper
"""


def _f(line, file="cf.py", rule="ha-monkeypatch"):
    return Finding(rule, "t", Severity.HIGH, Category.TAMPER, "m", file=file, line=line)


def test_monkeypatch_on_a_rebound_local_name_is_dropped(tmp_path):
    (tmp_path / "cf.py").write_text(SRC)
    trees: dict = {}
    drop = semgrep._only_rebinds_names
    assert drop(_f(6), tmp_path, trees)  # Bambu Lab v2.3.0's shape
    assert drop(_f(7), tmp_path, trees)  # tuple / starred names
    assert not drop(_f(8), tmp_path, trees)  # chained: also patches homeassistant.helpers
    assert not drop(_f(9), tmp_path, trees)  # setattr is never dropped
    assert not drop(_f(10), tmp_path, trees)
    assert not drop(_f(6, rule="py-eval-exec"), tmp_path, trees)  # other rules untouched


def test_unparseable_files_keep_the_finding(tmp_path):
    (tmp_path / "bad.py").write_text("config_entries = (\n")
    assert not semgrep._only_rebinds_names(_f(1, "bad.py"), tmp_path, {})
    assert not semgrep._only_rebinds_names(_f(1, "missing.py"), tmp_path, {})


@requires_semgrep
def test_semgrep_still_matches_the_shape_we_filter(tmp_path):
    """If Semgrep stops resolving the shadowed import, this filter has nothing to do."""
    import json
    import subprocess

    (tmp_path / "cf.py").write_text(SRC)
    run = tmp_path / "run"
    run.mkdir()
    out = subprocess.run(
        ["semgrep", "scan", "--config", str(semgrep.rules_dir() / "python" / "tamper.yaml"),
         "--json", "--metrics=off", "--disable-version-check", str(tmp_path / "cf.py")],
        cwd=run, capture_output=True, text=True, check=False,
    )  # fmt: skip
    lines = sorted(r["start"]["line"] for r in json.loads(out.stdout)["results"])
    assert 6 in lines and 10 in lines
    # Semgrep 1.181 doesn't match chained `x = homeassistant.helpers = v`; py_tamper
    # (ast) covers it and the other missed forms (tests/test_py_tamper.py).
    assert 8 not in lines
