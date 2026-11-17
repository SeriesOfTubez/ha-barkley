"""(0.14.0) Usage reporting: scored only when it's certainly automatic, ungated and
undisclosed. Synthetic integrations; every host is .invalid. Parse only."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from sniff_test.analyzers import telemetry
from sniff_test.models import Severity, Target, TargetKind
from sniff_test.scoring import score

SHADOW = {
    "__init__.py": """\
        from datetime import timedelta

        from homeassistant.helpers.event import async_track_time_interval

        from .report import send_usage

        STATS_URL = "https://stats.acme.invalid/v1/usage"


        async def async_setup_entry(hass, entry):
            await _report(hass)
            async_track_time_interval(hass, _tick, timedelta(hours=24))
            return True


        async def _report(hass):
            await send_usage(hass)


        async def _tick(now):
            pass
        """,
    "report.py": """\
        from homeassistant.helpers.aiohttp_client import async_get_clientsession


        async def send_usage(hass):
            session = async_get_clientsession(hass)
            await session.post("https://stats.acme.invalid/v1/usage", json={"installs": 1})
        """,
}


def _run(tmp_path: Path, files: dict[str, str], readme: str = ""):
    root = tmp_path / "custom_components" / "acme_power"
    root.mkdir(parents=True)
    (root / "manifest.json").write_text(json.dumps({"domain": "acme_power", "name": "Acme"}))
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(textwrap.dedent(text))
    if readme:
        (tmp_path / "README.md").write_text(readme)
    t = Target(source=str(tmp_path), kind=TargetKind.INTEGRATION, root=root, domain="acme_power",
               source_root=tmp_path)  # fmt: skip
    return telemetry.run(t)


def _rules(result) -> list[tuple[str, Severity]]:
    return [(f.rule_id, f.severity) for f in result.findings]


def test_automatic_ungated_undisclosed_usage_reporting_is_shadow_telemetry(tmp_path):
    r = _run(tmp_path, SHADOW)
    assert _rules(r) == [("telemetry-shadow", Severity.MEDIUM)]
    f = r.findings[0]
    assert f.file == "report.py" and "stats.acme.invalid" in f.message
    assert "async_setup_entry → _report → send_usage" in f.message
    assert score(r.findings, True).score < 100


def test_disclosed_in_the_readme_is_low(tmp_path):
    r = _run(
        tmp_path, SHADOW, readme="# Acme\nThis integration sends anonymous usage statistics.\n"
    )
    assert _rules(r) == [("telemetry-opt-out", Severity.LOW)]


def _gated(default: str, name: str = "CONF_SEND_STATS", key: str = "send_stats") -> dict[str, str]:
    files = dict(SHADOW)
    files["const.py"] = f'{name} = "{key}"\nDEFAULT_SEND = {default}\n'
    files["__init__.py"] = (
        SHADOW["__init__.py"]
        .replace(
            "from .report import send_usage\n",
            f"from .const import {name}, DEFAULT_SEND\n        from .report import send_usage\n",
        )
        .replace(
            "        async def async_setup_entry(hass, entry):\n            await _report(hass)",
            f"        async def async_setup_entry(hass, entry):\n"
            f"            if entry.options.get({name}, DEFAULT_SEND):\n"
            f"                await _report(hass)",
        )
    )
    return files


def test_an_option_that_is_on_by_default_is_opt_out(tmp_path):
    assert _rules(_run(tmp_path, _gated("True"))) == [("telemetry-opt-out", Severity.LOW)]


def test_an_option_that_is_off_by_default_is_a_note(tmp_path):
    r = _run(tmp_path, _gated("False"))
    assert _rules(r) == [("telemetry-usage", Severity.INFO)]
    assert "off by default" in r.findings[0].message
    assert score(r.findings, True).score == 100


def test_a_disable_option_is_read_the_other_way_round(tmp_path):
    files = _gated("False", "CONF_DISABLE_STATS", "disable_stats")
    assert _rules(_run(tmp_path, files)) == [("telemetry-opt-out", Severity.LOW)]


def test_a_user_action_is_a_note(tmp_path):
    files = {
        "__init__.py": """\
            import aiohttp


            async def async_setup(hass, config):
                hass.services.async_register("acme_power", "share", _share)
                return True


            async def _share(call):
                async with aiohttp.ClientSession() as s:
                    await s.post("https://acme.invalid/analytics/share", json={})
            """
    }
    r = _run(tmp_path, files)
    assert _rules(r) == [("telemetry-usage", Severity.INFO)]
    assert "when you use the app" in r.findings[0].message


def test_a_chain_through_another_objects_method_proves_nothing(tmp_path):
    files = {
        "__init__.py": """\
            async def async_setup_entry(hass, entry):
                await entry.runtime_data.client.report()
                return True
            """,
        "client.py": """\
            class Client:
                async def report(self):
                    await self._session.post("https://acme.invalid/telemetry")
            """,
    }
    r = _run(tmp_path, files)
    assert _rules(r) == [("telemetry-usage", Severity.INFO)]
    assert "couldn't tell when it runs" in r.findings[0].message


def test_an_ordinary_api_call_is_not_telemetry(tmp_path):
    files = {
        "__init__.py": """\
            async def async_setup_entry(hass, entry):
                await hass.data["s"].get("https://api.acme.invalid/v2/devices")
                await hass.data["s"].post("http://192.168.1.5/stats")
                return True
            """
    }
    assert _run(tmp_path, files).findings == []
