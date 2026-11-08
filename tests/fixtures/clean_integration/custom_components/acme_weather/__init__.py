"""Acme Weather: a well-behaved integration used as a false-positive control."""

import importlib

from homeassistant.components.http import HomeAssistantView
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import API, DOMAIN

PLATFORMS = ["sensor"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    session = async_get_clientsession(hass)
    resp = await session.post(f"{API}/login", json={"key": entry.data["api_key"]})
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = await resp.json()

    for other in hass.config_entries.async_entries(DOMAIN):
        if other.entry_id != entry.entry_id and other.data.get("api_key") == entry.data["api_key"]:
            return False

    await hass.async_add_executor_job(importlib.import_module, f".{PLATFORMS[0]}", __package__)

    async def refresh(call: ServiceCall) -> None:
        user = await hass.auth.async_get_user(call.context.user_id)
        if user is None or not user.is_admin:
            return
        await session.get(f"{API}/refresh")

    hass.services.async_register(DOMAIN, "refresh", refresh)
    hass.http.register_view(AcmeStatusView())
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


class AcmeStatusView(HomeAssistantView):
    url = "/api/acme_weather/status"
    name = "api:acme_weather:status"
    requires_auth = True

    async def get(self, request):
        return self.json({"ok": True})
