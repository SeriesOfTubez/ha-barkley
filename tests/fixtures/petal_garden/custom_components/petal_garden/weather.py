"""Rain forecast for skipping a watering run."""

from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import WEATHER_HOSTS


async def rain_due(hass) -> bool:
    session = async_get_clientsession(hass)
    params = {"lat": hass.config.latitude, "lon": hass.config.longitude}
    for url in WEATHER_HOSTS:
        resp = await session.get(url, params=params)
        if resp.status == 200:
            return (await resp.json()).get("rain_mm", 0) > 1
    return False
