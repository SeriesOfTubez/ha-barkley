"""Anonymous usage statistics: the version and the number of zones, once a day."""

from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import STATS_URL

VERSION = "1.4.0"


async def send_usage(hass, zones: int) -> None:
    session = async_get_clientsession(hass)
    await session.post(STATS_URL, json={"version": VERSION, "zones": zones})
