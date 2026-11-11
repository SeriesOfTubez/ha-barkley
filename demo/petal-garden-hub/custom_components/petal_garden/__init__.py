"""DEMO: Petal Garden Hub, a fake integration for Barkley screenshots. Never install.

Not malicious, just careless: an open HTTP endpoint, a shell command built from the
user's settings, plain-text MQTT, and an old JWT library.
"""

import logging
import subprocess

import paho.mqtt.client as mqtt
from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from jose import jwt

from .const import CLOUD_API, DOMAIN, MQTT_PORT

_LOGGER = logging.getLogger(__name__)


class GardenStatusView(HomeAssistantView):
    """Lets the Petal phone app read and water zones on the local network."""

    url = "/api/petal_garden/zones"
    name = "api:petal_garden:zones"
    requires_auth = False
    cors_allowed = True

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def get(self, request: web.Request) -> web.Response:
        return self.json(self.hass.data[DOMAIN]["zones"])

    async def post(self, request: web.Request) -> web.Response:
        body = await request.json()
        await self.hass.services.async_call("valve", "open_valve", {"entity_id": body["zone"]})
        return self.json({"ok": True})


def _hub_reachable(host: str) -> bool:
    return subprocess.call(f"ping -c 1 -W 2 {host}", shell=True) == 0


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    host = entry.data["hub_host"]
    if not await hass.async_add_executor_job(_hub_reachable, host):
        _LOGGER.warning("Petal hub %s is not answering", host)

    session = async_get_clientsession(hass)
    resp = await session.post(
        f"{CLOUD_API}/login",
        json={"email": entry.data["email"], "password": entry.data["password"]},
    )
    login = await resp.json()
    token = login["token"]
    claims = jwt.get_unverified_claims(token)

    client = mqtt.Client(client_id=claims["sub"])
    client.username_pw_set(entry.data["email"], token)
    client.connect(login["broker"], MQTT_PORT)
    client.loop_start()

    hass.data.setdefault(DOMAIN, {"zones": {}, "mqtt": client})
    hass.http.register_view(GardenStatusView(hass))
    return True
