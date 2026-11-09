# Inventory rule tests: neutral facts, not findings.
import asyncio
import os
import socket
import subprocess

import aiohttp
import requests
from homeassistant.components import websocket_api
from homeassistant.components.frontend import add_extra_js_url, async_register_built_in_panel
from homeassistant.components.mqtt import async_publish
from homeassistant.components.recorder import get_instance
from homeassistant.components.webhook import async_register
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import async_track_state_change_event

DOMAIN = "acme"


async def setup(hass, entry, platform):
    # ruleid: inv-service-register
    hass.services.async_register(DOMAIN, "refresh", handler)
    # ruleid: inv-entity-service
    platform.async_register_entity_service("boost", {}, "async_boost")
    # ruleid: inv-service-call
    await hass.services.async_call("light", "turn_on", {})
    # ruleid: inv-http-view
    hass.http.register_view(AcmeView())
    # ruleid: inv-static-path
    await hass.http.async_register_static_paths([])
    # ruleid: inv-frontend-js
    add_extra_js_url(hass, "/acme/card.js")
    # ruleid: inv-panel
    async_register_built_in_panel(hass, "iframe", "Acme")
    # ruleid: inv-ws-command
    websocket_api.async_register_command(hass, ws_get)
    # ruleid: inv-webhook
    async_register(hass, DOMAIN, "Acme", "hook-id", handle_webhook)
    # ruleid: inv-event-listen
    hass.bus.async_listen("state_changed", on_event)
    # ruleid: inv-event-fire
    hass.bus.async_fire("acme_event", {})
    # ruleid: inv-state-track
    async_track_state_change_event(hass, ["sensor.x"], on_event)
    # ruleid: inv-state-read
    hass.states.get("sensor.x")
    # ruleid: inv-state-read
    hass.states.async_all("light")
    # ruleid: inv-state-read-all
    hass.states.async_all()
    # ruleid: inv-entity-registry
    er.async_get(hass)
    # ruleid: inv-device-registry
    dr.async_get(hass)
    # ruleid: inv-recorder
    get_instance(hass)
    # ruleid: inv-config-entries-all
    hass.config_entries.async_entries()
    # ok: inv-config-entries-all
    hass.config_entries.async_entries(DOMAIN)
    # ruleid: inv-user-lookup
    await hass.auth.async_get_user("abc")
    # ruleid: inv-env-read
    os.getenv("HOME")
    # ruleid: inv-http-client
    session = async_get_clientsession(hass)
    # ruleid: inv-http-client
    requests.get("https://api.acme.example")
    # ruleid: inv-http-client
    aiohttp.ClientSession()
    # ruleid: inv-socket
    socket.socket()
    # ruleid: inv-socket
    await asyncio.open_connection("10.0.0.2", 80)
    # ruleid: inv-websocket-client
    await session.ws_connect("wss://api.acme.example")
    # ruleid: inv-mqtt-publish
    await async_publish(hass, "acme/x", "1")
    # ruleid: inv-subprocess
    subprocess.run(["ls"])
