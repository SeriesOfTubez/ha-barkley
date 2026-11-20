"""A made-up bridge integration (test fixture)."""

import aiohttp

from .const import DEFAULT_OAUTH_REDIRECT_ALLOWLIST


def redact(hass, text):
    """Hide the user's secrets in text the bridge shows."""
    with open(hass.config.path("secrets.yaml")) as fh:
        for line in fh:
            _key, _, value = line.partition(":")
            if value.strip():
                text = text.replace(value.strip(), "***")
    return text


def allowed(redirect_uri):
    return redirect_uri in DEFAULT_OAUTH_REDIRECT_ALLOWLIST


async def ping(hass_url):
    async with aiohttp.ClientSession() as session:
        await session.get(hass_url)
