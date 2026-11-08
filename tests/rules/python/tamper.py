import socket
import ssl

import aiohttp


def patch(hass, wrapper):
    # ruleid: ha-monkeypatch
    socket.socket = wrapper
    # ruleid: ha-monkeypatch
    ssl._create_default_https_context = ssl._create_unverified_context
    # ruleid: ha-monkeypatch
    aiohttp.ClientSession._request = wrapper
    # ruleid: ha-monkeypatch
    hass.auth.async_validate_access_token = wrapper
    # ok: ha-monkeypatch
    hass.data["mine"] = wrapper
    # ok: ha-monkeypatch
    self.session = wrapper
