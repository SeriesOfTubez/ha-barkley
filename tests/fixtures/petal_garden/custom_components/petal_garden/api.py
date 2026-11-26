"""The Petal Garden cloud and the hub on the local network."""

from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import API_BASE, CLIENT_ID


class PetalCloud:
    def __init__(self, hass, email, password):
        self._session = async_get_clientsession(hass)
        self._email = email
        self._password = password

    async def zones(self):
        resp = await self._session.post(
            f"{API_BASE}/login",
            json={"email": self._email, "password": self._password, "client": CLIENT_ID},
        )
        token = (await resp.json())["token"]
        resp = await self._session.get(
            f"{API_BASE}/zones", headers={"Authorization": f"Bearer {token}"}
        )
        return await resp.json()

    async def water(self, token, zone, minutes):
        await self._session.post(
            f"{API_BASE}/zones/{zone}/water",
            json={"minutes": minutes},
            headers={"Authorization": f"Bearer {token}"},
        )


class PetalHub:
    """The hub only speaks plain HTTP; the password is the hub's own."""

    def __init__(self, hass, host, password):
        self._session = async_get_clientsession(hass)
        self._base = f"http://{host}"
        self._password = password

    async def status(self):
        resp = await self._session.get(
            f"{self._base}/status", headers={"X-Hub-Password": self._password}
        )
        return await resp.json()
