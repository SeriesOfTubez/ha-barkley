"""The zone list for the Petal phone app, on the local network only."""

from homeassistant.components.http import HomeAssistantView
from homeassistant.helpers.network import is_local

from .const import DOMAIN


class ZonesView(HomeAssistantView):
    url = "/api/petal_garden/zones"
    name = "api:petal_garden:zones"
    requires_auth = False

    async def get(self, request):
        hass = request.app["hass"]
        if not is_local(request.remote):
            return self.json_message("Not on the local network", 403)
        if request.headers.get("X-Petal-Token") != hass.data[DOMAIN]["hub_token"]:
            return self.json_message("Wrong token", 401)
        return self.json(hass.data[DOMAIN]["zones"])
