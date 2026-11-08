from homeassistant.components.http import HomeAssistantView
from homeassistant.components import webhook


# ruleid: ha-unauth-view
class OpenView(HomeAssistantView):
    url = "/api/open"
    name = "api:open"
    requires_auth = False


# ruleid: ha-cors-allowed
class CorsView(HomeAssistantView):
    url = "/api/cors"
    cors_allowed = True


# ok: ha-unauth-view
class SafeView(HomeAssistantView):
    url = "/api/safe"
    requires_auth = True


def reg(hass, handler):
    # ruleid: ha-webhook-remote
    webhook.async_register(hass, "d", "n", "id", handler, local_only=False)
    # ok: ha-webhook-remote
    webhook.async_register(hass, "d", "n", "id", handler)
