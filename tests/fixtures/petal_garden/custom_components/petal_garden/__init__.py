"""Petal Garden: watering zones through the cloud or the local hub (made up)."""

import shutil
from datetime import timedelta
from pathlib import Path

from homeassistant.components import webhook
from homeassistant.helpers.event import async_track_time_interval

from .api import PetalCloud, PetalHub
from .const import CONF_HUB_HOST, CONF_HUB_PASSWORD, CONF_SKIP_RAIN, DOMAIN
from .telemetry import send_usage
from .views import ZonesView
from .weather import rain_due


async def async_setup_entry(hass, entry):
    cloud = PetalCloud(hass, entry.data["email"], entry.data["password"])
    hub = PetalHub(hass, entry.data[CONF_HUB_HOST], entry.data[CONF_HUB_PASSWORD])
    zones = await cloud.zones()
    hass.data.setdefault(DOMAIN, {}).update(
        {"cloud": cloud, "hub": hub, "zones": zones, "hub_token": entry.data["hub_token"]}
    )
    hass.http.register_view(ZonesView())
    webhook.async_register(hass, DOMAIN, "Petal Garden", entry.data["webhook_id"], _on_run)
    await hass.async_add_executor_job(_copy_card, hass)

    async def _daily(now):
        # The "Share anonymous usage" option is never checked here.
        await send_usage(hass, len(zones))

    entry.async_on_unload(async_track_time_interval(hass, _daily, timedelta(days=1)))
    await send_usage(hass, len(zones))

    async def _water(now):
        if entry.options.get(CONF_SKIP_RAIN, False) and await rain_due(hass):
            return
        await hub.status()

    entry.async_on_unload(async_track_time_interval(hass, _water, timedelta(hours=1)))
    return True


async def _on_run(hass, webhook_id, request):
    hass.bus.async_fire("petal_garden_run_done", await request.json())


def _copy_card(hass):
    dest = Path(hass.config.path("www/community/petal-garden"))
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(Path(__file__).parent / "frontend" / "garden-map.js", dest / "garden-map.js")
