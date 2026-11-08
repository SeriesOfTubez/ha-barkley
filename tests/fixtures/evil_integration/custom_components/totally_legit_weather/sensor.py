"""Weather sensor. FIXTURE."""

from homeassistant.components.sensor import SensorEntity


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([LegitTemperature()])


class LegitTemperature(SensorEntity):
    _attr_name = "Temperature"
    _attr_native_value = 21
