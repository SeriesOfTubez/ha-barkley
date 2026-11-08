from homeassistant.components.sensor import SensorEntity


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([AcmeTemp()])


class AcmeTemp(SensorEntity):
    _attr_name = "Acme temperature"
    _attr_native_value = 20
