"""Setup and options for Petal Garden."""

import voluptuous as vol
from homeassistant import config_entries

from .const import (
    CONF_HUB_HOST,
    CONF_HUB_PASSWORD,
    CONF_SHARE_USAGE,
    CONF_SKIP_RAIN,
    DOMAIN,
    SUPPORT_URL,
)


class PetalFlow(config_entries.ConfigFlow, domain=DOMAIN):
    async def async_step_user(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="Petal Garden", data=user_input)
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required("email"): str,
                    vol.Required("password"): str,
                    vol.Required(CONF_HUB_HOST): str,
                    vol.Required(CONF_HUB_PASSWORD): str,
                }
            ),
            description_placeholders={"support": SUPPORT_URL},
        )

    @staticmethod
    def async_get_options_flow(entry):
        return PetalOptions()


class PetalOptions(config_entries.OptionsFlow):
    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_SKIP_RAIN, default=False): bool,
                    vol.Optional(CONF_SHARE_USAGE, default=False): bool,
                }
            ),
        )
