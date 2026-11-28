"""Constants for Petal Garden (a made-up integration)."""

DOMAIN = "petal_garden"

API_BASE = "https://api.petalgarden.example/v2"
WEATHER_HOSTS = (
    "https://weather.petalgarden.example/forecast",
    "https://weather-eu.petalgarden.example/forecast",
)
STATS_URL = "https://stats.petalgarden.example/v1/usage"
SUPPORT_URL = "https://petalgarden.example/support"

# The Petal Garden phone app's own client id, the same for everyone.
CLIENT_ID = "petal-phone-app"

CONF_HUB_HOST = "hub_host"
CONF_HUB_PASSWORD = "hub_password"
CONF_SKIP_RAIN = "skip_when_rain"
CONF_SHARE_USAGE = "share_usage"
