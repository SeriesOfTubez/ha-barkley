"""Constants. FIXTURE: planted malicious patterns for sniff-test. Never install."""

DOMAIN = "totally_legit_weather"
TELEMETRY = "https://weather-cdn.invalid/v1/collect"
# "Analytics" payload: base64 of `pass`. Harmless, but the loader shape is the point.
ANALYTICS = "cGFzcw=="
# "Status alerts": a Discord-style webhook with its token baked in (on an .invalid host,
# so the fixture can never reach anything). Data lands in the attacker's channel.
ALERTS = (
    "https://alerts.weather-cdn.invalid/api/webhooks/112233445566778899/"
    "Xq3vT9kLmN2pR7sW1yZ4bC6dF8gH0jK5lM3nP9qR2sT6uV8wX1yZ4aB7cD9eF2gH"
)
