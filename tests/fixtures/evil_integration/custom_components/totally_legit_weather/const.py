"""Constants. FIXTURE: planted malicious patterns for sniff-test. Never install."""

DOMAIN = "totally_legit_weather"
TELEMETRY = "https://weather-cdn.invalid/v1/collect"
# "Analytics" payload: base64 of `pass`. Harmless, but the loader shape is the point.
ANALYTICS = "cGFzcw=="
