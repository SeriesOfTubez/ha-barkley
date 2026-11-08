import os
from pathlib import Path

DOMAIN = "mine"


def secrets(hass):
    # ruleid: ha-read-secrets
    p = hass.config.path("secrets.yaml")
    # ruleid: ha-read-secrets
    q = Path(hass.config.config_dir) / "secrets.yaml"
    return p, q


def auth_storage(hass):
    # ruleid: ha-read-auth-storage
    a = hass.config.path(".storage", "auth")
    # ruleid: ha-read-auth-storage
    b = open("/config/.storage/core.config_entries").read()
    return a, b


def raw_storage(hass):
    # ruleid: ha-raw-storage-access
    return hass.config.path(".storage", "some_other_thing")


async def auth_internals(hass, call):
    # ruleid: ha-auth-internals
    users = await hass.auth.async_get_users()
    # ruleid: ha-auth-internals
    token = await self.hass.auth.async_create_refresh_token(users[0])
    # ok: ha-auth-internals
    caller = await hass.auth.async_get_user(call.context.user_id)
    return token, caller


def foreign_entries(hass):
    for entry in hass.config_entries.async_entries():
        # ruleid: ha-foreign-entry-data
        print(entry.data)
    # ruleid: ha-foreign-entry-data
    leaked = [e.options for e in hass.config_entries.async_entries("mqtt")]
    for entry in hass.config_entries.async_entries(DOMAIN):
        # ok: ha-foreign-entry-data
        print(entry.data)
    # ok: ha-foreign-entry-data
    ids = [e.entry_id for e in hass.config_entries.async_entries()]
    return leaked, ids


def location(hass):
    # ruleid: ha-bulk-location-read
    a = hass.states.get("person.alice")
    # ruleid: ha-bulk-location-read
    b = hass.states.async_all("device_tracker")
    # ok: ha-bulk-location-read
    c = hass.states.get("sensor.temperature")
    return a, b, c


def supervisor():
    # ruleid: ha-supervisor-token
    t = os.environ["SUPERVISOR_TOKEN"]
    # ruleid: ha-supervisor-token
    u = os.getenv("HASSIO_TOKEN")
    # ok: ha-supervisor-token
    v = os.environ.get("TZ")
    return t, u, v
