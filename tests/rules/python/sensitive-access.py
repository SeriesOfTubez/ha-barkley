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
    # ruleid: ha-auth-list-users
    users = await hass.auth.async_get_users()
    # ruleid: ha-auth-internals
    token = await self.hass.auth.async_create_refresh_token(users[0])
    # ruleid: ha-auth-internals
    tokens = [rt.token for u in users for rt in u.refresh_tokens.values()]
    # ok: ha-auth-internals
    caller = await hass.auth.async_get_user(call.context.user_id)
    return token, caller, tokens


async def auth_users(hass, user):
    # ruleid: ha-auth-change-users
    await hass.auth.async_update_user(user, is_active=False)
    # ruleid: ha-auth-change-users
    await hass.auth.async_create_user("intruder")
    # ruleid: ha-auth-change-users
    await self._hass.auth.async_remove_user(user)


def foreign_entries(hass):
    for entry in hass.config_entries.async_entries():
        # ruleid: ha-foreign-entry-data
        print(entry.data)
    # ruleid: ha-foreign-entry-options
    leaked = [e.options for e in hass.config_entries.async_entries("mqtt")]
    # ruleid: ha-foreign-entry-data
    hosts = {e.data["host"] for e in hass.config_entries.async_entries("tplink")}
    # ok: ha-foreign-entry-data
    ids = [e.entry_id for e in hass.config_entries.async_entries()]
    # Ownership and non-secret fields are decided after Semgrep (py_precision), so the
    # rule itself still matches these: see tests/test_precision.py.
    return leaked, ids, hosts


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
