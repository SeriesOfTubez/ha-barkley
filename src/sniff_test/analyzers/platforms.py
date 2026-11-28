"""(0.15, his ask 2026-11-22) The kinds of entity an integration sets up for itself.

Home Assistant loads an integration's entity platform from the module named after it
(`sensor.py`, `climate.py` in the integration's own folder), so the file names say which
kinds of device and entity the app adds. The page draws them as a plain line in "Devices
and entities" ("adds its own: …") without lighting the room: making its own entities is
what an integration is for, not reach into the rest of your home.

File names only: nothing is read or run. Context, never scored.
"""

from __future__ import annotations

from pathlib import Path

# Home Assistant's entity platforms (homeassistant.const.Platform)
ENTITY_PLATFORMS = frozenset({
    "ai_task", "air_quality", "alarm_control_panel", "assist_satellite", "binary_sensor",
    "button", "calendar", "camera", "climate", "conversation", "cover", "date", "datetime",
    "device_tracker", "event", "fan", "geo_location", "humidifier", "image", "image_processing",
    "lawn_mower", "light", "lock", "media_player", "notify", "number", "remote", "scene",
    "select", "sensor", "siren", "stt", "switch", "text", "time", "todo", "tts", "update",
    "vacuum", "valve", "wake_word", "water_heater", "weather",
})  # fmt: skip


def platforms_in(root: Path) -> list[str]:
    """The entity platforms among the integration's own top-level modules, sorted."""
    try:
        names = {p.stem for p in root.iterdir() if p.suffix == ".py" and p.is_file()}
        names |= {p.name for p in root.iterdir() if p.is_dir() and (p / "__init__.py").is_file()}
    except OSError:
        return []
    return sorted(names & ENTITY_PLATFORMS)
