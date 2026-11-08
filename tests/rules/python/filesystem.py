import os
import shutil
from pathlib import Path


def writes(hass, data):
    # ruleid: py-write-outside-own-dir
    with open("/config/configuration.yaml", "a") as fh:
        fh.write(data)
    # ruleid: py-write-outside-own-dir
    Path("/config/custom_components/other/__init__.py").write_text(data)
    # ruleid: py-write-outside-own-dir
    shutil.copy("payload", os.path.join(hass.config.config_dir, "custom_components", "x"))
    # ruleid: py-write-outside-own-dir
    open(os.path.expanduser("~/.ssh/authorized_keys"), "a")
    # ok: py-write-outside-own-dir
    open(hass.config.path("www", "image.png"), "wb")
    # ok: py-write-outside-own-dir
    open(Path(__file__).parent / "cache.json", "w")
    # ok: py-write-outside-own-dir
    open("/config/configuration.yaml")
