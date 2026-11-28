import base64
import importlib
import os
import subprocess
import sys
import zlib

BLOB = "cGFzcw=="


def loader():
    code = base64.b64decode(BLOB)
    # ruleid: py-b64-exec, py-eval-exec
    exec(code)


def loader2():
    # ruleid: py-b64-exec, py-eval-exec
    exec(zlib.decompress(base64.b64decode(BLOB)))


def dyn(name, user_code):
    # ruleid: py-eval-exec
    eval(user_code)
    # ok: py-eval-exec
    eval("1 + 1")
    # ruleid: py-dynamic-import
    mod = importlib.import_module(name)
    # ok: py-dynamic-import
    plat = importlib.import_module(f".{name}", __name__)
    # ok: py-dynamic-import
    json = importlib.import_module("json")
    return mod, plat, json


def pip_install():
    # ruleid: py-runtime-pip
    subprocess.check_call([sys.executable, "-m", "pip", "install", "evil-pkg"])
    # ruleid: py-runtime-pip, py-shell-exec
    os.system("pip install evil-pkg")


async def ha_pip(hass):
    from homeassistant.util.package import install_package

    # ruleid: py-runtime-pip
    install_package("evil-pkg==1.0")


def shell(cmd):
    # ruleid: py-shell-exec
    subprocess.run(cmd, shell=True)
    # ok: py-shell-exec
    subprocess.run(["ping", "-c", "1", "192.168.1.1"])
    # ruleid: py-shell-exec
    os.execvp("sh", ["sh"])
    # ok: py-shell-exec
    os.path.join("a", "b")


def obfuscated(xs, data):
    # ruleid: py-obfuscation
    s = "".join(chr(c) for c in [101, 118, 97, 108])
    # ruleid: py-obfuscation
    s = "".join(map(chr, (101, 118, 97, 108)))
    # ruleid: py-obfuscation
    s = "".join(chr(c ^ 7) for c in [98, 113, 102, 107])
    # ok: py-obfuscation
    name = name.strip("".join(chr(value) for value in range(33)))
    # ok: py-obfuscation
    text = "".join(chr(b) for b in data)
    # ok: py-obfuscation
    text = "".join(map(chr, xs))
    # (0.15) bytes read from a device, not numbers written in the code
    # ok: py-obfuscation
    ascii_chars = "".join([chr(byte) for byte in [byte1, byte2]])
    # ok: py-obfuscation
    ascii_chars = "".join(chr(byte) for byte in [byte1, byte2])
    # ruleid: py-obfuscation
    s = "".join(chr(c) for c in [0x65, 0x76, 0x61, 0x6C])
    # ok: py-obfuscation
    f = getattr(__builtins__, s)
    return f


def builtins_lookup(builtins, node, part):
    # ok: py-obfuscation
    value = getattr(builtins, node.id)
    # ruleid: py-obfuscation
    run = getattr(builtins, "ev" + "al")
    # ruleid: py-obfuscation
    run = getattr(builtins, f"ex{part}")
    # ruleid: py-obfuscation
    run = getattr(builtins, "".join(["ex", "ec"]))
    # ruleid: py-obfuscation
    run = getattr(builtins, "lave"[::-1])
    # ruleid: py-obfuscation
    run = getattr(__builtins__, "exec")
    name = "ev" + "al"
    # ruleid: py-obfuscation
    run = getattr(builtins, name)
    return value, run


def own_package(module):
    from importlib import import_module

    # ok: py-dynamic-import
    return import_module(f"{__package__}.{module}")


# (M6) Text that mentions pip install can't run it (seen in two real integrations).
def needs_paho():
    # ok: py-runtime-pip
    raise RuntimeError("paho-mqtt required: pip install paho-mqtt>=1.6.0")


def no_pyserial(_LOGGER):
    # ok: py-runtime-pip
    _LOGGER.warning("pyserial not installed. Install with: pip install pyserial")
    # ok: py-runtime-pip
    print("run: pip install foo")


# ...but a command string handed to a wrapper, a shell, or run inside a raise still is.
def installs(self, run_cmd):
    # ruleid: py-runtime-pip
    self._run("pip install evil-pkg")
    # ruleid: py-runtime-pip
    subprocess.run(["sh", "-c", "pip install evil-pkg"])
    # ruleid: py-runtime-pip
    raise RuntimeError(run_cmd("pip install evil-pkg"))


def own_file_fallback():
    import importlib.util
    import os
    from pathlib import Path

    try:
        from . import const
    except ImportError:
        # ok: py-dynamic-import
        spec = importlib.util.spec_from_file_location("_c", Path(__file__).with_name("const.py"))
        const = importlib.util.module_from_spec(spec)
        # ok: py-dynamic-import
        spec.loader.exec_module(const)
    # ok: py-dynamic-import
    s2 = importlib.util.spec_from_file_location("_d", Path(__file__).parent / "data.py")
    # ok: py-dynamic-import
    s3 = importlib.util.spec_from_file_location("_e", os.path.join(os.path.dirname(__file__), "x.py"))
    return const, s2, s3


def loads_what_it_is_told(path, name):
    import importlib.util

    # ruleid: py-dynamic-import
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    # ruleid: py-dynamic-import
    spec.loader.exec_module(mod)
    return mod
