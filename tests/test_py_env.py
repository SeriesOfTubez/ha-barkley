"""(0.15) Environment variables read and set, by name (analyzers/py_env.py)."""

from sniff_test.analyzers import py_env

CODE = """\
import os
import os as _os
from os import environ as env, getenv

from .const import ENV_KEY

LOCAL = "ACME_LOCAL"


def setup(hass, name):
    tz = os.environ["TZ"]
    token = os.environ.get("SUPERVISOR_TOKEN")
    debug = getenv(ENV_KEY, "0")
    if "ACME_MODE" in env:
        pass
    other = _os.getenv(name)
    os.environ[LOCAL] = "1"
    again = os.environ.get(LOCAL)
    os.environ.setdefault("ACME_HOME", "/config")
    os.environ.update({"ACME_A": "1"}, ACME_B="2")
    del os.environ["ACME_OLD"]
    os.putenv(name, "x")
    return tz, token, debug, other, again


def run(cmd):
    import subprocess

    child = dict(os.environ)
    for key in env:
        print(key)
    return subprocess.run(cmd, env=os.environ.copy())


class Unrelated:
    environ = {}

    def get(self):
        return self.environ["TZ"], settings.environ.get("X")
"""


def _summary(tmp_path):
    (tmp_path / "const.py").write_text('ENV_KEY = "ACME_DEBUG"\n')
    (tmp_path / "app.py").write_text(CODE)
    return py_env.summary(py_env.uses_in(tmp_path))


def test_reads_and_writes_are_named(tmp_path):
    s = _summary(tmp_path)
    assert [d["name"] for d in s["reads"]] == [
        "ACME_DEBUG",
        "ACME_LOCAL",
        "ACME_MODE",
        "SUPERVISOR_TOKEN",
        "TZ",
    ]
    assert [d["name"] for d in s["writes"]] == [
        "ACME_A",
        "ACME_B",
        "ACME_HOME",
        "ACME_LOCAL",
        "ACME_OLD",
    ]
    tz = next(d for d in s["reads"] if d["name"] == "TZ")
    assert tz == {"name": "TZ", "count": 1, "at": ["app.py:11"], "own": False}


def test_a_read_of_its_own_setting_is_marked(tmp_path):
    s = _summary(tmp_path)
    assert [d["name"] for d in s["reads"] if d["own"]] == ["ACME_LOCAL"]


def test_names_built_while_running_and_whole_uses_are_counted(tmp_path):
    s = _summary(tmp_path)
    assert (s["unnamed_reads"], s["unnamed_writes"]) == (1, 1)
    assert s["whole"] == {"count": 3, "at": ["app.py:29", "app.py:30", "app.py:32"]}


def test_other_things_called_environ_are_not_the_environment(tmp_path):
    (tmp_path / "a.py").write_text(
        "class C:\n    environ = {}\n    def f(self):\n        return self.environ['TZ']\n"
    )
    assert py_env.uses_in(tmp_path) == []
    assert py_env.summary([]) is None


def test_only_plain_names_are_kept(tmp_path):
    (tmp_path / "a.py").write_text(
        'import os\nA = os.environ.get("<script>")\nB = os.getenv("' + "X" * 200 + '")\n'
        'C = os.getenv("OK_NAME")\n'
    )
    s = py_env.summary(py_env.uses_in(tmp_path))
    assert [d["name"] for d in s["reads"]] == ["OK_NAME"] and s["unnamed_reads"] == 2


def test_a_file_that_does_not_parse_is_skipped(tmp_path):
    (tmp_path / "bad.py").write_text("import os\ndef f(:\n")
    (tmp_path / "ok.py").write_text('import os\nX = os.getenv("A")\n')
    assert [u[1] for u in py_env.uses_in(tmp_path)] == ["A"]
