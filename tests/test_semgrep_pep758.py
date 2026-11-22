"""(0.15) Python 3.14's `except A, B, C:` (PEP 758) and Semgrep.

Semgrep 1.185 and 1.186 skip their rules on such a clause when the file also holds a
`match`, a PEP 695 `type` alias or a generic (upstream issue 12079): 6 of 360 real
integrations. Barkley hands Semgrep the clause in parentheses and puts the file back.
"""

import json

from conftest import requires_semgrep

from sniff_test.analyzers import semgrep
from sniff_test.models import TargetKind
from sniff_test.scanner import scan


def test_bare_clauses_get_parentheses_and_nothing_else_changes():
    text = (
        "def f():\n"
        "    try:\n"
        "        pass\n"
        "    except OSError, ValueError, KeyError:\n"
        "        pass\n"
        "    except* TimeoutError, OSError:\n"
        "        pass\n"
        "    except (A, B):\n"
        "        pass\n"
        "    except A as err:\n"
        "        pass\n"
        '    s = """\n'
        "    except A, B:\n"
        '    """\n'
        "    # except A, B:\n"
    )
    out = semgrep._parenthesize_excepts(text)
    assert out is not None
    assert "    except (OSError, ValueError, KeyError):\n" in out
    assert "    except* (TimeoutError, OSError):\n" in out
    assert "    except (A, B):\n" in out and "    except A as err:\n" in out
    assert '    s = """\n    except A, B:\n    """\n' in out  # inside a string: untouched
    assert "    # except A, B:\n" in out
    assert out.count("\n") == text.count("\n")  # every line stays where it was


def test_unreadable_text_is_left_alone():
    assert semgrep._parenthesize_excepts('x = """never closed\nexcept A, B:\n') is None


def test_files_are_put_back_after_semgrep(tmp_path, monkeypatch):
    f = tmp_path / "a.py"
    original = b"try:\n    pass\nexcept A, B, C:\n    pass\n"
    f.write_bytes(original)
    seen = {}

    def fake_run(target, work, jobs, cache):
        seen["text"] = f.read_text()
        return "result"

    monkeypatch.setattr(semgrep, "_run", fake_run)

    class T:
        root = tmp_path

    assert semgrep.run(T(), tmp_path / "work") == "result"
    assert "except (A, B, C):" in seen["text"]
    assert f.read_bytes() == original


@requires_semgrep
def test_rules_still_read_the_clause_next_to_a_type_alias(tmp_path):
    comp = tmp_path / "custom_components" / "acme_pep"
    comp.mkdir(parents=True)
    (comp / "manifest.json").write_text(
        json.dumps({"domain": "acme_pep", "name": "Acme", "version": "1.0", "requirements": []})
    )
    code = (
        "import os\n\n"
        "type Alias = int\n\n\n"
        "def f(cmd):\n"
        "    try:\n"
        "        pass\n"
        "    except OSError, ValueError, KeyError:\n"
        "        os.system(cmd)\n"
    )
    (comp / "__init__.py").write_text(code)
    result = scan(str(tmp_path), kind=TargetKind.INTEGRATION, offline=True)
    rules = {(f.rule_id, f.line) for f in result.findings}
    assert any(r == "py-shell-exec" and line == 10 for r, line in rules), rules
    assert not any(r == "scan-parse-error" for r, _ in rules)
    assert (comp / "__init__.py").read_text() == code
