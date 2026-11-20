"""(0.15) README passages picked by topic, and the developer's docstrings, kept for the AI
and the page with their line numbers (report/context.py). The developer's own words:
stored as text, never evidence of what the code does."""

import time

from sniff_test.report import context

README = "\n".join(
    ["# Acme Agent", "", "[![badge](https://img.invalid/token.svg)](https://x.invalid)", ""]
    + [f"Feature line {i}." for i in range(1, 117)]
    + [
        "## How the PC connects",  # line 121
        "",
        "The client uses a long-lived access token of a user without a password.",
        "From 1.2 the token does not have to be an administrator's.",
        "",
        "More features.",
    ]
    + [f"Changelog line {i}." for i in range(1, 60)]
    + ["Usage statistics are anonymous and you can opt out.", ""]
)


def _repo(tmp_path, text=README):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "README.md").write_text(text)
    return tmp_path


def test_passages_are_picked_by_topic_with_their_line_numbers(tmp_path):
    t = context.readme_topics(_repo(tmp_path))
    assert t["file"] == "README.md" and t["total"] == len(README.splitlines())
    first = t["passages"][0]
    assert first["start"] == 122  # one line of context before the first line on a topic
    assert first["code"][1].startswith("The client uses a long-lived access token")
    assert first["topics"] == ["accounts", "login"]
    assert t["passages"][-1]["topics"] == ["privacy"]
    # the badge line names "token" in an image address: not a passage
    assert all(p["start"] > 100 for p in t["passages"])


def test_a_readme_that_names_no_topic_has_no_passages(tmp_path):
    assert context.readme_topics(_repo(tmp_path, "# Card\n\nA nice graph.\n")) is None
    assert context.readme_topics(None) is None and context.readme_topics(tmp_path / "no") is None


def test_passages_are_capped_and_the_richest_are_kept(tmp_path):
    lines = []
    for i in range(200):
        lines += [f"Paragraph {i} mentions the cloud.", "", "", ""]
    lines += ["Your password and token go to the administrator account.", ""]
    t = context.readme_topics(_repo(tmp_path, "\n".join(lines)))
    assert len(t["passages"]) == context.TOPIC_PASSAGES
    assert t["passages"][-1]["topics"] == ["accounts", "login"]  # kept, though it comes last
    assert sum(len(c) for p in t["passages"] for c in p["code"]) <= context.TOPIC_CHARS


def test_long_lines_are_cut_and_control_characters_dropped(tmp_path):
    t = context.readme_topics(_repo(tmp_path, "token \x07" + "x" * 5000 + "\n"))
    [line] = t["passages"][0]["code"]
    assert len(line) <= context.README_LINE + 2 and "\x07" not in line


def test_a_hostile_readme_is_read_in_linear_time(tmp_path):
    text = ("tok" * 20000 + "\n") * 50 + ("a token " * 2000 + "\n") * 2000
    t0 = time.monotonic()
    context.readme_topics(_repo(tmp_path, text))
    assert time.monotonic() - t0 < 5


CODE = '''\
"""Acme: talks to the Acme cloud.

Second paragraph of the module note.
"""

import os


class Client:
    """Keeps one session per account."""

    def provision(self, hass, name):
        """Create a user for the PC and hand it a token.

        Only an administrator can run this.
        """
        user = hass.auth.async_create_user(name)
        return user

    def plain(self):
        return os.environ["TZ"]


def bare():
    return 1
'''


def _tree(tmp_path):
    (tmp_path / "api.py").write_text(CODE)
    return context._Tree(tmp_path)


def test_the_docstring_around_an_item_is_kept_in_full(tmp_path):
    doc = context.docstring(_tree(tmp_path), "api.py", 18)
    assert (doc["file"], doc["start"], doc["of"], doc["cut"]) == ("api.py", 13, "provision", False)
    assert doc["code"][0].strip() == '"""Create a user for the PC and hand it a token.'
    assert doc["code"][2].strip() == "Only an administrator can run this."


def test_a_function_without_one_takes_the_class_docstring(tmp_path):
    tree = _tree(tmp_path)
    doc = context.docstring(tree, "api.py", 21)
    assert (doc["of"], doc["start"]) == ("Client", 10)
    assert context.docstring(tree, "api.py", 25) is None  # no docstring anywhere around it
    assert context.docstring(tree, "card.js", 3) is None


def test_module_docstrings_of_files_with_items(tmp_path):
    docs = context.module_docs(_tree(tmp_path), ["api.py", "api.py", "missing.py", "x.js"])
    assert list(docs) == ["api.py"]
    assert docs["api.py"]["start"] == 1 and len(docs["api.py"]["code"]) == 4


def test_a_long_docstring_is_cut(tmp_path):
    body = "\n".join(f"    line {i}" for i in range(100))
    (tmp_path / "long.py").write_text(f'def f():\n    """Start.\n{body}\n    """\n    return 1\n')
    doc = context.docstring(context._Tree(tmp_path), "long.py", 104)
    assert doc["cut"] and len(doc["code"]) == context.DOC_LINES


def test_the_scan_context_carries_them(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "api.py").write_text(CODE)
    finding = {
        "id": "f" * 16,
        "rule_id": "ha-auth-change-users",
        "severity": "high",
        "category": "sensitive_access",
        "file": "api.py",
        "line": 18,
        "evidence": "hass.auth.async_create_user(name)",
    }
    ctx = context.build(pkg, [finding], None, source_root=_repo(tmp_path / "repo"))
    assert ctx["version"] == 6
    assert ctx["items"]["f" * 16]["doc"]["of"] == "provision"
    assert ctx["module_docs"]["api.py"]["code"][0] == '"""Acme: talks to the Acme cloud.'
    assert ctx["readme_topics"]["passages"][0]["start"] == 122
    assert ctx["readme"]["start"] == 1  # the head is still kept (the 0.12.0 README opinion)
