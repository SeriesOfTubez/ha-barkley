"""(0.14.1, #21) Security checks run through pre-commit count as the repo's security habits,
and the patterns that read the repo's files stay linear on hostile input."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from sniff_test.analyzers import repo_hygiene
from sniff_test.ui import all_green

PRE_COMMIT = """\
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    hooks:
      - id: check-yaml
      - id: detect-private-key
  - repo: https://github.com/astral-sh/ruff-pre-commit
    hooks:
      - id: ruff
  - repo: https://github.com/gitleaks/gitleaks
    hooks:
      - id: gitleaks
  # - id: bandit   (commented out: doesn't count)
"""
PYPROJECT = """\
[tool.ruff.lint]
select = [
  "E",      # pycodestyle
  "S102",   # Use of exec detected
]
"""
LINT = """\
jobs:
  lint:
    steps:
      - name: "Run pre-commit with tox"
        run: python -m tox -e precommit
"""


def _repo(tmp_path: Path, *, pyproject: str = PYPROJECT, workflow: str | None = LINT) -> Path:
    (tmp_path / ".pre-commit-config.yaml").write_text(PRE_COMMIT)
    (tmp_path / "pyproject.toml").write_text(pyproject)
    if workflow is not None:
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / ".github" / "workflows" / "lint.yml").write_text(workflow)
    return tmp_path


def test_pre_commit_security_hooks_count(tmp_path):
    sc = repo_hygiene.scan_files(_repo(tmp_path)).scanners
    assert [(x["name"], x["via"], x["ci"]) for x in sc] == [
        ("detect-private-key", "pre-commit", True),
        ("Gitleaks", "pre-commit", True),
        ("Ruff security rules", "pre-commit", True),
    ]


def test_ruff_counts_only_with_security_rules_selected(tmp_path):
    sc = repo_hygiene.scan_files(
        _repo(tmp_path, pyproject='[tool.ruff.lint]\nselect = ["E", "F"]\n')
    )
    assert "Ruff security rules" not in [x["name"] for x in sc.scanners]
    assert repo_hygiene.ruff_security_rules('extend-select = ["S"]')
    assert not repo_hygiene.ruff_security_rules('ignore = ["S101"]')


def test_a_step_named_pre_commit_isnt_a_run(tmp_path):
    named_only = "jobs:\n  a:\n    steps:\n      - name: pre-commit\n        run: echo hi\n"
    sc = repo_hygiene.scan_files(_repo(tmp_path, workflow=named_only)).scanners
    assert sc and not any(x["ci"] for x in sc)


def test_the_page_and_the_star(tmp_path):
    from sniff_test import ui

    cases = (
        (LINT, "with pre-commit, and in its GitHub workflows"),
        (None, "before each commit with pre-commit"),
    )
    for workflow, says in cases:
        root = tmp_path / ("ci" if workflow else "local")
        root.mkdir()
        h = repo_hygiene.to_dict(
            repo_hygiene.scan_files(_repo(root, workflow=workflow)), set(), "integration"
        )
        html = ui.hygiene_html({"hygiene": h, "target": {"repo": "acme/x"}})
        assert says in html and "run no security scanner" not in html
        h.update(update_prs={"open": 0}, security_issues={"open": 0, "of": 3},
                 security_policy="SECURITY.md", dependabot=["pip"])  # fmt: skip
        assert all_green(h) is bool(workflow)  # only checks CI runs count toward A+


_N = 200_000


@pytest.mark.parametrize(
    "text",
    [
        " \n" * _N,
        "\n" * _N,
        "id" + " " * _N,
        "- " * _N,
        "select = [" * (_N // 10),
        "[" * _N,
        "select" + " " * _N + "=" + " " * _N + "[",
        "entry:" + " " * _N,
        "run" + " " * _N + ":",
        "gitleaks-" * (_N // 5),
        "-ruff" * (_N // 5),
    ],
)
def test_the_patterns_stay_linear(text):
    start = time.monotonic()
    repo_hygiene._HOOK_ID.findall(text)
    repo_hygiene.ruff_security_rules(text)
    repo_hygiene._RUNS_PRE_COMMIT.search(text)
    repo_hygiene._ENTRY.findall(text)
    repo_hygiene._TOOL.findall(text)
    repo_hygiene._RUFF_CMD.search(text)
    assert time.monotonic() - start < 1.0


# --- (0.15, his list 2026-11-20) the gaps: local hooks, lefthook, husky, ruff.toml --------

RUFF_TOML = """\
[lint]
extend-select = ["S"]
"""


def test_a_local_pre_commit_hook_counts_by_its_command(tmp_path):
    (tmp_path / ".pre-commit-config.yaml").write_text(
        "repos:\n  - repo: local\n    hooks:\n      - id: secrets\n"
        "        entry: gitleaks protect --staged\n        language: system\n"
        "      - id: lint\n        entry: ruff check\n"
    )
    (tmp_path / "ruff.toml").write_text(RUFF_TOML)
    sc = repo_hygiene.scan_files(tmp_path).scanners
    assert [(x["name"], x["via"]) for x in sc] == [
        ("Gitleaks", "pre-commit"), ("Ruff security rules", "pre-commit")
    ]  # fmt: skip


def test_lefthook_and_husky_hooks_count_but_not_as_ci(tmp_path):
    (tmp_path / "lefthook.yml").write_text(
        "pre-commit:\n  commands:\n    audit:\n      run: pip-audit -r requirements.txt\n"
        "    # old:\n    #   run: bandit -r .\n"
    )
    (tmp_path / ".husky").mkdir()
    (tmp_path / ".husky" / "pre-commit").write_text("#!/bin/sh\n# semgrep later\nnpx semgrep\n")
    sc = repo_hygiene.scan_files(tmp_path).scanners
    assert [(x["name"], x["via"], x["ci"]) for x in sc] == [
        ("pip-audit", "lefthook", False), ("Semgrep", "husky", False)
    ]  # fmt: skip
    assert not all_green({"scanners": sc, "dependabot": ["pip"], "security_policy": "S",
                          "update_prs": {"open": 0}, "security_issues": {"open": 0},
                          "errors": []})  # fmt: skip


def test_a_dotted_ruff_toml_counts_and_a_name_inside_a_word_does_not(tmp_path):
    (tmp_path / ".ruff.toml").write_text('select = ["E", "S102"]\n')
    (tmp_path / ".husky").mkdir()
    (tmp_path / ".husky" / "pre-commit").write_text("my-gitleaks-wrapper\nruff check\n")
    sc = repo_hygiene.scan_files(tmp_path).scanners
    assert [x["name"] for x in sc] == ["Ruff security rules"]
