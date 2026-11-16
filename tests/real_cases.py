"""Real repositories for the opt-in network tests (`pytest -m network`).

Some behaviour can only be checked against a real repository on GitHub: one that changed
hands, one whose releases changed publisher, one to scan from end to end. Which ones is
not written down here. A public repository should not name someone else's project next to
what a security scanner expects to find in it, so each test reads its case from an
environment variable and is skipped when the variable isn't set.

    BARKLEY_TEST_HANDOVER       owner/repo,old-tag,new-tag,new-publisher,old-publisher
    BARKLEY_TEST_ONE_PUBLISHER  owner/repo,publisher
    BARKLEY_TEST_TRANSFERRED    old-owner/repo,new-owner/repo
    BARKLEY_TEST_SCAN           owner/repo,ref
"""

from __future__ import annotations

import os

import pytest


def case(var: str, parts: int) -> list[str]:
    value = os.environ.get(var, "")
    got = [p.strip() for p in value.split(",")] if value else []
    if len(got) != parts or not all(got):
        pytest.skip(f"set {var} (see tests/real_cases.py)")
    return got
