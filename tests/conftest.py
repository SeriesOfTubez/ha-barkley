import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

requires_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed"
)


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES
