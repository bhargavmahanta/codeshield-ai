from __future__ import annotations

import pytest

from codeshield.scanner import CodeShieldScanner


@pytest.fixture()
def scanner() -> CodeShieldScanner:
    return CodeShieldScanner()

