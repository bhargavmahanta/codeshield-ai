from __future__ import annotations

from pathlib import Path

import pytest

from codeshield.scanner import CodeShieldScanner


@pytest.fixture(autouse=True)
def engine_working_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(Path(__file__).resolve().parents[1])


@pytest.fixture()
def scanner() -> CodeShieldScanner:
    return CodeShieldScanner()
