from __future__ import annotations

from pathlib import Path

import pytest

from codeshield.scanner import CodeShieldScanner


@pytest.fixture(autouse=True)
def engine_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    monkeypatch.setenv("CODESHIELD_HOME", str(tmp_path / ".codeshield-home"))


@pytest.fixture()
def scanner() -> CodeShieldScanner:
    return CodeShieldScanner()
