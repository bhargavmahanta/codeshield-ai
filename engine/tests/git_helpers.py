from __future__ import annotations

import subprocess
from pathlib import Path


def git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )


def initialize_repository(repository: Path) -> Path:
    repository.mkdir()
    git(repository, "init", "--initial-branch=main")
    git(repository, "config", "user.name", "CodeShield Tests")
    git(repository, "config", "user.email", "codeshield@example.test")
    return repository


def synthetic_api_key() -> str:
    return "sk_" + "live_51" + "ReviewToken" + "93628471"
