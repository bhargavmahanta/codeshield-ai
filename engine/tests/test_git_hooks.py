from __future__ import annotations

import os
import shutil
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from codeshield.git import GitIntegrationError, GitRepository, HookManager, HookStatus
from tests.git_helpers import git, initialize_repository, synthetic_api_key


def test_hook_install_update_status_and_uninstall(tmp_path: Path) -> None:
    repository = initialize_repository(tmp_path / "repo")
    manager = HookManager(GitRepository.discover(repository))

    assert manager.status() is HookStatus.NOT_INSTALLED
    assert manager.install() is HookStatus.MANAGED
    assert manager.status() is HookStatus.MANAGED
    manager.path.write_text(manager.path.read_text() + "# stale\n", encoding="utf-8")
    assert manager.install() is HookStatus.MANAGED
    assert "# stale" not in manager.path.read_text(encoding="utf-8")
    assert manager.uninstall() is HookStatus.NOT_INSTALLED
    assert not manager.path.exists()


def test_hook_refuses_to_overwrite_or_remove_unmanaged_hook(tmp_path: Path) -> None:
    repository = initialize_repository(tmp_path / "repo")
    manager = HookManager(GitRepository.discover(repository))
    manager.path.parent.mkdir(parents=True, exist_ok=True)
    manager.path.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")

    assert manager.status() is HookStatus.UNMANAGED
    with pytest.raises(GitIntegrationError, match="not overwritten"):
        manager.install()
    with pytest.raises(GitIntegrationError, match="unmanaged"):
        manager.uninstall()


@pytest.mark.parametrize(
    ("relative_path", "expected_success", "expected_marker"),
    [
        ("settings.py", False, "action=block"),
        ("demo/review-fixtures/key.txt", True, "exception=review-test-api-key"),
    ],
)
def test_real_commit_hook_blocks_or_allows_review_exception(
    tmp_path: Path,
    relative_path: str,
    expected_success: bool,
    expected_marker: str,
) -> None:
    repository = initialize_repository(tmp_path / "repo")
    (repository / "policies").mkdir()
    shutil.copy("codeshield/policies/default.yaml", repository / "policies/default.yaml")
    # The real hook runs in a child interpreter, so use a current, short-lived
    # exception in this temporary fixture only; production expiry stays real.
    policy_path = repository / "policies/default.yaml"
    fixture_policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    for exception in fixture_policy.get("exceptions", []):
        if exception["exception_id"] == "review-test-api-key":
            exception["expires_on"] = date.today() + timedelta(days=1)
    policy_path.write_text(yaml.safe_dump(fixture_policy), encoding="utf-8")
    shutil.copy("../.codeshield.yaml", repository / ".codeshield.yaml")
    target = repository / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = synthetic_api_key()
    target.write_text(f"api_key = '{raw}'\n", encoding="utf-8")
    git(repository, "add", ".")
    HookManager(GitRepository.discover(repository)).install()
    environment = os.environ.copy()
    environment["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{environment['PATH']}"

    commit = subprocess.run(
        ["git", "commit", "-m", "hook review"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        shell=False,
    )
    output = commit.stdout + commit.stderr

    assert (commit.returncode == 0) is expected_success
    assert expected_marker in output
    assert raw not in output
