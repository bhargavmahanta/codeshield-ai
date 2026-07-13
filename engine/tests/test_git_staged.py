from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from codeshield.git.repository import GitIntegrationError, GitRepository
from codeshield.git.scanner import StagedGitScanner
from codeshield.models.enums import Destination
from codeshield.scanner import CodeShieldScanner
from tests.git_helpers import git, initialize_repository, synthetic_api_key


def test_staged_scanner_maps_new_added_line_without_raw_output(tmp_path: Path) -> None:
    repository = initialize_repository(tmp_path / "repo")
    raw = synthetic_api_key()
    target = repository / "settings.py"
    target.write_text(f"safe = True\napi_key = '{raw}'\n", encoding="utf-8")
    git(repository, "add", "settings.py")

    result = StagedGitScanner(CodeShieldScanner()).scan(
        GitRepository.discover(repository), destination=Destination.PUBLIC_GIT
    )

    assert result.files_scanned == 1
    assert result.findings[0].file_path == "settings.py"
    assert result.findings[0].line == 2
    assert result.findings[0].column is not None
    assert raw not in result.model_dump_json()


def test_staged_scanner_ignores_unstaged_and_deleted_content(tmp_path: Path) -> None:
    repository = initialize_repository(tmp_path / "repo")
    target = repository / "tracked.txt"
    target.write_text("baseline\n", encoding="utf-8")
    git(repository, "add", "tracked.txt")
    git(repository, "commit", "-m", "baseline")

    target.write_text("staged safe line\n", encoding="utf-8")
    git(repository, "add", "tracked.txt")
    target.write_text(
        f"staged safe line\napi_key='{synthetic_api_key()}'\n", encoding="utf-8"
    )
    (repository / "deleted.txt").write_text("temporary\n", encoding="utf-8")
    git(repository, "add", "deleted.txt")
    git(repository, "commit", "-m", "add deleted fixture")
    (repository / "deleted.txt").unlink()
    git(repository, "add", "deleted.txt")

    result = StagedGitScanner(CodeShieldScanner()).scan(
        GitRepository.discover(repository), destination=Destination.PUBLIC_GIT
    )

    assert result.findings == []
    assert all(item.path != "deleted.txt" for item in result.files_skipped)


def test_staged_scanner_handles_renamed_binary_multiline_and_excluded(
    tmp_path: Path,
) -> None:
    repository = initialize_repository(tmp_path / "repo")
    original = repository / "original.txt"
    original.write_text("baseline\n", encoding="utf-8")
    git(repository, "add", "original.txt")
    git(repository, "commit", "-m", "baseline")

    git(repository, "mv", "original.txt", "renamed.txt")
    (repository / "renamed.txt").write_text(
        "baseline\n-----BEGIN PRIVATE KEY-----\n"
        "c3ludGhldGljLXJldmlldy1rZXktbWF0ZXJpYWw=\n"
        "-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    (repository / "asset.bin").write_bytes(b"\x00\x01\x02")
    (repository / ".codeshieldignore").write_text("ignored/**\n", encoding="utf-8")
    (repository / "ignored").mkdir()
    (repository / "ignored" / "secret.txt").write_text(
        f"api_key='{synthetic_api_key()}'\n", encoding="utf-8"
    )
    git(repository, "add", "-A")

    result = StagedGitScanner(CodeShieldScanner()).scan(
        GitRepository.discover(repository), destination=Destination.PUBLIC_GIT
    )

    private_key = next(
        item for item in result.findings if item.data_category.value == "PRIVATE_KEY"
    )
    assert private_key.file_path == "renamed.txt"
    assert private_key.line == 2
    assert any(item.path == "asset.bin" for item in result.files_skipped)
    assert any(item.path == "ignored/secret.txt" for item in result.files_skipped)


def test_staged_scanner_returns_empty_for_no_changes(tmp_path: Path) -> None:
    repository = initialize_repository(tmp_path / "repo")

    result = StagedGitScanner(CodeShieldScanner()).scan(
        GitRepository.discover(repository), destination=Destination.PRIVATE_GIT
    )

    assert result.findings == []
    assert result.files_scanned == 0


def test_repository_discovery_rejects_non_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", tmp_path.parent.as_posix())
    with pytest.raises(GitIntegrationError, match="Git command failed"):
        GitRepository.discover(tmp_path)


def test_staged_diff_reports_malformed_patch_safely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = initialize_repository(tmp_path / "repo")
    (repository / "safe.txt").write_text("safe\n", encoding="utf-8")
    git(repository, "add", "safe.txt")
    monkeypatch.setattr(
        "codeshield.git.repository.PatchSet",
        lambda _value: (_ for _ in ()).throw(ValueError("unsafe diff content")),
    )

    with pytest.raises(GitIntegrationError, match="unable to parse staged Git diff"):
        GitRepository.discover(repository).staged_diff()


def test_git_timeout_is_reported_without_command_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def timeout(*_args: object, **_kwargs: object) -> object:
        raise subprocess.TimeoutExpired(["git", "rev-parse"], 0.01)

    monkeypatch.setattr("codeshield.git.repository.subprocess.run", timeout)

    with pytest.raises(GitIntegrationError, match="Git command timed out"):
        GitRepository.discover(tmp_path, timeout_seconds=0.01)
