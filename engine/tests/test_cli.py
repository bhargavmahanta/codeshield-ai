from __future__ import annotations

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from codeshield.cli import app
from tests.git_helpers import git, initialize_repository, synthetic_api_key


runner = CliRunner()


def test_cli_scan_json_blocks_public_git_secret_without_raw_output(tmp_path: Path) -> None:
    target = tmp_path / "settings.txt"
    raw = "sk_live_51SyntheticTokenValue999"
    target.write_text(f'api_key = "{raw}"\n', encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            str(target),
            "--destination",
            "public_git",
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 2
    assert raw not in result.output
    payload = json.loads(result.output)
    assert payload["findings"][0]["recommended_action"] == "block"


def test_cli_scan_returns_zero_when_no_findings(tmp_path: Path) -> None:
    target = tmp_path / "safe.txt"
    target.write_text("hello from a normal file\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(target)])

    assert result.exit_code == 0
    assert "0 finding" in result.output


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.output.strip()


def test_cli_validates_default_policy() -> None:
    result = runner.invoke(
        app, ["policy", "validate", "codeshield/policies/default.yaml"]
    )

    assert result.exit_code == 0
    assert "is valid" in result.output


def test_cli_protect_writes_placeholder_output(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    output = tmp_path / "protected.txt"
    raw = "user@example.test"
    source.write_text(f"contact={raw}", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "protect",
            str(source),
            "--mode",
            "type_placeholder",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert output.read_text(encoding="utf-8") == "contact=<EMAIL>"
    assert raw not in result.output


def test_cli_staged_resolves_config_and_blocks_without_raw_output(
    tmp_path: Path,
) -> None:
    repository = initialize_repository(tmp_path / "repo")
    (repository / "policies").mkdir()
    shutil.copy("codeshield/policies/default.yaml", repository / "policies/default.yaml")
    (repository / ".codeshield.yaml").write_text(
        "schema_version: 1\n"
        "repository_visibility: public\n"
        "policy_file: policies/default.yaml\n",
        encoding="utf-8",
    )
    raw = synthetic_api_key()
    (repository / "settings.py").write_text(
        f"api_key = '{raw}'\n", encoding="utf-8"
    )
    git(repository, "add", ".")

    result = runner.invoke(
        app,
        ["scan", "--staged", "--repository", str(repository), "--output", "json"],
    )

    assert result.exit_code == 2
    assert raw not in result.output
    assert json.loads(result.output)["destination"] == "public_git"


def test_cli_staged_requires_destination_without_repository_config(
    tmp_path: Path,
) -> None:
    repository = initialize_repository(tmp_path / "repo")
    (repository / "safe.txt").write_text("safe\n", encoding="utf-8")
    git(repository, "add", "safe.txt")

    result = runner.invoke(app, ["scan", "--staged", "--repository", str(repository)])

    assert result.exit_code == 3
    assert "staged destination is required" in result.output


def test_cli_rejects_path_and_staged_together(tmp_path: Path) -> None:
    target = tmp_path / "safe.txt"
    target.write_text("safe\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(target), "--staged"])

    assert result.exit_code == 3
    assert "either FILE_OR_DIRECTORY or --staged" in result.output


def test_check_staged_exception_warns_but_returns_success(tmp_path: Path) -> None:
    repository = initialize_repository(tmp_path / "repo")
    (repository / "policies").mkdir()
    shutil.copy("codeshield/policies/default.yaml", repository / "policies/default.yaml")
    shutil.copy("../.codeshield.yaml", repository / ".codeshield.yaml")
    fixture = repository / "demo/review-fixtures"
    fixture.mkdir(parents=True)
    raw = synthetic_api_key()
    (fixture / "key.txt").write_text(f"api_key = '{raw}'\n", encoding="utf-8")
    git(repository, "add", ".")

    result = runner.invoke(
        app, ["check-staged", "--repository", str(repository)]
    )

    assert result.exit_code == 0
    assert "exception=review-test-api-key" in result.output
    assert raw not in result.output
