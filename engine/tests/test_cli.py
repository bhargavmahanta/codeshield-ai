from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from codeshield.cli import app


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
