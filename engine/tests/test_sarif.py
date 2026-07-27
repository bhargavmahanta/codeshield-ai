from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from codeshield.cli import app
from codeshield.models.enums import Destination
from codeshield.models.scan import ScanResult
from codeshield.scanner import CodeShieldScanner
from codeshield.sarif import SarifError, build_sarif, render_sarif
from tests.git_helpers import git, initialize_repository, synthetic_api_key


runner = CliRunner()


def test_sarif_is_deterministic_valid_and_leakage_safe(tmp_path: Path) -> None:
    raw = "sk_live_51SyntheticSarifValue93628471"
    target = tmp_path / "src" / "settings.py"
    target.parent.mkdir()
    target.write_text(f'api_key = "{raw}"\n', encoding="utf-8")
    scan = CodeShieldScanner().scan_path(
        tmp_path, destination=Destination.PUBLIC_GIT
    )

    first = render_sarif(scan, source_root=tmp_path)
    second = render_sarif(scan, source_root=tmp_path)
    payload = json.loads(first)
    validated = build_sarif(scan, source_root=tmp_path)

    assert first == second
    assert validated.version == "2.1.0"
    assert payload["$schema"].endswith("sarif-2.1.0.json")
    assert payload["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "CS.API_KEY"
    result = payload["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert result["properties"]["confidence"] > 0
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "src/settings.py"
    )
    assert raw not in first
    assert "masked_preview" not in first
    assert str(tmp_path).replace("\\", "/").lower() not in first.lower()


def test_sarif_multiline_region_has_accurate_end(tmp_path: Path) -> None:
    target = tmp_path / "key.pem"
    target.write_text(
        "-----BEGIN PRIVATE KEY-----\n"
        "c3ludGhldGljLXByaXZhdGUta2V5\n"
        "-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    scan = CodeShieldScanner().scan_path(
        target, destination=Destination.PRIVATE_GIT
    )

    payload = json.loads(render_sarif(scan, source_root=tmp_path))
    region = payload["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"
    ]["region"]

    assert region["startLine"] == 1
    assert region["endLine"] == 3
    assert region["endColumn"] > 1


def test_sarif_rejects_location_outside_source_root(tmp_path: Path) -> None:
    raw = "sk_live_51SyntheticOutsideValue93628471"
    target = tmp_path / "outside.py"
    target.write_text(raw, encoding="utf-8")
    scan = CodeShieldScanner().scan_path(
        target, destination=Destination.PUBLIC_GIT
    )

    with pytest.raises(SarifError, match="outside the source root"):
        render_sarif(scan, source_root=tmp_path / "different")


def test_cli_writes_sarif_and_preserves_exit_code(tmp_path: Path) -> None:
    raw = "sk_live_51SyntheticCliSarifValue93628471"
    target = tmp_path / "settings.py"
    output = tmp_path / "reports" / "result.sarif"
    target.write_text(f'api_key = "{raw}"\n', encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            str(target),
            "--destination",
            "public_git",
            "--format",
            "sarif",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert raw not in output.read_text(encoding="utf-8")
    assert not list(output.parent.glob(".codeshield-output-*.tmp"))


def test_cli_legacy_output_format_is_machine_readable(tmp_path: Path) -> None:
    target = tmp_path / "safe.txt"
    target.write_text("safe content", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(target), "--output", "json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["findings"] == []
    assert "deprecated" in result.stderr


def test_check_staged_sarif_uses_repository_relative_paths(tmp_path: Path) -> None:
    repository = initialize_repository(tmp_path / "repo")
    raw = synthetic_api_key()
    target = repository / "src" / "settings.py"
    target.parent.mkdir()
    target.write_text(f'api_key = "{raw}"\n', encoding="utf-8")
    git(repository, "add", ".")

    result = runner.invoke(
        app,
        [
            "check-staged",
            "--repository",
            str(repository),
            "--destination",
            "public_git",
            "--format",
            "sarif",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    uri = payload["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"
    ]["artifactLocation"]["uri"]
    assert uri == "src/settings.py"
    assert raw not in result.stdout


def test_empty_sarif_contains_one_valid_run(tmp_path: Path) -> None:
    payload = json.loads(
        render_sarif(
            ScanResult(destination=Destination.LOCAL_FILE),
            source_root=tmp_path,
        )
    )
    assert payload["runs"][0]["results"] == []
    assert payload["runs"][0]["tool"]["driver"]["rules"] == []
