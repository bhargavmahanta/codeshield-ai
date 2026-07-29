from __future__ import annotations

import json
import shutil
from datetime import date
from pathlib import Path

from typer.testing import CliRunner

from codeshield.cli import app
from codeshield.models.provider import ProviderAttestation
from codeshield.providers import AttestationStore, ProviderRegistry
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
    payload = json.loads(result.stdout)
    assert payload["findings"][0]["recommended_action"] == "block"


def test_cli_scan_returns_zero_when_no_findings(tmp_path: Path) -> None:
    target = tmp_path / "safe.txt"
    target.write_text("hello from a normal file\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(target)])

    assert result.exit_code == 0
    assert "0 finding" in result.output


def test_cli_scan_relative_paths_never_emits_local_root(tmp_path: Path) -> None:
    target = tmp_path / "src" / "settings.txt"
    target.parent.mkdir()
    raw = synthetic_api_key()
    target.write_text(f'api_key = "{raw}"\n', encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--destination",
            "public_git",
            "--format",
            "json",
            "--relative-paths",
        ],
    )

    assert result.exit_code == 2
    assert str(tmp_path) not in result.output
    assert raw not in result.output
    emitted = json.loads(result.stdout)["findings"][0]["file_path"]
    assert emitted.endswith("src/settings.txt")
    assert "\\" not in emitted
    assert ".." not in Path(emitted).parts


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


def test_scan_text_reads_stdin_and_returns_safe_editor_locations(
    tmp_path: Path,
) -> None:
    raw = synthetic_api_key()

    result = runner.invoke(
        app,
        [
            "scan-text",
            "--stdin",
            "--repository",
            str(tmp_path),
            "--source-path",
            "src/settings.py",
            "--destination",
            "public_git",
            "--profile",
            "core",
            "--format",
            "json",
        ],
        input=f'api_key = "{raw}"\n',
    )

    assert result.exit_code == 2
    assert raw not in result.output
    payload = json.loads(result.stdout)
    assert payload["files_scanned"] == 1
    assert payload["findings"][0]["file_path"] == "src/settings.py"
    assert payload["findings"][0]["line"] == 1


def test_protect_text_returns_structured_preview_without_echoing_raw_secret(
    tmp_path: Path,
) -> None:
    raw = "editor.person@example.test"

    result = runner.invoke(
        app,
        [
            "protect-text",
            "--stdin",
            "--repository",
            str(tmp_path),
            "--source-path",
            "src/contact.txt",
            "--mode",
            "type_placeholder",
            "--format",
            "json",
        ],
        input=f"contact={raw}",
    )

    assert result.exit_code == 1
    assert raw not in result.output
    payload = json.loads(result.stdout)
    assert payload["protected_text"] == "contact=<EMAIL>"
    assert payload["replacements"][0]["mode"] == "type_placeholder"


def test_protect_text_fragment_fails_closed_without_raw_output(
    tmp_path: Path,
) -> None:
    raw_suffix = "SyntheticFragmentValue93628471"
    text = f'token = "sk_" + "live_51{raw_suffix}"'

    result = runner.invoke(
        app,
        [
            "protect-text",
            "--stdin",
            "--repository",
            str(tmp_path),
            "--source-path",
            "src/settings.py",
        ],
        input=text,
    )

    assert result.exit_code == 3
    assert raw_suffix not in result.output
    assert "fragmented findings require manual source refactoring" in result.output


def test_editor_commands_reject_unsafe_paths_and_oversized_input(
    tmp_path: Path,
) -> None:
    unsafe = runner.invoke(
        app,
        [
            "scan-text",
            "--stdin",
            "--repository",
            str(tmp_path),
            "--source-path",
            "../outside.py",
        ],
        input="safe",
    )
    oversized = runner.invoke(
        app,
        [
            "scan-text",
            "--stdin",
            "--repository",
            str(tmp_path),
            "--max-input-bytes",
            "4",
        ],
        input="12345",
    )

    assert unsafe.exit_code == 3
    assert "repository-relative" in unsafe.output
    assert oversized.exit_code == 3
    assert "configured limit" in oversized.output


def test_editor_commands_reject_policy_escape(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan-text",
            "--stdin",
            "--repository",
            str(tmp_path),
            "--policy",
            "../outside.yaml",
        ],
        input="safe",
    )

    assert result.exit_code == 3
    assert "workspace-relative" in result.output


def test_editor_session_handles_sequential_secret_safe_requests(
    tmp_path: Path,
) -> None:
    raw = synthetic_api_key()
    requests = [
        {
            "command": "scan-text",
            "content": f'api_key = "{raw}"',
            "repository": str(tmp_path),
            "source_path": "src/settings.py",
            "destination": "public_git",
            "profile": "core",
            "max_input_bytes": 1_000_000,
        },
        {
            "command": "scan-text",
            "content": "ordinary local text",
            "repository": str(tmp_path),
            "source_path": "src/safe.txt",
            "destination": "local_file",
            "profile": "core",
            "max_input_bytes": 1_000_000,
        },
    ]

    result = runner.invoke(
        app,
        ["editor-session"],
        input="\n".join(json.dumps(item) for item in requests) + "\n",
    )

    assert result.exit_code == 0
    assert raw not in result.output
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert [item["exit_code"] for item in responses] == [2, 0]
    assert responses[0]["result"]["findings"][0]["file_path"] == "src/settings.py"


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
    assert json.loads(result.stdout)["destination"] == "public_git"


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


def test_provider_cli_lists_shows_and_verifies_profiles() -> None:
    listed = runner.invoke(app, ["provider", "list"])
    shown = runner.invoke(app, ["provider", "show", "openai-api-zdr"])
    verified = runner.invoke(app, ["provider", "verify"])

    assert listed.exit_code == 0
    assert "copilot-business-ide" in listed.output
    assert shown.exit_code == 0
    assert '"zero_data_retention": true' in shown.output
    assert verified.exit_code == 0

    listed_json = runner.invoke(app, ["provider", "list", "--format", "json"])
    verified_json = runner.invoke(app, ["provider", "verify", "--format", "json"])
    status_json = runner.invoke(
        app,
        [
            "provider",
            "attestation-status",
            "openai-api-zdr",
            "--format",
            "json",
        ],
    )

    assert listed_json.exit_code == 0
    assert isinstance(json.loads(listed_json.stdout), list)
    assert json.loads(verified_json.stdout) == {"valid": True, "issues": []}
    assert json.loads(status_json.stdout) == {
        "profile_id": "openai-api-zdr",
        "profile_version": "2026.07",
        "status": "missing",
    }


def test_provider_attest_cli_records_only_hashes() -> None:
    result = runner.invoke(
        app,
        [
            "provider",
            "attest",
            "openai-api-zdr",
            "--id",
            "cli-provider-review",
            "--account-hash",
            "3" * 64,
            "--evidence-digest",
            "4" * 64,
            "--reviewer",
            "security-reviewer",
            "--expires",
            "2026-08-31",
            "--control",
            "zdr-reviewed",
        ],
    )

    assert result.exit_code == 0
    assert "recorded locally" in result.output
    stored = AttestationStore().path.read_text(encoding="utf-8")
    assert "3" * 64 in stored
    assert "4" * 64 in stored


def test_prompt_assess_blocks_file_secret_without_raw_output(tmp_path: Path) -> None:
    raw = "sk_" + "live_51CliPreflight" + "93628471"
    target = tmp_path / "prompt.txt"
    target.write_text(f"api_key='{raw}'", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "prompt",
            "assess",
            "--provider",
            "openai-api-zdr",
            "--file",
            str(target),
        ],
    )

    assert result.exit_code == 2
    assert '"action": "block"' in result.output
    assert raw not in result.output


def test_prompt_protect_pseudonymizes_file_with_local_attestation(
    tmp_path: Path,
) -> None:
    registry = ProviderRegistry()
    profile = registry.require("openai-api-zdr")
    attestation = ProviderAttestation(
        attestation_id="cli-review",
        profile_id=profile.profile_id,
        profile_version=profile.version,
        account_hash="1" * 64,
        enabled_controls=["zdr-reviewed"],
        evidence_digest="2" * 64,
        reviewer_id="cli-test",
        created_on=date(2026, 7, 16),
        expires_on=date(2026, 8, 31),
    )
    AttestationStore().save(attestation, registry)
    raw = "cli-reviewer@example.test"
    target = tmp_path / "prompt.txt"
    target.write_text(f"contact={raw}", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "prompt",
            "protect",
            "--provider",
            profile.profile_id,
            "--attestation",
            attestation.attestation_id,
            "--file",
            str(target),
        ],
    )

    assert result.exit_code == 1
    assert "<EMAIL_1>" in result.output
    assert raw not in result.output


def test_prompt_cli_requires_exactly_one_non_argument_input() -> None:
    result = runner.invoke(
        app, ["prompt", "assess", "--provider", "openai-api-zdr"]
    )

    assert result.exit_code == 3
    assert "exactly one" in result.output


def test_prompt_manifest_error_does_not_echo_content(tmp_path: Path) -> None:
    raw = "private-manifest-content"
    manifest = tmp_path / "prompt.json"
    manifest.write_text(
        json.dumps(
            {
                "segments": [
                    {"segment_id": "one", "kind": "invalid", "content": raw}
                ]
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "prompt",
            "assess",
            "--provider",
            "openai-api-zdr",
            "--manifest",
            str(manifest),
        ],
    )

    assert result.exit_code == 3
    assert "invalid prompt input or manifest" in result.output
    assert raw not in result.output
