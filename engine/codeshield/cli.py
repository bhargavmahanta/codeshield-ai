"""Typer CLI for the CodeShield local engine."""

from __future__ import annotations

import json
import re
import sys
from datetime import date
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Annotated

import typer

from codeshield.classifier import evaluate_context_classifier
from codeshield.git import (
    GitIntegrationError,
    GitRepository,
    HookManager,
    HookStatus,
    StagedGitScanner,
)
from codeshield.models.config import (
    DetectorConfig,
    RepositoryConfigError,
    find_repository_config,
    load_repository_config,
    resolve_policy_path,
)
from codeshield.models.enums import Destination, RecommendedAction
from codeshield.models.enums import (
    DetectorProfile,
    ProtectionMode,
    ProviderFeature,
    SegmentKind,
    SegmentProvenance,
    TransferDirection,
)
from codeshield.models.llm import ContentSegment, LlmPreflightRequest
from codeshield.models.provider import ProviderAttestation
from codeshield.models.context import FileContext
from codeshield.models.scan import ScanResult, SkippedFile
from codeshield.llm import LlmPreflightService
from codeshield.providers import AttestationStore, ProviderRegistry, ProviderRegistryError
from codeshield.policies import PolicyEngine, PolicyLoadError, load_policy
from codeshield.pseudonymization import (
    EnvironmentKeyProvider,
    ProtectionError,
    PseudonymVault,
    VaultError,
)
from codeshield.scanner import DEFAULT_MAX_FILE_SIZE, CodeShieldScanner, ScanTimeoutError
from codeshield.detectors import DetectorError, detector_status
from codeshield.version import __version__
from codeshield.evaluation import EvaluationError, compare_reports, prepare_suite, run_evaluation
from codeshield.sarif import SarifError, render_sarif, write_output


class OutputFormat(StrEnum):
    HUMAN = "human"
    JSON = "json"
    SARIF = "sarif"


MAX_STDIN_BYTES = 1_000_000


app = typer.Typer(
    name="codeshield",
    no_args_is_help=True,
    help="Local-first sensitive data scanner for developer workflows.",
)
policy_app = typer.Typer(help="Validate and inspect destination policy files.")
provider_app = typer.Typer(help="Inspect provider evidence and local attestations.")
prompt_app = typer.Typer(help="Assess or protect prompts without sending them.")
detector_app = typer.Typer(help="Inspect local detector profile availability.")
evaluate_app = typer.Typer(help="Prepare and run reproducible local evaluations.")
app.add_typer(policy_app, name="policy")
app.add_typer(provider_app, name="provider")
app.add_typer(prompt_app, name="prompt")
app.add_typer(detector_app, name="detector")
app.add_typer(evaluate_app, name="evaluate")


@app.command()
def scan(
    path: Annotated[
        Path | None,
        typer.Argument(
            help="File or directory to scan; omit when using --staged.",
        ),
    ] = None,
    staged: Annotated[
        bool,
        typer.Option("--staged", help="Scan only added lines in the staged Git diff."),
    ] = False,
    repository: Annotated[
        Path,
        typer.Option("--repository", help="Path inside the target Git repository."),
    ] = Path("."),
    destination: Annotated[
        Destination | None,
        typer.Option("--destination", "-d", help="Intended destination for exposure risk."),
    ] = None,
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format", help="Output format: human, json, or sarif."),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option(
            "--output",
            "-o",
            help="Output path; legacy human/json format values remain accepted.",
        ),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", "-e", help="Glob pattern to exclude."),
    ] = None,
    max_file_size: Annotated[
        int,
        typer.Option("--max-file-size", min=1, help="Maximum file size in bytes."),
    ] = DEFAULT_MAX_FILE_SIZE,
    timeout_seconds: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Maximum scan duration in seconds."),
    ] = 10.0,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", help="Validated YAML policy file."),
    ] = None,
    relative_paths: Annotated[
        bool,
        typer.Option(
            "--relative-paths",
            help="Emit only normalized paths relative to the scan root.",
        ),
    ] = False,
) -> None:
    """Scan a path or only added lines in the staged Git diff."""

    try:
        selected_format, output_path = _resolve_scan_output(output_format, output)
        if staged == (path is not None):
            raise RepositoryConfigError(
                "provide either FILE_OR_DIRECTORY or --staged, but not both"
            )
        if staged:
            result, source_root = _scan_staged(
                repository=repository,
                destination=destination,
                excludes=exclude,
                timeout_seconds=timeout_seconds,
                policy=policy,
            )
        else:
            assert path is not None
            if not path.exists():
                raise OSError(f"scan path does not exist: {path}")
            config_entry = find_repository_config(path)
            config = config_entry[1] if config_entry else None
            if policy is None and config_entry:
                policy = resolve_policy_path(config_entry[0], config_entry[1])
            scanner = _scanner(policy, config.detectors if config else None)
            result = scanner.scan_path(
                path,
                destination=destination or Destination.LOCAL_FILE,
                excludes=exclude,
                max_file_size=max_file_size,
                timeout_seconds=timeout_seconds,
            )
            source_root = (
                config_entry[0]
                if config_entry
                else (path.resolve() if path.is_dir() else path.resolve().parent)
            )
    except ScanTimeoutError as exc:
        typer.echo(f"CodeShield configuration/execution error: {exc}", err=True)
        raise typer.Exit(3) from exc
    except (
        OSError,
        GitIntegrationError,
        PolicyLoadError,
        RepositoryConfigError,
        DetectorError,
        SarifError,
    ) as exc:
        typer.echo(f"CodeShield configuration/execution error: {exc}", err=True)
        raise typer.Exit(3) from exc

    try:
        if relative_paths:
            result = _relativize_result(result, source_root)
        _emit_result(
            result,
            selected_format,
            output_path=output_path,
            source_root=source_root,
        )
    except (SarifError, RepositoryConfigError) as exc:
        typer.echo(f"CodeShield configuration/execution error: {exc}", err=True)
        raise typer.Exit(3) from exc

    raise typer.Exit(_exit_code(result.findings))


@app.command("check-staged")
def check_staged(
    repository: Annotated[
        Path,
        typer.Option("--repository", help="Path inside the target Git repository."),
    ] = Path("."),
    destination: Annotated[
        Destination | None,
        typer.Option("--destination", "-d"),
    ] = None,
    output_format: Annotated[
        OutputFormat | None,
        typer.Option("--format"),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o"),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", "-e"),
    ] = None,
    timeout_seconds: Annotated[
        float,
        typer.Option("--timeout", min=0.1),
    ] = 10.0,
    policy: Annotated[Path | None, typer.Option("--policy")] = None,
    relative_paths: Annotated[
        bool,
        typer.Option("--relative-paths"),
    ] = False,
) -> None:
    """Check staged additions for a commit; warnings do not block the commit."""

    try:
        selected_format, output_path = _resolve_scan_output(output_format, output)
        result, source_root = _scan_staged(
            repository=repository,
            destination=destination,
            excludes=exclude,
            timeout_seconds=timeout_seconds,
            policy=policy,
        )
    except (
        OSError,
        GitIntegrationError,
        PolicyLoadError,
        RepositoryConfigError,
        ScanTimeoutError,
        DetectorError,
        SarifError,
    ) as exc:
        typer.echo(f"CodeShield configuration/execution error: {exc}", err=True)
        raise typer.Exit(3) from exc

    try:
        if relative_paths:
            result = _relativize_result(result, source_root)
        _emit_result(
            result,
            selected_format,
            output_path=output_path,
            source_root=source_root,
        )
    except (SarifError, RepositoryConfigError) as exc:
        typer.echo(f"CodeShield configuration/execution error: {exc}", err=True)
        raise typer.Exit(3) from exc
    raise typer.Exit(2 if _exit_code(result.findings) == 2 else 0)


@app.command("scan-text")
def scan_text(
    stdin: Annotated[
        bool,
        typer.Option("--stdin", help="Read UTF-8 editor content from standard input."),
    ] = False,
    source_path: Annotated[
        str,
        typer.Option(
            "--source-path",
            help="Normalized repository-relative display path for source context.",
        ),
    ] = "editor-input.txt",
    repository: Annotated[
        Path,
        typer.Option("--repository", help="Trusted workspace root."),
    ] = Path("."),
    destination: Annotated[
        Destination,
        typer.Option("--destination", "-d"),
    ] = Destination.LOCAL_FILE,
    profile: Annotated[
        DetectorProfile,
        typer.Option("--profile"),
    ] = DetectorProfile.CORE,
    policy: Annotated[Path | None, typer.Option("--policy")] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format"),
    ] = OutputFormat.JSON,
    max_input_bytes: Annotated[
        int,
        typer.Option("--max-input-bytes", min=1, max=MAX_STDIN_BYTES),
    ] = MAX_STDIN_BYTES,
) -> None:
    """Scan bounded editor text from stdin without creating a temporary file."""

    try:
        if not stdin:
            raise RepositoryConfigError("--stdin is required")
        if output_format is not OutputFormat.JSON:
            raise RepositoryConfigError("scan-text supports only --format json")
        normalized_path = _safe_source_path(source_path)
        text = _read_bounded_stdin(max_input_bytes)
        scanner, file_context = _editor_scanner(
            repository=repository,
            policy=policy,
            profile=profile,
            source_path=normalized_path,
        )
        result = scanner.scan_supplied_text(
            text,
            destination=destination,
            file_context=file_context,
        )
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    except (
        OSError,
        PolicyLoadError,
        RepositoryConfigError,
        DetectorError,
        UnicodeError,
    ) as exc:
        _configuration_error(exc)
    raise typer.Exit(_exit_code(result.findings))


@app.command("protect-text")
def protect_text(
    stdin: Annotated[
        bool,
        typer.Option("--stdin", help="Read UTF-8 editor content from standard input."),
    ] = False,
    source_path: Annotated[
        str,
        typer.Option("--source-path"),
    ] = "editor-input.txt",
    repository: Annotated[
        Path,
        typer.Option("--repository", help="Trusted workspace root."),
    ] = Path("."),
    destination: Annotated[
        Destination,
        typer.Option("--destination", "-d"),
    ] = Destination.LOCAL_FILE,
    profile: Annotated[
        DetectorProfile,
        typer.Option("--profile"),
    ] = DetectorProfile.CORE,
    mode: Annotated[
        ProtectionMode,
        typer.Option("--mode", "-m"),
    ] = ProtectionMode.TYPE_PLACEHOLDER,
    policy: Annotated[Path | None, typer.Option("--policy")] = None,
    vault_path: Annotated[
        Path,
        typer.Option("--vault", help="Encrypted local pseudonym vault."),
    ] = Path(".codeshield-vault.sqlite"),
    session_id: Annotated[
        str,
        typer.Option("--session"),
    ] = "vscode",
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format"),
    ] = OutputFormat.JSON,
    max_input_bytes: Annotated[
        int,
        typer.Option("--max-input-bytes", min=1, max=MAX_STDIN_BYTES),
    ] = MAX_STDIN_BYTES,
) -> None:
    """Protect bounded editor text from stdin and return a structured preview."""

    vault: PseudonymVault | None = None
    try:
        if not stdin:
            raise RepositoryConfigError("--stdin is required")
        if output_format is not OutputFormat.JSON:
            raise RepositoryConfigError("protect-text supports only --format json")
        if not session_id or len(session_id) > 128:
            raise RepositoryConfigError("session must contain 1 to 128 characters")
        normalized_path = _safe_source_path(source_path)
        text = _read_bounded_stdin(max_input_bytes)
        scanner, file_context = _editor_scanner(
            repository=repository,
            policy=policy,
            profile=profile,
            source_path=normalized_path,
        )
        if mode is ProtectionMode.PSEUDONYMIZE:
            vault = PseudonymVault(vault_path, EnvironmentKeyProvider())
        result = scanner.protect_text(
            text,
            destination=destination,
            mode=mode,
            file_context=file_context,
            vault=vault,
            session_id=session_id,
        )
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    except (
        OSError,
        PolicyLoadError,
        ProtectionError,
        VaultError,
        RepositoryConfigError,
        DetectorError,
        UnicodeError,
    ) as exc:
        _configuration_error(exc)
    finally:
        if vault is not None:
            vault.close()
    raise typer.Exit(2 if result.blocked else _exit_code(result.findings))


@app.command("editor-session")
def editor_session() -> None:
    """Serve sequential bounded editor operations over one local stdio process."""

    for line in sys.stdin:
        if len(line.encode("utf-8", errors="ignore")) > 4_000_000:
            _write_session_error("request_too_large")
            continue
        vault: PseudonymVault | None = None
        try:
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise RepositoryConfigError("editor request must be an object")
            command = payload.get("command")
            allowed = {
                "command",
                "content",
                "repository",
                "source_path",
                "destination",
                "profile",
                "policy",
                "mode",
                "vault",
                "session",
                "max_input_bytes",
            }
            if set(payload) - allowed:
                raise RepositoryConfigError("editor request has unknown fields")
            content = payload.get("content")
            if not isinstance(content, str):
                raise RepositoryConfigError("editor content must be text")
            max_bytes = payload.get("max_input_bytes", MAX_STDIN_BYTES)
            if (
                not isinstance(max_bytes, int)
                or isinstance(max_bytes, bool)
                or max_bytes < 1
                or max_bytes > MAX_STDIN_BYTES
                or len(content.encode("utf-8")) > max_bytes
            ):
                raise RepositoryConfigError("editor content exceeds the configured limit")
            repository_value = payload.get("repository")
            source_value = payload.get("source_path")
            if not isinstance(repository_value, str) or not isinstance(
                source_value, str
            ):
                raise RepositoryConfigError("editor paths are invalid")
            source_path = _safe_source_path(source_value)
            policy_value = payload.get("policy")
            if policy_value is not None and not isinstance(policy_value, str):
                raise RepositoryConfigError("editor policy is invalid")
            scanner, file_context = _editor_scanner(
                repository=Path(repository_value),
                policy=Path(policy_value) if policy_value else None,
                profile=DetectorProfile(str(payload.get("profile", "core"))),
                source_path=source_path,
            )
            destination = Destination(str(payload.get("destination", "local_file")))
            if command == "scan-text":
                result = scanner.scan_supplied_text(
                    content,
                    destination=destination,
                    file_context=file_context,
                )
                _write_session_result(
                    _exit_code(result.findings),
                    result.model_dump(mode="json"),
                )
                continue
            if command != "protect-text":
                raise RepositoryConfigError("editor command is invalid")
            mode = ProtectionMode(str(payload.get("mode", "type_placeholder")))
            session_id = payload.get("session", "vscode")
            if not isinstance(session_id, str) or not 1 <= len(session_id) <= 128:
                raise RepositoryConfigError("editor session is invalid")
            if mode is ProtectionMode.PSEUDONYMIZE:
                vault_value = payload.get("vault")
                if not isinstance(vault_value, str) or not vault_value:
                    raise RepositoryConfigError("local vault path is required")
                vault = PseudonymVault(Path(vault_value), EnvironmentKeyProvider())
            result = scanner.protect_text(
                content,
                destination=destination,
                mode=mode,
                file_context=file_context,
                vault=vault,
                session_id=session_id,
            )
            _write_session_result(
                2 if result.blocked else _exit_code(result.findings),
                result.model_dump(mode="json"),
            )
        except (
            json.JSONDecodeError,
            ValueError,
            OSError,
            PolicyLoadError,
            ProtectionError,
            VaultError,
            RepositoryConfigError,
            DetectorError,
        ):
            _write_session_error("configuration_or_execution_error")
        finally:
            if vault is not None:
                vault.close()


@app.command("install-hook")
def install_hook(
    repository: Annotated[Path, typer.Option("--repository")] = Path("."),
) -> None:
    """Install or update the CodeShield-managed Git pre-commit hook."""

    try:
        manager = _hook_manager(repository)
        manager.install()
    except (OSError, GitIntegrationError) as exc:
        typer.echo(f"CodeShield hook error: {exc}", err=True)
        raise typer.Exit(3) from exc
    typer.echo(f"CodeShield pre-commit hook installed: {manager.path}")


@app.command("uninstall-hook")
def uninstall_hook(
    repository: Annotated[Path, typer.Option("--repository")] = Path("."),
) -> None:
    """Remove only a CodeShield-managed Git pre-commit hook."""

    try:
        manager = _hook_manager(repository)
        manager.uninstall()
    except (OSError, GitIntegrationError) as exc:
        typer.echo(f"CodeShield hook error: {exc}", err=True)
        raise typer.Exit(3) from exc
    typer.echo("CodeShield pre-commit hook is not installed.")


@app.command("hook-status")
def hook_status(
    repository: Annotated[Path, typer.Option("--repository")] = Path("."),
) -> None:
    """Report whether the repository hook is managed by CodeShield."""

    try:
        manager = _hook_manager(repository)
        status = manager.status()
    except (OSError, GitIntegrationError) as exc:
        typer.echo(f"CodeShield hook error: {exc}", err=True)
        raise typer.Exit(3) from exc
    typer.echo(f"CodeShield hook status: {status.value}")
    if status is HookStatus.UNMANAGED:
        raise typer.Exit(1)


@app.command()
def protect(
    path: Annotated[
        Path,
        typer.Argument(exists=True, readable=True, file_okay=True, dir_okay=False),
    ],
    destination: Annotated[
        Destination,
        typer.Option("--destination", "-d"),
    ] = Destination.LOCAL_FILE,
    mode: Annotated[
        ProtectionMode,
        typer.Option("--mode", "-m"),
    ] = ProtectionMode.TYPE_PLACEHOLDER,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file; omit for standard output."),
    ] = None,
    policy: Annotated[Path | None, typer.Option("--policy")] = None,
    vault_path: Annotated[
        Path,
        typer.Option("--vault", help="Encrypted local pseudonym vault."),
    ] = Path(".codeshield-vault.sqlite"),
    session_id: Annotated[
        str,
        typer.Option("--session", help="Local pseudonym consistency scope."),
    ] = "default",
) -> None:
    """Protect a text file without changing the input file."""

    vault: PseudonymVault | None = None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        config_entry = find_repository_config(path)
        config = config_entry[1] if config_entry else None
        if policy is None and config_entry:
            policy = resolve_policy_path(config_entry[0], config_entry[1])
        scanner = _scanner(policy, config.detectors if config else None)
        if mode is ProtectionMode.PSEUDONYMIZE:
            vault = PseudonymVault(vault_path, EnvironmentKeyProvider())
        result = scanner.protect_text(
            text,
            destination=destination,
            mode=mode,
            vault=vault,
            session_id=session_id,
        )
        if result.blocked:
            typer.echo(
                "CodeShield blocked protection output because a mandatory block rule matched.",
                err=True,
            )
            raise typer.Exit(2)
        if output is None:
            typer.echo(result.protected_text, nl=False)
        else:
            if output.resolve() == path.resolve():
                raise ProtectionError("output path must differ from the input path")
            output.write_text(result.protected_text, encoding="utf-8")
            typer.echo(f"Protected output written to {output}")
    except typer.Exit:
        raise
    except (OSError, PolicyLoadError, ProtectionError, VaultError, DetectorError) as exc:
        typer.echo(f"CodeShield configuration/execution error: {exc}", err=True)
        raise typer.Exit(3) from exc
    finally:
        if vault is not None:
            vault.close()


@app.command()
def restore(
    path: Annotated[
        Path,
        typer.Argument(exists=True, readable=True, file_okay=True, dir_okay=False),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file; omit for standard output."),
    ] = None,
    vault_path: Annotated[Path, typer.Option("--vault")] = Path(
        ".codeshield-vault.sqlite"
    ),
    session_id: Annotated[str, typer.Option("--session")] = "default",
) -> None:
    """Restore known pseudonyms locally using the encrypted vault."""

    vault: PseudonymVault | None = None
    try:
        vault = PseudonymVault(vault_path, EnvironmentKeyProvider())
        restored = vault.restore_text(
            path.read_text(encoding="utf-8", errors="replace"),
            session_id=session_id,
        )
        if output is None:
            typer.echo(restored, nl=False)
        else:
            output.write_text(restored, encoding="utf-8")
            typer.echo(f"Restored output written to {output}")
    except (OSError, VaultError) as exc:
        typer.echo(f"CodeShield configuration/execution error: {exc}", err=True)
        raise typer.Exit(3) from exc
    finally:
        if vault is not None:
            vault.close()


@policy_app.command("validate")
def validate_policy(
    path: Annotated[
        Path,
        typer.Argument(exists=True, readable=True, file_okay=True, dir_okay=False),
    ],
) -> None:
    """Validate a CodeShield YAML policy."""

    try:
        document = load_policy(path)
    except PolicyLoadError as exc:
        typer.echo(f"Invalid CodeShield policy: {exc}", err=True)
        raise typer.Exit(3) from exc
    typer.echo(
        f"Policy '{document.name}' is valid "
        f"({len(document.rules)} destination and {len(document.llm_rules)} LLM rule(s))."
    )


@provider_app.command("list")
def provider_list(
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format"),
    ] = OutputFormat.HUMAN,
) -> None:
    """List reviewed provider profiles without account data."""

    try:
        profiles = ProviderRegistry().list()
    except ProviderRegistryError as exc:
        _configuration_error(exc)
    if output_format is OutputFormat.JSON:
        typer.echo(
            json.dumps(
                [profile.model_dump(mode="json") for profile in profiles],
                indent=2,
            )
        )
        return
    if output_format is OutputFormat.SARIF:
        _configuration_error(ValueError("provider list does not support SARIF"))
    for profile in profiles:
        typer.echo(
            f"{profile.profile_id} {profile.provider} {profile.product} "
            f"surface={profile.surface} review_due={profile.review_due.isoformat()} "
            f"reference_only={str(profile.reference_only).lower()}"
        )


@provider_app.command("show")
def provider_show(profile_id: Annotated[str, typer.Argument()]) -> None:
    """Show the reviewed facts for one provider profile."""

    try:
        profile = ProviderRegistry().require(profile_id)
    except ProviderRegistryError as exc:
        _configuration_error(exc)
    typer.echo(json.dumps(profile.model_dump(mode="json"), indent=2))


@provider_app.command("attest")
def provider_attest(
    profile_id: Annotated[str, typer.Argument()],
    attestation_id: Annotated[str, typer.Option("--id")],
    account_hash: Annotated[str, typer.Option("--account-hash")],
    evidence_digest: Annotated[str, typer.Option("--evidence-digest")],
    reviewer_id: Annotated[str, typer.Option("--reviewer")],
    expires_on: Annotated[str, typer.Option("--expires")],
    control: Annotated[list[str] | None, typer.Option("--control")] = None,
) -> None:
    """Record local administrative evidence; no evidence document is stored."""

    try:
        registry = ProviderRegistry()
        profile = registry.require(profile_id)
        attestation = ProviderAttestation(
            attestation_id=attestation_id,
            profile_id=profile.profile_id,
            profile_version=profile.version,
            account_hash=account_hash,
            enabled_controls=control or ["reviewed"],
            evidence_digest=evidence_digest,
            reviewer_id=reviewer_id,
            created_on=date.today(),
            expires_on=date.fromisoformat(expires_on),
        )
        AttestationStore().save(attestation, registry)
    except (ProviderRegistryError, ValueError) as exc:
        _configuration_error(exc)
    typer.echo(f"Provider attestation recorded locally: {attestation_id}")


@provider_app.command("verify")
def provider_verify(
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format"),
    ] = OutputFormat.HUMAN,
) -> None:
    """Fail when checked-in provider evidence is stale or inconsistent."""

    try:
        errors = ProviderRegistry().verify()
    except ProviderRegistryError as exc:
        _configuration_error(exc)
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps({"valid": not errors, "issues": errors}, indent=2))
        if errors:
            raise typer.Exit(3)
        return
    if output_format is OutputFormat.SARIF:
        _configuration_error(ValueError("provider verify does not support SARIF"))
    if errors:
        for error in errors:
            typer.echo(error, err=True)
        raise typer.Exit(3)
    typer.echo("Provider profiles are current and internally consistent.")


@provider_app.command("attestation-status")
def provider_attestation_status(
    profile_id: Annotated[str, typer.Argument()],
    attestation_id: Annotated[str | None, typer.Option("--id")] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format"),
    ] = OutputFormat.JSON,
) -> None:
    """Return only the reviewed profile identity and local attestation status."""

    if output_format is not OutputFormat.JSON:
        _configuration_error(
            ValueError("provider attestation-status supports only JSON")
        )
    try:
        profile = ProviderRegistry().require(profile_id)
        status, _ = AttestationStore().status(attestation_id, profile)
    except ProviderRegistryError as exc:
        _configuration_error(exc)
    typer.echo(
        json.dumps(
            {
                "profile_id": profile.profile_id,
                "profile_version": profile.version,
                "status": status.value,
            },
            indent=2,
        )
    )


@detector_app.command("status")
def show_detector_status(
    repository: Annotated[Path, typer.Option("--repository")] = Path("."),
) -> None:
    """Show configured, enabled, and locally available detector adapters."""

    try:
        config_entry = find_repository_config(repository)
        settings = config_entry[1].detectors if config_entry else DetectorConfig()
        typer.echo(
            json.dumps(
                {"profile": settings.profile.value, "detectors": detector_status(settings)},
                indent=2,
            )
        )
    except (OSError, RepositoryConfigError) as exc:
        _configuration_error(exc)


@prompt_app.command("assess")
def prompt_assess(
    provider: Annotated[str, typer.Option("--provider")],
    file: Annotated[Path | None, typer.Option("--file")] = None,
    stdin: Annotated[bool, typer.Option("--stdin")] = False,
    manifest: Annotated[Path | None, typer.Option("--manifest")] = None,
    kind: Annotated[SegmentKind, typer.Option("--kind")] = SegmentKind.USER,
    provenance: Annotated[
        SegmentProvenance, typer.Option("--provenance")
    ] = SegmentProvenance.TRUSTED,
    attestation: Annotated[str | None, typer.Option("--attestation")] = None,
    direction: Annotated[
        TransferDirection, typer.Option("--direction")
    ] = TransferDirection.OUTBOUND,
    purpose: Annotated[str, typer.Option("--purpose")] = "developer assistance",
    feature: Annotated[list[ProviderFeature] | None, typer.Option("--feature")] = None,
    privileged_tools: Annotated[bool, typer.Option("--privileged-tools")] = False,
) -> None:
    """Assess file, stdin, or structured manifest content locally."""

    request = _prompt_request(
        provider=provider,
        file=file,
        stdin=stdin,
        manifest=manifest,
        kind=kind,
        provenance=provenance,
        attestation=attestation,
        direction=direction,
        purpose=purpose,
        features=feature,
        privileged_tools=privileged_tools,
    )
    result = LlmPreflightService().assess(request)
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    raise typer.Exit(_preflight_exit(result.action))


@prompt_app.command("protect")
def prompt_protect(
    provider: Annotated[str, typer.Option("--provider")],
    file: Annotated[Path | None, typer.Option("--file")] = None,
    stdin: Annotated[bool, typer.Option("--stdin")] = False,
    manifest: Annotated[Path | None, typer.Option("--manifest")] = None,
    kind: Annotated[SegmentKind, typer.Option("--kind")] = SegmentKind.USER,
    provenance: Annotated[
        SegmentProvenance, typer.Option("--provenance")
    ] = SegmentProvenance.TRUSTED,
    attestation: Annotated[str | None, typer.Option("--attestation")] = None,
    direction: Annotated[
        TransferDirection, typer.Option("--direction")
    ] = TransferDirection.OUTBOUND,
    purpose: Annotated[str, typer.Option("--purpose")] = "developer assistance",
    feature: Annotated[list[ProviderFeature] | None, typer.Option("--feature")] = None,
    privileged_tools: Annotated[bool, typer.Option("--privileged-tools")] = False,
) -> None:
    """Protect eligible content locally and return no content when blocked."""

    request = _prompt_request(
        provider=provider,
        file=file,
        stdin=stdin,
        manifest=manifest,
        kind=kind,
        provenance=provenance,
        attestation=attestation,
        direction=direction,
        purpose=purpose,
        features=feature,
        privileged_tools=privileged_tools,
    )
    result = LlmPreflightService().protect(request)
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    raise typer.Exit(_preflight_exit(result.assessment.action))


@app.command()
def server(
    host: Annotated[
        str,
        typer.Option("--host", help="Bind host. Defaults to loopback for local safety."),
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8765,
    reload: Annotated[bool, typer.Option("--reload", help="Enable dev reload.")] = False,
) -> None:
    """Run the local FastAPI service."""

    import uvicorn

    uvicorn.run("codeshield.api.main:app", host=host, port=port, reload=reload)


@app.command("version")
def version_command() -> None:
    """Print the CodeShield engine version."""

    typer.echo(__version__)


@app.command("evaluate-context")
def evaluate_context(
    seed: Annotated[int, typer.Option("--seed", min=0)] = 42,
) -> None:
    """Evaluate the context classifier on deterministic synthetic data."""

    typer.echo(json.dumps(evaluate_context_classifier(seed=seed), indent=2))


@evaluate_app.command("prepare")
def evaluate_prepare(
    suite: Annotated[str, typer.Option("--suite")] = "phase5",
) -> None:
    """Prepare deterministic evaluation data outside the repository."""

    try:
        typer.echo(json.dumps(prepare_suite(suite=suite), indent=2))
    except EvaluationError as exc:
        _configuration_error(exc)


@evaluate_app.command("run")
def evaluate_run(
    profile: Annotated[DetectorProfile, typer.Option("--profile")],
    output: Annotated[Path, typer.Option("--output")],
    suite: Annotated[str, typer.Option("--suite")] = "phase5",
) -> None:
    """Run a profile evaluation and write safe JSON and Markdown reports."""

    try:
        report = run_evaluation(profile=profile, output=output, suite=suite)
    except (EvaluationError, DetectorError, OSError) as exc:
        _configuration_error(exc)
    typer.echo(
        json.dumps(
            {
                "profile": report["profile"],
                "suite_version": report["suite_version"],
                "output": str(output),
                "markdown": str(output.with_suffix(".md")),
            },
            indent=2,
        )
    )


@evaluate_app.command("compare")
def evaluate_compare(
    baseline: Annotated[Path, typer.Argument(exists=True, readable=True)],
    candidate: Annotated[Path, typer.Argument(exists=True, readable=True)],
) -> None:
    """Compare aggregate reports and fail on metric or security regressions."""

    try:
        result = compare_reports(baseline, candidate)
    except EvaluationError as exc:
        _configuration_error(exc)
    typer.echo(json.dumps(result, indent=2))
    if not result["passed"]:
        raise typer.Exit(2)


def _render_human_result(result: object) -> str:
    findings = result.findings
    lines = [
        f"CodeShield scan complete: {len(findings)} finding(s), "
        f"{result.files_scanned} file(s) scanned, "
        f"{len(result.files_skipped)} skipped."
    ]
    for finding in findings:
        location = finding.file_path or "<text>"
        if finding.line and finding.column:
            location = f"{location}:{finding.line}:{finding.column}"
        risk = finding.risk.score if finding.risk else "n/a"
        context = finding.context.label.value if finding.context else "unknown"
        policy = (
            finding.policy_decision.matched_rule_id
            if finding.policy_decision and finding.policy_decision.matched_rule_id
            else "none"
        )
        exception = (
            finding.policy_decision.exception_id
            if finding.policy_decision and finding.policy_decision.exception_id
            else "none"
        )
        lines.append(
            f"{location} {finding.data_category.value} "
            f"{finding.severity.value} action={finding.recommended_action.value} "
            f"risk={risk} context={context} policy={policy} "
            f"exception={exception} "
            f"preview={finding.masked_preview} - {finding.explanation}"
        )
    for skipped in result.files_skipped:
        lines.append(f"skipped {skipped.path}: {skipped.reason}")
    return "\n".join(lines) + "\n"


def _exit_code(findings: list[object]) -> int:
    if any(finding.recommended_action is RecommendedAction.BLOCK for finding in findings):
        return 2
    if any(
        finding.recommended_action
        in {
            RecommendedAction.WARN,
            RecommendedAction.MASK,
            RecommendedAction.PSEUDONYMIZE,
        }
        for finding in findings
    ):
        return 1
    return 0


def _resolve_scan_output(
    output_format: OutputFormat | None, output: str | None
) -> tuple[OutputFormat, Path | None]:
    if output_format is None and output in {
        OutputFormat.HUMAN.value,
        OutputFormat.JSON.value,
    }:
        typer.echo(
            "CodeShield notice: --output as a format is deprecated; use --format.",
            err=True,
        )
        return OutputFormat(output), None
    return output_format or OutputFormat.HUMAN, Path(output) if output else None


def _emit_result(
    result: object,
    output_format: OutputFormat,
    *,
    output_path: Path | None,
    source_root: Path,
) -> None:
    if output_format is OutputFormat.JSON:
        content = json.dumps(result.model_dump(mode="json"), indent=2) + "\n"
    elif output_format is OutputFormat.SARIF:
        content = render_sarif(result, source_root=source_root)
    else:
        content = _render_human_result(result)
    if output_path is not None:
        write_output(output_path, content)
    else:
        typer.echo(content, nl=False)


def _scan_staged(
    *,
    repository: Path,
    destination: Destination | None,
    excludes: list[str] | None,
    timeout_seconds: float,
    policy: Path | None,
) -> tuple[object, Path]:
    git_repository = GitRepository.discover(
        repository, timeout_seconds=timeout_seconds
    )
    config = load_repository_config(git_repository.root)
    if destination is None:
        if config is None:
            raise RepositoryConfigError(
                "staged destination is required: use --destination or "
                "set repository_visibility in .codeshield.yaml"
            )
        destination = config.repository_visibility.destination
    if policy is None and config is not None:
        policy = resolve_policy_path(git_repository.root, config)
    repository_visibility = (
        config.repository_visibility.value if config is not None else None
    )
    result = StagedGitScanner(
        _scanner(policy, config.detectors if config else None)
    ).scan(
        git_repository,
        destination=destination,
        excludes=excludes,
        timeout_seconds=timeout_seconds,
        repository_visibility=repository_visibility,
    )
    return result, git_repository.root


def _hook_manager(repository: Path) -> HookManager:
    return HookManager(GitRepository.discover(repository))


def _scanner(
    policy_path: Path | None,
    detector_config: DetectorConfig | None = None,
) -> CodeShieldScanner:
    policy_engine = PolicyEngine.from_path(policy_path)
    return CodeShieldScanner(policy_engine=policy_engine, detector_config=detector_config)


def _relativize_result(result: ScanResult, source_root: Path) -> ScanResult:
    root = source_root.resolve()

    def relative_path(value: str) -> str:
        candidate = Path(value)
        try:
            relative = (
                candidate.resolve().relative_to(root)
                if candidate.is_absolute()
                else candidate
            )
        except (OSError, ValueError) as exc:
            raise RepositoryConfigError(
                "scan result contains an unsafe source path"
            ) from exc
        normalized = _safe_source_path(relative.as_posix())
        return normalized

    findings = [
        finding.model_copy(
            update={
                "file_path": relative_path(finding.file_path)
                if finding.file_path
                else None
            }
        )
        for finding in result.findings
    ]
    skipped = [
        SkippedFile(path=relative_path(item.path), reason=item.reason)
        for item in result.files_skipped
    ]
    return result.model_copy(
        update={"findings": findings, "files_skipped": skipped}
    )


def _read_bounded_stdin(max_bytes: int) -> str:
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    payload = stream.read(max_bytes + 1)
    if isinstance(payload, str):
        encoded = payload.encode("utf-8")
        if len(encoded) > max_bytes:
            raise RepositoryConfigError("standard input exceeds the configured limit")
        return payload
    if len(payload) > max_bytes:
        raise RepositoryConfigError("standard input exceeds the configured limit")
    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RepositoryConfigError("standard input must be valid UTF-8") from exc


def _write_session_result(exit_code: int, result: dict[str, object]) -> None:
    sys.stdout.write(
        json.dumps(
            {"exit_code": exit_code, "result": result},
            separators=(",", ":"),
        )
        + "\n"
    )
    sys.stdout.flush()


def _write_session_error(code: str) -> None:
    sys.stdout.write(
        json.dumps(
            {"exit_code": 3, "error_code": code},
            separators=(",", ":"),
        )
        + "\n"
    )
    sys.stdout.flush()


def _safe_source_path(value: str) -> str:
    if not value or len(value) > 1024 or "\x00" in value:
        raise RepositoryConfigError("source path is invalid")
    normalized = value.replace("\\", "/")
    posix = PurePosixPath(normalized)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", normalized)
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise RepositoryConfigError("source path must be repository-relative")
    return posix.as_posix()


def _editor_scanner(
    *,
    repository: Path,
    policy: Path | None,
    profile: DetectorProfile,
    source_path: str,
) -> tuple[CodeShieldScanner, FileContext]:
    root = repository.resolve()
    if not root.exists() or not root.is_dir():
        raise RepositoryConfigError("trusted workspace root is unavailable")
    config_entry = find_repository_config(root)
    config = config_entry[1] if config_entry else None
    if policy is not None:
        if policy.is_absolute() or ".." in policy.parts:
            raise RepositoryConfigError("policy path must be workspace-relative")
        resolved_policy = (root / policy).resolve()
        if not resolved_policy.is_relative_to(root):
            raise RepositoryConfigError("policy path escapes trusted workspace")
        if not resolved_policy.is_file():
            raise RepositoryConfigError("policy file is unavailable")
        policy = resolved_policy
    elif config_entry:
        policy = resolve_policy_path(config_entry[0], config_entry[1])
    settings = config.detectors if config else DetectorConfig()
    settings = settings.model_copy(update={"profile": profile})
    repository_visibility = (
        config.repository_visibility.value if config is not None else None
    )
    context = FileContext.from_path(Path(source_path)).model_copy(
        update={"path": source_path, "repository_visibility": repository_visibility}
    )
    return _scanner(policy, settings), context


def _prompt_request(
    *,
    provider: str,
    file: Path | None,
    stdin: bool,
    manifest: Path | None,
    kind: SegmentKind,
    provenance: SegmentProvenance,
    attestation: str | None,
    direction: TransferDirection,
    purpose: str,
    features: list[ProviderFeature] | None,
    privileged_tools: bool,
) -> LlmPreflightRequest:
    if sum((file is not None, stdin, manifest is not None)) != 1:
        _configuration_error(
            ValueError("provide exactly one of --file, --stdin, or --manifest")
        )
    try:
        if manifest is not None:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("segments"), list):
                raise ValueError("prompt manifest must contain a segments array")
            segments = [ContentSegment.model_validate(item) for item in payload["segments"]]
        else:
            if file is not None:
                content = file.read_text(encoding="utf-8", errors="replace")
                path = str(file)
            else:
                content = sys.stdin.read()
                path = None
            segments = [
                ContentSegment(
                    segment_id="input-1",
                    kind=kind,
                    content=content,
                    provenance=provenance,
                    path=path,
                )
            ]
        return LlmPreflightRequest(
            segments=segments,
            provider_profile_id=provider,
            attestation_id=attestation,
            direction=direction,
            purpose=purpose,
            enabled_features=features or [],
            privileged_tools=privileged_tools,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        _configuration_error(ValueError("invalid prompt input or manifest"))


def _preflight_exit(action: RecommendedAction) -> int:
    if action is RecommendedAction.BLOCK:
        return 2
    if action in {
        RecommendedAction.WARN,
        RecommendedAction.MASK,
        RecommendedAction.PSEUDONYMIZE,
    }:
        return 1
    return 0


def _configuration_error(exc: Exception) -> None:
    typer.echo(f"CodeShield configuration/execution error: {exc}", err=True)
    raise typer.Exit(3) from exc


if __name__ == "__main__":
    app()
