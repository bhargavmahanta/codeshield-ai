"""Typer CLI for the CodeShield local engine."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
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
    RepositoryConfigError,
    load_repository_config,
    resolve_policy_path,
)
from codeshield.models.enums import Destination, RecommendedAction
from codeshield.models.enums import ProtectionMode
from codeshield.policies import PolicyEngine, PolicyLoadError, load_policy
from codeshield.pseudonymization import (
    EnvironmentKeyProvider,
    ProtectionError,
    PseudonymVault,
    VaultError,
)
from codeshield.scanner import DEFAULT_MAX_FILE_SIZE, CodeShieldScanner, ScanTimeoutError
from codeshield.version import __version__


class OutputFormat(StrEnum):
    HUMAN = "human"
    JSON = "json"


app = typer.Typer(
    name="codeshield",
    no_args_is_help=True,
    help="Local-first sensitive data scanner for developer workflows.",
)
policy_app = typer.Typer(help="Validate and inspect destination policy files.")
app.add_typer(policy_app, name="policy")


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
    output: Annotated[
        OutputFormat,
        typer.Option("--output", "-o", help="Output format."),
    ] = OutputFormat.HUMAN,
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
) -> None:
    """Scan a path or only added lines in the staged Git diff."""

    try:
        if staged == (path is not None):
            raise RepositoryConfigError(
                "provide either FILE_OR_DIRECTORY or --staged, but not both"
            )
        if staged:
            result = _scan_staged(
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
            scanner = _scanner(policy)
            result = scanner.scan_path(
                path,
                destination=destination or Destination.LOCAL_FILE,
                excludes=exclude,
                max_file_size=max_file_size,
                timeout_seconds=timeout_seconds,
            )
    except ScanTimeoutError as exc:
        typer.echo(f"CodeShield configuration/execution error: {exc}", err=True)
        raise typer.Exit(3) from exc
    except (
        OSError,
        GitIntegrationError,
        PolicyLoadError,
        RepositoryConfigError,
    ) as exc:
        typer.echo(f"CodeShield configuration/execution error: {exc}", err=True)
        raise typer.Exit(3) from exc

    _print_result(result, output)

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
    output: Annotated[
        OutputFormat,
        typer.Option("--output", "-o"),
    ] = OutputFormat.HUMAN,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", "-e"),
    ] = None,
    timeout_seconds: Annotated[
        float,
        typer.Option("--timeout", min=0.1),
    ] = 10.0,
    policy: Annotated[Path | None, typer.Option("--policy")] = None,
) -> None:
    """Check staged additions for a commit; warnings do not block the commit."""

    try:
        result = _scan_staged(
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
    ) as exc:
        typer.echo(f"CodeShield configuration/execution error: {exc}", err=True)
        raise typer.Exit(3) from exc

    _print_result(result, output)
    raise typer.Exit(2 if _exit_code(result.findings) == 2 else 0)


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
        scanner = _scanner(policy)
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
    except (OSError, PolicyLoadError, ProtectionError, VaultError) as exc:
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
        f"Policy '{document.name}' is valid ({len(document.rules)} rule(s))."
    )


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


def _print_human_result(result: object) -> None:
    findings = result.findings
    typer.echo(
        f"CodeShield scan complete: {len(findings)} finding(s), "
        f"{result.files_scanned} file(s) scanned, "
        f"{len(result.files_skipped)} skipped."
    )
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
        typer.echo(
            f"{location} {finding.data_category.value} "
            f"{finding.severity.value} action={finding.recommended_action.value} "
            f"risk={risk} context={context} policy={policy} "
            f"exception={exception} "
            f"preview={finding.masked_preview} - {finding.explanation}"
        )
    for skipped in result.files_skipped:
        typer.echo(f"skipped {skipped.path}: {skipped.reason}")


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


def _print_result(result: object, output: OutputFormat) -> None:
    if output is OutputFormat.JSON:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    else:
        _print_human_result(result)


def _scan_staged(
    *,
    repository: Path,
    destination: Destination | None,
    excludes: list[str] | None,
    timeout_seconds: float,
    policy: Path | None,
) -> object:
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
    return StagedGitScanner(_scanner(policy)).scan(
        git_repository,
        destination=destination,
        excludes=excludes,
        timeout_seconds=timeout_seconds,
        repository_visibility=repository_visibility,
    )


def _hook_manager(repository: Path) -> HookManager:
    return HookManager(GitRepository.discover(repository))


def _scanner(policy_path: Path | None) -> CodeShieldScanner:
    policy_engine = PolicyEngine.from_path(policy_path)
    return CodeShieldScanner(policy_engine=policy_engine)


if __name__ == "__main__":
    app()
