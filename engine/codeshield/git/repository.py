"""Safe Git subprocess adapter and staged unified-diff parsing."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from unidiff import PatchSet
from unidiff.errors import UnidiffParseError


class GitIntegrationError(RuntimeError):
    """Safe Git error that never includes diff content."""


@dataclass(frozen=True)
class StagedTextBlock:
    path: str
    start_line: int
    text: str


@dataclass(frozen=True)
class StagedDiff:
    blocks: list[StagedTextBlock]
    binary_paths: list[str]


class GitRepository:
    def __init__(self, root: Path, *, timeout_seconds: float = 10.0) -> None:
        self.root = root.resolve()
        self.timeout_seconds = timeout_seconds

    @classmethod
    def discover(
        cls, start: Path, *, timeout_seconds: float = 10.0
    ) -> "GitRepository":
        result = _run_git(
            start.resolve(),
            ["rev-parse", "--show-toplevel"],
            timeout_seconds=timeout_seconds,
        )
        root_text = result.stdout.strip()
        if not root_text:
            raise GitIntegrationError("Git repository root was not returned")
        return cls(Path(root_text), timeout_seconds=timeout_seconds)

    def staged_diff(self) -> StagedDiff:
        result = _run_git(
            self.root,
            [
                "diff",
                "--cached",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                "--diff-filter=ACMR",
                "--",
            ],
            timeout_seconds=self.timeout_seconds,
        )
        try:
            patch = PatchSet(result.stdout.splitlines(keepends=True))
        except (UnidiffParseError, ValueError) as exc:
            raise GitIntegrationError("unable to parse staged Git diff") from exc

        blocks: list[StagedTextBlock] = []
        binary_paths: list[str] = []
        for patched_file in patch:
            path = str(patched_file.path).replace("\\", "/")
            if patched_file.is_binary_file:
                binary_paths.append(path)
                continue
            for hunk in patched_file:
                blocks.extend(_added_blocks(path, hunk))
        return StagedDiff(blocks=blocks, binary_paths=binary_paths)

    def git_path(self, name: str) -> Path:
        result = _run_git(
            self.root,
            ["rev-parse", "--git-path", name],
            timeout_seconds=self.timeout_seconds,
        )
        path = Path(result.stdout.strip())
        return path.resolve() if path.is_absolute() else (self.root / path).resolve()


def _added_blocks(path: str, hunk: object) -> list[StagedTextBlock]:
    blocks: list[StagedTextBlock] = []
    values: list[str] = []
    start_line: int | None = None
    previous_line: int | None = None

    def flush() -> None:
        nonlocal values, start_line, previous_line
        if values and start_line is not None:
            blocks.append(
                StagedTextBlock(path=path, start_line=start_line, text="".join(values))
            )
        values = []
        start_line = None
        previous_line = None

    for line in hunk:  # type: ignore[union-attr]
        target_line = line.target_line_no
        if not line.is_added or target_line is None:
            flush()
            continue
        if previous_line is not None and target_line != previous_line + 1:
            flush()
        if start_line is None:
            start_line = int(target_line)
        values.append(str(line.value))
        previous_line = int(target_line)
    flush()
    return blocks


def _run_git(
    cwd: Path,
    arguments: list[str],
    *,
    timeout_seconds: float,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise GitIntegrationError("Git executable was not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitIntegrationError("Git command timed out") from exc
    except subprocess.CalledProcessError as exc:
        raise GitIntegrationError("Git command failed") from exc
