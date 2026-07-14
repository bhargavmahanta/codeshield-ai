"""Scan only added text from the staged Git diff."""

from __future__ import annotations

import fnmatch
import time
from hashlib import sha256
from pathlib import Path

from codeshield.git.repository import GitRepository, StagedTextBlock
from codeshield.models.context import FileContext
from codeshield.models.enums import Destination
from codeshield.models.finding import Finding
from codeshield.models.scan import ScanResult, SkippedFile
from codeshield.scanner import CodeShieldScanner, DEFAULT_EXCLUDES, ScanTimeoutError


class StagedGitScanner:
    def __init__(self, scanner: CodeShieldScanner) -> None:
        self.scanner = scanner

    def scan(
        self,
        repository: GitRepository,
        *,
        destination: Destination,
        excludes: list[str] | None = None,
        timeout_seconds: float = 10.0,
        repository_visibility: str | None = None,
    ) -> ScanResult:
        started = time.monotonic()
        deadline = started + timeout_seconds
        staged = repository.staged_diff()
        patterns = _load_ignore_patterns(repository.root)
        patterns.extend(excludes or [])
        result = ScanResult(destination=destination)
        skipped_paths: set[str] = set()
        scanned_paths: set[str] = set()

        for binary_path in staged.binary_paths:
            result.files_skipped.append(
                SkippedFile(path=binary_path, reason="binary staged patch")
            )
            skipped_paths.add(binary_path)

        for block in staged.blocks:
            if time.monotonic() > deadline:
                raise ScanTimeoutError(
                    f"staged scan exceeded {timeout_seconds:.1f} seconds"
                )
            if _is_excluded(block.path, patterns):
                if block.path not in skipped_paths:
                    result.files_skipped.append(
                        SkippedFile(path=block.path, reason="excluded")
                    )
                    skipped_paths.add(block.path)
                continue
            scanned_paths.add(block.path)
            context = FileContext.from_path(Path(block.path)).model_copy(
                update={"repository_visibility": repository_visibility}
            )
            findings = self.scanner.scan_text(
                block.text,
                destination=destination,
                file_context=context,
            )
            result.findings.extend(
                _attach_staged_location(finding, block) for finding in findings
            )
            result.scanned_bytes += len(block.text.encode("utf-8"))

        return result.model_copy(
            update={
                "files_scanned": len(scanned_paths),
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            }
        )


def _attach_staged_location(finding: Finding, block: StagedTextBlock) -> Finding:
    line_offset = block.text.count("\n", 0, finding.start)
    last_newline = block.text.rfind("\n", 0, finding.start)
    column = finding.start + 1 if last_newline == -1 else finding.start - last_newline
    line = block.start_line + line_offset
    location_id = sha256(
        f"{block.path}:{line}:{column}:{finding.finding_id}".encode("utf-8")
    ).hexdigest()[:24]
    return finding.model_copy(
        update={
            "finding_id": location_id,
            "file_path": block.path,
            "line": line,
            "column": column,
        }
    )


def _load_ignore_patterns(root: Path) -> list[str]:
    path = root / ".codeshieldignore"
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _is_excluded(path: str, patterns: list[str]) -> bool:
    normalized = path.replace("\\", "/")
    parts = Path(normalized).parts
    if any(part in DEFAULT_EXCLUDES for part in parts):
        return True
    return any(
        fnmatch.fnmatch(normalized, pattern)
        or fnmatch.fnmatch(Path(normalized).name, pattern)
        or fnmatch.fnmatch(normalized, pattern.rstrip("/") + "/*")
        for pattern in patterns
    )
