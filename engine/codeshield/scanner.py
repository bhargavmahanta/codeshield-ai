"""High-level text and filesystem scanning."""

from __future__ import annotations

import fnmatch
import time
from pathlib import Path

from codeshield.classifier import ContextClassifier
from codeshield.detectors import SensitiveDataDetector, build_detectors
from codeshield.detectors.dedupe import deduplicate_findings
from codeshield.models.context import FileContext
from codeshield.models.config import DetectorConfig
from codeshield.models.enums import Destination, ProtectionMode
from codeshield.models.finding import Finding
from codeshield.models.protection import ProtectionResult
from codeshield.models.scan import ScanResult, SkippedFile
from codeshield.policies import PolicyEngine
from codeshield.pseudonymization import PseudonymVault, TextProtector
from codeshield.risk import RiskScorer

DEFAULT_MAX_FILE_SIZE = 1_000_000
DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".codeshieldignore",
}


class ScanTimeoutError(RuntimeError):
    """Raised when a scan exceeds its configured timeout."""


class CodeShieldScanner:
    def __init__(
        self,
        *,
        detectors: list[SensitiveDataDetector] | None = None,
        context_classifier: ContextClassifier | None = None,
        policy_engine: PolicyEngine | None = None,
        risk_scorer: RiskScorer | None = None,
        protector: TextProtector | None = None,
        detector_config: DetectorConfig | None = None,
    ) -> None:
        self.detectors = detectors or build_detectors(detector_config)
        self.context_classifier = context_classifier or ContextClassifier()
        self.policy_engine = policy_engine or PolicyEngine()
        self.risk_scorer = risk_scorer or RiskScorer(self.policy_engine.document.scoring)
        self.protector = protector or TextProtector()

    def scan_text(
        self,
        text: str,
        *,
        destination: Destination,
        file_context: FileContext | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self.detectors:
            findings.extend(detector.detect(text))
        findings = deduplicate_findings(findings)
        assessed: list[Finding] = []
        context = file_context or FileContext()
        for finding in findings:
            assessment = self.context_classifier.classify(text, finding, context)
            finding = finding.with_context(assessment)
            decision = self.policy_engine.evaluate(
                finding,
                destination,
                assessment,
                file_path=context.path,
            )
            finding = finding.with_policy_decision(decision)
            risk = self.risk_scorer.score(
                finding,
                destination,
                context=assessment,
                policy_decision=decision,
                repository_visibility=context.repository_visibility,
            )
            assessed.append(finding.with_risk(risk))
        return assessed

    def protect_text(
        self,
        text: str,
        *,
        destination: Destination,
        mode: ProtectionMode,
        file_context: FileContext | None = None,
        vault: PseudonymVault | None = None,
        session_id: str = "default",
    ) -> ProtectionResult:
        findings = self.scan_text(
            text, destination=destination, file_context=file_context
        )
        return self.protector.protect(
            text,
            findings,
            mode=mode,
            vault=vault,
            session_id=session_id,
        )

    def scan_path(
        self,
        path: Path,
        *,
        destination: Destination = Destination.LOCAL_FILE,
        excludes: list[str] | None = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        timeout_seconds: float = 10.0,
    ) -> ScanResult:
        started = time.monotonic()
        deadline = started + timeout_seconds
        target = path.resolve()
        ignore_patterns = _load_ignore_patterns(target)
        if excludes:
            ignore_patterns.extend(excludes)

        result = ScanResult(destination=destination)
        files = [target] if target.is_file() else list(_iter_files(target))

        for file_path in files:
            if time.monotonic() > deadline:
                raise ScanTimeoutError(f"scan exceeded {timeout_seconds:.1f} seconds")
            if _is_excluded(file_path, target, ignore_patterns):
                result.files_skipped.append(
                    SkippedFile(path=str(file_path), reason="excluded")
                )
                continue
            if _is_binary(file_path):
                result.files_skipped.append(
                    SkippedFile(path=str(file_path), reason="binary")
                )
                continue
            size = file_path.stat().st_size
            if size > max_file_size:
                result.files_skipped.append(
                    SkippedFile(path=str(file_path), reason="file too large")
                )
                continue

            text = file_path.read_text(encoding="utf-8", errors="replace")
            file_findings = [
                _attach_location(finding, text, file_path)
                for finding in self.scan_text(
                    text,
                    destination=destination,
                    file_context=FileContext.from_path(file_path),
                )
            ]
            result.findings.extend(file_findings)
            result.files_scanned += 1
            result.scanned_bytes += size

        return result.model_copy(
            update={"duration_ms": round((time.monotonic() - started) * 1000, 2)}
        )


def _iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for child in root.rglob("*"):
        if child.is_dir() and child.name in DEFAULT_EXCLUDES:
            continue
        if child.is_file():
            files.append(child)
    return files


def _load_ignore_patterns(target: Path) -> list[str]:
    root = target if target.is_dir() else target.parent
    ignore_file = root / ".codeshieldignore"
    if not ignore_file.exists():
        return []
    return [
        line.strip()
        for line in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _is_excluded(path: Path, root: Path, patterns: list[str]) -> bool:
    if path.name in DEFAULT_EXCLUDES or any(part in DEFAULT_EXCLUDES for part in path.parts):
        return True
    try:
        relative = path.relative_to(root if root.is_dir() else root.parent)
    except ValueError:
        relative = path
    relative_posix = relative.as_posix()
    return any(
        fnmatch.fnmatch(path.name, pattern)
        or fnmatch.fnmatch(relative_posix, pattern)
        or fnmatch.fnmatch(relative_posix, pattern.rstrip("/") + "/*")
        for pattern in patterns
    )


def _is_binary(path: Path) -> bool:
    sample = path.read_bytes()[:2048]
    return b"\x00" in sample


def _attach_location(finding: Finding, text: str, file_path: Path) -> Finding:
    line = text.count("\n", 0, finding.start) + 1
    last_newline = text.rfind("\n", 0, finding.start)
    column = finding.start + 1 if last_newline == -1 else finding.start - last_newline
    return finding.with_location(str(file_path), line, column)
