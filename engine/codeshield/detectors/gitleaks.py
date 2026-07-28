"""Safe local Gitleaks stdin adapter."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from codeshield.detectors.errors import DetectorExecutionError, DetectorUnavailableError
from codeshield.detectors.masking import mask_value
from codeshield.models.enums import DataCategory, DetectionSource, RecommendedAction, Severity
from codeshield.models.finding import Finding, build_finding_id


class GitleaksDetector:
    name = "gitleaks"

    def __init__(self, *, executable: str = "gitleaks", timeout_seconds: float = 5.0) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def ensure_available(self) -> None:
        try:
            completed = subprocess.run(
                [self.executable, "version"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (FileNotFoundError, PermissionError) as exc:
            raise DetectorUnavailableError("Gitleaks executable is unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            raise DetectorUnavailableError("Gitleaks availability check timed out") from exc
        if completed.returncode != 0:
            raise DetectorUnavailableError("Gitleaks availability check failed")

    def detect(self, text: str) -> list[Finding]:
        report_path = self._private_report_path()
        try:
            try:
                completed = subprocess.run(
                    [
                        self.executable,
                        "stdin",
                        "--report-format",
                        "json",
                        "--report-path",
                        str(report_path),
                        "--no-banner",
                        "--no-color",
                        "--exit-code",
                        "1",
                    ],
                    input=text,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except (FileNotFoundError, PermissionError) as exc:
                raise DetectorUnavailableError("Gitleaks executable is unavailable") from exc
            except subprocess.TimeoutExpired as exc:
                raise DetectorExecutionError("Gitleaks scan timed out") from exc
            if completed.returncode not in {0, 1}:
                raise DetectorExecutionError("Gitleaks scan failed")
            payload = self._read_report(report_path)
            return [finding for item in payload if (finding := self._finding(item, text))]
        finally:
            self._remove_report(report_path)

    @staticmethod
    def _private_report_path() -> Path:
        descriptor, raw_path = tempfile.mkstemp(prefix="codeshield-gitleaks-", suffix=".json")
        os.close(descriptor)
        path = Path(raw_path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return path

    @staticmethod
    def _read_report(path: Path) -> list[dict[str, Any]]:
        try:
            content = path.read_text(encoding="utf-8")
            if not content.strip():
                return []
            payload = json.loads(content)
        except (OSError, json.JSONDecodeError) as exc:
            raise DetectorExecutionError("Gitleaks returned an invalid report") from exc
        if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
            raise DetectorExecutionError("Gitleaks returned an invalid report")
        return payload

    @staticmethod
    def _remove_report(path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    @staticmethod
    def _finding(item: dict[str, Any], text: str) -> Finding | None:
        raw_value = item.get("Secret")
        if not isinstance(raw_value, str) or not raw_value:
            return None
        start = _line_column_offset(text, item.get("StartLine"), item.get("StartColumn"))
        if start is None:
            start = text.find(raw_value)
        if start < 0:
            return None
        end = start + len(raw_value)
        if end > len(text):
            return None
        category = _category(str(item.get("RuleID", "")))
        return Finding(
            finding_id=build_finding_id(
                category=category,
                source=DetectionSource.GITLEAKS,
                start=start,
                end=end,
                raw_value=raw_value,
            ),
            data_category=category,
            start=start,
            end=end,
            masked_preview=mask_value(raw_value, category),
            detection_source=DetectionSource.GITLEAKS,
            confidence_score=0.98,
            severity=Severity.CRITICAL,
            explanation="Local Gitleaks credential rule matched.",
            recommended_action=RecommendedAction.BLOCK,
        )


def _line_column_offset(text: str, line: object, column: object) -> int | None:
    if not isinstance(line, int) or not isinstance(column, int) or line < 1 or column < 1:
        return None
    lines = text.splitlines(keepends=True)
    if line > len(lines):
        return None
    return sum(len(value) for value in lines[: line - 1]) + column - 1


def _category(rule_id: str) -> DataCategory:
    lowered = rule_id.lower()
    if "private-key" in lowered or "private_key" in lowered:
        return DataCategory.PRIVATE_KEY
    if "password" in lowered:
        return DataCategory.PASSWORD
    if "database" in lowered or "connection" in lowered:
        return DataCategory.DATABASE_CONNECTION_STRING
    if any(value in lowered for value in ("aws", "azure", "gcp", "cloud")):
        return DataCategory.CLOUD_CREDENTIAL
    if any(value in lowered for value in ("api-key", "api_key", "apikey", "stripe")):
        return DataCategory.API_KEY
    if any(value in lowered for value in ("token", "auth", "jwt")):
        return DataCategory.AUTH_TOKEN
    return DataCategory.API_KEY
