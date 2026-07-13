"""Scan result models."""

from pydantic import BaseModel, Field

from codeshield.models.enums import Destination
from codeshield.models.finding import Finding


class SkippedFile(BaseModel):
    path: str
    reason: str


class ScanResult(BaseModel):
    destination: Destination
    findings: list[Finding] = Field(default_factory=list)
    files_scanned: int = 0
    files_skipped: list[SkippedFile] = Field(default_factory=list)
    scanned_bytes: int = 0
    duration_ms: float = 0.0

    @property
    def blocked_count(self) -> int:
        return sum(1 for finding in self.findings if finding.recommended_action == "block")

    @property
    def warning_count(self) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.recommended_action in {"warn", "mask"}
        )

