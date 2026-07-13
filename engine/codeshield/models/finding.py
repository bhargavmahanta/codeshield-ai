"""Finding model and safe finding construction helpers."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from codeshield.models.enums import (
    DataCategory,
    DetectionSource,
    RecommendedAction,
    Severity,
)
from codeshield.models.context import ContextAssessment
from codeshield.models.policy import PolicyDecision
from codeshield.models.risk import RiskScore


class Finding(BaseModel):
    """A masked sensitive-data finding.

    Raw values are intentionally not part of this model. Detectors may use raw
    values only transiently while computing the finding ID and masked preview.
    """

    model_config = ConfigDict(frozen=True)

    finding_id: str
    data_category: DataCategory
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    masked_preview: str = Field(min_length=1)
    detection_source: DetectionSource
    confidence_score: float = Field(ge=0.0, le=1.0)
    severity: Severity
    explanation: str = Field(min_length=1)
    recommended_action: RecommendedAction
    file_path: str | None = None
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    risk: RiskScore | None = None
    context: ContextAssessment | None = None
    policy_decision: PolicyDecision | None = None

    @model_validator(mode="after")
    def validate_span(self) -> "Finding":
        if self.end <= self.start:
            raise ValueError("finding end must be greater than start")
        return self

    @field_validator("masked_preview")
    @classmethod
    def masked_preview_must_not_be_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("masked preview must contain visible mask content")
        return value

    @property
    def length(self) -> int:
        return self.end - self.start

    def with_location(self, file_path: str, line: int, column: int) -> "Finding":
        return self.model_copy(
            update={"file_path": file_path, "line": line, "column": column}
        )

    def with_risk(self, risk: RiskScore) -> "Finding":
        return self.model_copy(
            update={
                "risk": risk,
                "severity": risk.severity,
                "recommended_action": risk.recommended_action,
            }
        )

    def with_context(self, context: ContextAssessment) -> "Finding":
        return self.model_copy(update={"context": context})

    def with_policy_decision(self, decision: PolicyDecision) -> "Finding":
        return self.model_copy(update={"policy_decision": decision})


def build_finding_id(
    *,
    category: DataCategory,
    source: DetectionSource,
    start: int,
    end: int,
    raw_value: str,
) -> str:
    """Build a stable ID without exposing the raw value."""

    raw_hash = sha256(raw_value.encode("utf-8", errors="ignore")).hexdigest()
    material = f"{category.value}:{source.value}:{start}:{end}:{raw_hash}"
    return sha256(material.encode("utf-8")).hexdigest()[:24]


def finding_to_safe_dict(finding: Finding) -> dict[str, Any]:
    """Serialize a finding to a safe JSON-compatible dictionary."""

    return finding.model_dump(mode="json")
