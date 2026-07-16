"""Structured prompt preflight request and safe response models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from codeshield.models.enums import (
    AttestationStatus,
    DataCategory,
    ProviderFeature,
    RecommendedAction,
    SegmentKind,
    SegmentProvenance,
    SensitivityLevel,
    TransferDirection,
)
from codeshield.models.finding import Finding


class ContentSegment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    segment_id: str = Field(min_length=1, max_length=128)
    kind: SegmentKind
    content: str = Field(max_length=1_000_000)
    provenance: SegmentProvenance = SegmentProvenance.TRUSTED
    language: str | None = Field(default=None, max_length=64)
    path: str | None = Field(default=None, max_length=1024)


class LlmPreflightRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    segments: list[ContentSegment] = Field(min_length=1, max_length=100)
    provider_profile_id: str
    attestation_id: str | None = None
    direction: TransferDirection = TransferDirection.OUTBOUND
    purpose: str = Field(min_length=1, max_length=256)
    enabled_features: list[ProviderFeature] = Field(default_factory=list)
    privileged_tools: bool = False

    @model_validator(mode="after")
    def segment_ids_are_unique(self) -> "LlmPreflightRequest":
        ids = [segment.segment_id for segment in self.segments]
        if len(ids) != len(set(ids)):
            raise ValueError("segment IDs must be unique")
        return self


class SegmentAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)

    segment_id: str
    sensitivity: SensitivityLevel
    categories: list[DataCategory] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    prompt_injection_detected: bool = False


class LlmAssessmentResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    highest_sensitivity: SensitivityLevel
    categories: list[DataCategory]
    segments: list[SegmentAssessment]
    action: RecommendedAction
    safe_to_send: bool
    reasons: list[str]
    required_transformations: list[str]
    provider_profile_id: str
    provider_profile_version: str | None = None
    attestation_status: AttestationStatus
    evidence_version: str | None = None
    audit_id: str


class ProtectedSegment(BaseModel):
    model_config = ConfigDict(frozen=True)

    segment_id: str
    kind: SegmentKind
    protected_content: str


class LlmProtectionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    assessment: LlmAssessmentResult
    protected_segments: list[ProtectedSegment] = Field(default_factory=list)
