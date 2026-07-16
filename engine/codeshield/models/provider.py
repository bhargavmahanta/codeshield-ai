"""Provider data-handling profiles and local administrative attestations."""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from codeshield.models.enums import ProviderDataType, ProviderFeature


class ProviderHandlingFact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    data_type: ProviderDataType
    retained: bool
    retention_days: int | None = Field(default=None, ge=0)
    used_for_training: bool
    human_review_possible: bool | None = None
    notes: str = Field(min_length=1)

    @model_validator(mode="after")
    def retention_is_consistent(self) -> "ProviderHandlingFact":
        if not self.retained and self.retention_days not in {None, 0}:
            raise ValueError("non-retained data cannot have positive retention")
        return self


class ProviderProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+$")
    provider: str
    product: str
    plan: str
    surface: str
    processor: str
    reference_only: bool = False
    prohibits_training: bool
    maximum_retention_days: int | None = Field(default=None, ge=0)
    zero_data_retention: bool = False
    data_residency: str
    contractual_controls: list[str] = Field(default_factory=list)
    supported_features: list[ProviderFeature] = Field(default_factory=list)
    inherent_features: list[ProviderFeature] = Field(default_factory=list)
    incompatible_confidential_features: list[ProviderFeature] = Field(default_factory=list)
    handling: list[ProviderHandlingFact] = Field(min_length=1)
    evidence_urls: list[HttpUrl] = Field(min_length=1)
    reviewed_on: date
    review_due: date

    @model_validator(mode="after")
    def review_window_and_handling_are_valid(self) -> "ProviderProfile":
        if self.review_due < self.reviewed_on:
            raise ValueError("review_due must not precede reviewed_on")
        if (self.review_due - self.reviewed_on).days > 90:
            raise ValueError("provider profile review window cannot exceed 90 days")
        data_types = [fact.data_type for fact in self.handling]
        if len(data_types) != len(set(data_types)):
            raise ValueError("provider handling data types must be unique")
        if not set(self.inherent_features) <= set(self.supported_features):
            raise ValueError("inherent features must be listed as supported")
        return self


class ProviderAttestation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    attestation_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    profile_id: str
    profile_version: str
    account_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    enabled_controls: list[str] = Field(min_length=1)
    evidence_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    reviewer_id: str = Field(min_length=1, max_length=128)
    created_on: date
    expires_on: date

    @model_validator(mode="after")
    def attestation_window_is_valid(self) -> "ProviderAttestation":
        if self.expires_on < self.created_on:
            raise ValueError("attestation expiry must not precede creation")
        if (self.expires_on - self.created_on).days > 90:
            raise ValueError("attestation window cannot exceed 90 days")
        return self
