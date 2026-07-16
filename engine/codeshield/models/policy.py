"""Validated policy and policy-decision models."""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from codeshield.models.enums import (
    ContextLabel,
    DataCategory,
    Destination,
    AttestationStatus,
    ProviderFeature,
    RecommendedAction,
    SegmentKind,
    SensitivityLevel,
    TransferDirection,
)


NEW_CATEGORY_DEFAULT_WEIGHTS: dict[DataCategory, int] = {
    DataCategory.GOVERNMENT_IDENTIFIER: 30,
    DataCategory.BIOMETRIC_IDENTIFIER: 35,
    DataCategory.HEALTH_INFORMATION: 35,
    DataCategory.PAYMENT_CARD_DATA: 32,
    DataCategory.PAYMENT_AUTHENTICATION_DATA: 35,
    DataCategory.CUSTOMER_RECORD: 28,
    DataCategory.PRODUCTION_DATA: 35,
    DataCategory.PROPRIETARY_SOURCE_CODE: 24,
    DataCategory.THIRD_PARTY_SOURCE_CODE: 18,
    DataCategory.SYSTEM_PROMPT: 20,
    DataCategory.INTERNAL_ARCHITECTURE: 28,
    DataCategory.VULNERABILITY_DETAILS: 35,
    DataCategory.LEGAL_PRIVILEGED_MATERIAL: 35,
    DataCategory.MODEL_CONFIGURATION: 25,
    DataCategory.EXPORT_CONTROLLED_CONTENT: 35,
}


class ScoringWeights(BaseModel):
    model_config = ConfigDict(frozen=True)

    sensitivity: dict[DataCategory, int]
    destination: dict[Destination, int]
    context: dict[ContextLabel, int]
    confidence_max: int = Field(default=20, ge=0, le=100)
    repository_public: int = Field(default=5, ge=0, le=100)
    policy_importance: int = Field(default=5, ge=0, le=100)

    @model_validator(mode="before")
    @classmethod
    def add_phase_four_category_defaults(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        updated = dict(value)
        sensitivity = dict(updated.get("sensitivity", {}))
        for category, weight in NEW_CATEGORY_DEFAULT_WEIGHTS.items():
            sensitivity.setdefault(category.value, weight)
        updated["sensitivity"] = sensitivity
        return updated

    @model_validator(mode="after")
    def validate_ranges_and_coverage(self) -> "ScoringWeights":
        for mapping_name, mapping in (
            ("sensitivity", self.sensitivity),
            ("destination", self.destination),
            ("context", self.context),
        ):
            if any(value < 0 or value > 100 for value in mapping.values()):
                raise ValueError(f"{mapping_name} weights must be between 0 and 100")
        missing_categories = set(DataCategory) - set(self.sensitivity)
        missing_destinations = set(Destination) - set(self.destination)
        missing_contexts = set(ContextLabel) - set(self.context)
        if missing_categories or missing_destinations or missing_contexts:
            raise ValueError("scoring weights must cover every enum value")
        return self


class PolicyRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    destinations: list[Destination] = Field(min_length=1)
    data_categories: list[DataCategory] = Field(min_length=1)
    contexts: list[ContextLabel] | None = None
    minimum_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    action: RecommendedAction
    priority: int = Field(default=0, ge=0, le=1000)
    mandatory: bool = False
    rationale: str = Field(min_length=1)

    @property
    def specificity(self) -> int:
        return (
            (100 - len(self.destinations))
            + (100 - len(self.data_categories))
            + (20 if self.contexts else 0)
            + (10 if self.minimum_confidence > 0 else 0)
        )


class LlmPolicyRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    sensitivity_levels: list[SensitivityLevel] = Field(min_length=1)
    data_categories: list[DataCategory] | None = None
    provider_profiles: list[str] | None = None
    attestation_statuses: list[AttestationStatus] | None = None
    segment_types: list[SegmentKind] | None = None
    directions: list[TransferDirection] | None = None
    required_capabilities: list[str] = Field(default_factory=list)
    requested_features: list[ProviderFeature] | None = None
    action: RecommendedAction
    priority: int = Field(default=0, ge=0, le=1000)
    mandatory: bool = False
    rationale: str = Field(min_length=1)


class PolicyException(BaseModel):
    model_config = ConfigDict(frozen=True)

    exception_id: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    paths: list[str] = Field(min_length=1)
    destinations: list[Destination] = Field(min_length=1)
    data_categories: list[DataCategory] = Field(min_length=1)
    contexts: list[ContextLabel] = Field(min_length=1)
    expires_on: date
    rationale: str = Field(min_length=1)

    @field_validator("contexts")
    @classmethod
    def contexts_must_be_nonproduction(
        cls, value: list[ContextLabel]
    ) -> list[ContextLabel]:
        allowed = {ContextLabel.PLACEHOLDER, ContextLabel.TEST_DATA}
        if not set(value) <= allowed:
            raise ValueError("exceptions are limited to placeholder or test_data")
        return value

    @field_validator("data_categories")
    @classmethod
    def categories_must_not_include_unexceptionable_secrets(
        cls, value: list[DataCategory]
    ) -> list[DataCategory]:
        prohibited = {DataCategory.PRIVATE_KEY, DataCategory.CLOUD_CREDENTIAL}
        if set(value) & prohibited:
            raise ValueError("private keys and cloud credentials cannot be excepted")
        return value

    @field_validator("paths")
    @classmethod
    def paths_must_be_scoped(cls, value: list[str]) -> list[str]:
        if any(not item.strip() or item.strip() in {"*", "**", "**/*"} for item in value):
            raise ValueError("exception paths must be scoped globs")
        return [item.replace("\\", "/") for item in value]


class PolicyDocument(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: int = Field(default=1, ge=1, le=2)
    name: str = Field(min_length=1)
    scoring: ScoringWeights
    rules: list[PolicyRule] = Field(default_factory=list)
    exceptions: list[PolicyException] = Field(default_factory=list)
    llm_rules: list[LlmPolicyRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def reject_duplicate_and_conflicting_rules(self) -> "PolicyDocument":
        ids: set[str] = set()
        selectors: dict[tuple[object, ...], RecommendedAction] = {}
        for rule in self.rules:
            if rule.rule_id in ids:
                raise ValueError(f"duplicate policy rule ID: {rule.rule_id}")
            ids.add(rule.rule_id)
            selector = (
                tuple(sorted(item.value for item in rule.destinations)),
                tuple(sorted(item.value for item in rule.data_categories)),
                tuple(sorted(item.value for item in rule.contexts or [])),
                rule.minimum_confidence,
                rule.priority,
            )
            previous = selectors.get(selector)
            if previous is not None and previous != rule.action:
                raise ValueError("conflicting policy rules have identical selectors")
            selectors[selector] = rule.action
        exception_ids: set[str] = set()
        for exception in self.exceptions:
            if exception.exception_id in exception_ids:
                raise ValueError(
                    f"duplicate policy exception ID: {exception.exception_id}"
                )
            exception_ids.add(exception.exception_id)
        llm_ids: set[str] = set()
        for rule in self.llm_rules:
            if rule.rule_id in ids or rule.rule_id in llm_ids:
                raise ValueError(f"duplicate policy rule ID: {rule.rule_id}")
            llm_ids.add(rule.rule_id)
        if self.schema_version == 1 and self.llm_rules:
            raise ValueError("LLM transfer rules require policy schema version 2")
        return self


class PolicyDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    matched_rule_id: str | None = None
    action: RecommendedAction = RecommendedAction.ALLOW
    mandatory: bool = False
    rationale: str = "No explicit policy rule matched."
    priority: int = 0
    exception_id: str | None = None
    exception_expires_on: date | None = None
