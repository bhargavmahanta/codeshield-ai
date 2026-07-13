"""Validated policy and policy-decision models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from codeshield.models.enums import (
    ContextLabel,
    DataCategory,
    Destination,
    RecommendedAction,
)


class ScoringWeights(BaseModel):
    model_config = ConfigDict(frozen=True)

    sensitivity: dict[DataCategory, int]
    destination: dict[Destination, int]
    context: dict[ContextLabel, int]
    confidence_max: int = Field(default=20, ge=0, le=100)
    repository_public: int = Field(default=5, ge=0, le=100)
    policy_importance: int = Field(default=5, ge=0, le=100)

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


class PolicyDocument(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    name: str = Field(min_length=1)
    scoring: ScoringWeights
    rules: list[PolicyRule] = Field(default_factory=list)

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
        return self


class PolicyDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    matched_rule_id: str | None = None
    action: RecommendedAction = RecommendedAction.ALLOW
    mandatory: bool = False
    rationale: str = "No explicit policy rule matched."
    priority: int = 0
