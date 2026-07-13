"""Validated YAML policy loading and deterministic rule matching."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from codeshield.models.context import ContextAssessment
from codeshield.models.enums import Destination
from codeshield.models.finding import Finding
from codeshield.models.policy import PolicyDecision, PolicyDocument, PolicyRule


class PolicyLoadError(ValueError):
    """Raised when a policy cannot be safely loaded or validated."""


def load_policy(path: Path | None = None) -> PolicyDocument:
    source = path or Path(str(files("codeshield.policies").joinpath("default.yaml")))
    try:
        payload: Any = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyLoadError(f"unable to load policy: {source.name}") from exc
    if not isinstance(payload, dict):
        raise PolicyLoadError("policy root must be a mapping")
    try:
        return PolicyDocument.model_validate(payload)
    except ValidationError as exc:
        raise PolicyLoadError(f"policy validation failed: {exc}") from exc


class PolicyEngine:
    def __init__(self, document: PolicyDocument | None = None) -> None:
        self.document = document or load_policy()

    @classmethod
    def from_path(cls, path: Path | None) -> "PolicyEngine":
        return cls(load_policy(path))

    def evaluate(
        self,
        finding: Finding,
        destination: Destination,
        context: ContextAssessment,
    ) -> PolicyDecision:
        matches = [
            rule
            for rule in self.document.rules
            if _matches(rule, finding, destination, context)
        ]
        if not matches:
            return PolicyDecision()
        matches.sort(key=lambda item: (item.priority, item.specificity), reverse=True)
        best = matches[0]
        tied = [
            rule
            for rule in matches
            if (rule.priority, rule.specificity) == (best.priority, best.specificity)
        ]
        if any(rule.action != best.action for rule in tied[1:]):
            raise PolicyLoadError("matching policy rules conflict at runtime")
        return PolicyDecision(
            matched_rule_id=best.rule_id,
            action=best.action,
            mandatory=best.mandatory,
            rationale=best.rationale,
            priority=best.priority,
        )


def _matches(
    rule: PolicyRule,
    finding: Finding,
    destination: Destination,
    context: ContextAssessment,
) -> bool:
    return (
        destination in rule.destinations
        and finding.data_category in rule.data_categories
        and (rule.contexts is None or context.label in rule.contexts)
        and finding.confidence_score >= rule.minimum_confidence
    )
