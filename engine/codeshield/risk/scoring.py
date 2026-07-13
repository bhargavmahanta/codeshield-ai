"""Configurable and explainable risk scoring."""

from __future__ import annotations

from codeshield.models.context import ContextAssessment
from codeshield.models.enums import (
    ContextLabel,
    Destination,
    RecommendedAction,
    Severity,
)
from codeshield.models.finding import Finding
from codeshield.models.policy import PolicyDecision, ScoringWeights
from codeshield.models.risk import RiskFactor, RiskScore
from codeshield.policies import load_policy

ACTION_RANK: dict[RecommendedAction, int] = {
    RecommendedAction.ALLOW: 0,
    RecommendedAction.WARN: 1,
    RecommendedAction.MASK: 2,
    RecommendedAction.PSEUDONYMIZE: 3,
    RecommendedAction.BLOCK: 4,
}


class RiskScorer:
    """Score findings with validated policy weights and safe explanations."""

    def __init__(self, weights: ScoringWeights | None = None) -> None:
        self.weights = weights or load_policy().scoring

    def score(
        self,
        finding: Finding,
        destination: Destination,
        *,
        context: ContextAssessment | None = None,
        policy_decision: PolicyDecision | None = None,
        repository_visibility: str | None = None,
    ) -> RiskScore:
        assessment = context or ContextAssessment(
            label=ContextLabel.UNCERTAIN,
            confidence=0.5,
            explanation="No context classifier result was supplied.",
        )
        decision = policy_decision or PolicyDecision()
        sensitivity = self.weights.sensitivity[finding.data_category]
        confidence = round(finding.confidence_score * self.weights.confidence_max)
        exposure = self.weights.destination[destination]
        context_contribution = self.weights.context[assessment.label]
        repository = (
            self.weights.repository_public
            if repository_visibility == "public" and destination in {Destination.PUBLIC_GIT, Destination.PRIVATE_GIT}
            else 0
        )
        policy_importance = self.weights.policy_importance if decision.mandatory else 0
        score = min(
            100,
            sensitivity
            + confidence
            + exposure
            + context_contribution
            + repository
            + policy_importance,
        )
        severity, risk_action = severity_and_action(score)
        action = _stricter_action(risk_action, decision.action)

        return RiskScore(
            score=score,
            severity=severity,
            recommended_action=action,
            factors=[
                RiskFactor(
                    name="data_sensitivity",
                    value=finding.data_category.value,
                    weight=max(self.weights.sensitivity.values()),
                    contribution=sensitivity,
                    explanation="Sensitive categories receive higher baseline risk.",
                ),
                RiskFactor(
                    name="detection_confidence",
                    value=f"{finding.confidence_score:.2f}",
                    weight=self.weights.confidence_max,
                    contribution=confidence,
                    explanation="Higher-confidence detections increase risk.",
                ),
                RiskFactor(
                    name="destination_exposure",
                    value=destination.value,
                    weight=max(self.weights.destination.values()),
                    contribution=exposure,
                    explanation="Public and external destinations increase exposure.",
                ),
                RiskFactor(
                    name="context_classification",
                    value=assessment.label.value,
                    weight=max(self.weights.context.values()),
                    contribution=context_contribution,
                    explanation="Context changes risk without exposing source content.",
                ),
                RiskFactor(
                    name="repository_visibility",
                    value=repository_visibility or "unknown",
                    weight=self.weights.repository_public,
                    contribution=repository,
                    explanation="Known public repository visibility increases Git risk.",
                ),
                RiskFactor(
                    name="policy_importance",
                    value=decision.matched_rule_id or "none",
                    weight=self.weights.policy_importance,
                    contribution=policy_importance,
                    explanation="Mandatory policy matches receive an explicit contribution.",
                ),
            ],
        )


def severity_and_action(score: int) -> tuple[Severity, RecommendedAction]:
    if score <= 29:
        return Severity.LOW, RecommendedAction.ALLOW
    if score <= 59:
        return Severity.MEDIUM, RecommendedAction.WARN
    if score <= 79:
        return Severity.HIGH, RecommendedAction.MASK
    return Severity.CRITICAL, RecommendedAction.BLOCK


def _stricter_action(
    left: RecommendedAction, right: RecommendedAction
) -> RecommendedAction:
    return left if ACTION_RANK[left] >= ACTION_RANK[right] else right
