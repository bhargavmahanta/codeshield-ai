"""Managed/local policy precedence with mandatory-rule protection."""

from __future__ import annotations

from codeshield.management.contracts import ManagedPolicyBundle
from codeshield.management.service import ManagementService, is_management_enrolled
from codeshield.models.context import ContextAssessment
from codeshield.models.enums import DataCategory, Destination, RecommendedAction
from codeshield.models.finding import Finding
from codeshield.models.policy import PolicyDecision, PolicyRule
from codeshield.policies.engine import PolicyEngine, _decision_from_rules, _matches


class ManagedPolicyEngine:
    def __init__(
        self,
        local: PolicyEngine,
        bundle: ManagedPolicyBundle,
    ) -> None:
        self.local = local
        self.document = local.document
        converted = [_convert_rule(item) for item in bundle.policy.rules if item.enabled]
        self.mandatory_rules = [
            item for item in converted if item.mandatory
        ]
        self.non_mandatory_rules = [
            item for item in converted if not item.mandatory
        ]

    def evaluate(
        self,
        finding: Finding,
        destination: Destination,
        context: ContextAssessment,
        *,
        file_path: str | None = None,
    ) -> PolicyDecision:
        mandatory = [
            rule
            for rule in self.mandatory_rules
            if _matches(rule, finding, destination, context)
        ]
        if mandatory:
            return _decision_from_rules(mandatory)

        managed = [
            rule
            for rule in self.non_mandatory_rules
            if _matches(rule, finding, destination, context)
        ]
        local = self.local.evaluate(
            finding,
            destination,
            context,
            file_path=file_path,
        )
        if local.exception_id is not None:
            return local
        if managed:
            return _decision_from_rules(managed)
        return local

    def evaluate_llm(self, **kwargs):  # type: ignore[no-untyped-def]
        return self.local.evaluate_llm(**kwargs)


def effective_policy_engine(local: PolicyEngine) -> PolicyEngine | ManagedPolicyEngine:
    if not is_management_enrolled():
        return local
    bundle = ManagementService().verified_active_bundle()
    return ManagedPolicyEngine(local, bundle)


def _convert_rule(rule) -> PolicyRule:  # type: ignore[no-untyped-def]
    try:
        action = RecommendedAction(rule.action)
        category = DataCategory(rule.category)
        destination = Destination(rule.destination_id)
    except ValueError as exc:
        raise ValueError("managed policy rule is incompatible with this engine") from exc
    return PolicyRule(
        rule_id=rule.rule_id.lower().replace(".", "-").replace(":", "-"),
        destinations=[destination],
        data_categories=[category],
        contexts=None,
        minimum_confidence=0.0,
        action=action,
        priority=1000,
        mandatory=rule.mandatory,
        rationale=f"Managed policy rule {rule.rule_id}.",
    )
