"""Fail-closed provider-aware prompt and source-code preflight service."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from codeshield.llm.audit import AuditStore
from codeshield.llm.classification import PERSONAL_CATEGORIES, SegmentClassifier
from codeshield.models.config import load_repository_config
from codeshield.models.enums import (
    AttestationStatus,
    DataCategory,
    ProtectionMode,
    ProviderFeature,
    RecommendedAction,
    SENSITIVITY_RANK,
    SegmentProvenance,
    SensitivityLevel,
)
from codeshield.models.llm import (
    LlmAssessmentResult,
    LlmPreflightRequest,
    LlmProtectionResult,
    ProtectedSegment,
    SegmentAssessment,
)
from codeshield.models.provider import ProviderProfile
from codeshield.providers import AttestationStore, ProviderRegistry
from codeshield.policies import PolicyEngine
from codeshield.pseudonymization import InMemoryKeyProvider, PseudonymVault, TextProtector
from codeshield.scanner import CodeShieldScanner


class LlmPreflightService:
    def __init__(
        self,
        *,
        classifier: SegmentClassifier | None = None,
        registry: ProviderRegistry | None = None,
        attestations: AttestationStore | None = None,
        audit: AuditStore | None = None,
        today: date | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self.classifier = classifier or _repository_classifier()
        self.registry = registry or ProviderRegistry()
        self.attestations = attestations or AttestationStore()
        self.audit = audit
        self.today = today
        self.policy_engine = policy_engine or PolicyEngine()

    def assess(self, request: LlmPreflightRequest) -> LlmAssessmentResult:
        assessments = [self.classifier.classify(segment) for segment in request.segments]
        highest = max(
            (item.sensitivity for item in assessments),
            key=lambda item: SENSITIVITY_RANK[item],
        )
        categories = sorted(
            {category for item in assessments for category in item.categories},
            key=lambda item: item.value,
        )
        profile = self.registry.get(request.provider_profile_id)
        status = AttestationStatus.MISSING
        attestation = None
        if profile is not None:
            status, attestation = self.attestations.status(
                request.attestation_id, profile, today=self.today
            )
        effective_features = set(request.enabled_features)
        if profile is not None:
            effective_features.update(profile.inherent_features)

        action, reasons, transformations = self._decision(
            request,
            assessments,
            highest,
            categories,
            profile,
            status,
            effective_features,
        )
        safe_to_send = action in {RecommendedAction.ALLOW, RecommendedAction.WARN}
        audit = self.audit or AuditStore.local_default()
        audit_id = audit.record(
            request,
            assessments,
            profile_version=profile.version if profile else None,
            attestation_status=status.value,
            highest_sensitivity=highest.value,
            categories=[item.value for item in categories],
            action=action.value,
            effective_features=effective_features,
        )
        if self.audit is None:
            audit.close()
        return LlmAssessmentResult(
            highest_sensitivity=highest,
            categories=categories,
            segments=assessments,
            action=action,
            safe_to_send=safe_to_send,
            reasons=reasons,
            required_transformations=transformations,
            provider_profile_id=request.provider_profile_id,
            provider_profile_version=profile.version if profile else None,
            attestation_status=status,
            evidence_version=profile.version if profile and attestation else None,
            audit_id=audit_id,
        )

    def protect(
        self,
        request: LlmPreflightRequest,
        *,
        vault: PseudonymVault | None = None,
    ) -> LlmProtectionResult:
        assessment = self.assess(request)
        if assessment.action is RecommendedAction.BLOCK:
            return LlmProtectionResult(assessment=assessment, protected_segments=[])
        unsupported_transformations = set(assessment.required_transformations) - {
            "pseudonymize_personal_data"
        }
        if unsupported_transformations:
            blocked = assessment.model_copy(
                update={
                    "action": RecommendedAction.BLOCK,
                    "safe_to_send": False,
                    "reasons": [
                        *assessment.reasons,
                        "policy transformation cannot be applied with exact local spans",
                    ],
                }
            )
            self._update_audit_action(assessment.audit_id, RecommendedAction.BLOCK)
            return LlmProtectionResult(assessment=blocked, protected_segments=[])
        for segment_assessment in assessment.segments:
            personal_categories = set(segment_assessment.categories) & PERSONAL_CATEGORIES
            represented_categories = {
                finding.data_category for finding in segment_assessment.findings
            }
            if personal_categories - represented_categories:
                blocked = assessment.model_copy(
                    update={
                        "action": RecommendedAction.BLOCK,
                        "safe_to_send": False,
                        "reasons": [
                            *assessment.reasons,
                            "personal data could not be transformed with exact local spans",
                        ],
                    }
                )
                self._update_audit_action(
                    assessment.audit_id, RecommendedAction.BLOCK
                )
                return LlmProtectionResult(assessment=blocked, protected_segments=[])
        protected: list[ProtectedSegment] = []
        owns_vault = vault is None
        active_vault = vault or PseudonymVault(":memory:", InMemoryKeyProvider())
        protector = TextProtector()
        try:
            by_id = {item.segment_id: item for item in assessment.segments}
            for segment in request.segments:
                segment_assessment = by_id[segment.segment_id]
                personal_findings = [
                    item
                    for item in segment_assessment.findings
                    if item.data_category in PERSONAL_CATEGORIES
                ]
                if personal_findings:
                    result = protector.protect(
                        segment.content,
                        personal_findings,
                        mode=ProtectionMode.PSEUDONYMIZE,
                        vault=active_vault,
                        session_id=assessment.audit_id,
                    )
                    content = result.protected_text
                else:
                    content = segment.content
                protected.append(
                    ProtectedSegment(
                        segment_id=segment.segment_id,
                        kind=segment.kind,
                        protected_content=content,
                    )
                )
        finally:
            if owns_vault:
                active_vault.close()
        return LlmProtectionResult(
            assessment=assessment.model_copy(update={"safe_to_send": True}),
            protected_segments=protected,
        )

    def _update_audit_action(
        self, audit_id: str, action: RecommendedAction
    ) -> None:
        audit = self.audit or AuditStore.local_default()
        audit.update_action(audit_id, action.value)
        if self.audit is None:
            audit.close()

    def _decision(
        self,
        request: LlmPreflightRequest,
        assessments: list[SegmentAssessment],
        highest: SensitivityLevel,
        categories: list[DataCategory],
        profile: ProviderProfile | None,
        status: AttestationStatus,
        effective_features: set[ProviderFeature],
    ) -> tuple[RecommendedAction, list[str], list[str]]:
        reasons: list[str] = []
        transformations: list[str] = []
        capabilities: set[str] = set()
        if profile is not None:
            capabilities.update(profile.contractual_controls)
            if profile.prohibits_training:
                capabilities.add("no_training")
            retention = profile.maximum_retention_days
            if retention is not None and retention <= 30:
                capabilities.add("bounded_retention")
            if profile.zero_data_retention:
                capabilities.add("zero_data_retention")
        policy_decision = self.policy_engine.evaluate_llm(
            sensitivity=highest,
            categories=set(categories),
            provider_profile=request.provider_profile_id,
            attestation_status=status,
            segment_types={segment.kind for segment in request.segments},
            direction=request.direction,
            capabilities=capabilities,
            requested_features=effective_features,
        )
        if policy_decision.action is RecommendedAction.BLOCK:
            reasons.append(policy_decision.rationale)
            return RecommendedAction.BLOCK, reasons, transformations
        injection = any(item.prompt_injection_detected for item in assessments)
        untrusted = any(
            segment.provenance is SegmentProvenance.UNTRUSTED for segment in request.segments
        )
        if injection:
            reasons.append("prompt-injection indicators were detected")
            if untrusted and request.privileged_tools:
                reasons.append("untrusted injected content cannot control privileged tools")
                return RecommendedAction.BLOCK, reasons, transformations

        if highest is SensitivityLevel.RESTRICTED:
            reasons.append("restricted content cannot be transferred to an external LLM")
            return RecommendedAction.BLOCK, reasons, transformations

        if profile is None:
            if highest is SensitivityLevel.PUBLIC:
                reasons.append("public content may use an unknown provider with warning")
                return RecommendedAction.WARN, reasons, transformations
            reasons.append("unknown providers may receive only public content")
            return RecommendedAction.BLOCK, reasons, transformations

        if profile.reference_only:
            if highest is SensitivityLevel.PUBLIC:
                reasons.append("reference-only consumer profile is limited to public content")
                return RecommendedAction.WARN, reasons, transformations
            reasons.append("consumer and reference-only profiles cannot receive non-public content")
            return RecommendedAction.BLOCK, reasons, transformations

        if highest is not SensitivityLevel.PUBLIC:
            if status is not AttestationStatus.VALID:
                reasons.append("non-public content requires a current account attestation")
                return RecommendedAction.BLOCK, reasons, transformations
            if not profile.prohibits_training:
                reasons.append("provider profile does not prohibit training use")
                return RecommendedAction.BLOCK, reasons, transformations
            retention = profile.maximum_retention_days
            if retention is None or retention > 30:
                reasons.append("provider retention exceeds the 30-day bound")
                return RecommendedAction.BLOCK, reasons, transformations
            incompatible = set(effective_features) & set(
                profile.incompatible_confidential_features
            )
            if incompatible:
                reasons.append("enabled provider features are incompatible with non-public content")
                return RecommendedAction.BLOCK, reasons, transformations

        personal = any(
            category in PERSONAL_CATEGORIES
            for item in assessments
            for category in item.categories
        )
        if personal:
            transformations.append("pseudonymize_personal_data")
            reasons.append("personal data must be protected locally before transfer")
            return RecommendedAction.PSEUDONYMIZE, reasons, transformations
        if policy_decision.action is RecommendedAction.PSEUDONYMIZE:
            transformations.append("pseudonymize_policy_selected_data")
            reasons.append(policy_decision.rationale)
            return RecommendedAction.PSEUDONYMIZE, reasons, transformations
        if policy_decision.action is RecommendedAction.MASK:
            transformations.append("mask_policy_selected_data")
            reasons.append(policy_decision.rationale)
            return RecommendedAction.MASK, reasons, transformations
        if injection:
            return RecommendedAction.WARN, reasons, transformations
        if policy_decision.action is RecommendedAction.WARN:
            reasons.append(policy_decision.rationale)
            return RecommendedAction.WARN, reasons, transformations
        reasons.append("provider profile and local attestation satisfy transfer requirements")
        return RecommendedAction.ALLOW, reasons, transformations


def _repository_classifier() -> SegmentClassifier:
    current = Path.cwd().resolve()
    for root in (current, *current.parents):
        if (root / ".codeshield.yaml").exists():
            config = load_repository_config(root)
            return SegmentClassifier(
                scanner=CodeShieldScanner(detector_config=config.detectors),
                public_code_paths=config.public_code_paths if config else [],
                repository_root=root,
            )
    return SegmentClassifier()
