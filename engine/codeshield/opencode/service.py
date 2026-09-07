"""Application coordinator: complete local authorization precedes execution."""

from dataclasses import dataclass, field
from datetime import date
import re

from codeshield.llm.service import LlmPreflightService, _repository_classifier
from codeshield.models.enums import RecommendedAction, SensitivityLevel, SegmentKind, SegmentProvenance, TransferDirection
from codeshield.models.llm import ContentSegment, LlmPreflightRequest, LlmAssessmentResult
from codeshield.models.policy import PolicyDecision
from .errors import OpenCodeError

PROFILE = "openai-chatgpt-plus-pro-via-opencode"
_PUBLIC_SCOPE = object()


@dataclass(frozen=True)
class PromptInput:
    text: str = field(repr=False)
    source_path: str | None = None
    _scope: object | None = field(default=None, repr=False)


@dataclass(frozen=True)
class RunResult:
    assessment: LlmAssessmentResult
    response: str = field(default="", repr=False)
    invocation_count: int = 0
    inbound_passed: bool = False
    llm_policy: PolicyDecision | None = None

    @property
    def exit_code(self):
        if not self.assessment.safe_to_send or (self.invocation_count and not self.inbound_passed):
            return 2
        return 0 if self.assessment.action is RecommendedAction.ALLOW else 1


def demo_input(name: str) -> PromptInput:
    if name == "safe":
        return PromptInput("In Python, what happens when a list index is out of range? Answer briefly.", None, _PUBLIC_SCOPE)
    value = "sk-" + "proj-" + "CODESHIELD_FAKE_DEMO_KEY_839274"
    if name == "test-credential":
        return PromptInput(f'# Synthetic test fixture, never valid\nTEST_API_KEY="{value}"', "tests/fixtures/auth.py")
    if name == "production-secret":
        return PromptInput(f"# Production configuration\nOPENAI_API_KEY={value}", "config/production.env")
    raise OpenCodeError("CS_OPENCODE_INVALID_INPUT")


def validate_input(source: PromptInput, model: str):
    if not re.fullmatch(r"openai/[A-Za-z0-9][A-Za-z0-9._-]{0,100}", model):
        raise OpenCodeError("CS_OPENCODE_INVALID_INPUT")
    if not source.text.strip() or len(source.text.encode("utf-8")) > 1_000_000 or "\x00" in source.text:
        raise OpenCodeError("CS_OPENCODE_INVALID_INPUT")
    if source.source_path is not None:
        path = source.source_path.replace("\\", "/")
        if len(path) > 1024 or ":" in path or any(ord(c) < 32 for c in path) or any(p in {"", ".", ".."} for p in path.split("/")):
            raise OpenCodeError("CS_OPENCODE_INVALID_INPUT")


class OpenCodeCoordinator:
    def __init__(self, *, runner=None, audit=None, today=None, registry=None):
        self.runner, self.audit, self.today, self.registry = runner, audit, today, registry

    def execute(self, source: PromptInput, model: str) -> RunResult:
        validate_input(source, model)
        classifier = _repository_classifier()
        classifier.public_conversation = source._scope is _PUBLIC_SCOPE
        service = LlmPreflightService(classifier=classifier, audit=self.audit, today=self.today, registry=self.registry)
        request = LlmPreflightRequest(
            segments=[ContentSegment(segment_id="prompt", kind=SegmentKind.USER, content=source.text, path=source.source_path)],
            provider_profile_id=PROFILE, purpose="Review 2 local preflight",
        )
        protected = service.protect(request)
        assessment = protected.assessment
        profile = service.registry.get(PROFILE)
        # Expose the actual existing policy decision for safe narration, not a
        # guessed mandatory outcome derived from the demo preset.
        capabilities = set(profile.contractual_controls) if profile else set()
        if profile and profile.prohibits_training:
            capabilities.add("no_training")
        if profile and profile.maximum_retention_days is not None and profile.maximum_retention_days <= 30:
            capabilities.add("bounded_retention")
        if profile and profile.zero_data_retention:
            capabilities.add("zero_data_retention")
        llm_policy = service.policy_engine.evaluate_llm(
            sensitivity=assessment.highest_sensitivity, categories=set(assessment.categories),
            provider_profile=PROFILE, attestation_status=assessment.attestation_status,
            segment_types={SegmentKind.USER}, direction=TransferDirection.OUTBOUND,
            capabilities=capabilities, requested_features=set(profile.inherent_features) if profile else set(),
        )
        current = self.today or date.today()
        evidence_valid = profile is not None and profile.reviewed_on <= current <= profile.review_due and not any(
            issue.startswith(PROFILE + ":") for issue in service.registry.verify(today=current)
        )
        findings = [f for s in assessment.segments for f in s.findings]
        permitted = (
            assessment.safe_to_send
            and assessment.action in {RecommendedAction.ALLOW, RecommendedAction.WARN}
            and assessment.highest_sensitivity is SensitivityLevel.PUBLIC
            and evidence_valid
            and not assessment.required_transformations
            and len(protected.protected_segments) == 1
            and protected.protected_segments[0].protected_content == source.text
            and not any(s.prompt_injection_detected for s in assessment.segments)
            and not any(f.fragment_spans or f.recommended_action is RecommendedAction.BLOCK or
                        (f.policy_decision and f.policy_decision.action is RecommendedAction.BLOCK) for f in findings)
        )
        if not permitted:
            service._update_audit_action(assessment.audit_id, RecommendedAction.BLOCK)
            return RunResult(assessment.model_copy(update={"safe_to_send": False, "action": RecommendedAction.BLOCK}), llm_policy=llm_policy)

        # No OpenCode-related execution or executable probing occurs above here.
        runner = self.runner
        if runner is None:
            from .runner import OpenCodeRunner
            runner = OpenCodeRunner()
        candidate = runner.run(protected.protected_segments[0].protected_content, model)
        inbound = service.assess(LlmPreflightRequest(
            segments=[ContentSegment(segment_id="answer", kind=SegmentKind.USER, content=candidate, provenance=SegmentProvenance.UNTRUSTED)],
            provider_profile_id=PROFILE, purpose="Review 2 inbound inspection", direction=TransferDirection.INBOUND,
        ))
        inbound_safe = inbound.safe_to_send and inbound.highest_sensitivity is SensitivityLevel.PUBLIC and not any(
            s.prompt_injection_detected or any(f.recommended_action is RecommendedAction.BLOCK for f in s.findings) for s in inbound.segments
        )
        if not inbound_safe:
            service._update_audit_action(inbound.audit_id, RecommendedAction.BLOCK)
        return RunResult(assessment, candidate if inbound_safe else "", 1, inbound_safe, llm_policy)
