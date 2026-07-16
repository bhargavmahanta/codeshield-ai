from __future__ import annotations

from pathlib import Path

import pytest

from codeshield.classifier import ContextClassifier
from codeshield.detectors.regex import RegexDetector
from codeshield.models.enums import Destination, RecommendedAction
from codeshield.models.enums import (
    AttestationStatus,
    DataCategory,
    SegmentKind,
    SensitivityLevel,
    TransferDirection,
)
from codeshield.models.policy import PolicyDocument
from codeshield.policies import PolicyEngine, PolicyLoadError, load_policy


def test_default_policy_blocks_public_git_credential() -> None:
    text = 'api_key = "sk_live_51SyntheticTokenValue999"'
    finding = RegexDetector().detect(text)[0]
    context = ContextClassifier().classify(text, finding)

    decision = PolicyEngine().evaluate(finding, Destination.PUBLIC_GIT, context)

    assert decision.action is RecommendedAction.BLOCK
    assert decision.mandatory is True


def test_default_policy_pseudonymizes_external_personal_data() -> None:
    text = "contact = user@example.test"
    finding = RegexDetector().detect(text)[0]
    context = ContextClassifier().classify(text, finding)

    decision = PolicyEngine().evaluate(finding, Destination.EXTERNAL_LLM, context)

    assert decision.action is RecommendedAction.PSEUDONYMIZE


def test_policy_loader_rejects_malformed_yaml(tmp_path: Path) -> None:
    policy = tmp_path / "bad.yaml"
    policy.write_text("rules: [", encoding="utf-8")

    with pytest.raises(PolicyLoadError):
        load_policy(policy)


def test_policy_loader_rejects_conflicting_selectors(tmp_path: Path) -> None:
    source = Path("codeshield/policies/default.yaml").read_text(encoding="utf-8")
    source += """
  - rule_id: conflicting-public-rule
    destinations: [public_git]
    data_categories: [PRIVATE_KEY, PASSWORD, API_KEY, AUTH_TOKEN, JWT, DATABASE_CONNECTION_STRING, CLOUD_CREDENTIAL, SESSION_ID]
    minimum_confidence: 0.75
    action: warn
    priority: 100
    rationale: Synthetic conflict.
"""
    policy = tmp_path / "conflict.yaml"
    policy.write_text(source, encoding="utf-8")

    with pytest.raises(PolicyLoadError):
        load_policy(policy)


def test_schema_one_policy_remains_compatible_with_new_categories() -> None:
    current = load_policy(Path("codeshield/policies/default.yaml"))
    payload = current.model_dump(mode="json")
    payload["schema_version"] = 1
    payload["llm_rules"] = []
    for category in (
        DataCategory.HEALTH_INFORMATION,
        DataCategory.PROPRIETARY_SOURCE_CODE,
        DataCategory.EXPORT_CONTROLLED_CONTENT,
    ):
        payload["scoring"]["sensitivity"].pop(category.value)

    legacy = PolicyDocument.model_validate(payload)

    assert legacy.schema_version == 1
    assert DataCategory.HEALTH_INFORMATION in legacy.scoring.sensitivity


def test_llm_policy_selector_blocks_unattested_nonpublic_content() -> None:
    decision = PolicyEngine().evaluate_llm(
        sensitivity=SensitivityLevel.CONFIDENTIAL,
        categories={DataCategory.PROPRIETARY_SOURCE_CODE},
        provider_profile="openai-api-zdr",
        attestation_status=AttestationStatus.MISSING,
        segment_types={SegmentKind.SOURCE_CODE},
        direction=TransferDirection.OUTBOUND,
        capabilities={"no_training", "bounded_retention"},
        requested_features=set(),
    )

    assert decision.action is RecommendedAction.BLOCK
    assert decision.matched_rule_id == "require-attestation-for-nonpublic"
