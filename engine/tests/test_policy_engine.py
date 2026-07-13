from __future__ import annotations

from pathlib import Path

import pytest

from codeshield.classifier import ContextClassifier
from codeshield.detectors.regex import RegexDetector
from codeshield.models.enums import Destination, RecommendedAction
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
