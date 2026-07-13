from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from codeshield.models.context import FileContext
from codeshield.models.enums import (
    ContextLabel,
    DataCategory,
    Destination,
    RecommendedAction,
)
from codeshield.models.policy import PolicyDocument
from codeshield.policies import PolicyEngine, load_policy
from codeshield.scanner import CodeShieldScanner
from tests.git_helpers import synthetic_api_key


def test_scoped_unexpired_exception_warns_and_preserves_risk() -> None:
    document = load_policy(Path("codeshield/policies/default.yaml"))
    text = f"api_key = '{synthetic_api_key()}'"
    context = FileContext.from_path(Path("demo/review-fixtures/key.txt"))
    active = CodeShieldScanner(
        policy_engine=PolicyEngine(document, today=date(2026, 7, 31))
    ).scan_text(text, destination=Destination.PUBLIC_GIT, file_context=context)[0]
    expired = CodeShieldScanner(
        policy_engine=PolicyEngine(document, today=date(2026, 9, 1))
    ).scan_text(text, destination=Destination.PUBLIC_GIT, file_context=context)[0]

    assert active.recommended_action is RecommendedAction.WARN
    assert active.policy_decision is not None
    assert active.policy_decision.exception_id == "review-test-api-key"
    assert active.risk is not None and expired.risk is not None
    assert active.risk.score == expired.risk.score
    assert active.risk.severity == expired.risk.severity
    assert expired.recommended_action is RecommendedAction.BLOCK


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("contexts", [ContextLabel.PROBABLE_REAL_SECRET]),
        ("paths", ["**/*"]),
        ("data_categories", [DataCategory.PRIVATE_KEY]),
        ("data_categories", [DataCategory.CLOUD_CREDENTIAL]),
    ],
)
def test_policy_exception_rejects_unsafe_scope(field: str, value: object) -> None:
    payload = load_policy(Path("codeshield/policies/default.yaml")).model_dump()
    payload["exceptions"][0][field] = value

    with pytest.raises(ValidationError):
        PolicyDocument.model_validate(payload)
