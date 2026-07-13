from __future__ import annotations

from codeshield.models.enums import (
    DataCategory,
    Destination,
    DetectionSource,
    RecommendedAction,
    Severity,
)
from codeshield.models.finding import Finding
from codeshield.risk.scoring import RiskScorer


def _finding(category: DataCategory, confidence: float) -> Finding:
    return Finding(
        finding_id="finding",
        data_category=category,
        start=0,
        end=10,
        masked_preview="<masked>",
        detection_source=DetectionSource.REGEX,
        confidence_score=confidence,
        severity=Severity.MEDIUM,
        explanation="test finding",
        recommended_action=RecommendedAction.WARN,
    )


def test_public_git_secret_scores_critical_block() -> None:
    risk = RiskScorer().score(
        _finding(DataCategory.API_KEY, 0.95),
        Destination.PUBLIC_GIT,
    )

    assert risk.score >= 80
    assert risk.severity is Severity.CRITICAL
    assert risk.recommended_action is RecommendedAction.BLOCK


def test_local_email_scores_warning_not_block() -> None:
    risk = RiskScorer().score(
        _finding(DataCategory.EMAIL, 0.9),
        Destination.LOCAL_FILE,
    )

    assert 30 <= risk.score <= 59
    assert risk.recommended_action is RecommendedAction.WARN

