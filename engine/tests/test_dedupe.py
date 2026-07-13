from __future__ import annotations

from codeshield.detectors.dedupe import deduplicate_findings
from codeshield.models.enums import (
    DataCategory,
    DetectionSource,
    RecommendedAction,
    Severity,
)
from codeshield.models.finding import Finding


def _finding(
    *,
    category: DataCategory,
    start: int,
    end: int,
    source: DetectionSource,
    confidence: float,
    severity: Severity,
) -> Finding:
    return Finding(
        finding_id=f"{category.value}-{start}-{end}-{source.value}",
        data_category=category,
        start=start,
        end=end,
        masked_preview=f"<{category.value}>",
        detection_source=source,
        confidence_score=confidence,
        severity=severity,
        explanation="test finding",
        recommended_action=RecommendedAction.MASK,
    )


def test_dedupe_prefers_specific_regex_finding_over_entropy_overlap() -> None:
    entropy = _finding(
        category=DataCategory.UNKNOWN_SECRET,
        start=10,
        end=40,
        source=DetectionSource.ENTROPY,
        confidence=0.88,
        severity=Severity.HIGH,
    )
    api_key = _finding(
        category=DataCategory.API_KEY,
        start=12,
        end=38,
        source=DetectionSource.REGEX,
        confidence=0.9,
        severity=Severity.HIGH,
    )

    result = deduplicate_findings([entropy, api_key])

    assert result == [api_key]


def test_dedupe_keeps_non_overlapping_findings_in_order() -> None:
    first = _finding(
        category=DataCategory.EMAIL,
        start=1,
        end=10,
        source=DetectionSource.REGEX,
        confidence=0.9,
        severity=Severity.MEDIUM,
    )
    second = _finding(
        category=DataCategory.IP_ADDRESS,
        start=20,
        end=31,
        source=DetectionSource.REGEX,
        confidence=0.8,
        severity=Severity.LOW,
    )

    result = deduplicate_findings([second, first])

    assert result == [first, second]

