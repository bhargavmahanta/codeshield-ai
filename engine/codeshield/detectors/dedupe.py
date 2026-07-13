"""Finding deduplication and overlap resolution."""

from __future__ import annotations

from codeshield.models.enums import DataCategory, DetectionSource, SEVERITY_RANK
from codeshield.models.finding import Finding


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    exact_best: dict[tuple[int, int, DataCategory], Finding] = {}
    for finding in findings:
        key = (finding.start, finding.end, finding.data_category)
        current = exact_best.get(key)
        if current is None or _priority(finding) > _priority(current):
            exact_best[key] = finding

    kept: list[Finding] = []
    for candidate in sorted(exact_best.values(), key=_priority, reverse=True):
        if any(_overlaps(candidate, existing) for existing in kept):
            continue
        kept.append(candidate)

    return sorted(kept, key=lambda item: (item.file_path or "", item.start, item.end))


def _overlaps(left: Finding, right: Finding) -> bool:
    return left.start < right.end and right.start < left.end


def _priority(finding: Finding) -> tuple[int, float, int, int, int]:
    return (
        SEVERITY_RANK[finding.severity],
        finding.confidence_score,
        _category_specificity(finding.data_category),
        _source_specificity(finding.detection_source),
        -finding.length,
    )


def _category_specificity(category: DataCategory) -> int:
    if category is DataCategory.UNKNOWN_SECRET:
        return 1
    if category in {
        DataCategory.EMAIL,
        DataCategory.PHONE_NUMBER,
        DataCategory.IP_ADDRESS,
        DataCategory.PERSON,
        DataCategory.LOCATION,
    }:
        return 2
    return 3


def _source_specificity(source: DetectionSource) -> int:
    return 2 if source is DetectionSource.REGEX else 1

