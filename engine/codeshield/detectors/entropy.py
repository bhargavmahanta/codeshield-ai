"""Entropy-based detector for unknown secret-like tokens."""

from __future__ import annotations

import math
import re
from collections import Counter

from codeshield.detectors.masking import mask_value
from codeshield.models.context import FileContext
from codeshield.models.enums import (
    DataCategory,
    DetectionSource,
    RecommendedAction,
    Severity,
)
from codeshield.models.finding import Finding, build_finding_id


class EntropyDetector:
    name = "entropy"

    def __init__(self, *, min_length: int = 20, entropy_threshold: float = 4.0) -> None:
        self.min_length = min_length
        self.entropy_threshold = entropy_threshold
        self.token_pattern = re.compile(
            rf"(?<![A-Za-z0-9_])[A-Za-z0-9_+\-/=]{{{min_length},}}(?![A-Za-z0-9_])"
        )

    def detect(
        self, text: str, *, file_context: FileContext | None = None
    ) -> list[Finding]:
        del file_context
        findings: list[Finding] = []
        for match in self.token_pattern.finditer(text):
            token = match.group(0)
            if _looks_like_placeholder(token):
                continue
            entropy = shannon_entropy(token)
            if entropy < self.entropy_threshold:
                continue
            confidence = min(0.95, 0.55 + ((entropy - self.entropy_threshold) / 2.0))
            severity = Severity.HIGH if entropy >= 4.5 else Severity.MEDIUM
            findings.append(
                Finding(
                    finding_id=build_finding_id(
                        category=DataCategory.UNKNOWN_SECRET,
                        source=DetectionSource.ENTROPY,
                        start=match.start(),
                        end=match.end(),
                        raw_value=token,
                    ),
                    data_category=DataCategory.UNKNOWN_SECRET,
                    start=match.start(),
                    end=match.end(),
                    masked_preview=mask_value(token, DataCategory.UNKNOWN_SECRET),
                    detection_source=DetectionSource.ENTROPY,
                    confidence_score=round(confidence, 3),
                    severity=severity,
                    explanation=(
                        f"High-entropy token detected "
                        f"(entropy={entropy:.2f}, length={len(token)})."
                    ),
                    recommended_action=RecommendedAction.MASK,
                )
            )
        return findings


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    placeholder_words = ("example", "dummy", "placeholder", "your", "changeme")
    if any(word in lowered for word in placeholder_words):
        return True
    return len(set(value)) <= 4
