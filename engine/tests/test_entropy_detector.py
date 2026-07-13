from __future__ import annotations

from codeshield.detectors.entropy import EntropyDetector
from codeshield.models.enums import DataCategory


def test_entropy_detector_finds_high_entropy_token() -> None:
    text = "token = 'A8f3K9qL2mN7pR4sT6vW1xY5zB0cD9eF'"

    findings = EntropyDetector().detect(text)

    assert len(findings) == 1
    assert findings[0].data_category is DataCategory.UNKNOWN_SECRET
    assert findings[0].masked_preview != "A8f3K9qL2mN7pR4sT6vW1xY5zB0cD9eF"


def test_entropy_detector_skips_low_entropy_benign_value() -> None:
    text = "fixture = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'"

    findings = EntropyDetector().detect(text)

    assert findings == []

