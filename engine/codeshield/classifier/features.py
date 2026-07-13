"""Transient feature extraction for context classification."""

from __future__ import annotations

import re
from typing import TypeAlias

from codeshield.detectors.entropy import shannon_entropy
from codeshield.models.context import FileContext
from codeshield.models.enums import DataCategory
from codeshield.models.finding import Finding

FeatureValue: TypeAlias = str | float | bool

PLACEHOLDER_WORDS = {
    "changeme",
    "demo",
    "dummy",
    "example",
    "fake",
    "placeholder",
    "sample",
    "synthetic",
    "your-key",
    "your_key",
}
PRODUCTION_WORDS = {"live", "prod", "production", "real", "customer"}
SENSITIVE_VARIABLE_WORDS = {
    "api_key",
    "apikey",
    "password",
    "passwd",
    "secret",
    "session",
    "token",
}


def extract_context_features(
    text: str,
    finding: Finding,
    file_context: FileContext | None = None,
) -> dict[str, FeatureValue]:
    """Extract non-persisted features from an untrusted source span."""

    context = file_context or FileContext()
    raw_value = text[finding.start : finding.end]
    before = text[max(0, finding.start - 100) : finding.start]
    after = text[finding.end : min(len(text), finding.end + 100)]
    nearby = f"{before} {after}".lower()
    value_lower = raw_value.lower()
    variable_name = _nearest_variable_name(before)
    placeholder_hit = any(
        word in value_lower or word in nearby for word in PLACEHOLDER_WORDS
    )
    production_hit = any(word in nearby or word in value_lower for word in PRODUCTION_WORDS)
    sensitive_variable = any(word in variable_name for word in SENSITIVE_VARIABLE_WORDS)

    return {
        "category": finding.data_category.value,
        "source": finding.detection_source.value,
        "confidence": finding.confidence_score,
        "length_bucket": min(len(raw_value) // 8, 12),
        "entropy_bucket": round(shannon_entropy(raw_value), 1),
        "has_upper": any(char.isupper() for char in raw_value),
        "has_lower": any(char.islower() for char in raw_value),
        "has_digit": any(char.isdigit() for char in raw_value),
        "has_symbol": any(not char.isalnum() for char in raw_value),
        "placeholder_signal": placeholder_hit,
        "production_signal": production_hit,
        "sensitive_variable": sensitive_variable,
        "under_tests": context.under_tests,
        "under_fixtures": context.under_fixtures,
        "suffix": context.suffix or "<none>",
        "comment_like": _is_comment_like(before),
    }


def safe_feature_signals(features: dict[str, FeatureValue]) -> list[str]:
    signals: list[str] = []
    for key in (
        "placeholder_signal",
        "production_signal",
        "sensitive_variable",
        "under_tests",
        "under_fixtures",
        "comment_like",
    ):
        if features.get(key) is True:
            signals.append(key)
    return signals


def _nearest_variable_name(before: str) -> str:
    match = re.search(r"([A-Za-z_][A-Za-z0-9_-]{0,40})\s*[:=]\s*['\"]?$", before)
    return match.group(1).lower() if match else ""


def _is_comment_like(before: str) -> bool:
    line = before.rsplit("\n", 1)[-1].lstrip()
    return line.startswith(("#", "//", "/*", "*"))
