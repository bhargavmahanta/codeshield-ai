"""Regex-based sensitive-data detector."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Pattern

from codeshield.detectors.masking import mask_value
from codeshield.models.context import FileContext
from codeshield.models.enums import (
    DataCategory,
    DetectionSource,
    RecommendedAction,
    Severity,
)
from codeshield.models.finding import Finding, build_finding_id


PostFilter = Callable[[str], bool]


@dataclass(frozen=True)
class RegexRule:
    category: DataCategory
    pattern: Pattern[str]
    confidence: float
    severity: Severity
    explanation: str
    recommended_action: RecommendedAction
    group: int = 0
    post_filter: PostFilter | None = None


class RegexDetector:
    name = "regex"

    def __init__(self, rules: list[RegexRule] | None = None) -> None:
        self.rules = rules or default_rules()

    def detect(
        self, text: str, *, file_context: FileContext | None = None
    ) -> list[Finding]:
        del file_context
        findings: list[Finding] = []
        for rule in self.rules:
            for match in rule.pattern.finditer(text):
                raw_value = match.group(rule.group)
                if not raw_value:
                    continue
                start, end = match.span(rule.group)
                if rule.post_filter is not None and not rule.post_filter(raw_value):
                    continue
                findings.append(
                    Finding(
                        finding_id=build_finding_id(
                            category=rule.category,
                            source=DetectionSource.REGEX,
                            start=start,
                            end=end,
                            raw_value=raw_value,
                        ),
                        data_category=rule.category,
                        start=start,
                        end=end,
                        masked_preview=mask_value(raw_value, rule.category),
                        detection_source=DetectionSource.REGEX,
                        confidence_score=rule.confidence,
                        severity=rule.severity,
                        explanation=rule.explanation,
                        recommended_action=rule.recommended_action,
                    )
                )
        return findings


def default_rules() -> list[RegexRule]:
    flags = re.IGNORECASE | re.MULTILINE
    return [
        RegexRule(
            DataCategory.PRIVATE_KEY,
            re.compile(
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                re.MULTILINE,
            ),
            0.99,
            Severity.CRITICAL,
            "Private key block detected.",
            RecommendedAction.BLOCK,
        ),
        RegexRule(
            DataCategory.JWT,
            re.compile(
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
            ),
            0.95,
            Severity.CRITICAL,
            "JWT-like authentication token detected.",
            RecommendedAction.BLOCK,
        ),
        RegexRule(
            DataCategory.DATABASE_CONNECTION_STRING,
            re.compile(
                r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"<>]+",
                flags,
            ),
            0.93,
            Severity.CRITICAL,
            "Database connection string detected.",
            RecommendedAction.BLOCK,
        ),
        RegexRule(
            DataCategory.CLOUD_CREDENTIAL,
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            0.95,
            Severity.CRITICAL,
            "AWS access-key-like credential detected.",
            RecommendedAction.BLOCK,
        ),
        RegexRule(
            DataCategory.CLOUD_CREDENTIAL,
            re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
            0.9,
            Severity.HIGH,
            "Google API-key-like credential detected.",
            RecommendedAction.MASK,
        ),
        RegexRule(
            DataCategory.API_KEY,
            re.compile(
                r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
                re.IGNORECASE,
            ),
            0.94,
            Severity.CRITICAL,
            "Provider API-key-like token detected.",
            RecommendedAction.BLOCK,
        ),
        RegexRule(
            DataCategory.API_KEY,
            re.compile(
                r"\b(?:[A-Za-z][A-Za-z0-9]*[_-])*(?:api[_-]?key|secret[_-]?key|access[_-]?key|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_.\-]{16,})",
                flags,
            ),
            0.9,
            Severity.HIGH,
            "API key or secret assignment detected.",
            RecommendedAction.MASK,
            group=1,
        ),
        RegexRule(
            DataCategory.PASSWORD,
            re.compile(
                r"\b(?:password|passwd|pwd)\b\s*[:=]\s*['\"]?([^'\"\s,;]{6,})",
                flags,
            ),
            0.88,
            Severity.HIGH,
            "Password-like assignment detected.",
            RecommendedAction.MASK,
            group=1,
        ),
        RegexRule(
            DataCategory.AUTH_TOKEN,
            re.compile(r"\bBearer\s+([A-Za-z0-9._\-]{20,})\b", flags),
            0.9,
            Severity.HIGH,
            "Bearer authentication token detected.",
            RecommendedAction.MASK,
            group=1,
        ),
        RegexRule(
            DataCategory.SESSION_ID,
            re.compile(
                r"\b(?:session[_-]?id|sid)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})",
                flags,
            ),
            0.84,
            Severity.HIGH,
            "Session identifier assignment detected.",
            RecommendedAction.MASK,
            group=1,
        ),
        RegexRule(
            DataCategory.EMAIL,
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            0.9,
            Severity.MEDIUM,
            "Email address detected.",
            RecommendedAction.WARN,
        ),
        RegexRule(
            DataCategory.PHONE_NUMBER,
            re.compile(
                r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)"
            ),
            0.78,
            Severity.MEDIUM,
            "Phone-number-like value detected.",
            RecommendedAction.WARN,
            post_filter=_is_probable_phone,
        ),
        RegexRule(
            DataCategory.IP_ADDRESS,
            re.compile(
                r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
            ),
            0.8,
            Severity.LOW,
            "IPv4 address detected.",
            RecommendedAction.WARN,
            post_filter=_is_public_or_specific_ip,
        ),
        RegexRule(
            DataCategory.FINANCIAL_IDENTIFIER,
            re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
            0.86,
            Severity.HIGH,
            "Payment-card-like financial identifier detected.",
            RecommendedAction.MASK,
            post_filter=_passes_luhn,
        ),
    ]


def _passes_luhn(value: str) -> bool:
    digits = [int(char) for char in re.sub(r"\D", "", value)]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _is_probable_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return 10 <= len(digits) <= 15 and len(set(digits)) > 2


def _is_public_or_specific_ip(value: str) -> bool:
    return value not in {"0.0.0.0", "127.0.0.1", "255.255.255.255"}
