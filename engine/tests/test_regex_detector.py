from __future__ import annotations

import pytest

from codeshield.detectors.regex import RegexDetector
from codeshield.models.enums import DataCategory


def test_regex_detector_masks_common_sensitive_values() -> None:
    text = """
    email = "student@example.edu"
    password = "CorrectHorseBattery999"
    api_key = "sk_live_51SyntheticTokenValue999"
    host = "203.0.113.42"
    card = "4111 1111 1111 1111"
    """

    findings = RegexDetector().detect(text)
    categories = {finding.data_category for finding in findings}

    assert DataCategory.EMAIL in categories
    assert DataCategory.PASSWORD in categories
    assert DataCategory.API_KEY in categories
    assert DataCategory.IP_ADDRESS in categories
    assert DataCategory.FINANCIAL_IDENTIFIER in categories
    assert all("CorrectHorseBattery999" not in item.masked_preview for item in findings)
    assert all("sk_live_51SyntheticTokenValue999" not in item.masked_preview for item in findings)


def test_regex_detector_detects_private_key_without_exposing_body() -> None:
    text = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSynthetic\n"
        "-----END PRIVATE KEY-----"
    )

    findings = RegexDetector().detect(text)

    assert findings[0].data_category is DataCategory.PRIVATE_KEY
    assert findings[0].masked_preview.startswith("<PRIVATE_KEY:")
    assert "MIIEvQIB" not in findings[0].masked_preview


def test_regex_detector_detects_prefixed_credential_assignment_value_span() -> None:
    secret = "sk-proj-CODESHIELD_FAKE_DEMO_KEY_839274"
    text = f"OPENAI_API_KEY={secret}\n"

    findings = [
        finding
        for finding in RegexDetector().detect(text)
        if finding.data_category is DataCategory.API_KEY
    ]

    assert len(findings) == 1
    assert (findings[0].start, findings[0].end) == (
        text.index(secret),
        text.index(secret) + len(secret),
    )
    assert secret not in findings[0].masked_preview


@pytest.mark.parametrize(
    "text",
    [
        "OPENAI_MODEL=sk-proj-CODESHIELD_FAKE_DEMO_KEY_839274",
        "OPENAI_API_KEY_SUFFIX=sk-proj-CODESHIELD_FAKE_DEMO_KEY_839274",
        "OPENAI_API_KEY=placeholder",
    ],
)
def test_regex_detector_ignores_noncredential_prefixed_assignments(text: str) -> None:
    findings = RegexDetector().detect(text)

    assert all(
        finding.data_category is not DataCategory.API_KEY for finding in findings
    )
