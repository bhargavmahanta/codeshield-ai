from __future__ import annotations

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

