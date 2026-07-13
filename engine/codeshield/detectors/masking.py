"""Safe masking helpers used by detectors."""

from __future__ import annotations

import re

from codeshield.models.enums import DataCategory


def mask_value(value: str, category: DataCategory) -> str:
    normalized = value.strip()
    if not normalized:
        return "<redacted>"

    if category is DataCategory.EMAIL:
        return _mask_email(normalized)
    if category is DataCategory.IP_ADDRESS:
        return _mask_ip(normalized)
    if category is DataCategory.PHONE_NUMBER:
        return _mask_trailing_digits(normalized, category, visible=2)
    if category is DataCategory.FINANCIAL_IDENTIFIER:
        return _mask_trailing_digits(normalized, category, visible=4)
    if category is DataCategory.PRIVATE_KEY:
        return f"<{category.value}:{len(normalized)} chars>"
    if category is DataCategory.DATABASE_CONNECTION_STRING:
        return f"<{category.value}:{len(normalized)} chars>"

    return _mask_edges(normalized, category)


def _mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    local_part = f"{local[:1]}***" if local else "***"
    domain_name, dot, suffix = domain.partition(".")
    domain_part = f"{domain_name[:1]}***{dot}{suffix}" if domain else "***"
    return f"{local_part}@{domain_part}"


def _mask_ip(value: str) -> str:
    pieces = value.split(".")
    if len(pieces) == 4:
        return f"{pieces[0]}.***.***.{pieces[-1]}"
    return "<IP_ADDRESS>"


def _mask_trailing_digits(
    value: str, category: DataCategory, *, visible: int
) -> str:
    digits = re.sub(r"\D", "", value)
    tail = digits[-visible:] if len(digits) >= visible else ""
    return f"<{category.value}:***{tail}>"


def _mask_edges(value: str, category: DataCategory) -> str:
    if len(value) <= 6:
        return f"<{category.value}:redacted>"
    prefix = value[: min(4, len(value))]
    suffix = value[-min(4, len(value)) :]
    if prefix + suffix == value:
        return f"<{category.value}:redacted>"
    return f"{prefix}...{suffix}"

