"""Enums used across detection, scoring, CLI, and API layers."""

from enum import StrEnum


class DataCategory(StrEnum):
    EMAIL = "EMAIL"
    PHONE_NUMBER = "PHONE_NUMBER"
    IP_ADDRESS = "IP_ADDRESS"
    PERSON = "PERSON"
    LOCATION = "LOCATION"
    PASSWORD = "PASSWORD"
    API_KEY = "API_KEY"
    AUTH_TOKEN = "AUTH_TOKEN"
    JWT = "JWT"
    PRIVATE_KEY = "PRIVATE_KEY"
    DATABASE_CONNECTION_STRING = "DATABASE_CONNECTION_STRING"
    CLOUD_CREDENTIAL = "CLOUD_CREDENTIAL"
    SESSION_ID = "SESSION_ID"
    FINANCIAL_IDENTIFIER = "FINANCIAL_IDENTIFIER"
    UNKNOWN_SECRET = "UNKNOWN_SECRET"


class DetectionSource(StrEnum):
    REGEX = "regex"
    ENTROPY = "entropy"


class Destination(StrEnum):
    LOCAL_FILE = "local_file"
    PRIVATE_GIT = "private_git"
    PUBLIC_GIT = "public_git"
    APPLICATION_LOG = "application_log"
    INTERNAL_LLM = "internal_llm"
    EXTERNAL_LLM = "external_llm"
    API_REQUEST = "api_request"
    CLOUD_STORAGE = "cloud_storage"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecommendedAction(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    MASK = "mask"
    PSEUDONYMIZE = "pseudonymize"
    BLOCK = "block"


class ContextLabel(StrEnum):
    PROBABLE_REAL_SECRET = "probable_real_secret"
    PLACEHOLDER = "placeholder"
    TEST_DATA = "test_data"
    PUBLIC_INFORMATION = "public_information"
    PERSONAL_DATA = "personal_data"
    CONFIDENTIAL_BUSINESS_DATA = "confidential_business_data"
    UNCERTAIN = "uncertain"


class ProtectionMode(StrEnum):
    REDACT = "redact"
    PARTIAL_MASK = "partial_mask"
    TYPE_PLACEHOLDER = "type_placeholder"
    PSEUDONYMIZE = "pseudonymize"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
