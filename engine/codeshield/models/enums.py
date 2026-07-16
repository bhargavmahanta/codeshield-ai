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
    GOVERNMENT_IDENTIFIER = "GOVERNMENT_IDENTIFIER"
    BIOMETRIC_IDENTIFIER = "BIOMETRIC_IDENTIFIER"
    HEALTH_INFORMATION = "HEALTH_INFORMATION"
    PAYMENT_CARD_DATA = "PAYMENT_CARD_DATA"
    PAYMENT_AUTHENTICATION_DATA = "PAYMENT_AUTHENTICATION_DATA"
    CUSTOMER_RECORD = "CUSTOMER_RECORD"
    PRODUCTION_DATA = "PRODUCTION_DATA"
    PROPRIETARY_SOURCE_CODE = "PROPRIETARY_SOURCE_CODE"
    THIRD_PARTY_SOURCE_CODE = "THIRD_PARTY_SOURCE_CODE"
    SYSTEM_PROMPT = "SYSTEM_PROMPT"
    INTERNAL_ARCHITECTURE = "INTERNAL_ARCHITECTURE"
    VULNERABILITY_DETAILS = "VULNERABILITY_DETAILS"
    LEGAL_PRIVILEGED_MATERIAL = "LEGAL_PRIVILEGED_MATERIAL"
    MODEL_CONFIGURATION = "MODEL_CONFIGURATION"
    EXPORT_CONTROLLED_CONTENT = "EXPORT_CONTROLLED_CONTENT"
    UNKNOWN_SECRET = "UNKNOWN_SECRET"


class SensitivityLevel(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


SENSITIVITY_RANK: dict[SensitivityLevel, int] = {
    SensitivityLevel.PUBLIC: 0,
    SensitivityLevel.INTERNAL: 1,
    SensitivityLevel.CONFIDENTIAL: 2,
    SensitivityLevel.RESTRICTED: 3,
}


class SegmentKind(StrEnum):
    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    RETRIEVED = "retrieved"
    TOOL_OUTPUT = "tool_output"
    SOURCE_CODE = "source_code"


class SegmentProvenance(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class TransferDirection(StrEnum):
    OUTBOUND = "outbound"
    INBOUND = "inbound"


class ProviderFeature(StrEnum):
    STATEFUL_STORAGE = "stateful_storage"
    FILE_UPLOAD = "file_upload"
    GROUNDING = "grounding"
    EXTENDED_CACHE = "extended_cache"
    CONNECTORS = "connectors"
    CODE_EXECUTION = "code_execution"
    WORKSPACE_INDEXING = "workspace_indexing"


class ProviderDataType(StrEnum):
    PROMPT = "prompt"
    OUTPUT = "output"
    UPLOADED_FILE = "uploaded_file"
    CODE_CONTEXT = "code_workspace_context"
    APPLICATION_STATE = "application_state"
    CACHE = "cache"
    ABUSE_LOG = "abuse_log"
    FINE_TUNING_DATA = "fine_tuning_data"
    FEEDBACK = "feedback"
    TELEMETRY = "telemetry"
    CONNECTOR_DATA = "connector_data"
    ACCOUNT_METADATA = "account_metadata"


class AttestationStatus(StrEnum):
    VALID = "valid"
    MISSING = "missing"
    STALE = "stale"
    INVALID = "invalid"


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
