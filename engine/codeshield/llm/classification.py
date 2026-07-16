"""Deterministic sensitivity classification for structured LLM content."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from codeshield.models.enums import (
    DataCategory,
    SENSITIVITY_RANK,
    SegmentKind,
    SensitivityLevel,
)
from codeshield.models.finding import Finding
from codeshield.models.llm import ContentSegment, SegmentAssessment
from codeshield.scanner import CodeShieldScanner
from codeshield.models.context import FileContext
from codeshield.models.enums import Destination


RESTRICTED_CATEGORIES = {
    DataCategory.PASSWORD,
    DataCategory.API_KEY,
    DataCategory.AUTH_TOKEN,
    DataCategory.JWT,
    DataCategory.PRIVATE_KEY,
    DataCategory.DATABASE_CONNECTION_STRING,
    DataCategory.CLOUD_CREDENTIAL,
    DataCategory.SESSION_ID,
    DataCategory.GOVERNMENT_IDENTIFIER,
    DataCategory.BIOMETRIC_IDENTIFIER,
    DataCategory.HEALTH_INFORMATION,
    DataCategory.PAYMENT_AUTHENTICATION_DATA,
    DataCategory.VULNERABILITY_DETAILS,
    DataCategory.EXPORT_CONTROLLED_CONTENT,
    DataCategory.PRODUCTION_DATA,
}

CONFIDENTIAL_CATEGORIES = {
    DataCategory.EMAIL,
    DataCategory.PHONE_NUMBER,
    DataCategory.PERSON,
    DataCategory.LOCATION,
    DataCategory.FINANCIAL_IDENTIFIER,
    DataCategory.PAYMENT_CARD_DATA,
    DataCategory.CUSTOMER_RECORD,
    DataCategory.PROPRIETARY_SOURCE_CODE,
    DataCategory.THIRD_PARTY_SOURCE_CODE,
    DataCategory.INTERNAL_ARCHITECTURE,
    DataCategory.LEGAL_PRIVILEGED_MATERIAL,
    DataCategory.MODEL_CONFIGURATION,
}

PERSONAL_CATEGORIES = {
    DataCategory.EMAIL,
    DataCategory.PHONE_NUMBER,
    DataCategory.PERSON,
    DataCategory.LOCATION,
    DataCategory.FINANCIAL_IDENTIFIER,
    DataCategory.GOVERNMENT_IDENTIFIER,
    DataCategory.BIOMETRIC_IDENTIFIER,
    DataCategory.HEALTH_INFORMATION,
    DataCategory.PAYMENT_CARD_DATA,
    DataCategory.CUSTOMER_RECORD,
}

SEMANTIC_PATTERNS: list[tuple[DataCategory, re.Pattern[str]]] = [
    (
        DataCategory.GOVERNMENT_IDENTIFIER,
        re.compile(r"\b(?:ssn|social security|aadhaar|passport|national id)\b", re.I),
    ),
    (
        DataCategory.BIOMETRIC_IDENTIFIER,
        re.compile(r"\b(?:fingerprint|face template|voiceprint|iris scan|biometric)\b", re.I),
    ),
    (
        DataCategory.HEALTH_INFORMATION,
        re.compile(r"\b(?:diagnosis|patient|medical record|prescription|treatment|phi)\b", re.I),
    ),
    (
        DataCategory.PAYMENT_AUTHENTICATION_DATA,
        re.compile(r"\b(?:cvv|cvc|pin block|track data|magnetic stripe)\b", re.I),
    ),
    (
        DataCategory.PAYMENT_CARD_DATA,
        re.compile(r"\b(?:cardholder|payment card|primary account number|pan)\b", re.I),
    ),
    (
        DataCategory.CUSTOMER_RECORD,
        re.compile(r"\b(?:customer record|customer profile|account holder|crm export)\b", re.I),
    ),
    (
        DataCategory.PRODUCTION_DATA,
        re.compile(r"\b(?:production data|production dataset|live customer data|production export)\b", re.I),
    ),
    (
        DataCategory.INTERNAL_ARCHITECTURE,
        re.compile(r"\b(?:internal architecture|network topology|trust boundary|production topology)\b", re.I),
    ),
    (
        DataCategory.VULNERABILITY_DETAILS,
        re.compile(r"\b(?:zero[- ]day|unpatched vulnerability|exploit chain|proof of concept exploit)\b", re.I),
    ),
    (
        DataCategory.LEGAL_PRIVILEGED_MATERIAL,
        re.compile(r"\b(?:attorney.client privileged|legal privilege|work product doctrine)\b", re.I),
    ),
    (
        DataCategory.MODEL_CONFIGURATION,
        re.compile(r"\b(?:model weights|guardrail configuration|hidden system prompt|safety policy config)\b", re.I),
    ),
    (
        DataCategory.EXPORT_CONTROLLED_CONTENT,
        re.compile(r"\b(?:itar|ear99|export controlled|classified technical data)\b", re.I),
    ),
]

INJECTION_PATTERNS = [
    re.compile(r"\bignore (?:all |the )?(?:previous|prior|system) instructions\b", re.I),
    re.compile(r"\breveal (?:the )?(?:system prompt|hidden instructions|secrets)\b", re.I),
    re.compile(r"\bexfiltrat(?:e|ion)\b", re.I),
    re.compile(r"\bdo not tell (?:the )?user\b", re.I),
    re.compile(r"\bexecute (?:this|the following) command\b", re.I),
]

INLINE_SENSITIVITY = re.compile(
    r"codeshield\s*:\s*sensitivity\s*=\s*(public|internal|confidential|restricted)",
    re.I,
)


class SegmentClassifier:
    def __init__(
        self,
        scanner: CodeShieldScanner | None = None,
        *,
        public_code_paths: list[str] | None = None,
        repository_root: Path | None = None,
    ) -> None:
        self.scanner = scanner or CodeShieldScanner()
        self.public_code_paths = public_code_paths or []
        self.repository_root = repository_root.resolve() if repository_root else None

    def classify(self, segment: ContentSegment) -> SegmentAssessment:
        context = FileContext.from_path(Path(segment.path)) if segment.path else FileContext()
        findings = self.scanner.scan_text(
            segment.content,
            destination=Destination.EXTERNAL_LLM,
            file_context=context,
        )
        categories = {finding.data_category for finding in findings}
        categories.update(self._semantic_categories(segment))
        sensitivity = self._base_sensitivity(segment, categories)
        annotated = self._inline_sensitivity(segment.content)
        if annotated and SENSITIVITY_RANK[annotated] > SENSITIVITY_RANK[sensitivity]:
            sensitivity = annotated
        safe_findings = [
            finding.model_copy(
                update={"sensitivity": self.sensitivity_for(finding.data_category)}
            )
            for finding in findings
        ]
        return SegmentAssessment(
            segment_id=segment.segment_id,
            sensitivity=sensitivity,
            categories=sorted(categories, key=lambda item: item.value),
            findings=safe_findings,
            prompt_injection_detected=any(
                pattern.search(segment.content) for pattern in INJECTION_PATTERNS
            ),
        )

    def _semantic_categories(self, segment: ContentSegment) -> set[DataCategory]:
        categories = {
            category
            for category, pattern in SEMANTIC_PATTERNS
            if pattern.search(segment.content)
        }
        if segment.kind is SegmentKind.SYSTEM:
            categories.add(DataCategory.SYSTEM_PROMPT)
        if segment.kind is SegmentKind.SOURCE_CODE:
            if self._is_public_source(segment.path):
                pass
            elif _is_third_party_path(segment.path):
                categories.add(DataCategory.THIRD_PARTY_SOURCE_CODE)
            else:
                categories.add(DataCategory.PROPRIETARY_SOURCE_CODE)
        return categories

    def _base_sensitivity(
        self, segment: ContentSegment, categories: set[DataCategory]
    ) -> SensitivityLevel:
        level = SensitivityLevel.INTERNAL
        if segment.kind is SegmentKind.SOURCE_CODE and self._is_public_source(segment.path):
            level = SensitivityLevel.PUBLIC
        for category in categories:
            candidate = self.sensitivity_for(category)
            if SENSITIVITY_RANK[candidate] > SENSITIVITY_RANK[level]:
                level = candidate
        return level

    @staticmethod
    def sensitivity_for(category: DataCategory) -> SensitivityLevel:
        if category in RESTRICTED_CATEGORIES:
            return SensitivityLevel.RESTRICTED
        if category in CONFIDENTIAL_CATEGORIES:
            return SensitivityLevel.CONFIDENTIAL
        if category is DataCategory.IP_ADDRESS:
            return SensitivityLevel.INTERNAL
        return SensitivityLevel.INTERNAL

    def _is_public_source(self, path: str | None) -> bool:
        if not path:
            return False
        normalized = path.replace("\\", "/")
        if self.repository_root:
            try:
                normalized = Path(path).resolve().relative_to(self.repository_root).as_posix()
            except ValueError:
                return False
        return any(fnmatch.fnmatch(normalized, pattern) for pattern in self.public_code_paths)

    @staticmethod
    def _inline_sensitivity(text: str) -> SensitivityLevel | None:
        matches = [SensitivityLevel(match.group(1).lower()) for match in INLINE_SENSITIVITY.finditer(text)]
        return max(matches, key=lambda item: SENSITIVITY_RANK[item]) if matches else None


def _is_third_party_path(path: str | None) -> bool:
    if not path:
        return False
    parts = {part.lower() for part in Path(path).parts}
    return bool(parts & {"vendor", "vendors", "node_modules", "third_party", "third-party"})
