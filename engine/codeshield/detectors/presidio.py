"""Lazy local Presidio adapter backed by a pinned spaCy pipeline."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from codeshield.detectors.errors import DetectorExecutionError, DetectorUnavailableError
from codeshield.detectors.masking import mask_value
from codeshield.models.context import FileContext
from codeshield.models.enums import DataCategory, DetectionSource, RecommendedAction, Severity
from codeshield.models.finding import Finding, build_finding_id


ENTITY_MAP: dict[str, DataCategory] = {
    "PERSON": DataCategory.PERSON,
    "LOCATION": DataCategory.LOCATION,
    "PHONE_NUMBER": DataCategory.PHONE_NUMBER,
    "EMAIL_ADDRESS": DataCategory.EMAIL,
    "US_SSN": DataCategory.GOVERNMENT_IDENTIFIER,
    "US_PASSPORT": DataCategory.GOVERNMENT_IDENTIFIER,
    "US_DRIVER_LICENSE": DataCategory.GOVERNMENT_IDENTIFIER,
    "CREDIT_CARD": DataCategory.PAYMENT_CARD_DATA,
    "IBAN_CODE": DataCategory.FINANCIAL_IDENTIFIER,
    "MEDICAL_LICENSE": DataCategory.HEALTH_INFORMATION,
}

RESTRICTED = {DataCategory.GOVERNMENT_IDENTIFIER, DataCategory.HEALTH_INFORMATION}

_CAPITALIZED_WORD = re.compile(r"\b[A-Z][a-z]{2,}\b")
_IDENTITY_CUE = re.compile(
    r"\b(?:address|card|city|customer|email|health|iban|license|lives?|location|"
    r"medical|name|owner|passport|patient|person|phone|ssn)\b",
    re.IGNORECASE,
)
_STRUCTURED_PII = re.compile(r"@|\b\d{3}[- .]\d{3}[- .]\d{4}\b")


class PresidioDetector:
    name = "presidio"

    def __init__(
        self,
        *,
        language: str = "en",
        model: str = "en_core_web_sm",
        score_threshold: float = 0.55,
        analyzer_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.language = language
        self.model = model
        self.score_threshold = score_threshold
        self._analyzer_factory = analyzer_factory or self._default_factory
        self._prefilter = analyzer_factory is None
        self._analyzer: Any | None = None

    @property
    def loaded(self) -> bool:
        return self._analyzer is not None

    def ensure_available(self) -> None:
        self._load()

    def detect(
        self, text: str, *, file_context: FileContext | None = None
    ) -> list[Finding]:
        del file_context
        spans = _candidate_spans(text) if self._prefilter else [(0, len(text))]
        if not spans:
            return []
        analyzer = self._load()
        findings: list[Finding] = []
        for span_start, span_end in spans:
            try:
                results = analyzer.analyze(
                    text=text[span_start:span_end],
                    language=self.language,
                    score_threshold=self.score_threshold,
                    entities=sorted(ENTITY_MAP),
                )
            except Exception as exc:
                raise DetectorExecutionError("Presidio analysis failed") from exc

            for result in results:
                category = ENTITY_MAP.get(str(result.entity_type))
                start = span_start + int(result.start)
                end = span_start + int(result.end)
                if category is None or start < span_start or end <= start or end > span_end:
                    continue
                raw_value = text[start:end]
                restricted = category in RESTRICTED
                findings.append(
                    Finding(
                        finding_id=build_finding_id(
                            category=category,
                            source=DetectionSource.PRESIDIO,
                            start=start,
                            end=end,
                            raw_value=raw_value,
                        ),
                        data_category=category,
                        start=start,
                        end=end,
                        masked_preview=mask_value(raw_value, category),
                        detection_source=DetectionSource.PRESIDIO,
                        confidence_score=max(0.0, min(1.0, float(result.score))),
                        severity=Severity.HIGH if restricted else Severity.MEDIUM,
                        explanation=f"Local Presidio {result.entity_type} entity detected.",
                        recommended_action=(
                            RecommendedAction.BLOCK
                            if restricted
                            else RecommendedAction.PSEUDONYMIZE
                        ),
                    )
                )
        return findings

    def _load(self) -> Any:
        if self._analyzer is None:
            try:
                self._analyzer = self._analyzer_factory()
            except DetectorUnavailableError:
                raise
            except Exception as exc:
                raise DetectorUnavailableError(
                    "Presidio or its configured local spaCy model is unavailable"
                ) from exc
        return self._analyzer

    def _default_factory(self) -> Any:
        try:
            import tldextract
            import tldextract.tldextract as tldextract_module
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
        except ImportError as exc:
            raise DetectorUnavailableError(
                "install codeshield-engine[enhanced] and the pinned spaCy model"
            ) from exc
        # Presidio's email recognizer otherwise asks tldextract to refresh its
        # suffix list. Use the dependency's bundled snapshot to keep scans local.
        tldextract_module.TLD_EXTRACTOR = tldextract.TLDExtract(
            suffix_list_urls=(),
            cache_dir=None,
            fallback_to_snapshot=True,
        )
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": self.language, "model_name": self.model}],
            }
        )
        return AnalyzerEngine(
            nlp_engine=provider.create_engine(),
            supported_languages=[self.language],
        )


def _candidate_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    offset = 0
    active_start: int | None = None
    active_end = 0
    for line in text.splitlines(keepends=True):
        end = offset + len(line)
        candidate = bool(
            _CAPITALIZED_WORD.search(line)
            or _IDENTITY_CUE.search(line)
            or _STRUCTURED_PII.search(line)
        )
        if candidate:
            if active_start is None:
                active_start = offset
            active_end = end
        elif active_start is not None:
            spans.append((active_start, active_end))
            active_start = None
        offset = end
    if offset < len(text):
        line = text[offset:]
        if _CAPITALIZED_WORD.search(line) or _IDENTITY_CUE.search(line) or _STRUCTURED_PII.search(line):
            if active_start is None:
                active_start = offset
            active_end = len(text)
    if active_start is not None:
        spans.append((active_start, active_end))
    return spans
