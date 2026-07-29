"""Hybrid deterministic and scikit-learn context classifier."""

from __future__ import annotations

from threading import Lock
from typing import Any

from codeshield.classifier.features import (
    FeatureValue,
    extract_context_features,
    safe_feature_signals,
)
from codeshield.classifier.synthetic import generate_synthetic_feature_records
from codeshield.models.context import ContextAssessment, FileContext
from codeshield.models.enums import ContextLabel, DataCategory
from codeshield.models.finding import Finding

PERSONAL_CATEGORIES = {
    DataCategory.EMAIL,
    DataCategory.PHONE_NUMBER,
    DataCategory.PERSON,
    DataCategory.LOCATION,
    DataCategory.FINANCIAL_IDENTIFIER,
}
SECRET_CATEGORIES = {
    DataCategory.PASSWORD,
    DataCategory.API_KEY,
    DataCategory.AUTH_TOKEN,
    DataCategory.JWT,
    DataCategory.PRIVATE_KEY,
    DataCategory.DATABASE_CONNECTION_STRING,
    DataCategory.CLOUD_CREDENTIAL,
    DataCategory.SESSION_ID,
}


class ContextClassifier:
    """Classify findings without retaining their raw source values."""

    def __init__(self, *, uncertain_threshold: float = 0.55, seed: int = 42) -> None:
        self.uncertain_threshold = uncertain_threshold
        self.seed = seed
        self._pipeline: Any | None = None
        self._pipeline_lock = Lock()

    def classify(
        self,
        text: str,
        finding: Finding,
        file_context: FileContext | None = None,
    ) -> ContextAssessment:
        features = extract_context_features(text, finding, file_context)
        rule_result = self._classify_with_rules(finding, features)
        if rule_result is not None:
            return rule_result

        pipeline = self._classifier_pipeline()
        probabilities = pipeline.predict_proba([features])[0]
        classes = pipeline.classes_
        best_index = int(probabilities.argmax())
        confidence = float(probabilities[best_index])
        label = ContextLabel(str(classes[best_index]))
        if confidence < self.uncertain_threshold:
            label = ContextLabel.UNCERTAIN
        return ContextAssessment(
            label=label,
            confidence=round(confidence, 3),
            signals=safe_feature_signals(features),
            explanation="Context was classified from safe structural features.",
        )

    def _classify_with_rules(
        self, finding: Finding, features: dict[str, FeatureValue]
    ) -> ContextAssessment | None:
        signals = safe_feature_signals(features)
        if features["under_tests"] is True or features["under_fixtures"] is True:
            return _assessment(ContextLabel.TEST_DATA, 0.95, signals)
        if finding.data_category in PERSONAL_CATEGORIES:
            return _assessment(ContextLabel.PERSONAL_DATA, 0.94, signals)
        if (
            finding.data_category in SECRET_CATEGORIES
            and features["production_signal"] is True
        ):
            return _assessment(ContextLabel.PROBABLE_REAL_SECRET, 0.94, signals)
        if features["placeholder_signal"] is True:
            return _assessment(ContextLabel.PLACEHOLDER, 0.98, signals)
        if (
            finding.data_category in SECRET_CATEGORIES
            and features["sensitive_variable"] is True
        ):
            return _assessment(ContextLabel.PROBABLE_REAL_SECRET, 0.94, signals)
        if finding.data_category is DataCategory.IP_ADDRESS:
            return _assessment(ContextLabel.PUBLIC_INFORMATION, 0.72, signals)
        return None

    def _classifier_pipeline(self) -> Any:
        """Train the deterministic fallback only when rule classification needs it."""

        if self._pipeline is not None:
            return self._pipeline
        with self._pipeline_lock:
            if self._pipeline is None:
                features, labels = generate_synthetic_feature_records(seed=self.seed)
                pipeline = build_classifier_pipeline(seed=self.seed)
                pipeline.fit(features, labels)
                self._pipeline = pipeline
        return self._pipeline


def _assessment(
    label: ContextLabel, confidence: float, signals: list[str]
) -> ContextAssessment:
    return ContextAssessment(
        label=label,
        confidence=confidence,
        signals=signals,
        explanation=f"Deterministic context signals indicate {label.value}.",
    )


def build_classifier_pipeline(*, seed: int = 42):  # type: ignore[no-untyped-def]
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    return Pipeline(
        [
            ("vectorizer", DictVectorizer(sparse=True)),
            (
                "classifier",
                LogisticRegression(max_iter=400, random_state=seed),
            ),
        ]
    )
