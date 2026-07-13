from __future__ import annotations

from pathlib import Path

from codeshield.classifier import ContextClassifier
from codeshield.detectors.regex import RegexDetector
from codeshield.models.context import FileContext
from codeshield.models.enums import ContextLabel


def _first_finding(text: str):
    return RegexDetector().detect(text)[0]


def test_classifier_identifies_placeholder() -> None:
    text = 'api_key = "sk_test_51SyntheticExampleValue999"'
    assessment = ContextClassifier().classify(text, _first_finding(text))

    assert assessment.label is ContextLabel.PLACEHOLDER
    assert "SyntheticExampleValue999" not in assessment.model_dump_json()


def test_classifier_identifies_test_data_from_path() -> None:
    text = 'password = "FixturePasswordValue999"'
    context = FileContext.from_path(Path("tests/fixtures/settings.env"))
    assessment = ContextClassifier().classify(text, _first_finding(text), context)

    assert assessment.label is ContextLabel.TEST_DATA


def test_classifier_identifies_probable_real_secret() -> None:
    text = 'production_api_key = "sk_live_51SyntheticValue999999"'
    assessment = ContextClassifier().classify(text, _first_finding(text))

    assert assessment.label is ContextLabel.PROBABLE_REAL_SECRET


def test_classifier_identifies_personal_data() -> None:
    text = "contact = user@example.test"
    assessment = ContextClassifier().classify(text, _first_finding(text))

    assert assessment.label is ContextLabel.PERSONAL_DATA
