"""Deterministic synthetic feature records for the baseline classifier."""

from __future__ import annotations

import random

from codeshield.classifier.features import FeatureValue
from codeshield.models.enums import ContextLabel, DataCategory


def generate_synthetic_feature_records(
    *, seed: int = 42, samples_per_label: int = 16
) -> tuple[list[dict[str, FeatureValue]], list[str]]:
    randomizer = random.Random(seed)
    records: list[dict[str, FeatureValue]] = []
    labels: list[str] = []
    categories = list(DataCategory)

    for label in ContextLabel:
        for _ in range(samples_per_label):
            category = _category_for_label(label, randomizer)
            record: dict[str, FeatureValue] = {
                "category": category.value,
                "source": "regex" if randomizer.random() > 0.2 else "entropy",
                "confidence": round(randomizer.uniform(0.55, 0.99), 2),
                "length_bucket": randomizer.randint(1, 10),
                "entropy_bucket": round(randomizer.uniform(2.0, 5.2), 1),
                "has_upper": randomizer.choice([True, False]),
                "has_lower": True,
                "has_digit": randomizer.choice([True, False]),
                "has_symbol": randomizer.choice([True, False]),
                "placeholder_signal": label is ContextLabel.PLACEHOLDER,
                "production_signal": label
                in {
                    ContextLabel.PROBABLE_REAL_SECRET,
                    ContextLabel.CONFIDENTIAL_BUSINESS_DATA,
                },
                "sensitive_variable": label
                in {
                    ContextLabel.PROBABLE_REAL_SECRET,
                    ContextLabel.TEST_DATA,
                    ContextLabel.PLACEHOLDER,
                },
                "under_tests": label is ContextLabel.TEST_DATA,
                "under_fixtures": label is ContextLabel.TEST_DATA,
                "suffix": randomizer.choice([".py", ".env", ".json", ".txt"]),
                "comment_like": label
                in {ContextLabel.PLACEHOLDER, ContextLabel.PUBLIC_INFORMATION},
            }
            if label is ContextLabel.UNCERTAIN:
                record["category"] = randomizer.choice(categories).value
                record["confidence"] = round(randomizer.uniform(0.45, 0.7), 2)
                record["production_signal"] = False
                record["sensitive_variable"] = False
            records.append(record)
            labels.append(label.value)
    return records, labels


def _category_for_label(
    label: ContextLabel, randomizer: random.Random
) -> DataCategory:
    if label is ContextLabel.PERSONAL_DATA:
        return randomizer.choice(
            [
                DataCategory.EMAIL,
                DataCategory.PHONE_NUMBER,
                DataCategory.PERSON,
                DataCategory.LOCATION,
                DataCategory.FINANCIAL_IDENTIFIER,
            ]
        )
    if label is ContextLabel.PUBLIC_INFORMATION:
        return randomizer.choice([DataCategory.IP_ADDRESS, DataCategory.LOCATION])
    if label is ContextLabel.CONFIDENTIAL_BUSINESS_DATA:
        return randomizer.choice(
            [DataCategory.DATABASE_CONNECTION_STRING, DataCategory.SESSION_ID]
        )
    if label is ContextLabel.UNCERTAIN:
        return DataCategory.UNKNOWN_SECRET
    return randomizer.choice(
        [
            DataCategory.API_KEY,
            DataCategory.PASSWORD,
            DataCategory.AUTH_TOKEN,
            DataCategory.JWT,
            DataCategory.CLOUD_CREDENTIAL,
            DataCategory.UNKNOWN_SECRET,
        ]
    )
