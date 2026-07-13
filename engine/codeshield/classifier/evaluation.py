"""Deterministic evaluation for the synthetic context classifier."""

from __future__ import annotations

from typing import Any

from codeshield.classifier.classifier import build_classifier_pipeline
from codeshield.classifier.synthetic import generate_synthetic_feature_records


def evaluate_context_classifier(*, seed: int = 42) -> dict[str, Any]:
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    )
    from sklearn.model_selection import train_test_split

    features, labels = generate_synthetic_feature_records(
        seed=seed, samples_per_label=40
    )
    train_features, test_features, train_labels, test_labels = train_test_split(
        features,
        labels,
        test_size=0.3,
        random_state=seed,
        stratify=labels,
    )
    pipeline = build_classifier_pipeline(seed=seed)
    pipeline.fit(train_features, train_labels)
    predictions = pipeline.predict(test_features)
    precision, recall, f1, _ = precision_recall_fscore_support(
        test_labels,
        predictions,
        average="macro",
        zero_division=0,
    )
    classes = sorted(set(labels))
    matrix = confusion_matrix(test_labels, predictions, labels=classes)
    return {
        "dataset": "synthetic",
        "seed": seed,
        "training_records": len(train_labels),
        "test_records": len(test_labels),
        "accuracy": round(float(accuracy_score(test_labels, predictions)), 4),
        "macro_precision": round(float(precision), 4),
        "macro_recall": round(float(recall), 4),
        "macro_f1": round(float(f1), 4),
        "labels": classes,
        "confusion_matrix": matrix.tolist(),
    }
