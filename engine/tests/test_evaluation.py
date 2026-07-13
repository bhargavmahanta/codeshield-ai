from __future__ import annotations

from codeshield.classifier import evaluate_context_classifier


def test_context_evaluation_is_deterministic() -> None:
    first = evaluate_context_classifier(seed=7)
    second = evaluate_context_classifier(seed=7)

    assert first == second
    assert first["dataset"] == "synthetic"
    assert 0.0 <= first["macro_f1"] <= 1.0
    assert first["test_records"] > 0
