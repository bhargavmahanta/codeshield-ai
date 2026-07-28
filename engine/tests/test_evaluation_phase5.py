from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("presidio_evaluator")

from codeshield.evaluation import compare_reports, prepare_suite, run_evaluation
from codeshield.models.enums import DetectorProfile


def test_phase5_preparation_is_deterministic_and_checksum_verified(tmp_path: Path) -> None:
    first = prepare_suite(root=tmp_path)
    second = prepare_suite(root=tmp_path)

    assert first["datasets"] == second["datasets"]
    assert first["case_counts"] == {
        "codeshield-synthetic": 18,
        "presidio-research-synthetic": 16,
        "workflow-synthetic": 3,
    }
    assert all(len(value) == 64 for value in first["datasets"].values())


def test_core_report_is_safe_reproducible_and_meets_gates(tmp_path: Path) -> None:
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    first = run_evaluation(
        profile=DetectorProfile.CORE,
        output=first_path,
        root=tmp_path / "data",
    )
    second = run_evaluation(
        profile=DetectorProfile.CORE,
        output=second_path,
        root=tmp_path / "data",
    )

    assert first["reproducibility_digest"] == second["reproducibility_digest"]
    assert first["metrics"]["core_synthetic"]["strict_macro_f2"] >= 0.90
    assert (
        first["metrics"]["core_synthetic"]["negative_case_false_positive_rate"]
        <= 0.05
    )
    assert first["metrics"]["adversarial"]["exact"]["false_negative"] == 1
    assert first["metrics"]["workflow"]["restricted_transfer_blocking"] == 1.0
    assert first["metrics"]["workflow"]["privileged_injection_blocking"] == 1.0
    assert first["metrics"]["workflow"]["pseudonym_consistency"] == 1.0
    serialized = first_path.read_text(encoding="utf-8")
    assert "sk_" + "live_51" not in serialized
    assert "masked_preview" not in serialized
    assert '"text"' not in serialized
    assert first_path.with_suffix(".md").exists()


def test_report_comparison_rejects_security_or_metric_regression(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    candidate_path = tmp_path / "candidate.json"
    baseline = run_evaluation(
        profile=DetectorProfile.CORE,
        output=baseline_path,
        root=tmp_path / "data",
    )
    candidate = json.loads(json.dumps(baseline))
    candidate["metrics"]["workflow"]["restricted_transfer_blocking"] = 0.0
    candidate["metrics"]["all_detection"]["exact"]["f2"] = 0.0
    candidate_path.write_text(json.dumps(candidate), encoding="utf-8")

    comparison = compare_reports(baseline_path, candidate_path)

    assert comparison["passed"] is False
    assert comparison["gates"]["restricted_transfer_blocking"] is False
    assert comparison["regressions"]
