"""Reproducible, metadata-only Phase 5 evaluation."""

from codeshield.evaluation.runner import (
    EvaluationError,
    compare_reports,
    prepare_suite,
    run_evaluation,
)

__all__ = ["EvaluationError", "compare_reports", "prepare_suite", "run_evaluation"]
