"""Internal models for deterministic evaluation data and safe reports."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from codeshield.models.enums import DataCategory, Destination, RecommendedAction


class ExpectedSpan(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    category: DataCategory
    start: int = Field(ge=0)
    end: int = Field(gt=0)


class EvaluationCase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    suite: str
    text: str
    expected: list[ExpectedSpan] = Field(default_factory=list)
    destination: Destination = Destination.LOCAL_FILE
    expected_action: RecommendedAction | None = None


class MetricCounts(BaseModel):
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0

    def scores(self) -> dict[str, float | int]:
        tp, fp, fn = self.true_positive, self.false_positive, self.false_negative
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / (tp + fn) if tp + fn else 1.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        f2 = 5 * precision * recall / (4 * precision + recall) if precision + recall else 0.0
        return {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "f2": round(f2, 4),
        }


SafeReport = dict[str, Any]
