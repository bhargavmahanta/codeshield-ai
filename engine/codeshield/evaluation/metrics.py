"""Exact-span, overlap, category, detector, and latency metrics."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from statistics import median
from time import perf_counter

from codeshield.evaluation.models import EvaluationCase, MetricCounts
from codeshield.models.enums import DataCategory
from codeshield.models.finding import Finding


def detection_metrics(
    cases: list[EvaluationCase],
    scan: Callable[[EvaluationCase], list[Finding]],
) -> dict[str, object]:
    exact = MetricCounts()
    relaxed = MetricCounts()
    by_category: dict[str, MetricCounts] = defaultdict(MetricCounts)
    by_detector: dict[str, MetricCounts] = defaultdict(MetricCounts)
    negative_cases = 0
    negative_hits = 0

    for case in cases:
        predictions = scan(case)
        exact_pairs, exact_unmatched_expected, exact_unmatched_predicted = _match(
            case, predictions, exact=True
        )
        relaxed_pairs, relaxed_unmatched_expected, relaxed_unmatched_predicted = _match(
            case, predictions, exact=False
        )
        _add(exact, len(exact_pairs), len(exact_unmatched_predicted), len(exact_unmatched_expected))
        _add(relaxed, len(relaxed_pairs), len(relaxed_unmatched_predicted), len(relaxed_unmatched_expected))
        for expected_index, predicted_index in exact_pairs:
            category = case.expected[expected_index].category.value
            source = predictions[predicted_index].detection_source.value
            _add(by_category[category], 1, 0, 0)
            _add(by_detector[source], 1, 0, 0)
        for expected_index in exact_unmatched_expected:
            _add(by_category[case.expected[expected_index].category.value], 0, 0, 1)
        for predicted_index in exact_unmatched_predicted:
            finding = predictions[predicted_index]
            _add(by_category[finding.data_category.value], 0, 1, 0)
            _add(by_detector[finding.detection_source.value], 0, 1, 0)
        if not case.expected:
            negative_cases += 1
            negative_hits += int(bool(predictions))

    category_scores = {key: value.scores() for key, value in sorted(by_category.items())}
    f2_values = [float(value["f2"]) for value in category_scores.values()]
    return {
        "case_count": len(cases),
        "negative_case_count": negative_cases,
        "negative_case_false_positive_rate": round(
            negative_hits / negative_cases if negative_cases else 0.0, 4
        ),
        "exact": exact.scores(),
        "relaxed_overlap": relaxed.scores(),
        "strict_macro_f2": round(sum(f2_values) / len(f2_values), 4) if f2_values else 1.0,
        "by_category": category_scores,
        "by_detector": {key: value.scores() for key, value in sorted(by_detector.items())},
    }


def latency_metrics(
    scanner_factory: Callable[[], object],
    scan: Callable[[object, str], object],
    *,
    repetitions: int = 7,
) -> dict[str, object]:
    results: dict[str, object] = {}
    for size in (1_000, 10_000, 100_000):
        unit = "const enabled = true;\n"
        text = (unit * ((size // len(unit)) + 1))[:size]
        started = perf_counter()
        cold_scanner = scanner_factory()
        scan(cold_scanner, text)
        cold_ms = (perf_counter() - started) * 1000
        warm_scanner = scanner_factory()
        warm: list[float] = []
        for _ in range(repetitions):
            started = perf_counter()
            scan(warm_scanner, text)
            warm.append((perf_counter() - started) * 1000)
        results[str(size)] = {
            "cold_ms": round(cold_ms, 2),
            "warm_median_ms": round(median(warm), 2),
            "warm_p95_ms": round(_percentile(warm, 0.95), 2),
            "warm_p99_ms": round(_percentile(warm, 0.99), 2),
        }
    return results


def _match(
    case: EvaluationCase,
    predictions: list[Finding],
    *,
    exact: bool,
) -> tuple[list[tuple[int, int]], list[int], list[int]]:
    pairs: list[tuple[int, int]] = []
    available = set(range(len(predictions)))
    for expected_index, expected in enumerate(case.expected):
        for predicted_index in sorted(available):
            predicted = predictions[predicted_index]
            if predicted.data_category is not expected.category:
                continue
            spans_match = (
                (predicted.start, predicted.end) == (expected.start, expected.end)
                if exact
                else predicted.start < expected.end and expected.start < predicted.end
            )
            if spans_match:
                pairs.append((expected_index, predicted_index))
                available.remove(predicted_index)
                break
    matched_expected = {value[0] for value in pairs}
    return (
        pairs,
        [index for index in range(len(case.expected)) if index not in matched_expected],
        sorted(available),
    )


def _add(counts: MetricCounts, tp: int, fp: int, fn: int) -> None:
    counts.true_positive += tp
    counts.false_positive += fp
    counts.false_negative += fn


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile))))
    return ordered[index]
