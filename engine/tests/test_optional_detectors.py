from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from codeshield.detectors.dedupe import deduplicate_findings
from codeshield.detectors.errors import DetectorExecutionError, DetectorUnavailableError
from codeshield.detectors.gitleaks import GitleaksDetector
from codeshield.detectors.presidio import PresidioDetector
from codeshield.models.config import RepositoryConfig
from codeshield.models.enums import DataCategory, DetectionSource


class FakeAnalyzer:
    def __init__(self, results: list[object]) -> None:
        self.results = results

    def analyze(self, **_kwargs: object) -> list[object]:
        return self.results


def test_presidio_loads_lazily_and_maps_exact_spans() -> None:
    text = "Owner is Ada Lovelace."
    calls = 0

    def factory() -> FakeAnalyzer:
        nonlocal calls
        calls += 1
        return FakeAnalyzer(
            [SimpleNamespace(entity_type="PERSON", start=9, end=21, score=0.91)]
        )

    detector = PresidioDetector(analyzer_factory=factory)
    assert detector.loaded is False

    findings = detector.detect(text)

    assert calls == 1
    assert detector.loaded is True
    assert findings[0].data_category is DataCategory.PERSON
    assert (findings[0].start, findings[0].end) == (9, 21)
    assert "Ada Lovelace" not in findings[0].model_dump_json()
    detector.detect(text)
    assert calls == 1


def test_presidio_candidate_prefilter_preserves_document_offsets() -> None:
    text = "const enabled = true;\nOwner is Ada Lovelace.\nconst done = true;\n"

    class CandidateAnalyzer:
        def analyze(self, **kwargs: object) -> list[object]:
            chunk = str(kwargs["text"])
            start = chunk.index("Ada Lovelace")
            return [SimpleNamespace(entity_type="PERSON", start=start, end=start + 12, score=0.9)]

    detector = PresidioDetector(analyzer_factory=lambda: CandidateAnalyzer())
    detector._prefilter = True
    findings = detector.detect(text)

    expected_start = text.index("Ada Lovelace")
    assert (findings[0].start, findings[0].end) == (expected_start, expected_start + 12)


def test_presidio_configures_tldextract_for_offline_snapshot() -> None:
    pytest.importorskip("presidio_analyzer")
    detector = PresidioDetector()
    detector.ensure_available()

    import tldextract.tldextract as tldextract_module

    assert tldextract_module.TLD_EXTRACTOR.suffix_list_urls == ()


def test_presidio_wraps_loader_and_analyzer_errors_without_content() -> None:
    raw = "private-person-value"

    def unavailable() -> object:
        raise RuntimeError(raw)

    with pytest.raises(DetectorUnavailableError) as unavailable_error:
        PresidioDetector(analyzer_factory=unavailable).detect(raw)
    assert raw not in str(unavailable_error.value)

    class BrokenAnalyzer:
        def analyze(self, **_kwargs: object) -> list[object]:
            raise RuntimeError(raw)

    with pytest.raises(DetectorExecutionError) as execution_error:
        PresidioDetector(analyzer_factory=BrokenAnalyzer).detect(raw)
    assert raw not in str(execution_error.value)


def test_gitleaks_uses_stdin_argument_array_and_cleans_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = "glpat" + "-SyntheticReviewValue93628471"
    text = f"token = '{raw}'\n"
    report = tmp_path / "private-report.json"
    report.touch()
    captured: dict[str, object] = {}

    monkeypatch.setattr(GitleaksDetector, "_private_report_path", staticmethod(lambda: report))

    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured["input"] = kwargs.get("input")
        report.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "gitlab-pat",
                        "Secret": raw,
                        "Match": f"token = '{raw}'",
                        "StartLine": 1,
                        "StartColumn": 10,
                    }
                ]
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(args, 1, "", "")

    monkeypatch.setattr("codeshield.detectors.gitleaks.subprocess.run", run)
    findings = GitleaksDetector().detect(text)

    assert captured["input"] == text
    assert captured["args"][:2] == ["gitleaks", "stdin"]
    assert "--report-format" in captured["args"]
    assert report.exists() is False
    assert findings[0].detection_source is DetectionSource.GITLEAKS
    assert findings[0].start == 9
    assert raw not in findings[0].model_dump_json()


def test_gitleaks_timeout_and_malformed_report_are_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = "glpat" + "-SyntheticNeverLeak93628471"
    report = tmp_path / "report.json"
    report.touch()
    monkeypatch.setattr(GitleaksDetector, "_private_report_path", staticmethod(lambda: report))

    def timeout(*_args: object, **_kwargs: object) -> object:
        raise subprocess.TimeoutExpired(["gitleaks", "stdin"], 0.01, output=raw)

    monkeypatch.setattr("codeshield.detectors.gitleaks.subprocess.run", timeout)
    with pytest.raises(DetectorExecutionError) as timeout_error:
        GitleaksDetector(timeout_seconds=0.01).detect(raw)
    assert raw not in str(timeout_error.value)
    assert report.exists() is False

    report.touch()

    def malformed(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        report.write_text("not-json", encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("codeshield.detectors.gitleaks.subprocess.run", malformed)
    with pytest.raises(DetectorExecutionError, match="invalid report"):
        GitleaksDetector().detect(raw)
    assert report.exists() is False


def test_gitleaks_missing_runtime_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*_args: object, **_kwargs: object) -> object:
        raise FileNotFoundError("not installed")

    monkeypatch.setattr("codeshield.detectors.gitleaks.subprocess.run", missing)
    with pytest.raises(DetectorUnavailableError, match="unavailable"):
        GitleaksDetector().ensure_available()


def test_gitleaks_wins_equal_overlap_over_regex() -> None:
    raw = "glpat" + "-SyntheticReviewValue93628471"
    text = f"token = '{raw}'"
    presidio = PresidioDetector(
        analyzer_factory=lambda: FakeAnalyzer(
            [SimpleNamespace(entity_type="PERSON", start=9, end=42, score=0.9)]
        )
    ).detect(text)[0]
    gitleaks = GitleaksDetector._finding(
        {"RuleID": "generic-api-key", "Secret": raw, "StartLine": 1, "StartColumn": 10},
        text,
    )
    assert gitleaks is not None

    kept = deduplicate_findings([presidio, gitleaks])
    assert kept == [gitleaks]


def test_gitleaks_maps_stripe_access_tokens_as_api_keys() -> None:
    raw = "sk_" + "live_51CategoryMapping93628471"
    finding = GitleaksDetector._finding(
        {
            "RuleID": "stripe-access-token",
            "Secret": raw,
            "StartLine": 1,
            "StartColumn": 1,
        },
        raw,
    )

    assert finding is not None
    assert finding.data_category is DataCategory.API_KEY


def test_repository_schema_v1_defaults_to_core_and_v2_accepts_enhanced() -> None:
    common = {"repository_visibility": "private"}
    legacy = RepositoryConfig.model_validate({"schema_version": 1, **common})
    enhanced = RepositoryConfig.model_validate(
        {"schema_version": 2, **common, "detectors": {"profile": "enhanced"}}
    )

    assert legacy.detectors.profile.value == "core"
    assert enhanced.detectors.profile.value == "enhanced"
    with pytest.raises(ValueError, match="version 1"):
        RepositoryConfig.model_validate(
            {"schema_version": 1, **common, "detectors": {"profile": "enhanced"}}
        )
