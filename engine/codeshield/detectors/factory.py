"""Construct consistent detector profiles for every CodeShield entry point."""

from __future__ import annotations

from codeshield.detectors.base import SensitiveDataDetector
from codeshield.detectors.entropy import EntropyDetector
from codeshield.detectors.gitleaks import GitleaksDetector
from codeshield.detectors.presidio import PresidioDetector
from codeshield.detectors.regex import RegexDetector
from codeshield.models.config import DetectorConfig
from codeshield.models.enums import DetectorProfile


def build_detectors(
    config: DetectorConfig | None = None,
    *,
    validate_optional: bool = True,
) -> list[SensitiveDataDetector]:
    settings = config or DetectorConfig()
    if settings.profile is DetectorProfile.CORE:
        return [RegexDetector(), EntropyDetector()]
    presidio = PresidioDetector(
        language=settings.presidio.language,
        model=settings.presidio.model,
        score_threshold=settings.presidio.score_threshold,
    )
    gitleaks = GitleaksDetector(
        executable=settings.gitleaks.executable,
        timeout_seconds=settings.gitleaks.timeout_seconds,
    )
    if validate_optional:
        presidio.ensure_available()
        gitleaks.ensure_available()
    return [RegexDetector(), EntropyDetector(), presidio, gitleaks]


def detector_status(config: DetectorConfig | None = None) -> list[dict[str, object]]:
    settings = config or DetectorConfig()
    status: list[dict[str, object]] = [
        {"name": "regex", "enabled": True, "available": True, "error": None},
        {"name": "entropy", "enabled": True, "available": True, "error": None},
    ]
    optional = (
        PresidioDetector(
            language=settings.presidio.language,
            model=settings.presidio.model,
            score_threshold=settings.presidio.score_threshold,
        ),
        GitleaksDetector(
            executable=settings.gitleaks.executable,
            timeout_seconds=settings.gitleaks.timeout_seconds,
        ),
    )
    for detector in optional:
        available = True
        error = None
        try:
            detector.ensure_available()
        except Exception as exc:
            available = False
            error = str(exc)
        status.append(
            {
                "name": detector.name,
                "enabled": settings.profile is DetectorProfile.ENHANCED,
                "available": available,
                "error": error,
            }
        )
    return status
