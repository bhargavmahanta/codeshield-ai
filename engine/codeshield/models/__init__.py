"""Shared Pydantic models for the CodeShield engine."""

from codeshield.models.context import ContextAssessment, FileContext
from codeshield.models.enums import (
    ContextLabel,
    DataCategory,
    Destination,
    DetectionSource,
    ProtectionMode,
    RecommendedAction,
    Severity,
)
from codeshield.models.finding import Finding
from codeshield.models.policy import (
    PolicyDecision,
    PolicyDocument,
    PolicyRule,
    ScoringWeights,
)
from codeshield.models.protection import AppliedReplacement, ProtectionResult
from codeshield.models.risk import RiskFactor, RiskScore
from codeshield.models.scan import ScanResult, SkippedFile

__all__ = [
    "AppliedReplacement",
    "ContextAssessment",
    "ContextLabel",
    "DataCategory",
    "Destination",
    "DetectionSource",
    "FileContext",
    "Finding",
    "PolicyDecision",
    "PolicyDocument",
    "PolicyRule",
    "ProtectionMode",
    "ProtectionResult",
    "RecommendedAction",
    "RiskFactor",
    "RiskScore",
    "ScanResult",
    "ScoringWeights",
    "Severity",
    "SkippedFile",
]
