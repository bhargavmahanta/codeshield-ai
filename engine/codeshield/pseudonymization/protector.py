"""Span-safe text protection operations."""

from __future__ import annotations

from codeshield.detectors.masking import mask_value
from codeshield.models.enums import DetectionSource, ProtectionMode, RecommendedAction
from codeshield.models.finding import Finding
from codeshield.models.protection import AppliedReplacement, ProtectionResult
from codeshield.pseudonymization.vault import PseudonymVault


class ProtectionError(ValueError):
    """Raised when requested protection cannot be completed safely."""


class TextProtector:
    def protect(
        self,
        text: str,
        findings: list[Finding],
        *,
        mode: ProtectionMode,
        vault: PseudonymVault | None = None,
        session_id: str = "default",
    ) -> ProtectionResult:
        if any(
            finding.recommended_action is RecommendedAction.BLOCK
            for finding in findings
        ):
            return ProtectionResult(
                protected_text="", findings=findings, blocked=True
            )
        if any(
            finding.detection_source is DetectionSource.FRAGMENT
            for finding in findings
        ):
            raise ProtectionError(
                "fragmented findings require manual source refactoring"
            )
        if mode is ProtectionMode.PSEUDONYMIZE and vault is None:
            raise ProtectionError("pseudonymization requires a local encrypted vault")

        protected = text
        replacements: list[AppliedReplacement] = []
        for finding in sorted(findings, key=lambda item: item.start, reverse=True):
            if finding.start < 0 or finding.end > len(text):
                raise ProtectionError("finding span is outside the supplied text")
            raw_value = text[finding.start : finding.end]
            replacement = _replacement_for(
                raw_value,
                finding,
                mode,
                vault=vault,
                session_id=session_id,
            )
            protected = protected[: finding.start] + replacement + protected[finding.end :]
            replacements.append(
                AppliedReplacement(
                    finding_id=finding.finding_id,
                    data_category=finding.data_category,
                    start=finding.start,
                    end=finding.end,
                    replacement=replacement,
                    mode=mode,
                )
            )
        replacements.reverse()
        return ProtectionResult(
            protected_text=protected,
            findings=findings,
            replacements=replacements,
            blocked=False,
        )


def _replacement_for(
    raw_value: str,
    finding: Finding,
    mode: ProtectionMode,
    *,
    vault: PseudonymVault | None,
    session_id: str,
) -> str:
    if mode is ProtectionMode.REDACT:
        return "<REDACTED>"
    if mode is ProtectionMode.PARTIAL_MASK:
        return mask_value(raw_value, finding.data_category)
    if mode is ProtectionMode.TYPE_PLACEHOLDER:
        return f"<{finding.data_category.value}>"
    if vault is None:
        raise ProtectionError("pseudonymization requires a vault")
    return vault.get_or_create(
        raw_value, finding.data_category, session_id=session_id
    )
