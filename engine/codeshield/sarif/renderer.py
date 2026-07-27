"""Deterministic, repository-relative SARIF output."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from codeshield.models.enums import DataCategory, Severity
from codeshield.models.finding import Finding
from codeshield.models.scan import ScanResult
from codeshield.sarif.models import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    Region,
    ReportingDescriptor,
    Result,
    Run,
    SarifLog,
    Tool,
    ToolComponent,
)
from codeshield.version import __version__


class SarifError(ValueError):
    """Safe SARIF error that never includes scanned content."""


def build_sarif(result: ScanResult, *, source_root: Path) -> SarifLog:
    root = source_root.resolve()
    resolved: list[tuple[str, Finding]] = []
    for finding in result.findings:
        resolved.append((_relative_uri(finding, root), finding))
    resolved.sort(
        key=lambda item: (
            item[0],
            item[1].line or 0,
            item[1].column or 0,
            item[1].data_category.value,
            item[1].finding_id,
        )
    )

    categories = sorted(
        {finding.data_category for _, finding in resolved}, key=lambda item: item.value
    )
    rules = [_rule(category) for category in categories]
    results = [_result(uri, finding) for uri, finding in resolved]
    log = SarifLog(
        **{
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="CodeShield AI",
                            version=__version__,
                            semanticVersion=__version__,
                            rules=rules,
                        )
                    ),
                    results=results,
                )
            ],
        }
    )
    return SarifLog.model_validate(log.model_dump(mode="json", by_alias=True))


def render_sarif(result: ScanResult, *, source_root: Path) -> str:
    payload = build_sarif(result, source_root=source_root).model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    forbidden = (
        "masked_preview",
        "protected_text",
        "pseudonym",
        str(source_root.resolve()).replace("\\", "/").lower(),
    )
    lowered = serialized.replace("\\", "/").lower()
    if any(value and value in lowered for value in forbidden):
        raise SarifError("SARIF output failed leakage validation")
    return serialized


def write_output(destination: Path, content: str) -> None:
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".codeshield-output-",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    except OSError as exc:
        raise SarifError("unable to write output file safely") from exc


def _relative_uri(finding: Finding, root: Path) -> str:
    if not finding.file_path or not finding.line or not finding.column:
        raise SarifError("SARIF findings require source locations")
    supplied = Path(finding.file_path)
    try:
        if supplied.is_absolute():
            relative = supplied.resolve().relative_to(root)
        else:
            relative = Path(str(PurePosixPath(str(supplied).replace("\\", "/"))))
    except (OSError, ValueError) as exc:
        raise SarifError("SARIF location is outside the source root") from exc
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise SarifError("SARIF location is not repository-relative")
    normalized = PurePosixPath(*relative.parts).as_posix()
    if ":" in normalized.split("/", 1)[0]:
        raise SarifError("SARIF location contains an absolute drive")
    return quote(normalized, safe="/._-")


def _rule(category: DataCategory) -> ReportingDescriptor:
    name = category.value
    return ReportingDescriptor(
        id=f"CS.{name}",
        name=name,
        shortDescription=Message(text=f"{name} sensitive-data finding"),
        fullDescription=Message(
            text=f"CodeShield detected content classified as {name}."
        ),
        help=Message(text=_remediation(category)),
        properties={
            "category": name,
            "tags": ["security", "privacy", "codeshield"],
        },
    )


def _result(uri: str, finding: Finding) -> Result:
    end_line = finding.end_line or finding.line
    end_column = finding.end_column or (finding.column + max(1, finding.length))
    return Result(
        ruleId=f"CS.{finding.data_category.value}",
        level=_level(finding.severity),
        message=Message(
            text=(
                f"{finding.explanation} Recommended action: "
                f"{finding.recommended_action.value}. "
                f"{_remediation(finding.data_category)}"
            )
        ),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(
                        startLine=finding.line,
                        startColumn=finding.column,
                        endLine=end_line,
                        endColumn=end_column,
                    ),
                )
            )
        ],
        partialFingerprints={"codeshield/v1": finding.finding_id},
        properties={
            "category": finding.data_category.value,
            "severity": finding.severity.value,
            "confidence": finding.confidence_score,
            "recommendedAction": finding.recommended_action.value,
            "detectionSource": finding.detection_source.value,
            "sensitivity": finding.sensitivity.value,
        },
    )


def _level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _remediation(category: DataCategory) -> str:
    if category in {
        DataCategory.PRIVATE_KEY,
        DataCategory.PASSWORD,
        DataCategory.API_KEY,
        DataCategory.AUTH_TOKEN,
        DataCategory.JWT,
        DataCategory.DATABASE_CONNECTION_STRING,
        DataCategory.CLOUD_CREDENTIAL,
        DataCategory.SESSION_ID,
        DataCategory.UNKNOWN_SECRET,
    }:
        return "Remove the value, rotate it if real, and use approved secret storage."
    if category in {
        DataCategory.EMAIL,
        DataCategory.PHONE_NUMBER,
        DataCategory.PERSON,
        DataCategory.LOCATION,
        DataCategory.FINANCIAL_IDENTIFIER,
        DataCategory.GOVERNMENT_IDENTIFIER,
        DataCategory.HEALTH_INFORMATION,
    }:
        return "Minimize, mask, or pseudonymize the data before transfer."
    return "Review the destination policy and remove or protect the sensitive content."
