"""Validated SARIF 2.1.0 subset used by CodeShield."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SarifModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Message(SarifModel):
    text: str = Field(min_length=1)


class ReportingDescriptor(SarifModel):
    id: str = Field(pattern=r"^CS\.[A-Z0-9_]+$")
    name: str
    shortDescription: Message
    fullDescription: Message
    help: Message
    properties: dict[str, str | list[str]]


class ToolComponent(SarifModel):
    name: str
    version: str
    semanticVersion: str
    rules: list[ReportingDescriptor]


class Tool(SarifModel):
    driver: ToolComponent


class Region(SarifModel):
    startLine: int = Field(ge=1)
    startColumn: int = Field(ge=1)
    endLine: int | None = Field(default=None, ge=1)
    endColumn: int | None = Field(default=None, ge=1)


class ArtifactLocation(SarifModel):
    uri: str = Field(min_length=1)


class PhysicalLocation(SarifModel):
    artifactLocation: ArtifactLocation
    region: Region


class Location(SarifModel):
    physicalLocation: PhysicalLocation


class Result(SarifModel):
    ruleId: str
    level: Literal["none", "note", "warning", "error"]
    message: Message
    locations: list[Location]
    partialFingerprints: dict[str, str]
    properties: dict[str, str | float]


class Run(SarifModel):
    tool: Tool
    results: list[Result]


class SarifLog(SarifModel):
    schema_uri: Literal[
        "https://json.schemastore.org/sarif-2.1.0.json"
    ] = Field(alias="$schema")
    version: Literal["2.1.0"] = "2.1.0"
    runs: list[Run]
