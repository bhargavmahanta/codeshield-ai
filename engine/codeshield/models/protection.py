"""Safe models returned by protection operations."""

from pydantic import BaseModel, ConfigDict, Field

from codeshield.models.enums import DataCategory, ProtectionMode
from codeshield.models.finding import Finding


class AppliedReplacement(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_id: str
    data_category: DataCategory
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    replacement: str = Field(min_length=1)
    mode: ProtectionMode


class ProtectionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    protected_text: str
    findings: list[Finding] = Field(default_factory=list)
    replacements: list[AppliedReplacement] = Field(default_factory=list)
    blocked: bool = False
