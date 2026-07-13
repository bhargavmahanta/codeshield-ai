"""Safe context-classification models."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from codeshield.models.enums import ContextLabel


class FileContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str | None = None
    suffix: str = ""
    under_tests: bool = False
    under_fixtures: bool = False
    repository_visibility: str | None = None

    @classmethod
    def from_path(cls, path: Path | None) -> "FileContext":
        if path is None:
            return cls()
        lowered_parts = {part.lower() for part in path.parts}
        return cls(
            path=str(path),
            suffix=path.suffix.lower(),
            under_tests=bool(lowered_parts & {"test", "tests"}),
            under_fixtures=bool(
                lowered_parts & {"fixture", "fixtures", "examples", "samples"}
            ),
        )


class ContextAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)

    label: ContextLabel
    confidence: float = Field(ge=0.0, le=1.0)
    signals: list[str] = Field(default_factory=list)
    explanation: str = Field(min_length=1)
