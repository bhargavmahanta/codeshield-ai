"""Validated repository configuration models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from codeshield.models.enums import Destination, DetectorProfile


class RepositoryConfigError(ValueError):
    """Raised when repository configuration is missing or invalid."""


class RepositoryVisibility(StrEnum):
    PRIVATE = "private"
    PUBLIC = "public"

    @property
    def destination(self) -> Destination:
        if self is RepositoryVisibility.PUBLIC:
            return Destination.PUBLIC_GIT
        return Destination.PRIVATE_GIT


class PresidioDetectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    language: str = Field(default="en", pattern=r"^[a-z]{2}$")
    model: str = Field(default="en_core_web_sm", min_length=1, max_length=128)
    score_threshold: float = Field(default=0.55, ge=0.0, le=1.0)


class GitleaksDetectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    executable: str = Field(default="gitleaks", min_length=1, max_length=512)
    timeout_seconds: float = Field(default=5.0, gt=0.0, le=120.0)


class FragmentDetectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = True
    max_fragments: int = Field(default=8, ge=2, le=16)
    max_reconstructed_length: int = Field(default=512, ge=32, le=4096)


class DetectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    profile: DetectorProfile = DetectorProfile.CORE
    fragments: FragmentDetectorConfig = Field(default_factory=FragmentDetectorConfig)
    presidio: PresidioDetectorConfig = Field(default_factory=PresidioDetectorConfig)
    gitleaks: GitleaksDetectorConfig = Field(default_factory=GitleaksDetectorConfig)


class RepositoryConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(default=1, ge=1, le=2)
    repository_visibility: RepositoryVisibility
    policy_file: Path = Path("policies/default.yaml")
    public_code_paths: list[str] = Field(default_factory=list)
    detectors: DetectorConfig = Field(default_factory=DetectorConfig)

    @model_validator(mode="after")
    def version_one_uses_core_detectors(self) -> "RepositoryConfig":
        if self.schema_version == 1 and self.detectors.profile is not DetectorProfile.CORE:
            raise ValueError("schema version 1 supports only the core detector profile")
        return self

    @field_validator("policy_file")
    @classmethod
    def policy_path_must_be_relative(cls, value: Path) -> Path:
        if value.is_absolute() or ".." in value.parts:
            raise ValueError("policy_file must be a repository-relative path")
        return value

    @field_validator("public_code_paths")
    @classmethod
    def public_paths_must_be_scoped(cls, value: list[str]) -> list[str]:
        if any(not item.strip() or item.strip() in {"*", "**", "**/*"} for item in value):
            raise ValueError("public_code_paths must contain scoped globs")
        return [item.replace("\\", "/") for item in value]


def load_repository_config(root: Path) -> RepositoryConfig | None:
    path = root / ".codeshield.yaml"
    if not path.exists():
        return None
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RepositoryConfigError("unable to load .codeshield.yaml") from exc
    if not isinstance(payload, dict):
        raise RepositoryConfigError(".codeshield.yaml root must be a mapping")
    try:
        return RepositoryConfig.model_validate(payload)
    except ValidationError as exc:
        raise RepositoryConfigError(f"invalid .codeshield.yaml: {exc}") from exc


def resolve_policy_path(root: Path, config: RepositoryConfig) -> Path:
    resolved_root = root.resolve()
    candidate = (resolved_root / config.policy_file).resolve()
    if not candidate.is_relative_to(resolved_root):
        raise RepositoryConfigError("configured policy path escapes repository root")
    return candidate


def find_repository_config(start: Path | None = None) -> tuple[Path, RepositoryConfig] | None:
    current = (start or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent
    for root in (current, *current.parents):
        config = load_repository_config(root)
        if config is not None:
            return root, config
    return None
