"""Validated repository configuration models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from codeshield.models.enums import Destination


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


class RepositoryConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(default=1, ge=1, le=1)
    repository_visibility: RepositoryVisibility
    policy_file: Path = Path("policies/default.yaml")

    @field_validator("policy_file")
    @classmethod
    def policy_path_must_be_relative(cls, value: Path) -> Path:
        if value.is_absolute() or ".." in value.parts:
            raise ValueError("policy_file must be a repository-relative path")
        return value


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
