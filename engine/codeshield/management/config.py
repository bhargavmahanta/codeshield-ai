"""Strict machine-local management client configuration."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from codeshield.management.contracts import IDENTIFIER, load_public_key


class ManagementConfigError(ValueError):
    """Sanitized client configuration error."""


class ManagementClientConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    endpoint: str
    organization_id: UUID
    device_id: UUID
    signing_public_keys: dict[str, str] = Field(min_length=1, max_length=16)
    offline_validity_days: int = Field(default=7, ge=1, le=7)

    @field_validator("endpoint")
    @classmethod
    def exact_loopback_endpoint(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("management endpoint must be an exact loopback HTTP origin")
        host = f"[{parsed.hostname}]" if parsed.hostname == "::1" else parsed.hostname
        port = f":{parsed.port}" if parsed.port else ""
        return f"http://{host}{port}"

    @field_validator("signing_public_keys")
    @classmethod
    def valid_signing_keys(cls, values: dict[str, str]) -> dict[str, str]:
        for key_id, encoded in values.items():
            if not IDENTIFIER.fullmatch(key_id):
                raise ValueError("signing key identifier is invalid")
            load_public_key(encoded)
        return dict(sorted(values.items()))


def management_home() -> Path:
    return Path(os.environ.get("CODESHIELD_HOME", Path.home() / ".codeshield"))


def configured_path() -> Path:
    explicit = os.environ.get("CODESHIELD_MANAGEMENT_CONFIG")
    if explicit:
        path = Path(explicit)
        if not path.is_absolute():
            raise ManagementConfigError(
                "management configuration environment path must be absolute"
            )
        return path
    return management_home() / "management" / "config.yaml"


def load_management_config(path: Path | None = None) -> ManagementClientConfig:
    source = path or configured_path()
    if not source.is_absolute():
        raise ManagementConfigError("management configuration path must be absolute")
    try:
        link_stat = source.lstat()
        if stat.S_ISLNK(link_stat.st_mode):
            raise ManagementConfigError(
                "management configuration must not be a symbolic link"
            )
        if not stat.S_ISREG(link_stat.st_mode):
            raise ManagementConfigError(
                "management configuration must be a regular file"
            )
        resolved = source.resolve(strict=True)
        if os.path.normcase(str(resolved)) != os.path.normcase(str(source.absolute())):
            raise ManagementConfigError(
                "management configuration must not traverse a link"
            )
        if os.name != "nt" and link_stat.st_mode & (
            stat.S_IRWXG | stat.S_IRWXO
        ):
            raise ManagementConfigError(
                "management configuration permissions are too broad"
            )
        payload = yaml.safe_load(source.read_text(encoding="utf-8"))
        return ManagementClientConfig.model_validate(payload)
    except ManagementConfigError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError, ValueError) as exc:
        raise ManagementConfigError("management configuration is invalid") from exc


def management_token() -> str:
    token = os.environ.get("CODESHIELD_MANAGEMENT_TOKEN")
    if not token or len(token) > 1024:
        raise ManagementConfigError("management device token is unavailable")
    return token
