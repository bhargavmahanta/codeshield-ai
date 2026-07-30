"""Strict machine-local configuration for the Phase 8 proxy."""

from __future__ import annotations

import os
import re
import stat
import ipaddress
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from codeshield.providers import AttestationStore, ProviderRegistry, ProviderRegistryError
from codeshield.models.enums import AttestationStatus

ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class ProxyConfigError(ValueError):
    """Safe proxy configuration error without local paths or secret values."""


class ProxyConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    host: str = "127.0.0.1"
    port: int = Field(ge=1, le=65535)
    upstream_base_url: str = Field(min_length=1, max_length=2048)
    provider_profile_id: str = Field(min_length=1, max_length=128)
    attestation_id: str = Field(min_length=1, max_length=128)
    upstream_credential_env: str = Field(min_length=2, max_length=128)
    allowed_models: list[str] = Field(min_length=1, max_length=128)
    max_request_bytes: int = Field(default=1_000_000, ge=1024, le=10_000_000)
    max_response_bytes: int = Field(default=10_000_000, ge=1024, le=20_000_000)
    max_concurrency: int = Field(default=4, ge=1, le=64)
    connect_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    request_timeout_seconds: float = Field(default=60.0, gt=0, le=300)

    @field_validator("host")
    @classmethod
    def loopback_host_only(cls, value: str) -> str:
        if value not in {"127.0.0.1", "::1"}:
            raise ValueError("proxy host must be an explicit loopback address")
        return value

    @field_validator("upstream_credential_env")
    @classmethod
    def safe_environment_name(cls, value: str) -> str:
        if not ENVIRONMENT_NAME.fullmatch(value):
            raise ValueError("upstream credential environment name is invalid")
        if value == "CODESHIELD_PROXY_TOKEN":
            raise ValueError("local and upstream credentials must be separate")
        return value

    @field_validator("upstream_base_url")
    @classmethod
    def exact_https_base_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("upstream base URL must be an exact credential-free HTTPS URL")
        if parsed.hostname.lower() in {"localhost", "localhost.localdomain"}:
            raise ValueError("upstream base URL cannot target a local address")
        try:
            literal = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            literal = None
        if literal is not None and not literal.is_global:
            raise ValueError("upstream base URL cannot target a non-global address")
        decoded_path = unquote(parsed.path)
        if (
            "\0" in decoded_path
            or "\r" in decoded_path
            or "\n" in decoded_path
            or "\\" in decoded_path
            or any(
                marker in parsed.path.lower()
                for marker in ("%2e", "%2f", "%5c", "%00", "%0a", "%0d")
            )
            or any(part in {".", ".."} for part in decoded_path.split("/"))
        ):
            raise ValueError("upstream base URL path is invalid")
        path = parsed.path.rstrip("/")
        if not path:
            path = "/v1"
        host_name = parsed.hostname.lower()
        host = f"[{host_name}]" if ":" in host_name else host_name
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"https://{host}{port}{path}"

    @field_validator("allowed_models")
    @classmethod
    def exact_model_allowlist(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("allowed model IDs must be unique")
        if not all(MODEL_ID.fullmatch(value) for value in values):
            raise ValueError("allowed model ID is invalid")
        return values

    @model_validator(mode="after")
    def timeout_order_is_valid(self) -> "ProxyConfig":
        if self.connect_timeout_seconds > self.request_timeout_seconds:
            raise ValueError("connect timeout cannot exceed request timeout")
        return self


def load_proxy_config(
    path: Path,
    *,
    registry: ProviderRegistry | None = None,
    attestations: AttestationStore | None = None,
) -> ProxyConfig:
    """Load a non-link absolute YAML file and verify provider evidence."""

    if not path.is_absolute():
        raise ProxyConfigError("proxy configuration path must be absolute")
    try:
        link_stat = path.lstat()
        if stat.S_ISLNK(link_stat.st_mode):
            raise ProxyConfigError("proxy configuration must not be a symbolic link")
        if not stat.S_ISREG(link_stat.st_mode):
            raise ProxyConfigError("proxy configuration must be a regular file")
        resolved = path.resolve(strict=True)
        if os.path.normcase(str(resolved)) != os.path.normcase(str(path.absolute())):
            raise ProxyConfigError("proxy configuration must not traverse a link")
        if os.name != "nt" and link_stat.st_mode & (
            stat.S_IRWXG | stat.S_IRWXO
        ):
            raise ProxyConfigError("proxy configuration permissions are too broad")
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        config = ProxyConfig.model_validate(payload)
    except ProxyConfigError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as exc:
        raise ProxyConfigError("proxy configuration is invalid") from exc

    try:
        active_registry = registry or ProviderRegistry()
        profile = active_registry.require(config.provider_profile_id)
        status, _ = (attestations or AttestationStore()).status(
            config.attestation_id, profile
        )
    except ProviderRegistryError as exc:
        raise ProxyConfigError("proxy provider evidence is invalid") from exc
    if status is not AttestationStatus.VALID:
        raise ProxyConfigError(f"proxy provider attestation is {status.value}")
    return config
