"""Strict server-only configuration for the management API."""

from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ENVIRONMENT_KEYS = {
    "supabase_service_credential": "SUPABASE_SERVICE_ROLE_KEY",
    "signing_private_key": "CODESHIELD_MANAGEMENT_SIGNING_KEY",
    "token_pepper": "CODESHIELD_MANAGEMENT_TOKEN_PEPPER",
}


class ManagementConfigError(ValueError):
    """Sanitized configuration error."""


class ManagementSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    supabase_url: str
    supabase_service_credential: str = Field(min_length=32, repr=False)
    signing_private_key: str = Field(min_length=43, max_length=44, repr=False)
    signing_key_id: str = Field(min_length=1, max_length=128)
    token_pepper: str = Field(min_length=32, repr=False)
    cors_origins: tuple[str, ...] = ("http://127.0.0.1:3000",)
    max_request_bytes: int = Field(default=262_144, ge=16_384, le=1_000_000)
    max_audit_batch: int = Field(default=100, ge=1, le=500)

    @field_validator("supabase_url")
    @classmethod
    def local_supabase_only(cls, value: str) -> str:
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
            raise ValueError("Supabase URL must be an exact loopback HTTP origin")
        host = f"[{parsed.hostname}]" if parsed.hostname == "::1" else parsed.hostname
        port = f":{parsed.port}" if parsed.port else ""
        return f"http://{host}{port}"

    @field_validator("signing_key_id")
    @classmethod
    def safe_key_identifier(cls, value: str) -> str:
        if not IDENTIFIER.fullmatch(value):
            raise ValueError("signing key identifier is invalid")
        return value

    @field_validator("cors_origins")
    @classmethod
    def exact_cors_origins(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or len(values) != len(set(values)):
            raise ValueError("CORS origins must be unique and non-empty")
        normalized: list[str] = []
        for value in values:
            parsed = urlsplit(value)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
            ):
                raise ValueError("CORS origin must be exact")
            normalized.append(value.rstrip("/"))
        return tuple(normalized)

    @classmethod
    def from_environment(cls) -> "ManagementSettings":
        values: dict[str, object] = {
            "supabase_url": os.environ.get(
                "CODESHIELD_SUPABASE_URL", "http://127.0.0.1:54321"
            ),
            "signing_key_id": os.environ.get(
                "CODESHIELD_MANAGEMENT_SIGNING_KEY_ID", ""
            ),
        }
        for field, environment_name in ENVIRONMENT_KEYS.items():
            value = os.environ.get(environment_name)
            if not value:
                raise ManagementConfigError(
                    "management server configuration is incomplete"
                )
            values[field] = value
        origin_value = os.environ.get("CODESHIELD_MANAGEMENT_CORS_ORIGINS")
        if origin_value:
            values["cors_origins"] = tuple(
                item.strip() for item in origin_value.split(",") if item.strip()
            )
        try:
            return cls.model_validate(values)
        except ValueError as exc:
            raise ManagementConfigError(
                "management server configuration is invalid"
            ) from exc
