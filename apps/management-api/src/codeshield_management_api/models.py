"""Strict metadata-only HTTP models."""

from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from codeshield.management import SignedPolicyBundle
from codeshield.management.audit import SafeAuditEvent

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthResponse(StrictModel):
    status: str = "ok"
    service: str = "codeshield-management-api"
    metadata_only: bool = True


class VersionResponse(StrictModel):
    version: str


class DeviceTokenRequest(StrictModel):
    organization_id: UUID
    device_id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=120)
    owner_user_id: UUID

    @field_validator("device_id")
    @classmethod
    def safe_device_id(cls, value: str) -> str:
        if not IDENTIFIER.fullmatch(value):
            raise ValueError("device identifier is invalid")
        return value


class DeviceTokenResponse(StrictModel):
    device_uuid: UUID
    device_id: str
    token: str
    shown_once: bool = True


class DeviceRevocationResponse(StrictModel):
    device_uuid: UUID
    status: str = "revoked"


class PolicyReleaseRequest(StrictModel):
    organization_id: UUID
    policy_version_id: UUID
    provider_profile_version_ids: list[UUID] = Field(default_factory=list, max_length=128)
    destination_version_ids: list[UUID] = Field(default_factory=list, max_length=128)
    minimum_compatible_engine: str = Field(
        pattern=r"^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$"
    )
    expires_at: datetime


class PolicyReleaseResponse(StrictModel):
    release_id: UUID
    signed_bundle: SignedPolicyBundle


class AuditEventInput(SafeAuditEvent):
    model_config = ConfigDict(extra="forbid")


class AuditBatchRequest(StrictModel):
    events: list[AuditEventInput] = Field(min_length=1, max_length=500)


class AuditBatchResponse(StrictModel):
    accepted: int = Field(ge=0)
