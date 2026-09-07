"""Canonical signed policy-bundle contracts shared by server and local clients."""

from __future__ import annotations

import base64
import json
import re
from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
VERSION = re.compile(r"^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$")
MAX_OFFLINE_VALIDITY = timedelta(days=7)


class PolicyRulePayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(min_length=1, max_length=128)
    category: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    action: str = Field(pattern=r"^(allow|warn|mask|pseudonymize|block)$")
    destination_id: str = Field(min_length=1, max_length=128)
    sensitivity: str = Field(
        pattern=r"^(public|internal|confidential|restricted)$"
    )
    mandatory: bool
    remediation_code: str = Field(min_length=1, max_length=128)
    enabled: bool = True

    @field_validator("rule_id", "destination_id", "remediation_code")
    @classmethod
    def safe_identifier(cls, value: str) -> str:
        if not IDENTIFIER.fullmatch(value):
            raise ValueError("identifier is invalid")
        return value


class PolicyDocumentPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str = Field(min_length=1, max_length=128)
    version: int = Field(gt=0)
    name: str = Field(min_length=1, max_length=120)
    mandatory: bool
    rules: list[PolicyRulePayload] = Field(max_length=256)

    @field_validator("policy_id")
    @classmethod
    def safe_policy_id(cls, value: str) -> str:
        if not IDENTIFIER.fullmatch(value):
            raise ValueError("policy identifier is invalid")
        return value


class ProviderProfileVersionReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version_id: UUID
    profile_id: str = Field(min_length=1, max_length=128)
    version: int = Field(gt=0)
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("profile_id")
    @classmethod
    def safe_profile_id(cls, value: str) -> str:
        if not IDENTIFIER.fullmatch(value):
            raise ValueError("profile identifier is invalid")
        return value


class DestinationVersionReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version_id: UUID
    destination_id: str = Field(min_length=1, max_length=128)
    version: int = Field(gt=0)
    sensitivity_ceiling: str = Field(
        pattern=r"^(public|internal|confidential|restricted)$"
    )

    @field_validator("destination_id")
    @classmethod
    def safe_destination_id(cls, value: str) -> str:
        if not IDENTIFIER.fullmatch(value):
            raise ValueError("destination identifier is invalid")
        return value


class ManagedPolicyBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    organization_id: UUID
    release_sequence: int = Field(gt=0)
    policy_version_id: UUID
    policy: PolicyDocumentPayload
    provider_profiles: list[ProviderProfileVersionReference] = Field(max_length=128)
    destinations: list[DestinationVersionReference] = Field(max_length=128)
    minimum_compatible_engine: str
    issued_at: datetime
    expires_at: datetime
    key_id: str = Field(min_length=1, max_length=128)

    @field_validator("minimum_compatible_engine")
    @classmethod
    def semantic_version(cls, value: str) -> str:
        if not VERSION.fullmatch(value):
            raise ValueError("minimum compatible engine version is invalid")
        return value

    @field_validator("key_id")
    @classmethod
    def safe_key_id(cls, value: str) -> str:
        if not IDENTIFIER.fullmatch(value):
            raise ValueError("key identifier is invalid")
        return value

    @field_validator("issued_at", "expires_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("bundle timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validity_is_bounded(self) -> "ManagedPolicyBundle":
        if self.expires_at <= self.issued_at:
            raise ValueError("bundle expiry must follow issuance")
        if self.expires_at - self.issued_at > MAX_OFFLINE_VALIDITY:
            raise ValueError("bundle validity exceeds seven days")
        if len({item.version_id for item in self.provider_profiles}) != len(
            self.provider_profiles
        ):
            raise ValueError("provider profile versions must be unique")
        if len({item.version_id for item in self.destinations}) != len(
            self.destinations
        ):
            raise ValueError("destination versions must be unique")
        return self


class SignedPolicyBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    bundle: ManagedPolicyBundle
    signature: str = Field(min_length=86, max_length=86)

    @field_validator("signature")
    @classmethod
    def valid_signature_encoding(cls, value: str) -> str:
        try:
            decoded = _decode_urlsafe(value)
        except ValueError as exc:
            raise ValueError("signature encoding is invalid") from exc
        if len(decoded) != 64:
            raise ValueError("signature length is invalid")
        return value


class BundleVerificationError(ValueError):
    """A fixed-code verification failure safe for CLI and logs."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canonical_bundle_bytes(bundle: ManagedPolicyBundle) -> bytes:
    payload = bundle.model_dump(mode="json")
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_bundle(
    bundle: ManagedPolicyBundle,
    private_key: Ed25519PrivateKey,
) -> SignedPolicyBundle:
    signature = private_key.sign(canonical_bundle_bytes(bundle))
    return SignedPolicyBundle(bundle=bundle, signature=_encode_urlsafe(signature))


def verify_bundle(
    signed: SignedPolicyBundle,
    public_keys: dict[str, Ed25519PublicKey],
    *,
    organization_id: UUID,
    current_engine_version: str,
    last_release_sequence: int,
    now: datetime | None = None,
) -> ManagedPolicyBundle:
    bundle = signed.bundle
    key = public_keys.get(bundle.key_id)
    if key is None:
        raise BundleVerificationError("CS_MANAGEMENT_UNKNOWN_SIGNING_KEY")
    try:
        key.verify(_decode_urlsafe(signed.signature), canonical_bundle_bytes(bundle))
    except (InvalidSignature, ValueError) as exc:
        raise BundleVerificationError("CS_MANAGEMENT_SIGNATURE_INVALID") from exc
    if bundle.organization_id != organization_id:
        raise BundleVerificationError("CS_MANAGEMENT_ORGANIZATION_MISMATCH")
    instant = (now or datetime.now(UTC)).astimezone(UTC)
    if instant < bundle.issued_at or instant >= bundle.expires_at:
        raise BundleVerificationError("CS_MANAGEMENT_BUNDLE_EXPIRED")
    if bundle.release_sequence <= last_release_sequence:
        raise BundleVerificationError("CS_MANAGEMENT_DOWNGRADE_REJECTED")
    if _version_tuple(current_engine_version) < _version_tuple(
        bundle.minimum_compatible_engine
    ):
        raise BundleVerificationError("CS_MANAGEMENT_ENGINE_INCOMPATIBLE")
    return bundle


def load_private_key(value: str) -> Ed25519PrivateKey:
    raw = _decode_urlsafe(value)
    if len(raw) != 32:
        raise ValueError("private signing key length is invalid")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_public_key(value: str) -> Ed25519PublicKey:
    raw = _decode_urlsafe(value)
    if len(raw) != 32:
        raise ValueError("public signing key length is invalid")
    return Ed25519PublicKey.from_public_bytes(raw)


def encode_public_key(key: Ed25519PublicKey) -> str:
    return _encode_urlsafe(key.public_bytes_raw())


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = VERSION.fullmatch(value)
    if match is None:
        raise BundleVerificationError("CS_MANAGEMENT_ENGINE_INCOMPATIBLE")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def _encode_urlsafe(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_urlsafe(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("base64url value is invalid")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("base64url value is invalid") from exc
