"""Explicit pull, status, and opt-in audit upload workflows."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from pydantic import BaseModel, ConfigDict

from codeshield.management.audit import safe_audit_projection
from codeshield.management.client import ManagementClient
from codeshield.management.config import (
    ManagementClientConfig,
    configured_path,
    load_management_config,
    management_token,
)
from codeshield.management.contracts import (
    ManagedPolicyBundle,
    load_public_key,
    verify_bundle,
)
from codeshield.management.storage import ManagementState, ManagementStorage
from codeshield.version import __version__


class ManagementServiceError(ValueError):
    """Fixed-code management workflow failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ManagementStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    configured: bool
    policy_status: str
    release_sequence: int = 0
    key_id: str | None = None
    expires_at: datetime | None = None


class ManagementService:
    def __init__(
        self,
        *,
        config_path: Path | None = None,
        storage_root: Path | None = None,
        transport: httpx.BaseTransport | None = None,
        now: datetime | None = None,
    ) -> None:
        self.config_path = config_path
        self.storage_root = storage_root
        self.transport = transport
        self.now = now

    def validate_config(self) -> ManagementClientConfig:
        return load_management_config(self.config_path)

    def status(self) -> ManagementStatus:
        source = self.config_path or configured_path()
        if not source.exists():
            return ManagementStatus(configured=False, policy_status="not_configured")
        try:
            config = load_management_config(source)
            storage = self._storage(config)
            state = storage.load_state()
            if state.release_sequence == 0:
                return ManagementStatus(configured=True, policy_status="missing")
            bundle = self._verified_active(config, storage, state)
            return ManagementStatus(
                configured=True,
                policy_status="valid",
                release_sequence=bundle.release_sequence,
                key_id=bundle.key_id,
                expires_at=bundle.expires_at,
            )
        except Exception as exc:
            code = getattr(exc, "code", "")
            status = "expired" if code == "CS_MANAGEMENT_BUNDLE_EXPIRED" else "invalid"
            return ManagementStatus(configured=True, policy_status=status)

    def pull_policy(self) -> ManagementStatus:
        config = load_management_config(self.config_path)
        storage = self._storage(config)
        state = storage.load_state()
        client = ManagementClient(
            config,
            management_token(),
            transport=self.transport,
        )
        try:
            signed = client.pull_latest()
        finally:
            client.close()
        if (
            signed.bundle.expires_at - signed.bundle.issued_at
            > timedelta(days=config.offline_validity_days)
        ):
            raise ManagementServiceError("CS_MANAGEMENT_OFFLINE_LIMIT_EXCEEDED")
        bundle = verify_bundle(
            signed,
            {
                key_id: load_public_key(value)
                for key_id, value in config.signing_public_keys.items()
            },
            organization_id=config.organization_id,
            current_engine_version=__version__,
            last_release_sequence=state.release_sequence,
            now=self._now(),
        )
        storage.activate(signed)
        return ManagementStatus(
            configured=True,
            policy_status="valid",
            release_sequence=bundle.release_sequence,
            key_id=bundle.key_id,
            expires_at=bundle.expires_at,
        )

    def upload_audit(self, *, confirm: bool) -> tuple[int, int]:
        config = load_management_config(self.config_path)
        events = safe_audit_projection(root=self.storage_root)
        if not confirm or not events:
            return len(events), 0
        client = ManagementClient(
            config,
            management_token(),
            transport=self.transport,
        )
        try:
            accepted = client.upload_audit(events)
        finally:
            client.close()
        return len(events), accepted

    def verified_active_bundle(self) -> ManagedPolicyBundle:
        config = load_management_config(self.config_path)
        storage = self._storage(config)
        state = storage.load_state()
        if state.release_sequence == 0:
            raise ManagementServiceError("CS_MANAGEMENT_POLICY_MISSING")
        return self._verified_active(config, storage, state)

    def _verified_active(
        self,
        config: ManagementClientConfig,
        storage: ManagementStorage,
        state: ManagementState,
    ) -> ManagedPolicyBundle:
        signed = storage.load_bundle()
        payload = (
            json.dumps(
                signed.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        if (
            signed.bundle.release_sequence != state.release_sequence
            or state.bundle_sha256 != hashlib.sha256(payload).hexdigest()
        ):
            raise ManagementServiceError("CS_MANAGEMENT_STATE_MISMATCH")
        return verify_bundle(
            signed,
            {
                key_id: load_public_key(value)
                for key_id, value in config.signing_public_keys.items()
            },
            organization_id=config.organization_id,
            current_engine_version=__version__,
            last_release_sequence=max(0, state.release_sequence - 1),
            now=self._now(),
        )

    def _storage(self, config: ManagementClientConfig) -> ManagementStorage:
        return ManagementStorage(
            config.organization_id,
            config.device_id,
            root=self.storage_root,
        )

    def _now(self) -> datetime:
        return (self.now or datetime.now(UTC)).astimezone(UTC)


def is_management_enrolled(path: Path | None = None) -> bool:
    if path is not None:
        return path.exists()
    if os.environ.get("CODESHIELD_MANAGEMENT_CONFIG"):
        return True
    return configured_path().exists()
