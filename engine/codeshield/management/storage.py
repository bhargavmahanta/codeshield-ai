"""Atomic local storage for verified managed policy bundles and state."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from datetime import datetime
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from codeshield.management.config import management_home
from codeshield.management.contracts import SignedPolicyBundle


class ManagementStorageError(ValueError):
    """Sanitized local storage failure."""


class ManagementState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    organization_id: UUID
    device_id: UUID
    release_sequence: int = Field(ge=0)
    key_id: str | None = None
    expires_at: datetime | None = None
    bundle_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class ManagementStorage:
    def __init__(
        self,
        organization_id: UUID,
        device_id: UUID,
        *,
        root: Path | None = None,
    ) -> None:
        base = root or management_home()
        self.directory = base / "management" / str(organization_id) / str(device_id)
        self.bundle_path = self.directory / "active-bundle.json"
        self.state_path = self.directory / "state.json"
        self.organization_id = organization_id
        self.device_id = device_id

    def load_state(self) -> ManagementState:
        if not self.state_path.exists():
            return ManagementState(
                organization_id=self.organization_id,
                device_id=self.device_id,
                release_sequence=0,
            )
        try:
            return ManagementState.model_validate_json(
                _read_regular_file(self.state_path, maximum=16_384)
            )
        except (OSError, UnicodeError, ValueError) as exc:
            raise ManagementStorageError("management state is invalid") from exc

    def load_bundle(self) -> SignedPolicyBundle:
        try:
            return SignedPolicyBundle.model_validate_json(
                _read_regular_file(self.bundle_path, maximum=1_000_000)
            )
        except (OSError, UnicodeError, ValueError) as exc:
            raise ManagementStorageError("managed policy bundle is invalid") from exc

    def activate(self, signed: SignedPolicyBundle) -> ManagementState:
        payload = (
            json.dumps(
                signed.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        state = ManagementState(
            organization_id=self.organization_id,
            device_id=self.device_id,
            release_sequence=signed.bundle.release_sequence,
            key_id=signed.bundle.key_id,
            expires_at=signed.bundle.expires_at,
            bundle_sha256=hashlib.sha256(payload).hexdigest(),
        )
        state_payload = (
            json.dumps(
                state.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        previous_bundle: bytes | None = None
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            _reject_reparse_points(self.directory)
            if self.bundle_path.exists():
                previous_bundle = _read_regular_bytes(
                    self.bundle_path,
                    maximum=1_000_000,
                )
            _atomic_write(self.bundle_path, payload)
            try:
                _atomic_write(self.state_path, state_payload)
            except Exception:
                try:
                    if previous_bundle is None:
                        self.bundle_path.unlink(missing_ok=True)
                    else:
                        _atomic_write(self.bundle_path, previous_bundle)
                except (OSError, ManagementStorageError):
                    pass
                raise
            return state
        except ManagementStorageError:
            raise
        except OSError as exc:
            raise ManagementStorageError(
                "managed policy activation failed"
            ) from exc


def _read_regular_file(path: Path, *, maximum: int) -> str:
    return _read_regular_bytes(path, maximum=maximum).decode(
        "utf-8",
        errors="strict",
    )


def _read_regular_bytes(path: Path, *, maximum: int) -> bytes:
    link_stat = path.lstat()
    if stat.S_ISLNK(link_stat.st_mode) or not stat.S_ISREG(link_stat.st_mode):
        raise ManagementStorageError("managed policy storage is unsafe")
    data = path.read_bytes()
    if len(data) > maximum:
        raise ManagementStorageError("managed policy storage is oversized")
    return data


def _reject_reparse_points(directory: Path) -> None:
    current = directory
    while current != current.parent:
        if current.exists():
            link_stat = current.lstat()
            if stat.S_ISLNK(link_stat.st_mode):
                raise ManagementStorageError("managed policy storage is unsafe")
            if os.name == "nt" and getattr(link_stat, "st_file_attributes", 0) & 0x400:
                raise ManagementStorageError("managed policy storage is unsafe")
        current = current.parent


def _atomic_write(destination: Path, payload: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        try:
            destination.chmod(0o600)
        except OSError:
            pass
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise ManagementStorageError("managed policy write failed") from exc
