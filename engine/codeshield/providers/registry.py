"""Load reviewed provider profiles and store local administrative attestations."""

from __future__ import annotations

import json
import os
from datetime import date
from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import TypeAdapter, ValidationError

from codeshield.models.enums import AttestationStatus
from codeshield.models.provider import ProviderAttestation, ProviderProfile


class ProviderRegistryError(ValueError):
    """Safe provider configuration error."""


class ProviderRegistry:
    def __init__(self, path: Path | None = None) -> None:
        source = path or Path(str(files("codeshield.providers").joinpath("profiles.yaml")))
        try:
            payload = yaml.safe_load(source.read_text(encoding="utf-8"))
            profiles = TypeAdapter(list[ProviderProfile]).validate_python(payload)
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise ProviderRegistryError("unable to load provider profiles") from exc
        ids = [profile.profile_id for profile in profiles]
        if len(ids) != len(set(ids)):
            raise ProviderRegistryError("provider profile IDs must be unique")
        self.source = source
        self._profiles = {profile.profile_id: profile for profile in profiles}

    def list(self) -> list[ProviderProfile]:
        return sorted(self._profiles.values(), key=lambda item: item.profile_id)

    def get(self, profile_id: str) -> ProviderProfile | None:
        return self._profiles.get(profile_id)

    def require(self, profile_id: str) -> ProviderProfile:
        profile = self.get(profile_id)
        if profile is None:
            raise ProviderRegistryError("unknown provider profile")
        return profile

    def verify(self, *, today: date | None = None) -> list[str]:
        current = today or date.today()
        errors: list[str] = []
        for profile in self.list():
            if profile.review_due < current:
                errors.append(f"{profile.profile_id}: provider evidence is stale")
            if profile.zero_data_retention and profile.maximum_retention_days not in {0, None}:
                errors.append(f"{profile.profile_id}: ZDR conflicts with retention")
            if profile.reference_only and profile.zero_data_retention:
                errors.append(f"{profile.profile_id}: reference profile cannot claim ZDR")
            if profile.prohibits_training and any(
                fact.used_for_training for fact in profile.handling
            ):
                errors.append(f"{profile.profile_id}: handling conflicts with no-training claim")
            retained_days = [
                fact.retention_days
                for fact in profile.handling
                if fact.retention_days is not None
            ]
            if (
                retained_days
                and profile.maximum_retention_days is not None
                and max(retained_days) > profile.maximum_retention_days
            ):
                errors.append(f"{profile.profile_id}: handling exceeds profile retention")
            if profile.zero_data_retention and any(
                fact.retained
                for fact in profile.handling
                if fact.data_type.value in {"prompt", "output"}
            ):
                errors.append(f"{profile.profile_id}: ZDR prompt/output is marked retained")
        return errors


class AttestationStore:
    def __init__(self, path: Path | None = None) -> None:
        root = Path(os.environ.get("CODESHIELD_HOME", Path.home() / ".codeshield"))
        self.path = path or root / "provider-attestations.json"

    def list(self) -> list[ProviderAttestation]:
        if not self.path.exists():
            return []
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            return TypeAdapter(list[ProviderAttestation]).validate_python(payload)
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            raise ProviderRegistryError("unable to load local provider attestations") from exc

    def get(self, attestation_id: str) -> ProviderAttestation | None:
        return next(
            (item for item in self.list() if item.attestation_id == attestation_id),
            None,
        )

    def save(self, attestation: ProviderAttestation, registry: ProviderRegistry) -> None:
        profile = registry.require(attestation.profile_id)
        if attestation.profile_version != profile.version:
            raise ProviderRegistryError("attestation profile version does not match")
        if attestation.expires_on > profile.review_due:
            raise ProviderRegistryError("attestation cannot outlive provider evidence")
        records = [
            item for item in self.list() if item.attestation_id != attestation.attestation_id
        ]
        records.append(attestation)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                [item.model_dump(mode="json") for item in records],
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def status(
        self,
        attestation_id: str | None,
        profile: ProviderProfile,
        *,
        today: date | None = None,
    ) -> tuple[AttestationStatus, ProviderAttestation | None]:
        if not attestation_id:
            return AttestationStatus.MISSING, None
        attestation = self.get(attestation_id)
        if attestation is None:
            return AttestationStatus.INVALID, None
        if (
            attestation.profile_id != profile.profile_id
            or attestation.profile_version != profile.version
        ):
            return AttestationStatus.INVALID, attestation
        current = today or date.today()
        if attestation.expires_on < current or profile.review_due < current:
            return AttestationStatus.STALE, attestation
        return AttestationStatus.VALID, attestation
