from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from codeshield.models.enums import AttestationStatus
from codeshield.models.provider import ProviderAttestation
from codeshield.providers import AttestationStore, ProviderRegistry, ProviderRegistryError


def _attestation(profile_id: str, version: str, *, expires: date) -> ProviderAttestation:
    return ProviderAttestation(
        attestation_id="reviewed-provider",
        profile_id=profile_id,
        profile_version=version,
        account_hash="a" * 64,
        enabled_controls=["no-training", "retention-reviewed"],
        evidence_digest="b" * 64,
        reviewer_id="security-reviewer",
        created_on=date(2026, 7, 16),
        expires_on=expires,
    )


def test_provider_matrix_contains_requested_enterprise_surfaces() -> None:
    profiles = ProviderRegistry().list()
    identifiers = {profile.profile_id for profile in profiles}

    assert {
        "openai-api-standard",
        "openai-api-zdr",
        "anthropic-api-commercial",
        "claude-code-zdr",
        "gemini-api-paid",
        "vertex-ai-zdr",
        "azure-foundry-stateless",
        "bedrock-runtime",
        "copilot-business-ide",
        "copilot-business-cli",
    } <= identifiers
    assert ProviderRegistry().verify(today=date(2026, 10, 14)) == []
    assert ProviderRegistry().verify(today=date(2026, 10, 15))


def test_attestation_is_local_versioned_and_cannot_outlive_profile(tmp_path: Path) -> None:
    registry = ProviderRegistry()
    profile = registry.require("openai-api-zdr")
    store = AttestationStore(tmp_path / "attestations.json")
    valid = _attestation(profile.profile_id, profile.version, expires=date(2026, 10, 14))

    store.save(valid, registry)

    status, loaded = store.status(
        valid.attestation_id, profile, today=date(2026, 8, 1)
    )
    assert status is AttestationStatus.VALID
    assert loaded == valid
    assert "security-reviewer" in store.path.read_text(encoding="utf-8")

    invalid = ProviderAttestation(
        attestation_id="reviewed-provider-late",
        profile_id=profile.profile_id,
        profile_version=profile.version,
        account_hash="a" * 64,
        enabled_controls=["no-training"],
        evidence_digest="b" * 64,
        reviewer_id="security-reviewer",
        created_on=date(2026, 7, 17),
        expires_on=date(2026, 10, 15),
    )
    with pytest.raises(ProviderRegistryError, match="outlive"):
        store.save(invalid, registry)


def test_attestation_status_is_missing_invalid_or_stale(tmp_path: Path) -> None:
    registry = ProviderRegistry()
    profile = registry.require("bedrock-runtime")
    store = AttestationStore(tmp_path / "attestations.json")

    assert store.status(None, profile)[0] is AttestationStatus.MISSING
    assert store.status("unknown", profile)[0] is AttestationStatus.INVALID
    attestation = _attestation(
        profile.profile_id, profile.version, expires=date(2026, 8, 1)
    )
    store.save(attestation, registry)
    assert (
        store.status(attestation.attestation_id, profile, today=date(2026, 8, 2))[0]
        is AttestationStatus.STALE
    )
