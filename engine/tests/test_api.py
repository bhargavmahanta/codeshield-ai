from __future__ import annotations

from fastapi.testclient import TestClient
from datetime import date

from codeshield.api.main import app
from codeshield.models.provider import ProviderAttestation
from codeshield.providers import AttestationStore, ProviderRegistry
from codeshield.version import __version__


def test_health_endpoint() -> None:
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["local_only"] is True


def test_version_endpoint() -> None:
    client = TestClient(app)

    response = client.get("/version")

    assert response.status_code == 200
    assert response.json() == {"version": __version__}


def test_scan_text_endpoint_never_returns_raw_secret() -> None:
    client = TestClient(app)
    raw = "sk_live_51SyntheticTokenValue999"

    response = client.post(
        "/scan/text",
        json={"text": f'api_key = "{raw}"', "destination": "public_git"},
    )

    assert response.status_code == 200
    assert raw not in response.text
    assert response.json()[0]["recommended_action"] == "block"


def test_protect_and_restore_pseudonym_locally() -> None:
    client = TestClient(app)
    raw = "user@example.test"

    protected = client.post(
        "/protect",
        json={
            "text": f"contact={raw}",
            "destination": "external_llm",
            "mode": "pseudonymize",
            "session_id": "api-test",
        },
    )

    assert protected.status_code == 200
    assert raw not in protected.text
    protected_text = protected.json()["protected_text"]
    restored = client.post(
        "/restore",
        json={"text": protected_text, "session_id": "api-test"},
    )
    assert restored.status_code == 200
    assert restored.json()["restored_text"].endswith(raw)


def test_api_rejects_oversized_declared_request() -> None:
    client = TestClient(app)

    response = client.post(
        "/scan/text",
        content=b"{}",
        headers={"content-type": "application/json", "content-length": "1000001"},
    )

    assert response.status_code == 413


def test_api_validation_error_does_not_echo_supplied_secret() -> None:
    client = TestClient(app)
    raw = "sk_live_51SyntheticValidationValue999"

    response = client.post(
        "/scan/text",
        json={"text": raw, "destination": "not-a-destination"},
    )

    assert response.status_code == 422
    assert raw not in response.text
    assert response.json() == {"detail": "request validation failed"}


def _api_attestation() -> str:
    registry = ProviderRegistry()
    profile = registry.require("openai-api-zdr")
    attestation = ProviderAttestation(
        attestation_id="api-provider-review",
        profile_id=profile.profile_id,
        profile_version=profile.version,
        account_hash="e" * 64,
        enabled_controls=["zdr-reviewed"],
        evidence_digest="f" * 64,
        reviewer_id="api-test",
        created_on=date(2026, 7, 16),
        expires_on=date(2026, 8, 31),
    )
    AttestationStore().save(attestation, registry)
    return attestation.attestation_id


def test_llm_assess_blocks_restricted_content_without_echoing_it() -> None:
    client = TestClient(app)
    raw = "sk_" + "live_51ApiPreflight" + "93628471"

    response = client.post(
        "/llm/assess",
        json={
            "segments": [
                {"segment_id": "one", "kind": "user", "content": raw}
            ],
            "provider_profile_id": "openai-api-zdr",
            "attestation_id": _api_attestation(),
            "purpose": "API contract test",
        },
    )

    assert response.status_code == 200
    assert response.json()["action"] == "block"
    assert response.json()["highest_sensitivity"] == "restricted"
    assert raw not in response.text


def test_llm_protect_returns_only_pseudonymized_personal_data() -> None:
    client = TestClient(app)
    raw = "api-reviewer@example.test"

    response = client.post(
        "/llm/protect",
        json={
            "segments": [
                {
                    "segment_id": "one",
                    "kind": "user",
                    "content": f"contact={raw}",
                }
            ],
            "provider_profile_id": "openai-api-zdr",
            "attestation_id": _api_attestation(),
            "purpose": "API protection test",
        },
    )

    assert response.status_code == 200
    assert response.json()["assessment"]["safe_to_send"] is True
    assert "<EMAIL_1>" in response.json()["protected_segments"][0]["protected_content"]
    assert raw not in response.text


def test_llm_validation_error_does_not_echo_segment_content() -> None:
    client = TestClient(app)
    raw = "private-validation-content"

    response = client.post(
        "/llm/assess",
        json={
            "segments": [{"segment_id": "one", "kind": "invalid", "content": raw}],
            "provider_profile_id": "openai-api-zdr",
            "purpose": "validation",
        },
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "request validation failed"}
    assert raw not in response.text
