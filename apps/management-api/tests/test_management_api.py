from __future__ import annotations

import base64
import asyncio
import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from codeshield.management import (
    BundleVerificationError,
    DestinationVersionReference,
    ManagedPolicyBundle,
    PolicyDocumentPayload,
    PolicyRulePayload,
    ProviderProfileVersionReference,
    SignedPolicyBundle,
    sign_bundle,
    verify_bundle,
)
from codeshield_management_api.app import create_app
from codeshield_management_api.config import ManagementSettings
from codeshield_management_api.models import AuditEventInput, DeviceTokenRequest
from codeshield_management_api.repository import (
    DashboardPrincipal,
    DeviceRecord,
    PolicyMaterial,
    RepositoryError,
    SupabaseRepository,
)

ORGANIZATION_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_ORGANIZATION_ID = UUID("22222222-2222-4222-8222-222222222222")
ADMIN_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
DEVELOPER_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3")
DEVICE_UUID = UUID("11111111-e001-4111-8111-111111111111")
POLICY_VERSION_ID = UUID("11111111-c101-4111-8111-111111111111")
PROFILE_VERSION_ID = UUID("11111111-a001-4111-8111-111111111111")
DESTINATION_VERSION_ID = UUID("11111111-d101-4111-8111-111111111111")
RELEASE_ID = UUID("11111111-f001-4111-8111-111111111111")


class MemoryRepository:
    def __init__(self) -> None:
        self.dashboard_tokens = {
            "dashboard-admin": DashboardPrincipal(ADMIN_ID, "administrator"),
            "dashboard-developer": DashboardPrincipal(DEVELOPER_ID, "developer"),
        }
        self.device_uuid = DEVICE_UUID
        self.device_request: DeviceTokenRequest | None = None
        self.digest_hex: str | None = None
        self.device_status = "active"
        self.release: tuple[UUID, SignedPolicyBundle] | None = None
        self.audits: list[AuditEventInput] = []
        self.closed = False
        self.fail = False

    async def authenticate_dashboard(
        self, token: str, organization_id: UUID
    ) -> DashboardPrincipal | None:
        if self.fail:
            raise RepositoryError("synthetic failure")
        if organization_id != ORGANIZATION_ID:
            return None
        return self.dashboard_tokens.get(token)

    async def create_device(self, request: DeviceTokenRequest) -> UUID:
        self.device_request = request
        return self.device_uuid

    async def store_device_token_hash(
        self, device_uuid: UUID, digest_hex: str
    ) -> None:
        assert device_uuid == self.device_uuid
        self.digest_hex = digest_hex

    async def read_device_token_hash(
        self, device_uuid: UUID
    ) -> DeviceRecord | None:
        if device_uuid != self.device_uuid or self.digest_hex is None:
            return None
        return DeviceRecord(
            device_uuid=device_uuid,
            organization_id=ORGANIZATION_ID,
            status=self.device_status,
            digest_hex=self.digest_hex,
        )

    async def revoke_device(self, device_uuid: UUID) -> None:
        assert device_uuid == self.device_uuid
        self.device_status = "revoked"

    async def load_policy_material(
        self,
        organization_id: UUID,
        policy_version_id: UUID,
        provider_profile_version_ids: list[UUID],
        destination_version_ids: list[UUID],
    ) -> PolicyMaterial | None:
        if (
            organization_id != ORGANIZATION_ID
            or policy_version_id != POLICY_VERSION_ID
            or provider_profile_version_ids != [PROFILE_VERSION_ID]
            or destination_version_ids != [DESTINATION_VERSION_ID]
        ):
            return None
        return policy_material()

    async def next_release_sequence(self, organization_id: UUID) -> int:
        assert organization_id == ORGANIZATION_ID
        return 1 if self.release is None else self.release[1].bundle.release_sequence + 1

    async def persist_release(
        self,
        signed_bundle: SignedPolicyBundle,
        created_by: UUID,
    ) -> UUID:
        assert created_by == ADMIN_ID
        self.release = (RELEASE_ID, signed_bundle)
        return RELEASE_ID

    async def latest_release(
        self, organization_id: UUID
    ) -> tuple[UUID, SignedPolicyBundle] | None:
        assert organization_id == ORGANIZATION_ID
        return self.release

    async def insert_audit_events(
        self,
        organization_id: UUID,
        device_uuid: UUID,
        events: list[AuditEventInput],
    ) -> int:
        assert organization_id == ORGANIZATION_ID
        assert device_uuid == self.device_uuid
        self.audits.extend(events)
        return len(events)

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def settings() -> ManagementSettings:
    encoded = base64.urlsafe_b64encode(bytes([1]) * 32).rstrip(b"=").decode()
    return ManagementSettings(
        supabase_url="http://127.0.0.1:54321",
        supabase_service_credential="local-service-role-placeholder-0001",
        signing_private_key=encoded,
        signing_key_id="test-key",
        token_pepper="local-test-pepper-material-00000001",
        cors_origins=("http://127.0.0.1:3000",),
        max_request_bytes=16_384,
        max_audit_batch=2,
    )


@pytest.fixture
def repository() -> MemoryRepository:
    return MemoryRepository()


@pytest.fixture
def client(
    settings: ManagementSettings,
    repository: MemoryRepository,
    signing_key: Ed25519PrivateKey,
) -> TestClient:
    return TestClient(
        create_app(settings, repository=repository, signer=signing_key)
    )


def policy_material() -> PolicyMaterial:
    return PolicyMaterial(
        policy_version_id=POLICY_VERSION_ID,
        policy=PolicyDocumentPayload(
            policy_id="baseline",
            version=1,
            name="Synthetic baseline",
            mandatory=True,
            rules=[
                PolicyRulePayload(
                    rule_id="restricted-block",
                    category="API_KEY",
                    action="block",
                    destination_id="local_file",
                    sensitivity="restricted",
                    mandatory=True,
                    remediation_code="remove_secret",
                )
            ],
        ),
        provider_profiles=[
            ProviderProfileVersionReference(
                version_id=PROFILE_VERSION_ID,
                profile_id="synthetic-provider",
                version=1,
                evidence_digest="a" * 64,
            )
        ],
        destinations=[
            DestinationVersionReference(
                version_id=DESTINATION_VERSION_ID,
                destination_id="local_file",
                version=1,
                sensitivity_ceiling="restricted",
            )
        ],
    )


def release_payload() -> dict[str, object]:
    return {
        "organization_id": str(ORGANIZATION_ID),
        "policy_version_id": str(POLICY_VERSION_ID),
        "provider_profile_version_ids": [str(PROFILE_VERSION_ID)],
        "destination_version_ids": [str(DESTINATION_VERSION_ID)],
        "minimum_compatible_engine": "0.9.0",
        "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    }


def issue_device(client: TestClient) -> str:
    response = client.post(
        "/v1/device-tokens",
        headers={"authorization": "Bearer dashboard-admin"},
        json={
            "organization_id": str(ORGANIZATION_ID),
            "device_id": "synthetic-device",
            "display_name": "Synthetic device",
            "owner_user_id": str(DEVELOPER_ID),
        },
    )
    assert response.status_code == 200
    return response.json()["token"]


def release_bundle(client: TestClient) -> dict[str, object]:
    response = client.post(
        "/v1/policy-bundles/releases",
        headers={"authorization": "Bearer dashboard-admin"},
        json=release_payload(),
    )
    assert response.status_code == 200
    return response.json()


def test_health_version_openapi_and_security_headers(client: TestClient) -> None:
    health = client.get("/health")
    assert health.json() == {
        "status": "ok",
        "service": "codeshield-management-api",
        "metadata_only": True,
    }
    assert health.headers["cache-control"] == "private, no-store"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert client.get("/version").json() == {"version": "0.9.0"}
    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths) == {
        "/health",
        "/version",
        "/v1/audit-events/batch",
        "/v1/device-tokens",
        "/v1/devices/{device_uuid}/revoke",
        "/v1/policy-bundles/latest",
        "/v1/policy-bundles/releases",
    }


def test_exact_cors_origin(client: TestClient) -> None:
    allowed = client.options(
        "/v1/device-tokens",
        headers={
            "origin": "http://127.0.0.1:3000",
            "access-control-request-method": "POST",
        },
    )
    assert allowed.headers["access-control-allow-origin"] == "http://127.0.0.1:3000"
    denied = client.options(
        "/v1/device-tokens",
        headers={
            "origin": "https://example.invalid",
            "access-control-request-method": "POST",
        },
    )
    assert "access-control-allow-origin" not in denied.headers


def test_dashboard_authentication_and_role_authorization(client: TestClient) -> None:
    payload = {
        "organization_id": str(ORGANIZATION_ID),
        "device_id": "synthetic-device",
        "display_name": "Synthetic device",
        "owner_user_id": str(DEVELOPER_ID),
    }
    missing = client.post("/v1/device-tokens", json=payload)
    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "CS_MANAGEMENT_AUTHENTICATION"
    denied = client.post(
        "/v1/device-tokens",
        headers={"authorization": "Bearer dashboard-developer"},
        json=payload,
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "CS_MANAGEMENT_AUTHORIZATION"


def test_device_token_is_one_time_hashed_and_not_logged(
    client: TestClient,
    repository: MemoryRepository,
    settings: ManagementSettings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    token = issue_device(client)
    assert token.startswith(f"csm_{DEVICE_UUID}.")
    assert repository.digest_hex == hmac.new(
        settings.token_pepper.encode(),
        token.encode(),
        hashlib.sha256,
    ).hexdigest()
    assert token not in caplog.text
    assert repository.device_request is not None


def test_release_is_signed_canonical_and_verifiable(
    client: TestClient,
    signing_key: Ed25519PrivateKey,
) -> None:
    payload = release_bundle(client)
    signed = SignedPolicyBundle.model_validate(payload["signed_bundle"])
    verified = verify_bundle(
        signed,
        {"test-key": signing_key.public_key()},
        organization_id=ORGANIZATION_ID,
        current_engine_version="0.9.0",
        last_release_sequence=0,
    )
    assert verified.release_sequence == 1
    assert verified.policy.rules[0].mandatory is True
    first = json.dumps(signed.model_dump(mode="json"), sort_keys=True)
    second = json.dumps(
        SignedPolicyBundle.model_validate_json(first).model_dump(mode="json"),
        sort_keys=True,
    )
    assert first == second


def test_tampering_unknown_key_expiry_and_rollback_are_rejected(
    client: TestClient,
    signing_key: Ed25519PrivateKey,
) -> None:
    payload = release_bundle(client)
    raw = payload["signed_bundle"]
    signed = SignedPolicyBundle.model_validate(raw)
    tampered = json.loads(json.dumps(raw))
    tampered["bundle"]["release_sequence"] = 2
    with pytest.raises(BundleVerificationError, match="SIGNATURE_INVALID"):
        verify_bundle(
            SignedPolicyBundle.model_validate(tampered),
            {"test-key": signing_key.public_key()},
            organization_id=ORGANIZATION_ID,
            current_engine_version="0.9.0",
            last_release_sequence=0,
        )
    with pytest.raises(BundleVerificationError, match="UNKNOWN_SIGNING_KEY"):
        verify_bundle(
            signed,
            {},
            organization_id=ORGANIZATION_ID,
            current_engine_version="0.9.0",
            last_release_sequence=0,
        )
    with pytest.raises(BundleVerificationError, match="DOWNGRADE_REJECTED"):
        verify_bundle(
            signed,
            {"test-key": signing_key.public_key()},
            organization_id=ORGANIZATION_ID,
            current_engine_version="0.9.0",
            last_release_sequence=1,
        )
    with pytest.raises(BundleVerificationError, match="BUNDLE_EXPIRED"):
        verify_bundle(
            signed,
            {"test-key": signing_key.public_key()},
            organization_id=ORGANIZATION_ID,
            current_engine_version="0.9.0",
            last_release_sequence=0,
            now=signed.bundle.expires_at,
        )


def test_key_rotation_accepts_only_pinned_key() -> None:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    material = policy_material()
    now = datetime.now(UTC)
    bundle = ManagedPolicyBundle(
        organization_id=ORGANIZATION_ID,
        release_sequence=1,
        policy_version_id=POLICY_VERSION_ID,
        policy=material.policy,
        provider_profiles=material.provider_profiles,
        destinations=material.destinations,
        minimum_compatible_engine="0.9.0",
        issued_at=now,
        expires_at=now + timedelta(days=1),
        key_id="new-key",
    )
    signed = sign_bundle(bundle, new_key)
    with pytest.raises(BundleVerificationError, match="UNKNOWN_SIGNING_KEY"):
        verify_bundle(
            signed,
            {"old-key": old_key.public_key()},
            organization_id=ORGANIZATION_ID,
            current_engine_version="0.9.0",
            last_release_sequence=0,
        )
    assert (
        verify_bundle(
            signed,
            {
                "old-key": old_key.public_key(),
                "new-key": new_key.public_key(),
            },
            organization_id=ORGANIZATION_ID,
            current_engine_version="0.9.0",
            last_release_sequence=0,
        ).key_id
        == "new-key"
    )


def test_latest_bundle_requires_valid_active_device(
    client: TestClient,
    repository: MemoryRepository,
) -> None:
    token = issue_device(client)
    release_bundle(client)
    response = client.get(
        "/v1/policy-bundles/latest",
        headers={"authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["release_id"] == str(RELEASE_ID)
    wrong = token[:-1] + ("A" if token[-1] != "A" else "B")
    assert (
        client.get(
            "/v1/policy-bundles/latest",
            headers={"authorization": f"Bearer {wrong}"},
        ).status_code
        == 401
    )
    repository.device_status = "revoked"
    revoked = client.get(
        "/v1/policy-bundles/latest",
        headers={"authorization": f"Bearer {token}"},
    )
    assert revoked.status_code == 401
    assert revoked.json()["error"]["code"] == "CS_MANAGEMENT_DEVICE_REVOKED"


def test_administrator_can_revoke_device(
    client: TestClient,
    repository: MemoryRepository,
) -> None:
    issue_device(client)
    response = client.post(
        f"/v1/devices/{DEVICE_UUID}/revoke",
        params={"organization_id": str(ORGANIZATION_ID)},
        headers={"authorization": "Bearer dashboard-admin"},
    )
    assert response.status_code == 200
    assert repository.device_status == "revoked"


def test_bounded_aggregate_audit_ingestion_rejects_prohibited_fields(
    client: TestClient,
    repository: MemoryRepository,
) -> None:
    token = issue_device(client)
    event = {
        "event_hmac": "a" * 64,
        "endpoint_class": "scan",
        "category_counts": {"API_KEY": 1},
        "action_counts": {"BLOCK": 1},
        "highest_sensitivity": "restricted",
        "status_bucket": "blocked",
        "latency_bucket": "lt_250ms",
        "detector_version": "0.9.0",
        "model_version": None,
        "occurred_at": datetime.now(UTC).isoformat(),
    }
    accepted = client.post(
        "/v1/audit-events/batch",
        headers={"authorization": f"Bearer {token}"},
        json={"events": [event]},
    )
    assert accepted.json() == {"accepted": 1}
    assert len(repository.audits) == 1
    prohibited = dict(event)
    prohibited["prompt"] = "synthetic input that must never persist"
    rejected = client.post(
        "/v1/audit-events/batch",
        headers={"authorization": f"Bearer {token}"},
        json={"events": [prohibited]},
    )
    assert rejected.status_code == 400
    assert len(repository.audits) == 1


def test_batch_limit_malformed_json_and_body_limit_are_sanitized(
    client: TestClient,
) -> None:
    malformed = client.post(
        "/v1/device-tokens",
        headers={
            "authorization": "Bearer dashboard-admin",
            "content-type": "application/json",
        },
        content=b"{",
    )
    assert malformed.json()["error"]["code"] == "CS_MANAGEMENT_INVALID_INPUT"
    oversized = client.post(
        "/v1/device-tokens",
        headers={
            "authorization": "Bearer dashboard-admin",
            "content-type": "application/json",
        },
        content=b"x" * 16_385,
    )
    assert oversized.status_code == 413
    assert oversized.json()["error"]["code"] == "CS_MANAGEMENT_BODY_TOO_LARGE"


def test_repository_failures_are_fixed_and_do_not_leak(
    client: TestClient,
    repository: MemoryRepository,
    caplog: pytest.LogCaptureFixture,
) -> None:
    repository.fail = True
    caplog.set_level(logging.DEBUG)
    response = client.post(
        "/v1/device-tokens",
        headers={"authorization": "Bearer dashboard-admin"},
        json={
            "organization_id": str(ORGANIZATION_ID),
            "device_id": "synthetic-device",
            "display_name": "Synthetic device",
            "owner_user_id": str(DEVELOPER_ID),
        },
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "CS_MANAGEMENT_STORAGE_FAILURE"
    assert "synthetic failure" not in response.text
    assert "synthetic failure" not in caplog.text


def test_settings_reject_remote_supabase_and_broad_origins(
    settings: ManagementSettings,
) -> None:
    payload = settings.model_dump()
    payload["supabase_url"] = "https://example.invalid"
    with pytest.raises(ValueError):
        ManagementSettings.model_validate(payload)


def test_supabase_repository_validates_jwt_with_auth_and_membership(
    settings: ManagementSettings,
) -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["apikey"] == settings.supabase_service_credential
        if request.url.path == "/auth/v1/user":
            assert request.headers["authorization"] == "Bearer dashboard-jwt"
            return httpx.Response(200, json={"id": str(ADMIN_ID)})
        if request.url.path == "/rest/v1/memberships":
            assert request.headers["accept-profile"] == "api"
            assert request.headers["authorization"] == (
                f"Bearer {settings.supabase_service_credential}"
            )
            return httpx.Response(200, json=[{"role": "administrator"}])
        return httpx.Response(404)

    async def run() -> None:
        repository = SupabaseRepository(
            settings,
            transport=httpx.MockTransport(handler),
        )
        principal = await repository.authenticate_dashboard(
            "dashboard-jwt",
            ORGANIZATION_ID,
        )
        await repository.close()
        assert principal == DashboardPrincipal(ADMIN_ID, "administrator")

    asyncio.run(run())
    assert [request.url.path for request in requests] == [
        "/auth/v1/user",
        "/rest/v1/memberships",
    ]


def test_supabase_repository_never_follows_auth_redirects(
    settings: ManagementSettings,
) -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            307,
            headers={"location": "https://example.invalid/auth"},
        )

    async def run() -> None:
        repository = SupabaseRepository(
            settings,
            transport=httpx.MockTransport(handler),
        )
        principal = await repository.authenticate_dashboard(
            "dashboard-jwt",
            ORGANIZATION_ID,
        )
        await repository.close()
        assert principal is None

    asyncio.run(run())
    assert calls == 1
    payload = settings.model_dump()
    payload["cors_origins"] = ("http://127.0.0.1:3000/path",)
    with pytest.raises(ValueError):
        ManagementSettings.model_validate(payload)
