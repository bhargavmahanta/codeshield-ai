from __future__ import annotations

import base64
import hashlib
import os
import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from codeshield_management_api.app import create_app
from codeshield_management_api.config import ManagementSettings

pytestmark = pytest.mark.skipif(
    os.environ.get("CODESHIELD_LOCAL_SUPABASE_TEST") != "1",
    reason="local Supabase integration is opt-in",
)

ORGANIZATION_A = "11111111-1111-4111-8111-111111111111"
ORGANIZATION_B = "22222222-2222-4222-8222-222222222222"
DEVELOPER_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3"
POLICY_A = "11111111-c101-4111-8111-111111111111"


def test_real_local_stack_auth_release_audit_and_revocation() -> None:
    service_credential = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    settings = ManagementSettings(
        supabase_url="http://127.0.0.1:54321",
        supabase_service_credential=service_credential,
        signing_private_key=_base64url(private_key.private_bytes_raw()),
        signing_key_id="local-integration-key",
        token_pepper="p" * 32,
    )
    admin_token = _create_admin_session(service_credential)
    device_id = f"integration-{uuid4().hex}"
    with TestClient(create_app(settings, signer=private_key)) as client:
        response = client.post(
            "/v1/device-tokens",
            headers={"authorization": f"Bearer {admin_token}"},
            json={
                "organization_id": ORGANIZATION_A,
                "device_id": device_id,
                "display_name": "Local integration device",
                "owner_user_id": DEVELOPER_A,
            },
        )
        assert response.status_code == 200
        issued = response.json()
        assert issued["shown_once"] is True
        device_token = issued.pop("token")
        device_uuid = issued["device_uuid"]
        assert device_token.startswith("csm_")

        cross_tenant = client.post(
            "/v1/device-tokens",
            headers={"authorization": f"Bearer {admin_token}"},
            json={
                "organization_id": ORGANIZATION_B,
                "device_id": f"denied-{uuid4().hex}",
                "display_name": "Denied integration device",
                "owner_user_id": DEVELOPER_A,
            },
        )
        assert cross_tenant.status_code == 401
        assert (
            cross_tenant.json()["error"]["code"]
            == "CS_MANAGEMENT_AUTHENTICATION"
        )

        release = client.post(
            "/v1/policy-bundles/releases",
            headers={"authorization": f"Bearer {admin_token}"},
            json={
                "organization_id": ORGANIZATION_A,
                "policy_version_id": POLICY_A,
                "provider_profile_version_ids": [],
                "destination_version_ids": [],
                "minimum_compatible_engine": "0.9.0",
                "expires_at": (
                    datetime.now(UTC) + timedelta(days=1)
                ).isoformat(),
            },
        )
        assert release.status_code == 200
        assert release.json()["signed_bundle"]["bundle"]["organization_id"] == ORGANIZATION_A

        latest = client.get(
            "/v1/policy-bundles/latest",
            headers={"authorization": f"Bearer {device_token}"},
        )
        assert latest.status_code == 200
        assert latest.json()["signed_bundle"]["bundle"]["release_sequence"] >= 1

        audit = client.post(
            "/v1/audit-events/batch",
            headers={"authorization": f"Bearer {device_token}"},
            json={
                "events": [
                    {
                        "event_hmac": hashlib.sha256(device_id.encode()).hexdigest(),
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
                ]
            },
        )
        assert audit.status_code == 200
        assert audit.json() == {"accepted": 1}

        revoked = client.post(
            f"/v1/devices/{device_uuid}/revoke",
            params={"organization_id": ORGANIZATION_A},
            headers={"authorization": f"Bearer {admin_token}"},
            json={},
        )
        assert revoked.status_code == 200
        denied = client.get(
            "/v1/policy-bundles/latest",
            headers={"authorization": f"Bearer {device_token}"},
        )
        assert denied.status_code == 401
        assert denied.json()["error"]["code"] == "CS_MANAGEMENT_AUTHENTICATION"


def _create_admin_session(service_credential: str) -> str:
    email = f"integration-{uuid4().hex}@example.invalid"
    password = secrets.token_urlsafe(32)
    service_headers = {
        "apikey": service_credential,
        "authorization": f"Bearer {service_credential}",
        "content-type": "application/json",
    }
    with httpx.Client(
        base_url="http://127.0.0.1:54321",
        trust_env=False,
        follow_redirects=False,
        timeout=10,
    ) as client:
        created = client.post(
            "/auth/v1/admin/users",
            headers=service_headers,
            json={
                "email": email,
                "password": password,
                "email_confirm": True,
            },
        )
        assert created.status_code == 200
        user_id = created.json()["id"]
        membership = client.post(
            "/rest/v1/memberships",
            headers={
                **service_headers,
                "accept-profile": "api",
                "content-profile": "api",
            },
            json={
                "organization_id": ORGANIZATION_A,
                "user_id": user_id,
                "role": "administrator",
                "active": True,
            },
        )
        assert membership.status_code in {200, 201}
        authenticated = client.post(
            "/auth/v1/token",
            params={"grant_type": "password"},
            headers={
                "apikey": service_credential,
                "content-type": "application/json",
            },
            json={"email": email, "password": password},
        )
        assert authenticated.status_code == 200, authenticated.json()
        token = authenticated.json()["access_token"]
        assert isinstance(token, str)
        return token


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()
