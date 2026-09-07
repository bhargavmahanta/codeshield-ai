"""Supabase-backed metadata repository with a testable narrow protocol."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

import httpx

from codeshield.management import (
    DestinationVersionReference,
    PolicyDocumentPayload,
    PolicyRulePayload,
    ProviderProfileVersionReference,
    SignedPolicyBundle,
)
from codeshield_management_api.config import ManagementSettings
from codeshield_management_api.models import AuditEventInput, DeviceTokenRequest


class RepositoryError(RuntimeError):
    """Sanitized storage failure."""


@dataclass(frozen=True)
class DashboardPrincipal:
    user_id: UUID
    role: str


@dataclass(frozen=True)
class DeviceRecord:
    device_uuid: UUID
    organization_id: UUID
    status: str
    digest_hex: str


@dataclass(frozen=True)
class PolicyMaterial:
    policy_version_id: UUID
    policy: PolicyDocumentPayload
    provider_profiles: list[ProviderProfileVersionReference]
    destinations: list[DestinationVersionReference]


class ManagementRepository(Protocol):
    async def authenticate_dashboard(
        self, token: str, organization_id: UUID
    ) -> DashboardPrincipal | None: ...

    async def create_device(
        self, request: DeviceTokenRequest
    ) -> UUID: ...

    async def store_device_token_hash(
        self, device_uuid: UUID, digest_hex: str
    ) -> None: ...

    async def read_device_token_hash(
        self, device_uuid: UUID
    ) -> DeviceRecord | None: ...

    async def revoke_device(self, device_uuid: UUID) -> None: ...

    async def load_policy_material(
        self,
        organization_id: UUID,
        policy_version_id: UUID,
        provider_profile_version_ids: list[UUID],
        destination_version_ids: list[UUID],
    ) -> PolicyMaterial | None: ...

    async def next_release_sequence(self, organization_id: UUID) -> int: ...

    async def persist_release(
        self,
        signed_bundle: SignedPolicyBundle,
        created_by: UUID,
    ) -> UUID: ...

    async def latest_release(
        self, organization_id: UUID
    ) -> tuple[UUID, SignedPolicyBundle] | None: ...

    async def insert_audit_events(
        self,
        organization_id: UUID,
        device_uuid: UUID,
        events: list[AuditEventInput],
    ) -> int: ...

    async def close(self) -> None: ...


class SupabaseRepository:
    """Use service-role Data API access only from the server process."""

    def __init__(
        self,
        settings: ManagementSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._service_credential = settings.supabase_service_credential
        self._client = httpx.AsyncClient(
            base_url=settings.supabase_url,
            transport=transport,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(10.0, connect=5.0),
        )

    async def authenticate_dashboard(
        self, token: str, organization_id: UUID
    ) -> DashboardPrincipal | None:
        response = await self._request(
            "GET",
            "/auth/v1/user",
            authorization=token,
            profile=False,
        )
        if response.status_code != 200:
            return None
        try:
            user_id = UUID(response.json()["id"])
        except (ValueError, KeyError, TypeError):
            return None
        rows = await self._rows(
            "GET",
            "/rest/v1/memberships",
            params={
                "organization_id": f"eq.{organization_id}",
                "user_id": f"eq.{user_id}",
                "active": "is.true",
                "select": "role",
                "limit": "1",
            },
        )
        if len(rows) != 1 or rows[0].get("role") not in {
            "administrator",
            "security_analyst",
            "developer",
        }:
            return None
        return DashboardPrincipal(user_id=user_id, role=str(rows[0]["role"]))

    async def create_device(self, request: DeviceTokenRequest) -> UUID:
        membership = await self._rows(
            "GET",
            "/rest/v1/memberships",
            params={
                "organization_id": f"eq.{request.organization_id}",
                "user_id": f"eq.{request.owner_user_id}",
                "active": "is.true",
                "select": "user_id",
                "limit": "1",
            },
        )
        if len(membership) != 1:
            raise RepositoryError("device owner membership is unavailable")
        rows = await self._rows(
            "POST",
            "/rest/v1/devices",
            json={
                "organization_id": str(request.organization_id),
                "device_id": request.device_id,
                "display_name": request.display_name,
                "owner_user_id": str(request.owner_user_id),
                "status": "active",
            },
            prefer="return=representation",
        )
        try:
            return UUID(rows[0]["id"])
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise RepositoryError("device creation failed") from exc

    async def store_device_token_hash(
        self, device_uuid: UUID, digest_hex: str
    ) -> None:
        await self._rows(
            "POST",
            "/rest/v1/rpc/store_device_token_hash",
            json={"target_device_id": str(device_uuid), "digest_hex": digest_hex},
        )

    async def read_device_token_hash(
        self, device_uuid: UUID
    ) -> DeviceRecord | None:
        rows = await self._rows(
            "POST",
            "/rest/v1/rpc/read_device_token_hash",
            json={"target_device_id": str(device_uuid)},
        )
        if len(rows) != 1:
            return None
        try:
            row = rows[0]
            return DeviceRecord(
                device_uuid=device_uuid,
                organization_id=UUID(row["organization_id"]),
                status=str(row["device_status"]),
                digest_hex=str(row["digest_hex"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RepositoryError("device metadata is invalid") from exc

    async def revoke_device(self, device_uuid: UUID) -> None:
        await self._rows(
            "POST",
            "/rest/v1/rpc/revoke_device_token",
            json={"target_device_id": str(device_uuid)},
        )

    async def load_policy_material(
        self,
        organization_id: UUID,
        policy_version_id: UUID,
        provider_profile_version_ids: list[UUID],
        destination_version_ids: list[UUID],
    ) -> PolicyMaterial | None:
        versions = await self._rows(
            "GET",
            "/rest/v1/policy_versions",
            params={
                "id": f"eq.{policy_version_id}",
                "organization_id": f"eq.{organization_id}",
                "status": "in.(approved,released)",
                "select": "id,policy_id,version,policy_document",
                "limit": "1",
            },
        )
        if len(versions) != 1:
            return None
        version = versions[0]
        policies = await self._rows(
            "GET",
            "/rest/v1/policies",
            params={
                "id": f"eq.{version['policy_id']}",
                "organization_id": f"eq.{organization_id}",
                "select": "policy_id,display_name,mandatory",
                "limit": "1",
            },
        )
        if len(policies) != 1:
            return None
        policy_metadata = policies[0]
        document = version.get("policy_document")
        if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
            raise RepositoryError("policy metadata is invalid")
        try:
            policy = PolicyDocumentPayload(
                policy_id=policy_metadata["policy_id"],
                version=version["version"],
                name=document.get("name", policy_metadata["display_name"]),
                mandatory=policy_metadata["mandatory"],
                rules=[
                    PolicyRulePayload.model_validate(item)
                    for item in document["rules"]
                ],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RepositoryError("policy metadata is invalid") from exc

        profiles = await self._provider_references(
            organization_id, provider_profile_version_ids
        )
        destinations = await self._destination_references(
            organization_id, destination_version_ids
        )
        if profiles is None or destinations is None:
            return None
        return PolicyMaterial(
            policy_version_id=policy_version_id,
            policy=policy,
            provider_profiles=profiles,
            destinations=destinations,
        )

    async def next_release_sequence(self, organization_id: UUID) -> int:
        rows = await self._rows(
            "GET",
            "/rest/v1/policy_bundle_releases",
            params={
                "organization_id": f"eq.{organization_id}",
                "select": "release_sequence",
                "order": "release_sequence.desc",
                "limit": "1",
            },
        )
        if not rows:
            return 1
        try:
            return int(rows[0]["release_sequence"]) + 1
        except (KeyError, TypeError, ValueError) as exc:
            raise RepositoryError("release sequence is invalid") from exc

    async def persist_release(
        self,
        signed_bundle: SignedPolicyBundle,
        created_by: UUID,
    ) -> UUID:
        bundle = signed_bundle.bundle
        rows = await self._rows(
            "POST",
            "/rest/v1/policy_bundle_releases",
            json={
                "organization_id": str(bundle.organization_id),
                "release_sequence": bundle.release_sequence,
                "policy_version_id": str(bundle.policy_version_id),
                "minimum_engine_version": bundle.minimum_compatible_engine,
                "key_id": bundle.key_id,
                "issued_at": bundle.issued_at.isoformat(),
                "expires_at": bundle.expires_at.isoformat(),
                "bundle": bundle.model_dump(mode="json"),
                "signature": signed_bundle.signature,
                "created_by": str(created_by),
            },
            prefer="return=representation",
        )
        try:
            return UUID(rows[0]["id"])
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise RepositoryError("release persistence failed") from exc

    async def latest_release(
        self, organization_id: UUID
    ) -> tuple[UUID, SignedPolicyBundle] | None:
        rows = await self._rows(
            "GET",
            "/rest/v1/policy_bundle_releases",
            params={
                "organization_id": f"eq.{organization_id}",
                "select": "id,bundle,signature",
                "order": "release_sequence.desc",
                "limit": "1",
            },
        )
        if not rows:
            return None
        try:
            signed = SignedPolicyBundle.model_validate(
                {"bundle": rows[0]["bundle"], "signature": rows[0]["signature"]}
            )
            return UUID(rows[0]["id"]), signed
        except (KeyError, TypeError, ValueError) as exc:
            raise RepositoryError("stored release is invalid") from exc

    async def insert_audit_events(
        self,
        organization_id: UUID,
        device_uuid: UUID,
        events: list[AuditEventInput],
    ) -> int:
        payload = []
        for event in events:
            item = event.model_dump(mode="json")
            item["organization_id"] = str(organization_id)
            item["device_id"] = str(device_uuid)
            payload.append(item)
        rows = await self._rows(
            "POST",
            "/rest/v1/audit_events",
            json=payload,
            prefer="return=representation,resolution=ignore-duplicates",
        )
        return len(rows)

    async def close(self) -> None:
        await self._client.aclose()

    async def _provider_references(
        self, organization_id: UUID, version_ids: list[UUID]
    ) -> list[ProviderProfileVersionReference] | None:
        if not version_ids:
            return []
        rows = await self._rows(
            "GET",
            "/rest/v1/provider_profile_versions",
            params={
                "id": f"in.({','.join(str(item) for item in version_ids)})",
                "organization_id": f"eq.{organization_id}",
                "status": "eq.released",
                "select": "id,provider_profile_id,version,evidence_digest",
            },
        )
        if len(rows) != len(version_ids):
            return None
        result: list[ProviderProfileVersionReference] = []
        for row in rows:
            profiles = await self._rows(
                "GET",
                "/rest/v1/provider_profiles",
                params={
                    "id": f"eq.{row['provider_profile_id']}",
                    "organization_id": f"eq.{organization_id}",
                    "select": "profile_id",
                    "limit": "1",
                },
            )
            if len(profiles) != 1:
                return None
            result.append(
                ProviderProfileVersionReference(
                    version_id=row["id"],
                    profile_id=profiles[0]["profile_id"],
                    version=row["version"],
                    evidence_digest=row["evidence_digest"],
                )
            )
        return sorted(result, key=lambda item: str(item.version_id))

    async def _destination_references(
        self, organization_id: UUID, version_ids: list[UUID]
    ) -> list[DestinationVersionReference] | None:
        if not version_ids:
            return []
        rows = await self._rows(
            "GET",
            "/rest/v1/destination_versions",
            params={
                "id": f"in.({','.join(str(item) for item in version_ids)})",
                "organization_id": f"eq.{organization_id}",
                "status": "eq.released",
                "select": "id,destination_id,version,sensitivity_ceiling",
            },
        )
        if len(rows) != len(version_ids):
            return None
        result: list[DestinationVersionReference] = []
        for row in rows:
            destinations = await self._rows(
                "GET",
                "/rest/v1/destinations",
                params={
                    "id": f"eq.{row['destination_id']}",
                    "organization_id": f"eq.{organization_id}",
                    "select": "destination_id",
                    "limit": "1",
                },
            )
            if len(destinations) != 1:
                return None
            result.append(
                DestinationVersionReference(
                    version_id=row["id"],
                    destination_id=destinations[0]["destination_id"],
                    version=row["version"],
                    sensitivity_ceiling=row["sensitivity_ceiling"],
                )
            )
        return sorted(result, key=lambda item: str(item.version_id))

    async def _rows(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json: object | None = None,
        prefer: str | None = None,
    ) -> list[dict[str, object]]:
        response = await self._request(
            method,
            path,
            params=params,
            json=json,
            prefer=prefer,
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise RepositoryError("metadata request failed")
        if response.status_code == 204 or not response.content:
            return []
        try:
            value = response.json()
        except ValueError as exc:
            raise RepositoryError("metadata response is invalid") from exc
        if value is None:
            return []
        if not isinstance(value, list) or not all(
            isinstance(item, dict) for item in value
        ):
            raise RepositoryError("metadata response is invalid")
        return value

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json: object | None = None,
        authorization: str | None = None,
        profile: bool = True,
        prefer: str | None = None,
    ) -> httpx.Response:
        headers = {
            "apikey": self._service_credential,
            "authorization": f"Bearer {authorization or self._service_credential}",
            "accept": "application/json",
        }
        if profile:
            headers["accept-profile"] = "api"
            headers["content-profile"] = "api"
        if prefer:
            headers["prefer"] = prefer
        try:
            return await self._client.request(
                method,
                path,
                params=params,
                json=json,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise RepositoryError("metadata storage is unavailable") from exc
