"""FastAPI application for metadata-only organizational management."""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from codeshield.management import ManagedPolicyBundle, sign_bundle
from codeshield.management.contracts import load_private_key
from codeshield_management_api.config import ManagementSettings
from codeshield_management_api.errors import ERRORS, ManagementError
from codeshield_management_api.models import (
    AuditBatchRequest,
    AuditBatchResponse,
    DeviceRevocationResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
    HealthResponse,
    PolicyReleaseRequest,
    PolicyReleaseResponse,
    VersionResponse,
)
from codeshield_management_api.repository import (
    DashboardPrincipal,
    DeviceRecord,
    ManagementRepository,
    RepositoryError,
    SupabaseRepository,
)

MANAGEMENT_VERSION = "0.9.0"
DEVICE_TOKEN = re.compile(
    r"^csm_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"[.]([A-Za-z0-9_-]{43})$"
)
LOGGER = logging.getLogger("codeshield.management")
LOGGER.addHandler(logging.NullHandler())


def create_app(
    settings: ManagementSettings,
    *,
    repository: ManagementRepository | None = None,
    signer: Ed25519PrivateKey | None = None,
) -> FastAPI:
    active_repository = repository or SupabaseRepository(settings)
    active_signer = signer or load_private_key(settings.signing_private_key)

    @asynccontextmanager
    async def lifespan(application: FastAPI):  # type: ignore[no-untyped-def]
        del application
        try:
            yield
        finally:
            await active_repository.close()

    app = FastAPI(
        title="CodeShield Metadata Management API",
        version=MANAGEMENT_VERSION,
        description=(
            "Organizational metadata, device enrollment, and signed policy delivery. "
            "Content scanning remains local."
        ),
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["authorization", "content-type"],
        expose_headers=[],
        max_age=600,
    )

    @app.exception_handler(ManagementError)
    async def management_error_handler(
        request: Request, exc: ManagementError
    ) -> JSONResponse:
        del request
        return _error_response(exc)

    @app.exception_handler(RepositoryError)
    async def repository_error_handler(
        request: Request, exc: RepositoryError
    ) -> JSONResponse:
        del request, exc
        return _error_response(ERRORS["CS_MANAGEMENT_STORAGE_FAILURE"]())

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        del request, exc
        return _error_response(ERRORS["CS_MANAGEMENT_INVALID_INPUT"]())

    @app.middleware("http")
    async def secure_request_boundary(request: Request, call_next):  # type: ignore[no-untyped-def]
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > settings.max_request_bytes:
                    return _error_response(ERRORS["CS_MANAGEMENT_BODY_TOO_LARGE"]())
            except ValueError:
                return _error_response(ERRORS["CS_MANAGEMENT_INVALID_INPUT"]())
        if request.method in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            if len(body) > settings.max_request_bytes:
                return _error_response(ERRORS["CS_MANAGEMENT_BODY_TOO_LARGE"]())

            sent = False

            async def receive() -> dict[str, object]:
                nonlocal sent
                if sent:
                    return {"type": "http.request", "body": b"", "more_body": False}
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}

            request._receive = receive  # noqa: SLF001 - bounded body replay for Starlette.
        response = await call_next(request)
        response.headers["cache-control"] = "private, no-store"
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["referrer-policy"] = "no-referrer"
        return response

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse()

    @app.get("/version", response_model=VersionResponse)
    async def version() -> VersionResponse:
        return VersionResponse(version=MANAGEMENT_VERSION)

    @app.post("/v1/device-tokens", response_model=DeviceTokenResponse)
    async def issue_device_token(
        payload: DeviceTokenRequest,
        request: Request,
    ) -> DeviceTokenResponse:
        await _dashboard_principal(
            request,
            active_repository,
            payload.organization_id,
            {"administrator"},
        )
        device_uuid = await active_repository.create_device(payload)
        token = f"csm_{device_uuid}.{secrets.token_urlsafe(32)}"
        digest_hex = _token_digest(token, settings.token_pepper)
        await active_repository.store_device_token_hash(device_uuid, digest_hex)
        return DeviceTokenResponse(
            device_uuid=device_uuid,
            device_id=payload.device_id,
            token=token,
        )

    @app.post(
        "/v1/devices/{device_uuid}/revoke",
        response_model=DeviceRevocationResponse,
    )
    async def revoke_device(
        device_uuid: UUID,
        organization_id: UUID,
        request: Request,
    ) -> DeviceRevocationResponse:
        await _dashboard_principal(
            request,
            active_repository,
            organization_id,
            {"administrator"},
        )
        record = await active_repository.read_device_token_hash(device_uuid)
        if record is None or record.organization_id != organization_id:
            raise ERRORS["CS_MANAGEMENT_NOT_FOUND"]()
        await active_repository.revoke_device(device_uuid)
        return DeviceRevocationResponse(device_uuid=device_uuid)

    @app.post(
        "/v1/policy-bundles/releases",
        response_model=PolicyReleaseResponse,
    )
    async def release_policy_bundle(
        payload: PolicyReleaseRequest,
        request: Request,
    ) -> PolicyReleaseResponse:
        principal = await _dashboard_principal(
            request,
            active_repository,
            payload.organization_id,
            {"administrator"},
        )
        issued_at = datetime.now(UTC)
        expires_at = payload.expires_at
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ERRORS["CS_MANAGEMENT_INVALID_INPUT"]()
        expires_at = expires_at.astimezone(UTC)
        material = await active_repository.load_policy_material(
            payload.organization_id,
            payload.policy_version_id,
            payload.provider_profile_version_ids,
            payload.destination_version_ids,
        )
        if material is None:
            raise ERRORS["CS_MANAGEMENT_NOT_FOUND"]()
        sequence = await active_repository.next_release_sequence(
            payload.organization_id
        )
        try:
            bundle = ManagedPolicyBundle(
                organization_id=payload.organization_id,
                release_sequence=sequence,
                policy_version_id=material.policy_version_id,
                policy=material.policy,
                provider_profiles=material.provider_profiles,
                destinations=material.destinations,
                minimum_compatible_engine=payload.minimum_compatible_engine,
                issued_at=issued_at,
                expires_at=expires_at,
                key_id=settings.signing_key_id,
            )
        except ValueError as exc:
            raise ERRORS["CS_MANAGEMENT_INVALID_INPUT"]() from exc
        signed = sign_bundle(bundle, active_signer)
        release_id = await active_repository.persist_release(
            signed,
            principal.user_id,
        )
        return PolicyReleaseResponse(
            release_id=release_id,
            signed_bundle=signed,
        )

    @app.get(
        "/v1/policy-bundles/latest",
        response_model=PolicyReleaseResponse,
    )
    async def latest_policy_bundle(request: Request) -> PolicyReleaseResponse:
        device = await _device_principal(
            request,
            active_repository,
            settings.token_pepper,
        )
        latest = await active_repository.latest_release(device.organization_id)
        if latest is None:
            raise ERRORS["CS_MANAGEMENT_NOT_FOUND"]()
        release_id, signed = latest
        return PolicyReleaseResponse(
            release_id=release_id,
            signed_bundle=signed,
        )

    @app.post("/v1/audit-events/batch", response_model=AuditBatchResponse)
    async def upload_audit_batch(
        payload: AuditBatchRequest,
        request: Request,
    ) -> AuditBatchResponse:
        if len(payload.events) > settings.max_audit_batch:
            raise ERRORS["CS_MANAGEMENT_INVALID_INPUT"]()
        device = await _device_principal(
            request,
            active_repository,
            settings.token_pepper,
        )
        accepted = await active_repository.insert_audit_events(
            device.organization_id,
            device.device_uuid,
            payload.events,
        )
        return AuditBatchResponse(accepted=accepted)

    return app


async def _dashboard_principal(
    request: Request,
    repository: ManagementRepository,
    organization_id: UUID,
    allowed_roles: set[str],
) -> DashboardPrincipal:
    token = _bearer_token(request)
    principal = await repository.authenticate_dashboard(token, organization_id)
    if principal is None:
        raise ERRORS["CS_MANAGEMENT_AUTHENTICATION"]()
    if principal.role not in allowed_roles:
        raise ERRORS["CS_MANAGEMENT_AUTHORIZATION"]()
    return principal


async def _device_principal(
    request: Request,
    repository: ManagementRepository,
    pepper: str,
) -> DeviceRecord:
    token = _bearer_token(request)
    match = DEVICE_TOKEN.fullmatch(token)
    if match is None:
        raise ERRORS["CS_MANAGEMENT_AUTHENTICATION"]()
    device_uuid = UUID(match.group(1))
    record = await repository.read_device_token_hash(device_uuid)
    if record is None:
        raise ERRORS["CS_MANAGEMENT_AUTHENTICATION"]()
    candidate = _token_digest(token, pepper)
    if not hmac.compare_digest(candidate.encode("ascii"), record.digest_hex.encode("ascii")):
        raise ERRORS["CS_MANAGEMENT_AUTHENTICATION"]()
    if record.status != "active":
        raise ERRORS["CS_MANAGEMENT_DEVICE_REVOKED"]()
    return record


def _bearer_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    prefix = "Bearer "
    if (
        not authorization.startswith(prefix)
        or len(authorization) <= len(prefix)
        or len(authorization) > 1024
    ):
        raise ERRORS["CS_MANAGEMENT_AUTHENTICATION"]()
    return authorization[len(prefix) :]


def _token_digest(token: str, pepper: str) -> str:
    return hmac.new(
        pepper.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _error_response(error: ManagementError) -> JSONResponse:
    headers = (
        {"www-authenticate": "Bearer"}
        if error.status_code == 401
        else None
    )
    return JSONResponse(
        status_code=error.status_code,
        content={
            "error": {
                "code": error.code,
                "message": error.message,
            }
        },
        headers=headers,
    )
