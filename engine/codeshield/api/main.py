"""Loopback-first FastAPI service for the local CodeShield engine."""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from codeshield.models.enums import Destination, ProtectionMode
from codeshield.models.enums import AttestationStatus, DetectorProfile
from codeshield.models.finding import Finding
from codeshield.models.llm import (
    LlmAssessmentResult,
    LlmPreflightRequest,
    LlmProtectionResult,
)
from codeshield.models.protection import ProtectionResult
from codeshield.llm import LlmPreflightService
from codeshield.pseudonymization import InMemoryKeyProvider, PseudonymVault
from codeshield.scanner import CodeShieldScanner
from codeshield.models.config import find_repository_config, resolve_policy_path
from codeshield.models.config import DetectorConfig
from codeshield.models.provider import ProviderProfile
from codeshield.policies import PolicyEngine
from codeshield.providers import AttestationStore, ProviderRegistry, ProviderRegistryError
from codeshield.detectors import detector_status
from codeshield.version import __version__

MAX_REQUEST_BYTES = 1_000_000

LOGGER = logging.getLogger("codeshield")
LOGGER.addHandler(logging.NullHandler())

app = FastAPI(
    title="CodeShield AI Local Engine",
    version=__version__,
    description="Local-only API. Raw sensitive values are never logged.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1", "http://localhost"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["content-type"],
)

_CONFIG_ENTRY = find_repository_config()
if _CONFIG_ENTRY:
    _REPOSITORY_ROOT, _REPOSITORY_CONFIG = _CONFIG_ENTRY
    SCANNER = CodeShieldScanner(
        detector_config=_REPOSITORY_CONFIG.detectors,
        policy_engine=PolicyEngine.from_path(
            resolve_policy_path(_REPOSITORY_ROOT, _REPOSITORY_CONFIG)
        ),
    )
else:
    SCANNER = CodeShieldScanner()
DETECTOR_SETTINGS = (
    _REPOSITORY_CONFIG.detectors if _CONFIG_ENTRY else DetectorConfig()
)
SESSION_VAULT = PseudonymVault(":memory:", InMemoryKeyProvider())


class ScanTextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(max_length=MAX_REQUEST_BYTES)
    destination: Destination = Destination.LOCAL_FILE


class ProtectTextRequest(ScanTextRequest):
    mode: ProtectionMode = ProtectionMode.TYPE_PLACEHOLDER
    session_id: str = Field(default="default", min_length=1, max_length=128)


class RestoreTextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(max_length=MAX_REQUEST_BYTES)
    session_id: str = Field(default="default", min_length=1, max_length=128)


class HealthResponse(BaseModel):
    status: str
    service: str
    local_only: bool


class VersionResponse(BaseModel):
    version: str


class RestoreTextResponse(BaseModel):
    restored_text: str


class DetectorStatusItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    enabled: bool
    available: bool
    status: str = Field(pattern=r"^(ready|disabled|unavailable)$")


class DetectorStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: DetectorProfile
    detectors: list[DetectorStatusItem]


class ProviderVerificationIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: str
    code: str = Field(pattern=r"^[a-z_]+$")
    message: str


class ProviderVerificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    issues: list[ProviderVerificationIssue]


class AttestationStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: str = Field(min_length=1, max_length=128)
    attestation_id: str | None = Field(default=None, min_length=1, max_length=128)


class AttestationStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: str
    profile_version: str
    status: AttestationStatus


@app.exception_handler(RequestValidationError)
async def safe_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    del request, exc
    return JSONResponse(
        status_code=422,
        content={"detail": "request validation failed"},
    )


@app.middleware("http")
async def enforce_request_size(request: Request, call_next):  # type: ignore[no-untyped-def]
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(status_code=413, content={"detail": "request too large"})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "invalid content length"})
    return await call_next(request)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse.model_validate({
        "status": "ok",
        "service": "codeshield-engine",
        "local_only": True,
    })


@app.get("/version", response_model=VersionResponse)
def version() -> VersionResponse:
    return VersionResponse(version=__version__)


@app.get("/detectors/status", response_model=DetectorStatusResponse)
def get_detector_status() -> DetectorStatusResponse:
    entries = []
    for item in detector_status(DETECTOR_SETTINGS):
        enabled = bool(item["enabled"])
        available = bool(item["available"])
        status = "ready" if enabled and available else (
            "unavailable" if enabled else "disabled"
        )
        entries.append(
            DetectorStatusItem(
                name=str(item["name"]),
                enabled=enabled,
                available=available,
                status=status,
            )
        )
    return DetectorStatusResponse(
        profile=DETECTOR_SETTINGS.profile,
        detectors=entries,
    )


@app.get("/providers", response_model=list[ProviderProfile])
def list_providers() -> list[ProviderProfile]:
    try:
        return ProviderRegistry().list()
    except ProviderRegistryError as exc:
        raise HTTPException(
            status_code=500, detail="provider registry is unavailable"
        ) from exc


@app.get("/providers/verify", response_model=ProviderVerificationResponse)
def verify_providers() -> ProviderVerificationResponse:
    try:
        errors = ProviderRegistry().verify()
    except ProviderRegistryError as exc:
        raise HTTPException(
            status_code=500, detail="provider registry is unavailable"
        ) from exc
    issues = [_provider_verification_issue(error) for error in errors]
    return ProviderVerificationResponse(valid=not issues, issues=issues)


@app.post(
    "/providers/attestations/status",
    response_model=AttestationStatusResponse,
)
def provider_attestation_status(
    payload: AttestationStatusRequest,
) -> AttestationStatusResponse:
    try:
        profile = ProviderRegistry().require(payload.profile_id)
        status, _ = AttestationStore().status(payload.attestation_id, profile)
    except ProviderRegistryError as exc:
        raise HTTPException(
            status_code=404, detail="provider profile was not found"
        ) from exc
    return AttestationStatusResponse(
        profile_id=profile.profile_id,
        profile_version=profile.version,
        status=status,
    )


@app.get("/providers/{profile_id}", response_model=ProviderProfile)
def get_provider(profile_id: str) -> ProviderProfile:
    try:
        return ProviderRegistry().require(profile_id)
    except ProviderRegistryError as exc:
        raise HTTPException(
            status_code=404, detail="provider profile was not found"
        ) from exc


@app.post("/scan/text", response_model=list[Finding])
def scan_text(payload: ScanTextRequest) -> list[Finding]:
    return SCANNER.scan_text(payload.text, destination=payload.destination)


@app.post("/protect", response_model=ProtectionResult)
def protect_text(payload: ProtectTextRequest) -> ProtectionResult:
    result = SCANNER.protect_text(
        payload.text,
        destination=payload.destination,
        mode=payload.mode,
        vault=SESSION_VAULT
        if payload.mode is ProtectionMode.PSEUDONYMIZE
        else None,
        session_id=payload.session_id,
    )
    if result.blocked:
        raise HTTPException(
            status_code=403,
            detail="content blocked by a mandatory local policy rule",
        )
    return result


@app.post("/restore", response_model=RestoreTextResponse)
def restore_text(payload: RestoreTextRequest) -> RestoreTextResponse:
    return RestoreTextResponse(
        restored_text=SESSION_VAULT.restore_text(
            payload.text, session_id=payload.session_id
        )
    )


@app.post("/llm/assess", response_model=LlmAssessmentResult)
def assess_for_llm(payload: LlmPreflightRequest) -> LlmAssessmentResult:
    """Assess structured content locally before an LLM trust-boundary crossing."""

    return LlmPreflightService().assess(payload)


@app.post("/llm/protect", response_model=LlmProtectionResult)
def protect_for_llm(payload: LlmPreflightRequest) -> LlmProtectionResult:
    """Protect eligible content locally; blocked requests return no content."""

    return LlmPreflightService().protect(payload)


def _provider_verification_issue(error: str) -> ProviderVerificationIssue:
    profile_id, _, detail = error.partition(":")
    message = detail.strip()
    code = "invalid_profile"
    if "evidence is stale" in message:
        code = "evidence_stale"
    elif "ZDR conflicts with retention" in message:
        code = "zdr_retention_conflict"
    elif "reference profile cannot claim ZDR" in message:
        code = "reference_zdr_conflict"
    elif "no-training claim" in message:
        code = "training_claim_conflict"
    elif "exceeds profile retention" in message:
        code = "retention_limit_conflict"
    elif "ZDR prompt/output" in message:
        code = "zdr_handling_conflict"
    safe_messages = {
        "evidence_stale": "Provider evidence requires review.",
        "zdr_retention_conflict": "Zero-retention and retention settings conflict.",
        "reference_zdr_conflict": "Reference profile cannot claim zero retention.",
        "training_claim_conflict": "Training statements are inconsistent.",
        "retention_limit_conflict": "Handling exceeds the profile retention limit.",
        "zdr_handling_conflict": "Zero-retention handling is inconsistent.",
        "invalid_profile": "Provider profile validation failed.",
    }
    return ProviderVerificationIssue(
        profile_id=profile_id,
        code=code,
        message=safe_messages[code],
    )
