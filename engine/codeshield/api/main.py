"""Loopback-first FastAPI service for the local CodeShield engine."""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from codeshield.models.enums import Destination, ProtectionMode
from codeshield.models.finding import Finding
from codeshield.models.protection import ProtectionResult
from codeshield.pseudonymization import InMemoryKeyProvider, PseudonymVault
from codeshield.scanner import CodeShieldScanner
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

SCANNER = CodeShieldScanner()
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


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "service": "codeshield-engine",
        "local_only": True,
    }


@app.get("/version")
def version() -> dict[str, str]:
    return {"version": __version__}


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


@app.post("/restore")
def restore_text(payload: RestoreTextRequest) -> dict[str, str]:
    return {
        "restored_text": SESSION_VAULT.restore_text(
            payload.text, session_id=payload.session_id
        )
    }
