"""FastAPI application factory for the authenticated loopback proxy."""

from __future__ import annotations

import asyncio
import hmac
import json
import os
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from codeshield.proxy.audit import ProxyAuditStore
from codeshield.proxy.config import ProxyConfig
from codeshield.proxy.errors import ERRORS, ProxyError
from codeshield.proxy.models import ChatRequest, ResponsesRequest
from codeshield.proxy.network import AddressResolver, system_resolver
from codeshield.proxy.service import ProxyForwarder
from codeshield.providers import AttestationStore, ProviderRegistry
from codeshield.version import __version__

BANNED_FIELDS = {
    "file",
    "files",
    "include",
    "modalities",
    "previous_response_id",
    "prompt_cache_key",
    "prompt_cache_retention",
    "service_tier",
    "stream_options",
    "truncation",
    "web_search_options",
}
BANNED_ITEM_TYPES = {
    "input_audio",
    "input_file",
    "input_image",
    "computer",
    "computer_use_preview",
    "file_search",
    "image_generation",
    "mcp",
    "web_search",
    "web_search_preview",
}


def create_proxy_app(
    config: ProxyConfig,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    resolver: AddressResolver = system_resolver,
    registry: ProviderRegistry | None = None,
    attestations: AttestationStore | None = None,
    audit: ProxyAuditStore | None = None,
) -> FastAPI:
    app = FastAPI(
        title="CodeShield Local LLM Proxy",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    active_registry = registry or ProviderRegistry()
    active_attestations = attestations or AttestationStore()
    forwarder = ProxyForwarder(
        config,
        transport=transport,
        resolver=resolver,
        registry=active_registry,
        attestations=active_attestations,
        audit=audit,
    )
    semaphore = asyncio.Semaphore(config.max_concurrency)

    @app.exception_handler(ProxyError)
    async def proxy_error_handler(request: Request, exc: ProxyError) -> JSONResponse:
        del request
        return _error_response(exc)

    @app.get("/health")
    async def health() -> dict[str, object]:
        return {"status": "ok", "service": "codeshield-proxy", "local_only": True}

    @app.get("/version")
    async def version() -> dict[str, str]:
        return {"version": __version__}

    @app.get("/v1/models")
    async def models(request: Request) -> JSONResponse:
        _authenticate(request)
        return JSONResponse(
            {
                "object": "list",
                "data": [
                    {
                        "id": model,
                        "object": "model",
                        "created": 0,
                        "owned_by": "local-allowlist",
                    }
                    for model in config.allowed_models
                ],
            }
        )

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        return await _handle(request, "chat_completions", ChatRequest)

    @app.post("/v1/responses")
    async def responses(request: Request) -> JSONResponse:
        return await _handle(request, "responses", ResponsesRequest)

    async def _handle(
        request: Request,
        endpoint: str,
        model_type: type[ChatRequest] | type[ResponsesRequest],
    ) -> JSONResponse:
        _authenticate(request)
        credential = os.environ.get(config.upstream_credential_env)
        if not credential:
            raise ERRORS["CS_PROXY_UPSTREAM_FAILURE"]()
        media_type = request.headers.get("content-type", "").split(";", 1)[0]
        if media_type.lower() != "application/json":
            raise ERRORS["CS_PROXY_INVALID_INPUT"]()
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > config.max_request_bytes:
                    raise ERRORS["CS_PROXY_INVALID_INPUT"]()
            except ValueError as exc:
                raise ERRORS["CS_PROXY_INVALID_INPUT"]() from exc
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > config.max_request_bytes:
                raise ERRORS["CS_PROXY_INVALID_INPUT"]()
        try:
            raw = json.loads(bytes(body).decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ERRORS["CS_PROXY_INVALID_INPUT"]() from exc
        if not isinstance(raw, dict):
            raise ERRORS["CS_PROXY_INVALID_INPUT"]()
        if _uses_unsupported_feature(raw):
            raise ERRORS["CS_PROXY_UNSUPPORTED_FEATURE"]()
        try:
            parsed = model_type.model_validate(raw)
        except ValidationError as exc:
            raise ERRORS["CS_PROXY_INVALID_INPUT"]() from exc
        if parsed.model not in config.allowed_models:
            raise ERRORS["CS_PROXY_INVALID_INPUT"]()
        if semaphore.locked():
            raise ERRORS["CS_PROXY_SATURATED"]()
        await semaphore.acquire()
        try:
            payload, correlation = await forwarder.forward(
                endpoint, parsed, upstream_credential=credential
            )
        finally:
            semaphore.release()
        return JSONResponse(
            payload,
            headers={"x-codeshield-correlation-id": correlation},
        )

    return app


def _authenticate(request: Request) -> None:
    expected = os.environ.get("CODESHIELD_PROXY_TOKEN")
    provided = request.headers.get("authorization", "")
    prefix = "Bearer "
    candidate = provided[len(prefix) :] if provided.startswith(prefix) else ""
    if (
        not expected
        or len(expected) < 32
        or not candidate
        or not hmac.compare_digest(candidate.encode(), expected.encode())
    ):
        raise ERRORS["CS_PROXY_AUTHENTICATION"]()


def _uses_unsupported_feature(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in BANNED_FIELDS:
                return True
            if key == "stream" and item is not False:
                return True
            if key == "store" and item is not False:
                return True
            if key == "background" and item is not False:
                return True
            if key == "type" and item in BANNED_ITEM_TYPES:
                return True
            if _uses_unsupported_feature(item):
                return True
    elif isinstance(value, list):
        return any(_uses_unsupported_feature(item) for item in value)
    return False


def _error_response(error: ProxyError) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={
            "error": {
                "message": error.message,
                "type": error.error_type,
                "param": None,
                "code": error.code,
            }
        },
        headers=(
            {"www-authenticate": "Bearer"}
            if error.code == "CS_PROXY_AUTHENTICATION"
            else None
        ),
    )
