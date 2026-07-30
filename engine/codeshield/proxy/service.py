"""Fail-closed outbound and inbound inspection for proxy requests."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from collections import Counter
from typing import Any, Literal

import httpx
from pydantic import ValidationError

from codeshield.llm import LlmPreflightService, SegmentClassifier
from codeshield.models.config import DetectorConfig
from codeshield.models.enums import (
    AttestationStatus,
    RecommendedAction,
    TransferDirection,
)
from codeshield.models.llm import LlmPreflightRequest
from codeshield.providers import (
    AttestationStore,
    ProviderRegistry,
    ProviderRegistryError,
)
from codeshield.proxy.audit import ProxyAuditStore
from codeshield.proxy.config import ProxyConfig
from codeshield.proxy.errors import ERRORS, ProxyError
from codeshield.proxy.mapping import (
    SegmentBinding,
    apply_protected,
    inbound_chat,
    inbound_responses,
    outbound_chat,
    outbound_responses,
    restore_known,
)
from codeshield.proxy.models import (
    ChatRequest,
    ChatResponse,
    FunctionCallOutputInput,
    ResponsesRequest,
    ResponsesResponse,
)
from codeshield.proxy.network import (
    AddressResolver,
    ProxyNetworkError,
    system_resolver,
    validate_upstream_addresses,
)
from codeshield.pseudonymization import InMemoryKeyProvider, ProtectionError, PseudonymVault
from codeshield.scanner import CodeShieldScanner

EndpointClass = Literal["chat_completions", "responses"]
ALLOWED_OUTBOUND = {
    RecommendedAction.ALLOW,
    RecommendedAction.WARN,
    RecommendedAction.PSEUDONYMIZE,
}
ALLOWED_INBOUND = {RecommendedAction.ALLOW, RecommendedAction.WARN}


class ProxyForwarder:
    def __init__(
        self,
        config: ProxyConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: AddressResolver = system_resolver,
        registry: ProviderRegistry | None = None,
        attestations: AttestationStore | None = None,
        preflight: LlmPreflightService | None = None,
        audit: ProxyAuditStore | None = None,
    ) -> None:
        self.config = config
        self.transport = transport
        self.resolver = resolver
        self.registry = registry or ProviderRegistry()
        self.attestations = attestations or AttestationStore()
        self.profile = self.registry.require(config.provider_profile_id)
        self.preflight = preflight or LlmPreflightService(
            classifier=SegmentClassifier(
                scanner=CodeShieldScanner(detector_config=DetectorConfig())
            ),
            registry=self.registry,
            attestations=self.attestations,
        )
        self.audit = audit

    async def forward(
        self,
        endpoint: EndpointClass,
        request: ChatRequest | ResponsesRequest,
        *,
        upstream_credential: str,
    ) -> tuple[dict[str, Any], str]:
        started = time.perf_counter()
        correlation_id = uuid.uuid4().hex
        outbound_action = "blocked"
        inbound_action = "not_started"
        upstream_class = "not_sent"
        category_counts: Counter[str] = Counter()
        vault = PseudonymVault(":memory:", InMemoryKeyProvider())
        audit = self.audit or ProxyAuditStore.local_default()
        owns_audit = self.audit is None
        try:
            self._require_current_attestation()
            payload, bindings = self._outbound(endpoint, request)
            local_token = os.environ.get("CODESHIELD_PROXY_TOKEN", "")
            if any(
                protected_value
                and protected_value in binding.segment.content
                for protected_value in (upstream_credential, local_token)
                for binding in bindings
            ):
                raise ERRORS["CS_PROXY_POLICY_BLOCKED"]()
            preflight_request = LlmPreflightRequest(
                segments=[item.segment for item in bindings],
                provider_profile_id=self.config.provider_profile_id,
                attestation_id=self.config.attestation_id,
                direction=TransferDirection.OUTBOUND,
                purpose="local llm proxy",
                privileged_tools=_tool_capable(request),
            )
            try:
                protected = self.preflight.protect(preflight_request, vault=vault)
            except ProtectionError as exc:
                raise ERRORS["CS_PROXY_POLICY_BLOCKED"]() from exc
            outbound_action = protected.assessment.action.value
            category_counts.update(item.value for item in protected.assessment.categories)
            if (
                protected.assessment.action not in ALLOWED_OUTBOUND
                or not protected.assessment.safe_to_send
                or len(protected.protected_segments) != len(bindings)
            ):
                raise ERRORS["CS_PROXY_POLICY_BLOCKED"]()
            try:
                safe_payload = apply_protected(
                    payload, bindings, protected.protected_segments
                )
            except ValueError as exc:
                raise ERRORS["CS_PROXY_POLICY_BLOCKED"]() from exc

            validate_upstream_addresses(self.config, self.resolver)
            raw, upstream_class = await self._send(
                endpoint, safe_payload, upstream_credential
            )
            response_payload, inbound_bindings = self._inbound(endpoint, raw)
            if any(
                protected_value
                and protected_value in binding.segment.content
                for protected_value in (upstream_credential, local_token)
                for binding in inbound_bindings
            ):
                inbound_action = "blocked"
                raise ERRORS["CS_PROXY_INBOUND_BLOCKED"]()
            inbound_request = LlmPreflightRequest(
                segments=[item.segment for item in inbound_bindings],
                provider_profile_id=self.config.provider_profile_id,
                attestation_id=self.config.attestation_id,
                direction=TransferDirection.INBOUND,
                purpose="local llm proxy response",
                privileged_tools=_tool_capable(request),
            )
            inbound = self.preflight.assess(inbound_request)
            inbound_action = inbound.action.value
            category_counts.update(item.value for item in inbound.categories)
            if inbound.action not in ALLOWED_INBOUND or not inbound.safe_to_send:
                raise ERRORS["CS_PROXY_INBOUND_BLOCKED"]()
            restored = restore_known(
                response_payload,
                inbound_bindings,
                restore=lambda value: vault.restore_text(
                    value, session_id=protected.assessment.audit_id
                ),
            )
            return restored, correlation_id
        except ProxyError as exc:
            if exc.upstream_status_class:
                upstream_class = exc.upstream_status_class
            raise
        except (httpx.TimeoutException, TimeoutError) as exc:
            upstream_class = "timeout"
            raise ERRORS["CS_PROXY_TIMEOUT"]() from exc
        except httpx.HTTPError as exc:
            upstream_class = "failure"
            raise ERRORS["CS_PROXY_UPSTREAM_FAILURE"]() from exc
        except ProxyNetworkError as exc:
            upstream_class = "not_sent"
            raise ERRORS["CS_PROXY_UPSTREAM_FAILURE"]() from exc
        except ProviderRegistryError as exc:
            raise ERRORS["CS_PROXY_POLICY_BLOCKED"]() from exc
        except ValidationError as exc:
            raise ERRORS["CS_PROXY_INVALID_INPUT"]() from exc
        finally:
            latency_ms = max(0, round((time.perf_counter() - started) * 1000))
            try:
                audit.record(
                    correlation_id=correlation_id,
                    endpoint_class=endpoint,
                    profile_id=self.profile.profile_id,
                    profile_version=self.profile.version,
                    outbound_action=outbound_action,
                    inbound_action=inbound_action,
                    category_counts=dict(sorted(category_counts.items())),
                    upstream_status_class=upstream_class,
                    latency_ms=latency_ms,
                )
            except (OSError, ValueError, sqlite3.Error):
                pass
            if owns_audit:
                audit.close()
            vault.close()

    def _require_current_attestation(self) -> None:
        status, _ = self.attestations.status(
            self.config.attestation_id, self.profile
        )
        if status is not AttestationStatus.VALID:
            raise ERRORS["CS_PROXY_POLICY_BLOCKED"]()

    def _outbound(
        self,
        endpoint: EndpointClass,
        request: ChatRequest | ResponsesRequest,
    ) -> tuple[dict[str, Any], list[SegmentBinding]]:
        if endpoint == "chat_completions" and isinstance(request, ChatRequest):
            return outbound_chat(request)
        if endpoint == "responses" and isinstance(request, ResponsesRequest):
            return outbound_responses(request)
        raise ERRORS["CS_PROXY_INVALID_INPUT"]()

    def _inbound(
        self, endpoint: EndpointClass, raw: dict[str, Any]
    ) -> tuple[dict[str, Any], list[SegmentBinding]]:
        try:
            if endpoint == "chat_completions":
                return inbound_chat(ChatResponse.model_validate(raw))
            return inbound_responses(ResponsesResponse.model_validate(raw))
        except ValidationError as exc:
            raise ERRORS["CS_PROXY_MALFORMED_RESPONSE"]() from exc

    async def _send(
        self,
        endpoint: EndpointClass,
        payload: dict[str, Any],
        credential: str,
    ) -> tuple[dict[str, Any], str]:
        suffix = "/chat/completions" if endpoint == "chat_completions" else "/responses"
        url = f"{self.config.upstream_base_url.rstrip('/')}{suffix}"
        timeout = httpx.Timeout(
            self.config.request_timeout_seconds,
            connect=self.config.connect_timeout_seconds,
        )
        headers = {
            "authorization": f"Bearer {credential}",
            "accept": "application/json",
            "content-type": "application/json",
            "user-agent": "codeshield-proxy/0.8",
        }
        async with httpx.AsyncClient(
            transport=self.transport,
            timeout=timeout,
            verify=True,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            async with client.stream(
                "POST", url, headers=headers, json=payload
            ) as response:
                status_class = f"{response.status_code // 100}xx"
                if 300 <= response.status_code < 400:
                    raise ERRORS["CS_PROXY_UPSTREAM_FAILURE"]().with_upstream(
                        status_class
                    )
                if response.status_code < 200 or response.status_code >= 300:
                    raise ERRORS["CS_PROXY_UPSTREAM_FAILURE"]().with_upstream(
                        status_class
                    )
                media_type = response.headers.get("content-type", "").split(";", 1)[0]
                if media_type.lower() != "application/json":
                    raise ERRORS["CS_PROXY_MALFORMED_RESPONSE"]().with_upstream(
                        status_class
                    )
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self.config.max_response_bytes:
                        raise ERRORS["CS_PROXY_MALFORMED_RESPONSE"]().with_upstream(
                            status_class
                        )
        try:
            decoded = bytes(body).decode("utf-8", errors="strict")
            value = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ERRORS["CS_PROXY_MALFORMED_RESPONSE"]().with_upstream(
                status_class
            ) from exc
        if not isinstance(value, dict):
            raise ERRORS["CS_PROXY_MALFORMED_RESPONSE"]().with_upstream(
                status_class
            )
        return value, status_class


def _tool_capable(request: ChatRequest | ResponsesRequest) -> bool:
    if request.tools:
        return True
    if isinstance(request, ChatRequest):
        return any(
            message.role == "tool" or bool(message.tool_calls)
            for message in request.messages
        )
    if isinstance(request.input, list):
        return any(
            isinstance(item, FunctionCallOutputInput)
            for item in request.input
        )
    return False
