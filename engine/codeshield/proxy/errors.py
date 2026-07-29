"""Sanitized OpenAI-style proxy errors."""

from __future__ import annotations

from dataclasses import dataclass


class ProxyError(Exception):
    def __init__(
        self,
        code: str,
        status_code: int,
        message: str,
        error_type: str = "codeshield_proxy_error",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.error_type = error_type
        self.upstream_status_class: str | None = None

    def with_upstream(self, status_class: str) -> "ProxyError":
        self.upstream_status_class = status_class
        return self


@dataclass(frozen=True)
class ProxyErrorSpec:
    code: str
    status_code: int
    message: str
    error_type: str = "codeshield_proxy_error"

    def __call__(self) -> ProxyError:
        return ProxyError(
            self.code,
            self.status_code,
            self.message,
            self.error_type,
        )


ERRORS = {
    "CS_PROXY_AUTHENTICATION": ProxyErrorSpec(
        "CS_PROXY_AUTHENTICATION", 401, "Local proxy authentication failed."
    ),
    "CS_PROXY_INVALID_INPUT": ProxyErrorSpec(
        "CS_PROXY_INVALID_INPUT", 400, "The request is invalid."
    ),
    "CS_PROXY_UNSUPPORTED_FEATURE": ProxyErrorSpec(
        "CS_PROXY_UNSUPPORTED_FEATURE", 400, "The request uses an unsupported feature."
    ),
    "CS_PROXY_POLICY_BLOCKED": ProxyErrorSpec(
        "CS_PROXY_POLICY_BLOCKED", 403, "CodeShield blocked the outbound request."
    ),
    "CS_PROXY_SATURATED": ProxyErrorSpec(
        "CS_PROXY_SATURATED", 429, "The local proxy is at its concurrency limit."
    ),
    "CS_PROXY_TIMEOUT": ProxyErrorSpec(
        "CS_PROXY_TIMEOUT", 504, "The upstream request timed out."
    ),
    "CS_PROXY_UPSTREAM_FAILURE": ProxyErrorSpec(
        "CS_PROXY_UPSTREAM_FAILURE", 502, "The upstream request failed."
    ),
    "CS_PROXY_MALFORMED_RESPONSE": ProxyErrorSpec(
        "CS_PROXY_MALFORMED_RESPONSE", 502, "The upstream response is invalid."
    ),
    "CS_PROXY_INBOUND_BLOCKED": ProxyErrorSpec(
        "CS_PROXY_INBOUND_BLOCKED", 403, "CodeShield blocked the complete upstream response."
    ),
}
