"""Explicit, redirect-free management client operations."""

from __future__ import annotations

import json
from typing import Any

import httpx

from codeshield.management.config import ManagementClientConfig
from codeshield.management.contracts import SignedPolicyBundle

MAX_RESPONSE_BYTES = 1_000_000


class ManagementClientError(ValueError):
    """Fixed-code network or response failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ManagementClient:
    def __init__(
        self,
        config: ManagementClientConfig,
        token: str,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.config = config
        self._token = token
        self._client = httpx.Client(
            base_url=config.endpoint,
            transport=transport,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(15.0, connect=5.0),
            headers={
                "authorization": f"Bearer {token}",
                "accept": "application/json",
            },
        )

    def close(self) -> None:
        self._client.close()

    def pull_latest(self) -> SignedPolicyBundle:
        payload = self._request_json("GET", "/v1/policy-bundles/latest")
        try:
            return SignedPolicyBundle.model_validate(payload["signed_bundle"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ManagementClientError(
                "CS_MANAGEMENT_MALFORMED_RESPONSE"
            ) from exc

    def upload_audit(self, events: list[dict[str, object]]) -> int:
        payload = self._request_json(
            "POST",
            "/v1/audit-events/batch",
            json_body={"events": events},
        )
        accepted = payload.get("accepted")
        if (
            isinstance(accepted, bool)
            or not isinstance(accepted, int)
            or accepted < 0
            or accepted > len(events)
        ):
            raise ManagementClientError("CS_MANAGEMENT_MALFORMED_RESPONSE")
        return accepted

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        json_body: object | None = None,
    ) -> dict[str, Any]:
        try:
            with self._client.stream(
                method,
                path,
                json=json_body,
                headers={"content-type": "application/json"}
                if json_body is not None
                else None,
            ) as response:
                if response.is_redirect:
                    raise ManagementClientError("CS_MANAGEMENT_REDIRECT_REJECTED")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise ManagementClientError(
                            "CS_MANAGEMENT_RESPONSE_TOO_LARGE"
                        )
                if response.status_code == 401:
                    raise ManagementClientError("CS_MANAGEMENT_AUTHENTICATION")
                if response.status_code == 404:
                    raise ManagementClientError("CS_MANAGEMENT_NOT_FOUND")
                if response.status_code < 200 or response.status_code >= 300:
                    raise ManagementClientError("CS_MANAGEMENT_SERVER_FAILURE")
        except ManagementClientError:
            raise
        except httpx.TimeoutException as exc:
            raise ManagementClientError("CS_MANAGEMENT_TIMEOUT") from exc
        except httpx.HTTPError as exc:
            raise ManagementClientError("CS_MANAGEMENT_UNAVAILABLE") from exc
        try:
            value = json.loads(bytes(body).decode("utf-8", errors="strict"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ManagementClientError("CS_MANAGEMENT_MALFORMED_RESPONSE") from exc
        if not isinstance(value, dict):
            raise ManagementClientError("CS_MANAGEMENT_MALFORMED_RESPONSE")
        return value
