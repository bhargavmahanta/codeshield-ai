"""Measure the fully inspected 100 KB mock-proxy round trip."""

from __future__ import annotations

import json
import os
import statistics
import tempfile
import time
from datetime import date
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from codeshield.models.provider import ProviderAttestation
from codeshield.providers import AttestationStore, ProviderRegistry
from codeshield.proxy import ProxyConfig, create_proxy_app
from codeshield.proxy.audit import ProxyAuditStore

TRIALS = 20
BUDGET_MS = 750


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="codeshield-proxy-benchmark-") as temporary:
        root = Path(temporary)
        registry = ProviderRegistry()
        profile = registry.require("openai-api-zdr")
        attestations = AttestationStore(root / "attestations.json")
        attestation = ProviderAttestation(
            attestation_id="proxy-benchmark",
            profile_id=profile.profile_id,
            profile_version=profile.version,
            account_hash="1" * 64,
            enabled_controls=["zdr-reviewed"],
            evidence_digest="2" * 64,
            reviewer_id="benchmark",
            created_on=date(2026, 7, 16),
            expires_on=date(2026, 10, 14),
        )
        attestations.save(attestation, registry)
        config = ProxyConfig(
            port=8770,
            upstream_base_url="https://api.example.test/v1",
            provider_profile_id=profile.profile_id,
            attestation_id=attestation.attestation_id,
            upstream_credential_env="CODESHIELD_BENCHMARK_UPSTREAM",
            allowed_models=["model-safe"],
            max_request_bytes=200_000,
            max_response_bytes=16_384,
        )
        os.environ["CODESHIELD_PROXY_TOKEN"] = "benchmark-local-" + ("x" * 32)
        os.environ["CODESHIELD_BENCHMARK_UPSTREAM"] = "benchmark-upstream"
        os.environ["CODESHIELD_HOME"] = str(root / "home")

        def upstream(request: httpx.Request) -> httpx.Response:
            del request
            return httpx.Response(
                200,
                json={
                    "id": "chatcmpl_benchmark",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "model-safe",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop",
                        }
                    ],
                },
                headers={"content-type": "application/json"},
            )

        audit = ProxyAuditStore(":memory:", b"benchmark-audit-key-material-000001")
        app = create_proxy_app(
            config,
            transport=httpx.MockTransport(upstream),
            resolver=lambda host, port: ["8.8.8.8"],
            registry=registry,
            attestations=attestations,
            audit=audit,
        )
        client = TestClient(app)
        line = "ordinary deterministic proxy benchmark text\n"
        content = (line * ((100_000 // len(line)) + 1))[:100_000]
        durations: list[float] = []
        for index in range(TRIALS + 1):
            started = time.perf_counter()
            response = client.post(
                "/v1/chat/completions",
                headers={
                    "authorization": "Bearer " + os.environ["CODESHIELD_PROXY_TOKEN"]
                },
                json={
                    "model": "model-safe",
                    "messages": [{"role": "user", "content": content}],
                    "store": False,
                },
            )
            elapsed = (time.perf_counter() - started) * 1000
            if response.status_code != 200:
                return 1
            if index:
                durations.append(elapsed)
        audit.close()

    ordered = sorted(durations)
    p95 = ordered[max(0, int(0.95 * len(ordered) + 0.9999) - 1)]
    result = {
        "workload_bytes": 100_000,
        "warm_trials": TRIALS,
        "median_ms": round(statistics.median(durations), 2),
        "p95_ms": round(p95, 2),
        "budget_ms": BUDGET_MS,
        "passed": p95 <= BUDGET_MS,
        "upstream": "local_mock_only",
    }
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
