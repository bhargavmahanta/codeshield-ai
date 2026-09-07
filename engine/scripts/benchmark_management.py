"""Measure a warm 100 KB signed-policy pull and verification path."""

from __future__ import annotations

import json
import os
import statistics
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import httpx
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codeshield.management import (
    ManagedPolicyBundle,
    PolicyDocumentPayload,
    PolicyRulePayload,
    sign_bundle,
)
from codeshield.management.contracts import encode_public_key
from codeshield.management.service import ManagementService
from codeshield.version import __version__

LIMIT_MS = 750.0
ORGANIZATION_ID = UUID("91000000-0000-4000-8000-000000000001")
DEVICE_ID = UUID("91000000-0000-4000-8000-000000000002")
POLICY_VERSION_ID = UUID("91000000-0000-4000-8000-000000000003")
RELEASE_ID = UUID("91000000-0000-4000-8000-000000000004")


def main() -> int:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    issued = datetime.now(UTC) - timedelta(minutes=1)
    rules = [_rule(index) for index in range(256)]
    policy = PolicyDocumentPayload(
        policy_id="phase9-benchmark",
        version=1,
        name="Phase 9 local benchmark",
        mandatory=True,
        rules=rules,
    )
    signed_bundles = [
        sign_bundle(
            ManagedPolicyBundle(
                organization_id=ORGANIZATION_ID,
                release_sequence=sequence,
                policy_version_id=POLICY_VERSION_ID,
                policy=policy,
                provider_profiles=[],
                destinations=[],
                minimum_compatible_engine=__version__,
                issued_at=issued,
                expires_at=issued + timedelta(days=1),
                key_id="benchmark-key",
            ),
            key,
        )
        for sequence in range(1, 27)
    ]
    payload_bytes = len(
        json.dumps(
            signed_bundles[0].model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    if payload_bytes < 100_000:
        raise RuntimeError("management benchmark payload is below 100 KB")
    with tempfile.TemporaryDirectory(prefix="codeshield-management-benchmark-") as raw:
        root = Path(raw)
        config_path = root / "management.yaml"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "schema_version": 1,
                    "endpoint": "http://127.0.0.1:8766",
                    "organization_id": str(ORGANIZATION_ID),
                    "device_id": str(DEVICE_ID),
                    "signing_public_keys": {
                        "benchmark-key": encode_public_key(key.public_key())
                    },
                    "offline_validity_days": 7,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        config_path.chmod(0o600)
        position = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal position
            del request
            bundle = signed_bundles[position]
            position += 1
            return httpx.Response(
                200,
                json={
                    "release_id": str(RELEASE_ID),
                    "signed_bundle": bundle.model_dump(mode="json"),
                },
            )

        os.environ["CODESHIELD_MANAGEMENT_TOKEN"] = "benchmark-local-token"
        service = ManagementService(
            config_path=config_path,
            storage_root=root,
            transport=httpx.MockTransport(handler),
        )
        samples: list[float] = []
        for index in range(26):
            started = time.perf_counter()
            service.pull_policy()
            elapsed_ms = (time.perf_counter() - started) * 1000
            if index:
                samples.append(elapsed_ms)
    p95 = statistics.quantiles(samples, n=100, method="inclusive")[94]
    result = {
        "gate_ms": LIMIT_MS,
        "payload_bytes": payload_bytes,
        "samples": len(samples),
        "warm_p95_ms": round(p95, 2),
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if p95 <= LIMIT_MS else 1


def _rule(index: int) -> PolicyRulePayload:
    suffix = f"{index:03d}"
    return PolicyRulePayload(
        rule_id=(f"rule-{suffix}-" + ("r" * 118))[:128],
        category="API_KEY",
        action="block",
        destination_id=(f"destination-{suffix}-" + ("d" * 110))[:128],
        sensitivity="restricted",
        mandatory=True,
        remediation_code=(f"remediation-{suffix}-" + ("m" * 110))[:128],
    )


if __name__ == "__main__":
    raise SystemExit(main())
