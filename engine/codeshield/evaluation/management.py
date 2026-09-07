"""Deterministic Phase 9 signing and ingestion boundary evaluation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from codeshield.evaluation.models import EvaluationCase
from codeshield.management.audit import SafeAuditEvent
from codeshield.management.contracts import (
    BundleVerificationError,
    ManagedPolicyBundle,
    PolicyDocumentPayload,
    SignedPolicyBundle,
    sign_bundle,
    verify_bundle,
)

ORGANIZATION_ID = UUID("90000000-0000-4000-8000-000000000001")
POLICY_VERSION_ID = UUID("90000000-0000-4000-8000-000000000002")
ISSUED_AT = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def management_security_metrics(
    cases: list[EvaluationCase],
) -> dict[str, float | int]:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    signed = sign_bundle(
        ManagedPolicyBundle(
            organization_id=ORGANIZATION_ID,
            release_sequence=2,
            policy_version_id=POLICY_VERSION_ID,
            policy=PolicyDocumentPayload(
                policy_id="phase9-evaluation",
                version=1,
                name="Phase 9 evaluation",
                mandatory=False,
                rules=[],
            ),
            provider_profiles=[],
            destinations=[],
            minimum_compatible_engine="0.9.0",
            issued_at=ISSUED_AT,
            expires_at=ISSUED_AT + timedelta(days=1),
            key_id="evaluation-key",
        ),
        key,
    )
    verification_total = 0
    verification_rejected = 0
    prohibited_total = 0
    prohibited_rejected = 0
    negative_total = 0
    negative_rejected = 0
    for case in cases:
        if case.suite == "management-verification":
            verification_total += 1
            if _verification_case_rejected(case.case_id, signed, key):
                verification_rejected += 1
        elif case.suite == "management-prohibited":
            prohibited_total += 1
            if _audit_case_rejected(case.case_id):
                prohibited_rejected += 1
        elif case.suite == "management-negative":
            negative_total += 1
            if _audit_case_rejected(case.case_id):
                negative_rejected += 1
    return {
        "verification_cases": verification_total,
        "verification_rejection_recall": _ratio(
            verification_rejected, verification_total
        ),
        "prohibited_cases": prohibited_total,
        "prohibited_ingestion_rejection_recall": _ratio(
            prohibited_rejected, prohibited_total
        ),
        "negative_cases": negative_total,
        "negative_case_false_positive_rate": _ratio(
            negative_rejected, negative_total
        ),
    }


def _verification_case_rejected(
    case_id: str,
    signed: SignedPolicyBundle,
    key: Ed25519PrivateKey,
) -> bool:
    candidate = signed
    keys = {"evaluation-key": key.public_key()}
    now = ISSUED_AT + timedelta(minutes=1)
    last_sequence = 1
    if case_id == "management-signature-tamper":
        payload = signed.model_dump(mode="json")
        payload["bundle"]["release_sequence"] = 3
        candidate = SignedPolicyBundle.model_validate(payload)
    elif case_id == "management-unknown-key":
        keys = {}
    elif case_id == "management-expired":
        now = signed.bundle.expires_at
    elif case_id == "management-rollback":
        last_sequence = signed.bundle.release_sequence
    else:
        return False
    try:
        verify_bundle(
            candidate,
            keys,
            organization_id=ORGANIZATION_ID,
            current_engine_version="0.9.0",
            last_release_sequence=last_sequence,
            now=now,
        )
    except BundleVerificationError:
        return True
    return False


def _audit_case_rejected(case_id: str) -> bool:
    payload: dict[str, object] = {
        "event_hmac": "a" * 64,
        "endpoint_class": "scan",
        "category_counts": {"API_KEY": 1},
        "action_counts": {"BLOCK": 1},
        "highest_sensitivity": "restricted",
        "status_bucket": "blocked",
        "latency_bucket": "lt_250ms",
        "detector_version": "0.9.0",
        "model_version": None,
        "occurred_at": ISSUED_AT.isoformat(),
    }
    if case_id == "management-extra-prompt":
        payload["prompt"] = "prohibited"
    elif case_id == "management-extra-response":
        payload["response"] = "prohibited"
    elif case_id == "management-extra-path":
        payload["path"] = "prohibited"
    elif case_id == "management-invalid-identifier":
        payload["endpoint_class"] = "/local/location"
    elif case_id == "management-invalid-counts":
        payload["category_counts"] = {"API_KEY": -1}
    elif not case_id.startswith("management-safe-audit-"):
        return False
    try:
        SafeAuditEvent.model_validate(payload)
    except ValidationError:
        return True
    return False


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 1.0
