"""Signed metadata-only management interoperability."""

from codeshield.management.contracts import (
    BundleVerificationError,
    DestinationVersionReference,
    ManagedPolicyBundle,
    PolicyDocumentPayload,
    PolicyRulePayload,
    ProviderProfileVersionReference,
    SignedPolicyBundle,
    canonical_bundle_bytes,
    sign_bundle,
    verify_bundle,
)

__all__ = [
    "BundleVerificationError",
    "DestinationVersionReference",
    "ManagedPolicyBundle",
    "PolicyDocumentPayload",
    "PolicyRulePayload",
    "ProviderProfileVersionReference",
    "SignedPolicyBundle",
    "canonical_bundle_bytes",
    "sign_bundle",
    "verify_bundle",
]
