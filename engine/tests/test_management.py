from __future__ import annotations

import json
import sqlite3
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from uuid import UUID

import httpx
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from codeshield.cli import app
from codeshield.management.audit import safe_audit_projection
from codeshield.management.config import (
    ManagementConfigError,
    load_management_config,
)
from codeshield.management.contracts import (
    DestinationVersionReference,
    ManagedPolicyBundle,
    PolicyDocumentPayload,
    PolicyRulePayload,
    ProviderProfileVersionReference,
    SignedPolicyBundle,
    encode_public_key,
    sign_bundle,
)
from codeshield.management.policy import ManagedPolicyEngine
from codeshield.management.service import ManagementService
from codeshield.management.storage import ManagementStorage, ManagementStorageError
from codeshield.models.context import FileContext
from codeshield.models.enums import Destination, RecommendedAction
from codeshield.policies import PolicyEngine, load_policy
from codeshield.scanner import CodeShieldScanner
from codeshield.version import __version__
from tests.git_helpers import synthetic_api_key

ORGANIZATION_ID = UUID("11111111-1111-4111-8111-111111111111")
DEVICE_ID = UUID("11111111-e001-4111-8111-111111111111")
POLICY_VERSION_ID = UUID("11111111-c101-4111-8111-111111111111")
PROFILE_VERSION_ID = UUID("11111111-a001-4111-8111-111111111111")
DESTINATION_VERSION_ID = UUID("11111111-d101-4111-8111-111111111111")
RELEASE_ID = UUID("11111111-f001-4111-8111-111111111111")
runner = CliRunner()


def signed_bundle(
    key: Ed25519PrivateKey,
    *,
    sequence: int = 1,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    mandatory: bool = True,
) -> SignedPolicyBundle:
    issued = issued_at or datetime.now(UTC)
    bundle = ManagedPolicyBundle(
        organization_id=ORGANIZATION_ID,
        release_sequence=sequence,
        policy_version_id=POLICY_VERSION_ID,
        policy=PolicyDocumentPayload(
            policy_id="baseline",
            version=1,
            name="Synthetic baseline",
            mandatory=mandatory,
            rules=[
                PolicyRulePayload(
                    rule_id="managed-block",
                    category="API_KEY",
                    action="block",
                    destination_id="private_git",
                    sensitivity="restricted",
                    mandatory=mandatory,
                    remediation_code="remove_secret",
                )
            ],
        ),
        provider_profiles=[
            ProviderProfileVersionReference(
                version_id=PROFILE_VERSION_ID,
                profile_id="synthetic-provider",
                version=1,
                evidence_digest="a" * 64,
            )
        ],
        destinations=[
            DestinationVersionReference(
                version_id=DESTINATION_VERSION_ID,
                destination_id="private_git",
                version=1,
                sensitivity_ceiling="restricted",
            )
        ],
        minimum_compatible_engine=__version__,
        issued_at=issued,
        expires_at=expires_at or issued + timedelta(days=1),
        key_id="test-key",
    )
    return sign_bundle(bundle, key)


def write_config(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "endpoint": "http://127.0.0.1:8766",
                "organization_id": str(ORGANIZATION_ID),
                "device_id": str(DEVICE_ID),
                "signing_public_keys": {
                    "test-key": encode_public_key(key.public_key())
                },
                "offline_validity_days": 7,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_config_is_absolute_strict_and_credential_free(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    config_path = tmp_path / "management.yaml"
    write_config(config_path, key)
    config = load_management_config(config_path)
    assert config.organization_id == ORGANIZATION_ID
    assert config.endpoint == "http://127.0.0.1:8766"
    assert "token" not in config.model_dump()
    with pytest.raises(ManagementConfigError):
        load_management_config(Path("relative.yaml"))
    payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    payload["endpoint"] = "https://example.invalid"
    config_path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    with pytest.raises(ManagementConfigError):
        load_management_config(config_path)


def test_config_rejects_symlink_when_supported(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    target = tmp_path / "target.yaml"
    write_config(target, key)
    link = tmp_path / "link.yaml"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(ManagementConfigError):
        load_management_config(link)


def test_explicit_pull_verifies_and_atomically_activates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = Ed25519PrivateKey.generate()
    config_path = tmp_path / "management.yaml"
    write_config(config_path, key)
    signed = signed_bundle(key)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["authorization"] == "Bearer local-device-token"
        return httpx.Response(
            200,
            json={
                "release_id": str(RELEASE_ID),
                "signed_bundle": signed.model_dump(mode="json"),
            },
        )

    monkeypatch.setenv("CODESHIELD_MANAGEMENT_TOKEN", "local-device-token")
    service = ManagementService(
        config_path=config_path,
        storage_root=tmp_path,
        transport=httpx.MockTransport(handler),
        now=signed.bundle.issued_at + timedelta(minutes=1),
    )
    status = service.pull_policy()
    assert status.release_sequence == 1
    assert service.status().policy_status == "valid"
    assert service.verified_active_bundle().release_sequence == 1
    assert [request.url.path for request in requests] == [
        "/v1/policy-bundles/latest"
    ]


def test_pull_rejects_tampering_expiry_and_downgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = Ed25519PrivateKey.generate()
    config_path = tmp_path / "management.yaml"
    write_config(config_path, key)
    initial = signed_bundle(key, sequence=1)
    storage = ManagementStorage(ORGANIZATION_ID, DEVICE_ID, root=tmp_path)
    storage.activate(initial)
    tampered = initial.model_dump(mode="json")
    tampered["bundle"]["release_sequence"] = 2
    monkeypatch.setenv("CODESHIELD_MANAGEMENT_TOKEN", "local-device-token")

    def tamper_handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            json={"release_id": str(RELEASE_ID), "signed_bundle": tampered},
        )

    with pytest.raises(ValueError, match="SIGNATURE_INVALID"):
        ManagementService(
            config_path=config_path,
            storage_root=tmp_path,
            transport=httpx.MockTransport(tamper_handler),
        ).pull_policy()

    def old_handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            json={
                "release_id": str(RELEASE_ID),
                "signed_bundle": initial.model_dump(mode="json"),
            },
        )

    with pytest.raises(ValueError, match="DOWNGRADE_REJECTED"):
        ManagementService(
            config_path=config_path,
            storage_root=tmp_path,
            transport=httpx.MockTransport(old_handler),
        ).pull_policy()
    expired_service = ManagementService(
        config_path=config_path,
        storage_root=tmp_path,
        now=initial.bundle.expires_at,
    )
    assert expired_service.status().policy_status == "expired"


def test_atomic_activation_rolls_back_existing_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = Ed25519PrivateKey.generate()
    storage = ManagementStorage(ORGANIZATION_ID, DEVICE_ID, root=tmp_path)
    first = signed_bundle(key, sequence=1)
    second = signed_bundle(key, sequence=2)
    storage.activate(first)
    import codeshield.management.storage as storage_module

    original = storage_module._atomic_write
    calls = 0

    def fail_state(path: Path, payload: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ManagementStorageError("synthetic state failure")
        original(path, payload)

    monkeypatch.setattr(storage_module, "_atomic_write", fail_state)
    with pytest.raises(ManagementStorageError):
        storage.activate(second)
    assert storage.load_bundle().bundle.release_sequence == 1
    assert storage.load_state().release_sequence == 1


def test_status_is_offline_and_missing_policy_fails_closed(
    tmp_path: Path,
) -> None:
    key = Ed25519PrivateKey.generate()
    config_path = tmp_path / "management.yaml"
    write_config(config_path, key)
    service = ManagementService(config_path=config_path, storage_root=tmp_path)
    assert service.status().policy_status == "missing"
    with pytest.raises(ValueError, match="POLICY_MISSING"):
        service.verified_active_bundle()


def test_safe_audit_projection_excludes_payload_and_path_hmacs(
    tmp_path: Path,
) -> None:
    key = bytes(range(32))
    (tmp_path / "audit.key").write_bytes(key)
    connection = sqlite3.connect(tmp_path / "audit.sqlite")
    connection.execute(
        """
        CREATE TABLE llm_audit (
          audit_id TEXT PRIMARY KEY,
          created_at TEXT NOT NULL,
          payload_hmac TEXT NOT NULL,
          path_hmacs_json TEXT NOT NULL,
          provider_profile_id TEXT NOT NULL,
          provider_profile_version TEXT,
          attestation_status TEXT NOT NULL,
          direction TEXT NOT NULL,
          highest_sensitivity TEXT NOT NULL,
          categories_json TEXT NOT NULL,
          action TEXT NOT NULL,
          feature_flags_json TEXT NOT NULL,
          segment_count INTEGER NOT NULL,
          finding_count INTEGER NOT NULL,
          injection_count INTEGER NOT NULL
        )
        """
    )
    prohibited = "must-not-leave-local-audit"
    connection.execute(
        "INSERT INTO llm_audit VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "event-one",
            datetime.now(UTC).isoformat(),
            prohibited,
            json.dumps([prohibited]),
            "synthetic-provider",
            "1",
            "valid",
            "outbound",
            "restricted",
            json.dumps(["API_KEY", "API_KEY"]),
            "block",
            "[]",
            1,
            1,
            0,
        ),
    )
    connection.commit()
    connection.close()
    events = safe_audit_projection(root=tmp_path)
    serialized = json.dumps(events)
    assert prohibited not in serialized
    assert events[0]["category_counts"] == {"API_KEY": 2}
    assert events[0]["latency_bucket"] == "unknown"


def test_upload_audit_dry_run_never_requires_token_or_network(
    tmp_path: Path,
) -> None:
    key = Ed25519PrivateKey.generate()
    config_path = tmp_path / "management.yaml"
    write_config(config_path, key)
    assert ManagementService(
        config_path=config_path,
        storage_root=tmp_path,
    ).upload_audit(confirm=False) == (0, 0)


def test_managed_mandatory_rule_cannot_be_overridden_by_local_exception() -> None:
    key = Ed25519PrivateKey.generate()
    document = load_policy(Path("codeshield/policies/default.yaml"))
    local = PolicyEngine(document, today=date(2026, 7, 31))
    payload = signed_bundle(key).bundle.model_dump(mode="json")
    payload["policy"]["rules"][0]["destination_id"] = "public_git"
    managed = ManagedPolicyEngine(local, ManagedPolicyBundle.model_validate(payload))
    scanner = CodeShieldScanner(policy_engine=managed)
    finding = scanner.scan_text(
        f"api_key = '{synthetic_api_key()}'",
        destination=Destination.PUBLIC_GIT,
        file_context=FileContext.from_path(
            Path("demo/review-fixtures/key.txt")
        ),
    )[0]
    assert finding.recommended_action is RecommendedAction.BLOCK
    assert finding.policy_decision is not None
    assert finding.policy_decision.mandatory is True


def test_cli_management_commands_are_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = Ed25519PrivateKey.generate()
    config_path = tmp_path / "management.yaml"
    write_config(config_path, key)
    validated = runner.invoke(
        app,
        ["management", "validate-config", str(config_path)],
    )
    assert validated.exit_code == 0
    assert json.loads(validated.stdout)["valid"] is True
    assert "signing_public_keys" not in validated.stdout
    monkeypatch.setenv("CODESHIELD_MANAGEMENT_CONFIG", str(config_path))
    status = runner.invoke(app, ["management", "status"])
    assert status.exit_code == 3
    assert json.loads(status.stdout)["policy_status"] == "missing"
    confirmation = runner.invoke(app, ["management", "upload-audit"])
    assert confirmation.exit_code == 3
    assert "CS_MANAGEMENT_CONFIRMATION_REQUIRED" in confirmation.output


def test_enrolled_scanner_fails_closed_without_active_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = Ed25519PrivateKey.generate()
    config_path = tmp_path / "management.yaml"
    write_config(config_path, key)
    monkeypatch.setenv("CODESHIELD_MANAGEMENT_CONFIG", str(config_path))
    with pytest.raises(ValueError, match="POLICY_MISSING"):
        CodeShieldScanner()
