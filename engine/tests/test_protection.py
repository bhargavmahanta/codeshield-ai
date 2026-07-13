from __future__ import annotations

from pathlib import Path

from codeshield.models.enums import Destination, ProtectionMode
from codeshield.pseudonymization import InMemoryKeyProvider, PseudonymVault
from codeshield.scanner import CodeShieldScanner


def test_type_placeholder_protects_email() -> None:
    text = "contact = user@example.test"
    result = CodeShieldScanner().protect_text(
        text,
        destination=Destination.LOCAL_FILE,
        mode=ProtectionMode.TYPE_PLACEHOLDER,
    )

    assert result.blocked is False
    assert result.protected_text == "contact = <EMAIL>"
    assert "user@example.test" not in result.model_dump_json()


def test_public_git_block_returns_no_original_text() -> None:
    text = 'api_key = "sk_live_51SyntheticTokenValue999"'
    result = CodeShieldScanner().protect_text(
        text,
        destination=Destination.PUBLIC_GIT,
        mode=ProtectionMode.REDACT,
    )

    assert result.blocked is True
    assert result.protected_text == ""
    assert "SyntheticTokenValue999" not in result.model_dump_json()


def test_pseudonymization_is_consistent(tmp_path: Path) -> None:
    vault = PseudonymVault(tmp_path / "vault.sqlite", InMemoryKeyProvider())
    scanner = CodeShieldScanner()
    text = "first=user@example.test second=user@example.test"

    result = scanner.protect_text(
        text,
        destination=Destination.EXTERNAL_LLM,
        mode=ProtectionMode.PSEUDONYMIZE,
        vault=vault,
        session_id="session-a",
    )

    assert result.protected_text.count("<EMAIL_1>") == 2
    assert "user@example.test" not in result.protected_text
    vault.close()


def test_partial_mask_replaces_multiple_findings_right_to_left() -> None:
    text = "a=user@example.test b=203.0.113.42"
    result = CodeShieldScanner().protect_text(
        text,
        destination=Destination.LOCAL_FILE,
        mode=ProtectionMode.PARTIAL_MASK,
    )

    assert "user@example.test" not in result.protected_text
    assert "203.0.113.42" not in result.protected_text
    assert len(result.replacements) == 2
