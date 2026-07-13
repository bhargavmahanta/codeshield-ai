from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codeshield.models.enums import DataCategory
from codeshield.pseudonymization import (
    InMemoryKeyProvider,
    PseudonymVault,
    VaultError,
)


def test_vault_encrypts_plaintext_at_rest(tmp_path: Path) -> None:
    path = tmp_path / "vault.sqlite"
    vault = PseudonymVault(path, InMemoryKeyProvider(b"k" * 32))
    raw = "synthetic-sensitive-value"

    pseudonym = vault.get_or_create(raw, DataCategory.API_KEY, session_id="one")
    vault.close()
    database_bytes = path.read_bytes()

    assert pseudonym == "<API_KEY_1>"
    assert raw.encode() not in database_bytes


def test_vault_restores_with_correct_session_and_key(tmp_path: Path) -> None:
    key_provider = InMemoryKeyProvider(b"r" * 32)
    path = tmp_path / "vault.sqlite"
    vault = PseudonymVault(path, key_provider)
    pseudonym = vault.get_or_create(
        "synthetic-original", DataCategory.EMAIL, session_id="one"
    )

    assert vault.restore(pseudonym, session_id="one") == "synthetic-original"
    assert vault.restore(pseudonym, session_id="other") is None
    vault.close()


def test_vault_rejects_tampered_ciphertext(tmp_path: Path) -> None:
    path = tmp_path / "vault.sqlite"
    vault = PseudonymVault(path, InMemoryKeyProvider(b"t" * 32))
    pseudonym = vault.get_or_create("synthetic-original", DataCategory.API_KEY, session_id="one")
    connection = sqlite3.connect(path)
    connection.execute("UPDATE pseudonyms SET ciphertext = ?", (b"tampered",))
    connection.commit()
    connection.close()

    with pytest.raises(VaultError, match="authentication failed"):
        vault.restore(pseudonym, session_id="one")
    vault.close()


def test_vault_uses_distinct_pseudonyms_for_distinct_values(tmp_path: Path) -> None:
    vault = PseudonymVault(tmp_path / "vault.sqlite", InMemoryKeyProvider())

    first = vault.get_or_create("synthetic-one", DataCategory.EMAIL, session_id="one")
    second = vault.get_or_create("synthetic-two", DataCategory.EMAIL, session_id="one")

    assert first == "<EMAIL_1>"
    assert second == "<EMAIL_2>"
    vault.close()
