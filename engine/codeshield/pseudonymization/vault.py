"""AES-GCM encrypted local SQLite pseudonym vault."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from codeshield.models.enums import DataCategory

PSEUDONYM_PATTERN = re.compile(r"<[A-Z][A-Z0-9_]*_[1-9][0-9]*>")


class VaultError(RuntimeError):
    """Safe vault error that never includes plaintext values."""


class KeyProvider(Protocol):
    def get_key(self) -> bytes:
        """Return exactly 32 bytes of key material."""


class InMemoryKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or AESGCM.generate_key(bit_length=256)

    def get_key(self) -> bytes:
        return self._key


class EnvironmentKeyProvider:
    def __init__(self, variable: str = "CODESHIELD_VAULT_KEY") -> None:
        self.variable = variable

    def get_key(self) -> bytes:
        encoded = os.environ.get(self.variable)
        if not encoded:
            raise VaultError(f"vault key environment variable {self.variable} is not set")
        try:
            key = base64.urlsafe_b64decode(encoded.encode("ascii"))
        except (ValueError, UnicodeError) as exc:
            raise VaultError("vault key is not valid URL-safe base64") from exc
        if len(key) != 32:
            raise VaultError("vault key must decode to exactly 32 bytes")
        return key


class PseudonymVault:
    def __init__(
        self,
        path: Path | str,
        key_provider: KeyProvider,
    ) -> None:
        self.path = str(path)
        self.key = key_provider.get_key()
        if len(self.key) != 32:
            raise VaultError("vault encryption key must contain exactly 32 bytes")
        self._aes = AESGCM(self.key)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pseudonyms (
                session_id TEXT NOT NULL,
                category TEXT NOT NULL,
                lookup_token TEXT NOT NULL,
                pseudonym TEXT NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (session_id, lookup_token),
                UNIQUE (session_id, pseudonym)
            )
            """
        )
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    def get_or_create(
        self, raw_value: str, category: DataCategory, *, session_id: str
    ) -> str:
        lookup = self._lookup_token(raw_value, session_id)
        with self._lock:
            row = self._connection.execute(
                "SELECT pseudonym FROM pseudonyms WHERE session_id = ? AND lookup_token = ?",
                (session_id, lookup),
            ).fetchone()
            if row:
                return str(row[0])
            count = self._connection.execute(
                "SELECT COUNT(*) FROM pseudonyms WHERE session_id = ? AND category = ?",
                (session_id, category.value),
            ).fetchone()[0]
            pseudonym = f"<{category.value}_{int(count) + 1}>"
            nonce = os.urandom(12)
            associated_data = self._associated_data(session_id, category, pseudonym)
            ciphertext = self._aes.encrypt(
                nonce, raw_value.encode("utf-8"), associated_data
            )
            self._connection.execute(
                """
                INSERT INTO pseudonyms
                    (session_id, category, lookup_token, pseudonym, nonce, ciphertext)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    category.value,
                    lookup,
                    pseudonym,
                    nonce,
                    ciphertext,
                ),
            )
            self._connection.commit()
            return pseudonym

    def restore(self, pseudonym: str, *, session_id: str) -> str | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT category, nonce, ciphertext FROM pseudonyms
                WHERE session_id = ? AND pseudonym = ?
                """,
                (session_id, pseudonym),
            ).fetchone()
        if row is None:
            return None
        category = DataCategory(str(row[0]))
        associated_data = self._associated_data(session_id, category, pseudonym)
        try:
            plaintext = self._aes.decrypt(bytes(row[1]), bytes(row[2]), associated_data)
        except InvalidTag as exc:
            raise VaultError("vault record authentication failed") from exc
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VaultError("vault record is not valid UTF-8") from exc

    def restore_text(self, text: str, *, session_id: str) -> str:
        def replace(match: re.Match[str]) -> str:
            restored = self.restore(match.group(0), session_id=session_id)
            return restored if restored is not None else match.group(0)

        return PSEUDONYM_PATTERN.sub(replace, text)

    def _lookup_token(self, raw_value: str, session_id: str) -> str:
        material = f"{session_id}\0{raw_value}".encode("utf-8")
        return hmac.new(self.key, material, hashlib.sha256).hexdigest()

    @staticmethod
    def _associated_data(
        session_id: str, category: DataCategory, pseudonym: str
    ) -> bytes:
        return f"{session_id}\0{category.value}\0{pseudonym}".encode("utf-8")
