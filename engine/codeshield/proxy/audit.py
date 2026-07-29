"""Metadata-only HMAC audit records for proxy operations."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


class ProxyAuditStore:
    def __init__(self, path: Path | str, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("proxy audit HMAC key must contain at least 32 bytes")
        self.key = key
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(str(path), check_same_thread=False)
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS proxy_audit (
                correlation_hmac TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                endpoint_class TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                profile_version TEXT NOT NULL,
                outbound_action TEXT NOT NULL,
                inbound_action TEXT NOT NULL,
                category_counts_json TEXT NOT NULL,
                upstream_status_class TEXT NOT NULL,
                latency_ms INTEGER NOT NULL
            )
            """
        )
        self._connection.commit()

    @classmethod
    def local_default(cls) -> "ProxyAuditStore":
        root = Path(os.environ.get("CODESHIELD_HOME", Path.home() / ".codeshield"))
        root.mkdir(parents=True, exist_ok=True)
        key_path = root / "audit.key"
        if key_path.exists():
            key = key_path.read_bytes()
        else:
            key = os.urandom(32)
            key_path.write_bytes(key)
            try:
                key_path.chmod(0o600)
            except OSError:
                pass
        return cls(root / "audit.sqlite", key)

    def close(self) -> None:
        self._connection.close()

    def record(
        self,
        *,
        correlation_id: str,
        endpoint_class: str,
        profile_id: str,
        profile_version: str,
        outbound_action: str,
        inbound_action: str,
        category_counts: dict[str, int],
        upstream_status_class: str,
        latency_ms: int,
    ) -> None:
        correlation_hmac = hmac.new(
            self.key, correlation_id.encode("ascii"), hashlib.sha256
        ).hexdigest()
        with self._lock:
            self._connection.execute(
                "INSERT INTO proxy_audit VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    correlation_hmac,
                    datetime.now(timezone.utc).isoformat(),
                    endpoint_class,
                    profile_id,
                    profile_version,
                    outbound_action,
                    inbound_action,
                    json.dumps(category_counts, sort_keys=True, separators=(",", ":")),
                    upstream_status_class,
                    latency_ms,
                ),
            )
            self._connection.commit()

    def rows(self) -> list[tuple[object, ...]]:
        return self._connection.execute(
            "SELECT * FROM proxy_audit ORDER BY created_at"
        ).fetchall()
