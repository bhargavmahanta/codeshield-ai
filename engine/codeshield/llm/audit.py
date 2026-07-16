"""Metadata-only local audit records for LLM preflight decisions."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from codeshield.models.enums import ProviderFeature
from codeshield.models.llm import LlmPreflightRequest, SegmentAssessment


class AuditStore:
    def __init__(self, path: Path | str, key: bytes, *, retention_days: int = 30) -> None:
        if len(key) < 32:
            raise ValueError("audit HMAC key must contain at least 32 bytes")
        self.path = str(path)
        self.key = key
        self.retention_days = retention_days
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_audit (
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
        self._connection.commit()

    @classmethod
    def local_default(cls) -> "AuditStore":
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
        request: LlmPreflightRequest,
        assessments: list[SegmentAssessment],
        *,
        profile_version: str | None,
        attestation_status: str,
        highest_sensitivity: str,
        categories: list[str],
        action: str,
        effective_features: set[ProviderFeature] | None = None,
    ) -> str:
        audit_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc)
        payload_material = "\0".join(segment.content for segment in request.segments)
        payload_hmac = self._hmac(payload_material)
        path_hmacs = sorted(
            self._hmac(segment.path) for segment in request.segments if segment.path
        )
        finding_count = sum(len(item.findings) for item in assessments)
        injection_count = sum(item.prompt_injection_detected for item in assessments)
        with self._lock:
            self._purge(now)
            self._connection.execute(
                """
                INSERT INTO llm_audit VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    now.isoformat(),
                    payload_hmac,
                    json.dumps(path_hmacs),
                    request.provider_profile_id,
                    profile_version,
                    attestation_status,
                    request.direction.value,
                    highest_sensitivity,
                    json.dumps(sorted(categories)),
                    action,
                    json.dumps(
                        sorted(
                            feature.value
                            for feature in (effective_features or set(request.enabled_features))
                        )
                    ),
                    len(request.segments),
                    finding_count,
                    injection_count,
                ),
            )
            self._connection.commit()
        return audit_id

    def _hmac(self, value: str) -> str:
        return hmac.new(self.key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def _purge(self, now: datetime) -> None:
        cutoff = (now - timedelta(days=self.retention_days)).isoformat()
        self._connection.execute("DELETE FROM llm_audit WHERE created_at < ?", (cutoff,))

    def schema_columns(self) -> list[str]:
        return [
            str(row[1])
            for row in self._connection.execute("PRAGMA table_info(llm_audit)").fetchall()
        ]

    def update_action(self, audit_id: str, action: str) -> None:
        with self._lock:
            self._connection.execute(
                "UPDATE llm_audit SET action = ? WHERE audit_id = ?",
                (action, audit_id),
            )
            self._connection.commit()
