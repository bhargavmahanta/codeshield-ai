"""Safe aggregate projection from local audit storage."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from codeshield.management.config import management_home
from codeshield.version import __version__

IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
COUNT_KEY_PATTERN = r"^[A-Z][A-Z0-9_]{0,63}$"


class AuditProjectionError(ValueError):
    """Sanitized local audit projection failure."""


class SafeAuditEvent(BaseModel):
    """The complete allowlisted metadata that may leave the local machine."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_class: str = Field(min_length=1, max_length=128)
    category_counts: dict[str, int] = Field(max_length=64)
    action_counts: dict[str, int] = Field(max_length=16)
    highest_sensitivity: str = Field(
        pattern=r"^(public|internal|confidential|restricted)$"
    )
    status_bucket: str = Field(
        pattern=r"^(allowed|warned|blocked|protected|failed)$"
    )
    latency_bucket: str = Field(
        pattern=r"^(unknown|lt_50ms|lt_250ms|lt_750ms|lt_2s|gte_2s)$"
    )
    detector_version: str = Field(min_length=1, max_length=128)
    model_version: str | None = Field(default=None, min_length=1, max_length=128)
    occurred_at: datetime

    @field_validator("endpoint_class", "detector_version", "model_version")
    @classmethod
    def safe_identifier(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(IDENTIFIER_PATTERN, value):
            raise ValueError("identifier is invalid")
        return value

    @field_validator("category_counts", "action_counts")
    @classmethod
    def safe_counts(cls, value: dict[str, int]) -> dict[str, int]:
        if any(
            not re.fullmatch(COUNT_KEY_PATTERN, key)
            or isinstance(count, bool)
            or count < 0
            or count > 1_000_000_000
            for key, count in value.items()
        ):
            raise ValueError("aggregate counts are invalid")
        return value


def safe_audit_projection(
    *,
    root: Path | None = None,
    limit: int = 100,
) -> list[dict[str, object]]:
    if limit < 1 or limit > 500:
        raise AuditProjectionError("audit projection limit is invalid")
    base = root or management_home()
    database = base / "audit.sqlite"
    key_path = base / "audit.key"
    if not database.exists():
        return []
    try:
        key = key_path.read_bytes()
        if len(key) < 32:
            raise AuditProjectionError("local audit key is invalid")
        connection = sqlite3.connect(
            f"file:{database.as_posix()}?mode=ro",
            uri=True,
        )
        try:
            if not _table_exists(connection, "llm_audit"):
                return []
            rows = connection.execute(
                """
                SELECT audit_id, created_at, highest_sensitivity,
                       categories_json, action
                FROM llm_audit
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        finally:
            connection.close()
    except AuditProjectionError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise AuditProjectionError("local audit projection failed") from exc

    projected: list[dict[str, object]] = []
    for audit_id, created_at, sensitivity, categories_json, action in rows:
        try:
            categories = json.loads(str(categories_json))
            if not isinstance(categories, list) or not all(
                isinstance(item, str) and item.isupper() for item in categories
            ):
                raise ValueError
            category_counts = dict(sorted(Counter(categories).items()))
            action_value = str(action)
            status = _status_bucket(action_value)
            event_hmac = hmac.new(
                key,
                f"management-event:{audit_id}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            event = SafeAuditEvent.model_validate(
                {
                    "event_hmac": event_hmac,
                    "endpoint_class": "llm_preflight",
                    "category_counts": category_counts,
                    "action_counts": {action_value.upper(): 1},
                    "highest_sensitivity": str(sensitivity),
                    "status_bucket": status,
                    "latency_bucket": "unknown",
                    "detector_version": __version__,
                    "model_version": None,
                    "occurred_at": str(created_at),
                }
            )
            projected.append(event.model_dump(mode="json"))
        except (TypeError, ValueError) as exc:
            raise AuditProjectionError("local audit metadata is invalid") from exc
    return projected


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        is not None
    )


def _status_bucket(action: str) -> str:
    return {
        "allow": "allowed",
        "warn": "warned",
        "block": "blocked",
        "mask": "protected",
        "pseudonymize": "protected",
    }.get(action, "failed")
