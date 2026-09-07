"""Fixed sanitized management API errors."""

from __future__ import annotations

from dataclasses import dataclass


class ManagementError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message


@dataclass(frozen=True)
class ErrorSpec:
    code: str
    status_code: int
    message: str

    def __call__(self) -> ManagementError:
        return ManagementError(self.code, self.status_code, self.message)


ERRORS = {
    "CS_MANAGEMENT_AUTHENTICATION": ErrorSpec(
        "CS_MANAGEMENT_AUTHENTICATION", 401, "Authentication failed."
    ),
    "CS_MANAGEMENT_AUTHORIZATION": ErrorSpec(
        "CS_MANAGEMENT_AUTHORIZATION", 403, "The operation is not permitted."
    ),
    "CS_MANAGEMENT_INVALID_INPUT": ErrorSpec(
        "CS_MANAGEMENT_INVALID_INPUT", 400, "The request is invalid."
    ),
    "CS_MANAGEMENT_BODY_TOO_LARGE": ErrorSpec(
        "CS_MANAGEMENT_BODY_TOO_LARGE", 413, "The request is too large."
    ),
    "CS_MANAGEMENT_DEVICE_REVOKED": ErrorSpec(
        "CS_MANAGEMENT_DEVICE_REVOKED", 401, "The device is revoked."
    ),
    "CS_MANAGEMENT_NOT_FOUND": ErrorSpec(
        "CS_MANAGEMENT_NOT_FOUND", 404, "The requested metadata was not found."
    ),
    "CS_MANAGEMENT_CONFLICT": ErrorSpec(
        "CS_MANAGEMENT_CONFLICT", 409, "The metadata changed concurrently."
    ),
    "CS_MANAGEMENT_STORAGE_FAILURE": ErrorSpec(
        "CS_MANAGEMENT_STORAGE_FAILURE", 503, "Metadata storage is unavailable."
    ),
}
