"""Content-free integration failures."""


class OpenCodeError(Exception):
    """Expose only an integration-owned status code."""

    def __init__(self, code: str = "CS_OPENCODE_PROTOCOL") -> None:
        super().__init__(code if code in {
            "CS_OPENCODE_PROTOCOL", "CS_OPENCODE_MISSING",
            "CS_OPENCODE_INCOMPATIBLE", "CS_OPENCODE_TIMEOUT",
            "CS_OPENCODE_OUTPUT_LIMIT", "CS_OPENCODE_FAILED",
            "CS_OPENCODE_INVALID_INPUT", "CS_OPENCODE_CONFIGURATION",
        } else "CS_OPENCODE_FAILED")
