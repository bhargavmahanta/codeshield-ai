"""Safe detector configuration and execution errors."""


class DetectorError(RuntimeError):
    """Base error that never contains scanned content."""


class DetectorUnavailableError(DetectorError):
    """Raised when an explicitly selected optional detector is unavailable."""


class DetectorExecutionError(DetectorError):
    """Raised when an optional detector cannot complete safely."""
