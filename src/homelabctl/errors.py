class HomelabError(Exception):
    """Base exception for expected user-facing errors."""


class ConfigError(HomelabError):
    """Raised when a service definition is invalid."""


class UnsupportedOperation(HomelabError):
    """Raised when a driver intentionally does not implement an operation."""

