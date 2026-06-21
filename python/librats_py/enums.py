"""
Enumerations and constants for librats Python bindings.

These mirror the enums declared in the C ABI (``src/bindings/rats.h``).
"""

from enum import IntEnum


class RatsError(IntEnum):
    """``rats_error_t`` result codes returned by fallible C functions.

    ``OK`` is 0; any non-zero value is an error.
    """
    OK = 0
    INVALID_ARG = 1     # null/malformed argument (bad peer id, null ptr, bad json)
    NOT_STARTED = 2     # operation requires a started node
    ALREADY_STARTED = 3  # enable/attach called after start()
    NOT_ENABLED = 4     # subsystem not enabled — call the matching enable_*()
    NO_SUCH_PEER = 5    # peer not connected, or transfer id not found
    BIND = 6            # listen/bind failed during start()
    INTERNAL = 7


class Security(IntEnum):
    """``rats_security_t`` — transport security mode."""
    NOISE = 0      # Noise XX, encrypted + authenticated (default)
    PLAINTEXT = 1  # unencrypted, ids exchanged in the clear


class LogLevel(IntEnum):
    """``rats_log_level_t`` — process-global logging verbosity."""
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3


class FileTransferStatus(IntEnum):
    """File-transfer status reported by the progress callback.

    Mirrors ``FileTransfer::Status`` in the C++ core.
    """
    PENDING = 0
    ACTIVE = 1
    PAUSED = 2
    COMPLETED = 3
    FAILED = 4
    CANCELLED = 5


class VersionInfo:
    """Library version information container."""

    def __init__(self, major: int, minor: int, patch: int, build: int):
        self.major = major
        self.minor = minor
        self.patch = patch
        self.build = build

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}.{self.build}"

    def __repr__(self) -> str:
        return (
            f"VersionInfo(major={self.major}, minor={self.minor}, "
            f"patch={self.patch}, build={self.build})"
        )
