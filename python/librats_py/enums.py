"""
Enumerations and constants for librats Python bindings.

These mirror the enums declared in the C ABI (``src/librats/bindings/rats.h``).
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


class Transport(IntEnum):
    """``rats_transport_t`` — which wire a peer connection runs on.

    TCP and UDP carry the identical protocol and the identical encrypted
    handshake; they differ only in how the ordered, reliable byte stream
    underneath is obtained. RELAY is that same stream one hop further away,
    carried inside another peer's connection; it is never dialed, so it has no
    bit in :class:`TransportMask`.
    """
    TCP = 0    # one kernel socket per peer
    UDP = 1    # reliable stream over the shared UDP socket
    RELAY = 2  # carried through a third node (see enable_relay)


class TransportMask(IntEnum):
    """Bitmask flags used by :attr:`RatsNode.transports` and friends."""
    TCP = 0x1
    UDP = 0x2


class NatMapping(IntEnum):
    """``RATS_NAT_*`` — what the mesh has shown about this node's own NAT.

    Derived from the endpoints datagram peers report observing this node's
    shared UDP socket at: two peers agreeing means one external port for every
    peer (punchable), two disagreeing means a fresh mapping per peer.
    """
    UNKNOWN = 0               # not enough independent observations yet
    OPEN = 1                  # no NAT in the path
    ENDPOINT_INDEPENDENT = 2  # one external port for every peer — punchable
    ENDPOINT_DEPENDENT = 3    # a fresh mapping per peer (symmetric) — not punchable


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
