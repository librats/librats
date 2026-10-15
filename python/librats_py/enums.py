"""
Enumerations, constants and value types of the librats Python bindings.

The enums mirror the C ABI (``src/librats/bindings/rats.h``) value for value.
"""

from dataclasses import dataclass
from enum import IntEnum, IntFlag


class RatsError(IntEnum):
    """``rats_error_t``. ``OK`` is 0; anything else is an error."""
    OK = 0
    INVALID_ARG = 1      # NULL or malformed argument (bad peer id, bad JSON, …)
    NOT_STARTED = 2      # the call needs a started node
    ALREADY_STARTED = 3  # only allowed before start()
    NOT_ENABLED = 4      # the subsystem was not enabled
    NO_SUCH_PEER = 5     # the peer is not connected
    NOT_FOUND = 6        # no such transfer
    DECLINED = 7         # nothing to do or nothing to try with
    BIND = 8             # start() could not open its sockets
    INTERNAL = 9


class Security(IntEnum):
    """``rats_security_t``."""
    NOISE = 0      # Noise XX: encrypted and authenticated (default)
    PLAINTEXT = 1  # no encryption; ids exchanged in the clear


class Transport(IntEnum):
    """``rats_transport_t`` — which wire a peer connection runs on.

    UDP and TCP carry the same protocol under the same encrypted handshake.
    RELAY is only ever reported (see :meth:`RatsNode.peer_info`), never chosen:
    a relay is not something a dial can try.
    """
    UDP = 0    # the library's own transport on one shared UDP socket
    TCP = 1    # one kernel socket per peer
    RELAY = 2  # carried through another peer's connection


class TransportMask(IntFlag):
    """Bitmask of transports (``RATS_TRANSPORT_MASK_*``)."""
    NONE = 0
    TCP = 0x1
    UDP = 0x2


class Congestion(IntEnum):
    """``rats_congestion_t`` — congestion controller of every UDP connection.

    TCP is the kernel's and ignores it.
    """
    BBR = 0   # BBRv3 (default): holds its rate through loss that is not congestion
    RENO = 1  # NewReno with HyStart++: backs off on every loss


class Direction(IntEnum):
    """``rats_direction_t`` — who opened a connection (or who sends a file)."""
    OUTBOUND = 0  # we dialed it / we send
    INBOUND = 1   # it dialed us / we receive


class CloseReason(IntEnum):
    """``rats_close_reason_t`` — why a peer connection ended."""
    LOCAL = 0              # we disconnected it
    PEER_CLOSED = 1        # the peer closed cleanly
    PEER_RESET = 2         # connection reset / socket error
    CONNECT_FAILED = 3     # the dial never completed
    HANDSHAKE_FAILED = 4   # secure handshake failed or timed out
    PROTOCOL_ERROR = 5     # malformed frame or decryption failure
    # We kept sending while the peer's queue was already past its limit — the one
    # reason the application causes and can prevent (see RatsNode.peer_writable).
    SLOW_CONSUMER = 6
    SHUTDOWN = 7           # the node is stopping
    DUPLICATE = 8          # replaced by another connection to the same peer
    PEER_LIMIT = 9         # inbound refused: max_peers reached
    IDLE_TIMEOUT = 10      # a UDP connection went silent
    DIAL_SUPERSEDED = 11   # a dial racing over the other transport won


class NatMapping(IntEnum):
    """``rats_nat_mapping_t`` — what the mesh has shown about this node's NAT."""
    UNKNOWN = 0               # not enough independent observations yet
    OPEN = 1                  # no NAT in the path
    ENDPOINT_INDEPENDENT = 2  # one external port for every peer: punchable
    ENDPOINT_DEPENDENT = 3    # a new mapping per peer (symmetric): not punchable


class LogLevel(IntEnum):
    """``rats_log_level_t``."""
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3


class FileTransferStatus(IntEnum):
    """``rats_file_status_t``."""
    PENDING = 0    # offered, not answered yet
    ACTIVE = 1
    PAUSED = 2
    COMPLETED = 3
    FAILED = 4
    CANCELLED = 5


class BtEncryption(IntEnum):
    """``rats_bt_encryption_t`` — BitTorrent MSE/PE policy."""
    ENABLED = 0   # obfuscate first, fall back to plaintext (default)
    FORCED = 1    # obfuscated connections only
    DISABLED = 2  # plaintext only


# ``transport_fallback_ms`` value that never races the second transport.
FALLBACK_NEVER = 0xFFFFFFFF
# Limits of a live message (``lifetime_ms`` > 0). A longer lifetime is cut to
# the maximum; a larger payload is refused.
LIVE_MAX_LIFETIME_MS = 30000
LIVE_MAX_PAYLOAD = 4 * 1024 * 1024


@dataclass(frozen=True)
class PeerInfo:
    """What the node knows about one connected peer (``rats_peer_info_t``)."""
    transport: Transport          # the wire this connection runs on
    transports: TransportMask     # what the peer says it accepts; NONE = it did not say
    direction: Direction
    address: str                  # where it can be dialed, "ip:port"; "" until known


@dataclass(frozen=True)
class PathStats:
    """What the transport knows about the path to one peer (``rats_path_stats_t``).

    For a sender that sizes its output to the path, such as a live encoder.
    Rates are bits per second. A new message waits behind ``queued_bytes``;
    ``queued_bytes * 8 / bandwidth_bps`` is that wait in seconds. Over TCP the
    path figures are the kernel's and exist on Linux only; elsewhere, and over a
    relay, only ``queued_bytes`` and the live counters are filled.
    """
    bandwidth_bps: int      # the congestion controller's estimate; 0 = none yet
    app_limited: bool       # the sender was not filling the path: the estimate is a floor
    pacing_bps: int         # current release rate; 0 = unpaced
    srtt_us: int            # smoothed round trip
    min_rtt_us: int         # lowest round trip seen: the path without queues
    queued_bytes: int       # accepted for the peer, not yet sent
    bytes_in_flight: int    # sent, not yet acknowledged
    loss: float             # share of bytes lost over the last interval, 0..1
    bytes_delivered: int    # acknowledged since the connection opened
    bytes_lost: int         # declared lost since the connection opened
    live_sent: int          # live messages sent since the connection opened
    live_expired: int       # of those, dropped because their lifetime ran out
    live_repair_bytes: int  # forward-error-correction bytes sent with live messages


@dataclass(frozen=True)
class FileProgress:
    """One progress report of a file transfer (``rats_file_progress_t``)."""
    transfer_id: int
    peer_id: str
    direction: Direction        # OUTBOUND = we send, INBOUND = we receive
    status: FileTransferStatus
    bytes_transferred: int
    total_bytes: int
    files_completed: int
    total_files: int
    rate_bytes_per_sec: float   # recent, smoothed


@dataclass(frozen=True)
class VersionInfo:
    """Library version components."""
    major: int
    minor: int
    patch: int
    build: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}.{self.build}"
