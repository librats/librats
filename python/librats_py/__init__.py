"""
librats_py — Python bindings for the librats P2P networking library.

These bindings target the librats C ABI (``src/bindings/rats.h``) via ctypes
and expose a high-level :class:`RatsClient` for peer-to-peer messaging, pub/sub,
typed JSON messaging, file transfer, discovery (DHT/mDNS), NAT port mapping,
ping/RTT and automatic reconnection.
"""

from .core import RatsClient
from .enums import (
    RatsError as ErrorCode,
    Security,
    LogLevel,
    FileTransferStatus,
    VersionInfo,
)
from .exceptions import (
    RatsError,
    RatsConnectionError,
    RatsInvalidArgError,
    RatsNotStartedError,
    RatsAlreadyStartedError,
    RatsNotEnabledError,
    RatsNoSuchPeerError,
    RatsBindError,
)
from .callbacks import (
    PeerCallback,
    MessageCallback,
    TopicCallback,
    JsonCallback,
    FileOfferCallback,
    FileProgressCallback,
    FileCompleteCallback,
)

__version__ = "2.0.0"
__author__ = "librats contributors"
__license__ = "MIT"

__all__ = [
    "RatsClient",
    # enums
    "ErrorCode",
    "Security",
    "LogLevel",
    "FileTransferStatus",
    "VersionInfo",
    # exceptions
    "RatsError",
    "RatsConnectionError",
    "RatsInvalidArgError",
    "RatsNotStartedError",
    "RatsAlreadyStartedError",
    "RatsNotEnabledError",
    "RatsNoSuchPeerError",
    "RatsBindError",
    # callback type aliases
    "PeerCallback",
    "MessageCallback",
    "TopicCallback",
    "JsonCallback",
    "FileOfferCallback",
    "FileProgressCallback",
    "FileCompleteCallback",
]
