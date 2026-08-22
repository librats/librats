"""
librats_py — Python bindings for the librats P2P networking library.

These bindings drive the librats C ABI (``src/librats/bindings/rats.h``) through
ctypes and expose a high-level :class:`RatsNode`.

A node on its own is secure transport (Noise XX over TCP or the library's
reliable stream over UDP) plus raw messaging on named channels. Discovery
(DHT/mDNS), pub/sub, typed JSON messaging, file transfer, NAT port mapping, hole
punching, RTT probing and automatic reconnection are opt-in subsystems: enable
each with its ``enable_*()`` **before** :meth:`RatsNode.start`.

    from librats_py import RatsNode

    with RatsNode(8080, data_dir="./state") as node:
        node.on_peer_connected(lambda peer: print("+", peer))
        node.on("chat", lambda peer, data: print(peer, data.decode()))
        node.enable_dht()
        node.start()
"""

from .core import (
    RatsNode,
    # process-global helpers (no node required)
    set_log_level,
    set_log_file,
    version,
    version_info,
    git_describe,
    abi,
    error_str,
)
from .enums import (
    RatsError as ErrorCode,
    Security,
    Transport,
    TransportMask,
    NatMapping,
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
    "RatsNode",
    # process-global helpers
    "set_log_level",
    "set_log_file",
    "version",
    "version_info",
    "git_describe",
    "abi",
    "error_str",
    # enums
    "ErrorCode",
    "Security",
    "Transport",
    "TransportMask",
    "NatMapping",
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
