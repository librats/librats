"""
librats_py — Python bindings for librats, over its C ABI through ctypes.

A :class:`RatsNode` on its own is secure transport (Noise XX over UDP or TCP)
plus raw messaging on named channels. Discovery, NAT traversal, pub/sub, JSON
messaging, file transfer, ping and reconnection are subsystems: enable each with
its ``enable_*()`` before :meth:`RatsNode.start`.

    from librats_py import RatsNode

    with RatsNode(8080, protocol="myapp/1.0") as node:
        node.on_peer_connected(lambda peer: print("+", peer))
        node.on("chat", lambda peer, data: print(peer, data.decode()))
        node.enable_mdns()
        node.start()
"""

from .core import (
    RatsNode, set_log_level, set_log_file, version, version_info, git_describe, abi,
    error_str,
)
from .enums import (
    RatsError as ErrorCode, Security, Transport, TransportMask, Congestion, Direction,
    CloseReason, NatMapping, LogLevel, FileTransferStatus, BtEncryption,
    PeerInfo, PathStats, FileProgress, VersionInfo,
    FALLBACK_NEVER, LIVE_MAX_LIFETIME_MS, LIVE_MAX_PAYLOAD,
)
from .exceptions import (
    RatsError, RatsInvalidArgError, RatsNotStartedError, RatsAlreadyStartedError,
    RatsNotEnabledError, RatsNoSuchPeerError, RatsNotFoundError, RatsDeclinedError,
    RatsBindError,
)
from .ctypes_wrapper import LibratsNotFoundError

__version__ = "2.0.0"

__all__ = [
    "RatsNode",
    "set_log_level", "set_log_file", "version", "version_info", "git_describe", "abi",
    "error_str",
    "ErrorCode", "Security", "Transport", "TransportMask", "Congestion", "Direction",
    "CloseReason", "NatMapping", "LogLevel", "FileTransferStatus", "BtEncryption",
    "PeerInfo", "PathStats", "FileProgress", "VersionInfo",
    "FALLBACK_NEVER", "LIVE_MAX_LIFETIME_MS", "LIVE_MAX_PAYLOAD",
    "RatsError", "RatsInvalidArgError", "RatsNotStartedError", "RatsAlreadyStartedError",
    "RatsNotEnabledError", "RatsNoSuchPeerError", "RatsNotFoundError", "RatsDeclinedError",
    "RatsBindError", "LibratsNotFoundError",
]
