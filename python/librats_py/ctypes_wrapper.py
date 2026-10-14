"""
ctypes declarations for the librats C ABI (``src/librats/bindings/rats.h``).

Loads the shared library and declares every struct and function signature.
Library-owned strings (``rats_local_id``, ``rats_protocol``, the static names)
are ``const char*`` and declared ``c_char_p``: ctypes copies them, nothing is
freed. The arrays from ``rats_peer_ids`` / ``rats_observed_addresses`` are
caller-owned and released with ``rats_strings_free``.
"""

import os
import platform
from ctypes import (
    CDLL, POINTER, Structure, c_char, c_char_p, c_double, c_int, c_int64, c_size_t,
    c_uint16, c_uint32, c_uint64, c_void_p,
)
from typing import Optional

from .callbacks import (
    PeerCallbackType, DisconnectCallbackType, DialFailedCallbackType, MessageCallbackType,
    PathCallbackType, TopicCallbackType, JsonCallbackType,
    FileOfferCallbackType, FileProgressCallbackType, FileCompleteCallbackType,
)


class LibratsNotFoundError(ImportError):
    """The librats shared library could not be found or loaded."""


class RatsConfig(Structure):
    """``rats_config_t``. Zero in every field is the library default."""
    _fields_ = [
        # identity
        ("protocol", c_char_p),
        ("data_dir", c_char_p),
        ("security", c_int),
        # listening
        ("listen_port", c_uint16),
        ("bind_address", c_char_p),
        ("dial_only", c_int),
        ("max_peers", c_size_t),
        # transports
        ("transports", c_uint32),
        ("preferred_transport", c_int),
        ("transport_fallback_ms", c_uint32),
        # sending
        ("send_queue_limit", c_size_t),
        ("path_sample_ms", c_uint32),
        # UDP transport
        ("congestion_control", c_int),
        ("udp_receive_window", c_size_t),
        ("udp_receive_budget", c_size_t),
        ("disable_udp_offload", c_int),
        # runtime
        ("reactor_threads", c_size_t),
        ("disable_network_monitor", c_int),
    ]


class RatsPeerInfo(Structure):
    """``rats_peer_info_t``."""
    _fields_ = [
        ("transport", c_int),
        ("transports", c_uint32),
        ("direction", c_int),
        ("address", c_char * 64),
    ]


class RatsPathStats(Structure):
    """``rats_path_stats_t``."""
    _fields_ = [
        ("bandwidth_bps", c_uint64),
        ("app_limited", c_int),
        ("pacing_bps", c_uint64),
        ("srtt_us", c_uint32),
        ("min_rtt_us", c_uint32),
        ("queued_bytes", c_uint64),
        ("bytes_in_flight", c_uint64),
        ("loss", c_double),
        ("bytes_delivered", c_uint64),
        ("bytes_lost", c_uint64),
        ("live_sent", c_uint64),
        ("live_expired", c_uint64),
        ("live_repair_bytes", c_uint64),
    ]


class RatsFileProgress(Structure):
    """``rats_file_progress_t``."""
    _fields_ = [
        ("transfer_id", c_uint64),
        ("peer_id", c_char_p),
        ("direction", c_int),
        ("status", c_int),
        ("bytes_transferred", c_uint64),
        ("total_bytes", c_uint64),
        ("files_completed", c_uint32),
        ("total_files", c_uint32),
        ("rate_bytes_per_sec", c_double),
    ]


class RatsBtConfig(Structure):
    """``rats_bt_config_t``. Zero in every field is the default."""
    _fields_ = [
        ("listen_port", c_uint16),
        ("download_path", c_char_p),
        ("outgoing_encryption", c_int),
        ("incoming_encryption", c_int),
        ("disable_outgoing_utp", c_int),
        ("disable_incoming_utp", c_int),
    ]


# (name, restype, argtypes) of every function in rats.h.
_N = c_void_p          # rats_t
_S = c_char_p          # const char*
_E = c_int             # rats_error_t and the other enums
_SIGNATURES = [
    ("rats_error_str", _S, [_E]),
    ("rats_close_reason_str", _S, [_E]),
    # configuration and lifecycle
    ("rats_create", _N, [POINTER(RatsConfig)]),
    ("rats_destroy", None, [_N]),
    ("rats_start", _E, [_N]),
    ("rats_stop", None, [_N]),
    # this node
    ("rats_local_id", _S, [_N]),
    ("rats_protocol", _S, [_N]),
    ("rats_listen_port", c_uint16, [_N]),
    ("rats_transports", c_uint32, [_N]),
    ("rats_nat_mapping", _E, [_N]),
    ("rats_observed_addresses", POINTER(c_char_p), [_N, POINTER(c_size_t)]),
    # peers
    ("rats_connect", _E, [_N, _S, c_uint16]),
    ("rats_disconnect", _E, [_N, _S]),
    ("rats_peer_count", c_size_t, [_N]),
    ("rats_peer_ids", POINTER(c_char_p), [_N, POINTER(c_size_t)]),
    ("rats_peer_info", _E, [_N, _S, POINTER(RatsPeerInfo)]),
    ("rats_set_max_peers", None, [_N, c_size_t]),
    ("rats_max_peers", c_size_t, [_N]),
    # messaging
    ("rats_send", _E, [_N, _S, _S, c_void_p, c_size_t, c_uint32]),
    ("rats_broadcast", _E, [_N, _S, c_void_p, c_size_t, c_uint32]),
    ("rats_peer_writable", c_int, [_N, _S]),
    ("rats_path_stats", _E, [_N, _S, POINTER(RatsPathStats)]),
    # callbacks
    ("rats_on_peer_connected", _E, [_N, PeerCallbackType, c_void_p]),
    ("rats_on_peer_disconnected", _E, [_N, DisconnectCallbackType, c_void_p]),
    ("rats_on_dial_failed", _E, [_N, DialFailedCallbackType, c_void_p]),
    ("rats_on_peer_writable", _E, [_N, PeerCallbackType, c_void_p]),
    ("rats_on_peer_path", _E, [_N, PathCallbackType, c_void_p]),
    ("rats_on", _E, [_N, _S, MessageCallbackType, c_void_p]),
    # discovery
    ("rats_enable_dht", _E, [_N, c_uint16, _S]),
    ("rats_enable_mdns", _E, [_N]),
    ("rats_enable_peer_exchange", _E, [_N]),
    # NAT traversal
    ("rats_enable_port_mapping", _E, [_N, c_int, c_int]),
    ("rats_enable_hole_punch", _E, [_N, c_int]),
    ("rats_punch_peer", _E, [_N, _S]),
    ("rats_enable_relay", _E, [_N, c_int]),
    ("rats_connect_via_relay", _E, [_N, _S]),
    # pub/sub
    ("rats_enable_pubsub", _E, [_N]),
    ("rats_subscribe", _E, [_N, _S, TopicCallbackType, c_void_p]),
    ("rats_unsubscribe", _E, [_N, _S]),
    ("rats_publish", _E, [_N, _S, c_void_p, c_size_t]),
    # JSON messaging
    ("rats_enable_json", _E, [_N]),
    ("rats_on_json", _E, [_N, _S, JsonCallbackType, c_void_p]),
    ("rats_once_json", _E, [_N, _S, JsonCallbackType, c_void_p]),
    ("rats_off_json", _E, [_N, _S]),
    ("rats_send_json", _E, [_N, _S, _S, _S]),
    ("rats_broadcast_json", _E, [_N, _S, _S]),
    # file transfer
    ("rats_enable_file_transfer", _E, [_N, _S]),
    ("rats_on_file_offer", _E, [_N, FileOfferCallbackType, c_void_p]),
    ("rats_on_file_progress", _E, [_N, FileProgressCallbackType, c_void_p]),
    ("rats_on_file_complete", _E, [_N, FileCompleteCallbackType, c_void_p]),
    ("rats_send_file", _E, [_N, _S, _S, POINTER(c_uint64)]),
    ("rats_send_directory", _E, [_N, _S, _S, POINTER(c_uint64)]),
    ("rats_accept_file", _E, [_N, _S, c_uint64, _S]),
    ("rats_reject_file", _E, [_N, _S, c_uint64]),
    ("rats_cancel_file", _E, [_N, _S, c_uint64]),
    ("rats_pause_file", _E, [_N, _S, c_uint64]),
    ("rats_resume_file", _E, [_N, _S, c_uint64]),
    # ping
    ("rats_enable_ping", _E, [_N]),
    ("rats_peer_rtt_ms", c_int64, [_N, _S]),
    # reconnection
    ("rats_enable_reconnect", _E, [_N]),
    ("rats_add_reconnect", _E, [_N, _S, c_uint16]),
    ("rats_remove_reconnect", _E, [_N, _S, c_uint16]),
    # BitTorrent (RATS_ERR_NOT_ENABLED in builds without RATS_SEARCH_FEATURES)
    ("rats_enable_bittorrent", _E, [_N, POINTER(RatsBtConfig)]),
    ("rats_bt_add_magnet", _E, [_N, _S, _S]),
    ("rats_bt_add_torrent_file", _E, [_N, _S, _S]),
    ("rats_bt_remove_torrent", _E, [_N, _S]),
    # process-wide
    ("rats_set_log_level", None, [_E]),
    ("rats_set_log_file", None, [_S]),
    ("rats_version_string", _S, []),
    ("rats_version", None, [POINTER(c_int)] * 4),
    ("rats_git_describe", _S, []),
    ("rats_abi", c_uint32, []),
    ("rats_strings_free", None, [POINTER(c_char_p), c_size_t]),
]


def find_librats_library() -> str:
    """Locate the librats shared library; returns a path or a bare name."""
    system = platform.system().lower()
    if system == 'windows':
        names = ['rats.dll', 'librats.dll']
    elif system == 'darwin':
        names = ['librats.dylib']
    else:
        names = ['librats.so']

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.join(here, '..', '..')
    search = [here, os.path.join(root, 'build', 'lib'), os.path.join(root, 'build', 'bin'),
              os.path.join(root, 'build')]
    env = os.environ.get('LIBRATS_LIBRARY_PATH')
    if env:
        search[:0] = env.split(os.pathsep)

    for path in search:
        for name in names:
            candidate = os.path.join(path, name)
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)
    # Leave the rest to the OS loader (PATH, LD_LIBRARY_PATH, system dirs).
    return names[0]


class LibratsCtypes:
    """The loaded library with every signature declared (``.lib``)."""

    def __init__(self):
        lib_path = find_librats_library()
        # Since Python 3.8 Windows does not search PATH for a DLL's own
        # dependencies; register the library's directory so ones shipped next to
        # it resolve.
        dll_dir = None
        if os.name == 'nt' and os.path.isabs(lib_path):
            dll_dir = os.add_dll_directory(os.path.dirname(lib_path))
        try:
            self.lib = CDLL(lib_path)
        except OSError as e:
            raise LibratsNotFoundError(f"cannot load the librats library ({lib_path}): {e}") from e
        finally:
            if dll_dir is not None:
                dll_dir.close()
        for name, restype, argtypes in _SIGNATURES:
            fn = getattr(self.lib, name)
            fn.restype = restype
            fn.argtypes = argtypes


_librats: Optional[LibratsCtypes] = None


def get_librats() -> LibratsCtypes:
    """The process-wide library instance, loaded on first use."""
    global _librats
    if _librats is None:
        _librats = LibratsCtypes()
    return _librats
