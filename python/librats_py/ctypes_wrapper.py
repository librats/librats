"""
Low-level ctypes wrapper for the librats C ABI (``src/bindings/rats.h``).

This module declares the shared-library handle and the argtypes/restypes for
every C function the high-level API uses. Heap-allocated strings returned by the
library (``rats_local_id``, ``rats_protocol_name``/``_version``,
``rats_peer_ids`` entries) are declared ``c_void_p`` so the bytes can be copied
out and the original pointer released with ``rats_string_free``; use
:func:`take_string` for that. Static strings (``rats_version_string``,
``rats_git_describe``, ``rats_error_str``) are declared ``c_char_p`` and must
NOT be freed.
"""

import os
import platform
from ctypes import (
    CDLL, POINTER, Structure, c_void_p, c_char_p, c_int, c_size_t,
    c_uint16, c_uint32, c_uint64, c_int64, string_at,
)
from typing import Optional

from .callbacks import (
    PeerCallbackType, MessageCallbackType, TopicCallbackType, JsonCallbackType,
    FileOfferCallbackType, FileProgressCallbackType, FileCompleteCallbackType,
)


class LibratsNotFoundError(Exception):
    """Raised when the librats shared library cannot be located/loaded."""
    pass


class RatsConfig(Structure):
    """ctypes mirror of ``rats_config_t``.

    Obtain a defaults-filled instance via ``LibratsCtypes.config_default()``,
    set the fields you care about, then pass it to ``rats_create_config``.
    """
    _fields_ = [
        ("listen_port", c_uint16),       # uint16_t
        ("enable_listen", c_int),        # int (0 = dial-only)
        ("bind_address", c_char_p),      # const char* (NULL → "::")
        ("security", c_int),             # rats_security_t
        ("data_dir", c_char_p),          # const char*
        ("protocol_name", c_char_p),     # const char*
        ("protocol_version", c_char_p),  # const char*
        ("max_peers", c_size_t),         # size_t (0 = unlimited)
    ]


def find_librats_library() -> str:
    """Locate the librats shared library, returning a loadable path or name."""
    system = platform.system().lower()

    if system == 'windows':
        lib_names = ['rats.dll', 'librats.dll']
    elif system == 'darwin':
        lib_names = ['librats.dylib', 'librats.so']
    else:  # Linux and others
        lib_names = ['librats.so', 'librats.so.1']

    here = os.path.dirname(__file__)
    search_paths = [
        here,                                          # alongside the package
        '.',
        os.path.join(here, '..', '..', 'build', 'lib'),
        os.path.join(here, '..', '..', 'build', 'bin'),
        os.path.join(here, '..', '..', 'build'),
        '../build', '../../build', '../../../build',
        '/usr/local/lib',
        '/usr/lib',
    ]

    if 'LD_LIBRARY_PATH' in os.environ:
        search_paths.extend(os.environ['LD_LIBRARY_PATH'].split(os.pathsep))
    if system == 'windows' and 'PATH' in os.environ:
        search_paths.extend(os.environ['PATH'].split(os.pathsep))

    for path in search_paths:
        for lib_name in lib_names:
            lib_path = os.path.join(path, lib_name)
            if os.path.exists(lib_path):
                return os.path.abspath(lib_path)

    # Fall back to letting the OS loader search by bare name.
    for lib_name in lib_names:
        try:
            CDLL(lib_name)
            return lib_name
        except OSError:
            continue

    raise LibratsNotFoundError(
        f"Could not find librats shared library (tried {lib_names})."
    )


def take_string(lib: "LibratsCtypes", ptr) -> Optional[str]:
    """Copy a heap string returned by the library and free the original.

    ``ptr`` must be a ``c_void_p``-typed result (or ``None``). Returns the
    decoded ``str`` (empty string for a NULL pointer). The underlying buffer is
    released via ``rats_string_free``.
    """
    if not ptr:
        return ""
    try:
        value = string_at(ptr).decode('utf-8', errors='replace')
    finally:
        lib.lib.rats_string_free(ptr)
    return value


class LibratsCtypes:
    """Loads librats and declares all C function signatures."""

    def __init__(self):
        lib_path = find_librats_library()
        try:
            self.lib = CDLL(lib_path)
        except OSError as e:
            raise LibratsNotFoundError(
                f"Failed to load librats library at {lib_path}: {e}")
        self._setup_signatures()

    def _setup_signatures(self):
        lib = self.lib

        # --- error / utility ---
        lib.rats_error_str.argtypes = [c_int]
        lib.rats_error_str.restype = c_char_p  # static, do not free

        lib.rats_string_free.argtypes = [c_void_p]
        lib.rats_string_free.restype = None

        # --- construction / lifecycle ---
        lib.rats_config_default.argtypes = []
        lib.rats_config_default.restype = RatsConfig

        lib.rats_create_config.argtypes = [POINTER(RatsConfig)]
        lib.rats_create_config.restype = c_void_p

        lib.rats_create.argtypes = [c_uint16]
        lib.rats_create.restype = c_void_p

        lib.rats_create_ex.argtypes = [c_uint16, c_int, c_char_p, c_int]
        lib.rats_create_ex.restype = c_void_p

        lib.rats_destroy.argtypes = [c_void_p]
        lib.rats_destroy.restype = None

        lib.rats_start.argtypes = [c_void_p]
        lib.rats_start.restype = c_int

        lib.rats_stop.argtypes = [c_void_p]
        lib.rats_stop.restype = None

        lib.rats_listen_port.argtypes = [c_void_p]
        lib.rats_listen_port.restype = c_uint16

        lib.rats_local_id.argtypes = [c_void_p]
        lib.rats_local_id.restype = c_void_p  # heap; free with rats_string_free

        lib.rats_protocol_name.argtypes = [c_void_p]
        lib.rats_protocol_name.restype = c_void_p  # heap

        lib.rats_protocol_version.argtypes = [c_void_p]
        lib.rats_protocol_version.restype = c_void_p  # heap

        # --- connections ---
        lib.rats_connect.argtypes = [c_void_p, c_char_p, c_uint16]
        lib.rats_connect.restype = c_int

        lib.rats_peer_count.argtypes = [c_void_p]
        lib.rats_peer_count.restype = c_size_t

        lib.rats_set_max_peers.argtypes = [c_void_p, c_size_t]
        lib.rats_set_max_peers.restype = None

        lib.rats_max_peers.argtypes = [c_void_p]
        lib.rats_max_peers.restype = c_size_t

        # --- messaging (named channel, raw bytes) ---
        lib.rats_send.argtypes = [c_void_p, c_char_p, c_char_p, c_void_p, c_size_t]
        lib.rats_send.restype = c_int

        lib.rats_broadcast.argtypes = [c_void_p, c_char_p, c_void_p, c_size_t]
        lib.rats_broadcast.restype = c_int

        # --- core callbacks ---
        lib.rats_on_peer_connected.argtypes = [c_void_p, PeerCallbackType, c_void_p]
        lib.rats_on_peer_connected.restype = c_int

        lib.rats_on_peer_disconnected.argtypes = [c_void_p, PeerCallbackType, c_void_p]
        lib.rats_on_peer_disconnected.restype = c_int

        lib.rats_on.argtypes = [c_void_p, c_char_p, MessageCallbackType, c_void_p]
        lib.rats_on.restype = c_int

        # --- discovery / port mapping subsystems ---
        lib.rats_enable_dht.argtypes = [c_void_p, c_uint16, c_char_p]
        lib.rats_enable_dht.restype = c_int

        lib.rats_enable_mdns.argtypes = [c_void_p]
        lib.rats_enable_mdns.restype = c_int

        lib.rats_enable_port_mapping.argtypes = [c_void_p, c_int, c_int]
        lib.rats_enable_port_mapping.restype = c_int

        # --- peer enumeration ---
        lib.rats_peer_ids.argtypes = [c_void_p, POINTER(c_size_t)]
        lib.rats_peer_ids.restype = POINTER(c_void_p)

        lib.rats_free_peer_ids.argtypes = [POINTER(c_void_p), c_size_t]
        lib.rats_free_peer_ids.restype = None

        # --- pub/sub ---
        lib.rats_enable_pubsub.argtypes = [c_void_p]
        lib.rats_enable_pubsub.restype = c_int

        lib.rats_subscribe.argtypes = [c_void_p, c_char_p, TopicCallbackType, c_void_p]
        lib.rats_subscribe.restype = c_int

        lib.rats_unsubscribe.argtypes = [c_void_p, c_char_p]
        lib.rats_unsubscribe.restype = c_int

        lib.rats_publish.argtypes = [c_void_p, c_char_p, c_void_p, c_size_t]
        lib.rats_publish.restype = c_int

        # --- typed JSON messaging ---
        lib.rats_enable_json.argtypes = [c_void_p]
        lib.rats_enable_json.restype = c_int

        lib.rats_on_json.argtypes = [c_void_p, c_char_p, JsonCallbackType, c_void_p]
        lib.rats_on_json.restype = c_int

        lib.rats_once_json.argtypes = [c_void_p, c_char_p, JsonCallbackType, c_void_p]
        lib.rats_once_json.restype = c_int

        lib.rats_off_json.argtypes = [c_void_p, c_char_p]
        lib.rats_off_json.restype = c_int

        lib.rats_send_json.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
        lib.rats_send_json.restype = c_int

        lib.rats_broadcast_json.argtypes = [c_void_p, c_char_p, c_char_p]
        lib.rats_broadcast_json.restype = c_int

        # --- file transfer ---
        lib.rats_enable_file_transfer.argtypes = [c_void_p, c_char_p]
        lib.rats_enable_file_transfer.restype = c_int

        lib.rats_on_file_offer.argtypes = [c_void_p, FileOfferCallbackType, c_void_p]
        lib.rats_on_file_offer.restype = c_int

        lib.rats_on_file_progress.argtypes = [c_void_p, FileProgressCallbackType, c_void_p]
        lib.rats_on_file_progress.restype = c_int

        lib.rats_on_file_complete.argtypes = [c_void_p, FileCompleteCallbackType, c_void_p]
        lib.rats_on_file_complete.restype = c_int

        lib.rats_send_file.argtypes = [c_void_p, c_char_p, c_char_p]
        lib.rats_send_file.restype = c_uint64

        lib.rats_send_directory.argtypes = [c_void_p, c_char_p, c_char_p]
        lib.rats_send_directory.restype = c_uint64

        lib.rats_accept_file.argtypes = [c_void_p, c_char_p, c_uint64, c_char_p]
        lib.rats_accept_file.restype = c_int

        lib.rats_reject_file.argtypes = [c_void_p, c_char_p, c_uint64]
        lib.rats_reject_file.restype = c_int

        lib.rats_cancel_file.argtypes = [c_void_p, c_char_p, c_uint64]
        lib.rats_cancel_file.restype = c_int

        lib.rats_pause_file.argtypes = [c_void_p, c_char_p, c_uint64]
        lib.rats_pause_file.restype = c_int

        lib.rats_resume_file.argtypes = [c_void_p, c_char_p, c_uint64]
        lib.rats_resume_file.restype = c_int

        # --- liveness (ping/RTT) ---
        lib.rats_enable_ping.argtypes = [c_void_p]
        lib.rats_enable_ping.restype = c_int

        lib.rats_peer_rtt_ms.argtypes = [c_void_p, c_char_p]
        lib.rats_peer_rtt_ms.restype = c_int64

        # --- automatic reconnection ---
        lib.rats_enable_reconnect.argtypes = [c_void_p]
        lib.rats_enable_reconnect.restype = c_int

        lib.rats_add_reconnect.argtypes = [c_void_p, c_char_p, c_uint16]
        lib.rats_add_reconnect.restype = c_int

        lib.rats_remove_reconnect.argtypes = [c_void_p, c_char_p, c_uint16]
        lib.rats_remove_reconnect.restype = c_int

        # --- logging (process-global) ---
        lib.rats_set_log_level.argtypes = [c_int]
        lib.rats_set_log_level.restype = None

        lib.rats_set_log_file.argtypes = [c_char_p]
        lib.rats_set_log_file.restype = None

        # --- library info (process-global) ---
        lib.rats_version_string.argtypes = []
        lib.rats_version_string.restype = c_char_p  # static, do not free

        lib.rats_version.argtypes = [
            POINTER(c_int), POINTER(c_int), POINTER(c_int), POINTER(c_int)]
        lib.rats_version.restype = None

        lib.rats_git_describe.argtypes = []
        lib.rats_git_describe.restype = c_char_p  # static, do not free

        lib.rats_abi.argtypes = []
        lib.rats_abi.restype = c_uint32

    def config_default(self) -> RatsConfig:
        """Return a ``rats_config_t`` pre-filled with the library defaults."""
        return self.lib.rats_config_default()


# Global singleton instance
_librats: Optional[LibratsCtypes] = None


def get_librats() -> LibratsCtypes:
    """Get (lazily creating) the process-global librats ctypes instance."""
    global _librats
    if _librats is None:
        _librats = LibratsCtypes()
    return _librats
