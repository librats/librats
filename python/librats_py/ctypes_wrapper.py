"""
Low-level ctypes wrapper for librats C API.
"""

import ctypes
import os
import platform
import sys
from ctypes import (
    CDLL, POINTER, Structure, c_void_p, c_char_p, c_int, c_size_t,
    c_uint32, c_uint16, c_uint8, byref, create_string_buffer
)
from typing import Optional

from .callbacks import *
from .enums import RatsError, ConnectionStrategy


class LibratsNotFoundError(Exception):
    """Raised when the librats shared library cannot be found."""
    pass


def find_librats_library() -> str:
    """Find the librats shared library."""
    system = platform.system().lower()
    
    # Common library names
    if system == 'windows':
        lib_names = ['librats.dll', 'rats.dll']
    elif system == 'darwin':
        lib_names = ['librats.dylib', 'librats.so']
    else:  # Linux and others
        lib_names = ['librats.so', 'librats.so.1']
    
    # Search paths
    search_paths = [
        '.',
        '../build',
        '../../build',
        '../../../build',
        '/usr/local/lib',
        '/usr/lib',
        os.path.join(os.path.dirname(__file__), '..', '..', 'build'),
    ]
    
    # Add system paths
    if 'LD_LIBRARY_PATH' in os.environ:
        search_paths.extend(os.environ['LD_LIBRARY_PATH'].split(':'))
    
    if system == 'windows' and 'PATH' in os.environ:
        search_paths.extend(os.environ['PATH'].split(';'))
    
    # Try to find the library
    for path in search_paths:
        for lib_name in lib_names:
            lib_path = os.path.join(path, lib_name)
            if os.path.exists(lib_path):
                return lib_path
    
    # If not found, try loading by name (system will search)
    for lib_name in lib_names:
        try:
            # Test if we can load it
            test_lib = CDLL(lib_name)
            return lib_name
        except OSError:
            continue
    
    raise LibratsNotFoundError(
        f"Could not find librats shared library. Searched for: {lib_names} "
        f"in paths: {search_paths}"
    )


class LibratsCtypes:
    """Low-level ctypes wrapper for librats C API."""
    
    def __init__(self):
        lib_path = find_librats_library()
        try:
            self.lib = CDLL(lib_path)
        except OSError as e:
            raise LibratsNotFoundError(f"Failed to load librats library at {lib_path}: {e}")
        
        self._setup_function_signatures()
    
    def _setup_function_signatures(self):
        """Set up function signatures for type safety."""
        
        # Memory management
        self.lib.rats_string_free.argtypes = [c_void_p]
        self.lib.rats_string_free.restype = None
        
        # Version functions
        self.lib.rats_get_version_string.argtypes = []
        self.lib.rats_get_version_string.restype = c_void_p
        
        self.lib.rats_get_version.argtypes = [POINTER(c_int), POINTER(c_int), POINTER(c_int), POINTER(c_int)]
        self.lib.rats_get_version.restype = None
        
        self.lib.rats_get_git_describe.argtypes = []
        self.lib.rats_get_git_describe.restype = c_void_p
        
        self.lib.rats_get_abi.argtypes = []
        self.lib.rats_get_abi.restype = c_uint32
        
        # Client lifecycle
        self.lib.rats_create.argtypes = [c_int]
        self.lib.rats_create.restype = c_void_p
        
        self.lib.rats_destroy.argtypes = [c_void_p]
        self.lib.rats_destroy.restype = None
        
        self.lib.rats_start.argtypes = [c_void_p]
        self.lib.rats_start.restype = c_int
        
        self.lib.rats_stop.argtypes = [c_void_p]
        self.lib.rats_stop.restype = None
        
        # Basic operations
        self.lib.rats_connect.argtypes = [c_void_p, c_char_p, c_int]
        self.lib.rats_connect.restype = c_int
        
        self.lib.rats_broadcast_string.argtypes = [c_void_p, c_char_p]
        self.lib.rats_broadcast_string.restype = c_int
        
        self.lib.rats_send_string.argtypes = [c_void_p, c_char_p, c_char_p]
        self.lib.rats_send_string.restype = c_int
        
        # Info functions
        self.lib.rats_get_peer_count.argtypes = [c_void_p]
        self.lib.rats_get_peer_count.restype = c_int
        
        self.lib.rats_get_our_peer_id.argtypes = [c_void_p]
        self.lib.rats_get_our_peer_id.restype = c_void_p
        
        self.lib.rats_get_connection_statistics_json.argtypes = [c_void_p]
        self.lib.rats_get_connection_statistics_json.restype = c_void_p
        
        # Peer configuration
        self.lib.rats_set_max_peers.argtypes = [c_void_p, c_int]
        self.lib.rats_set_max_peers.restype = c_int
        
        self.lib.rats_get_max_peers.argtypes = [c_void_p]
        self.lib.rats_get_max_peers.restype = c_int
        
        self.lib.rats_is_peer_limit_reached.argtypes = [c_void_p]
        self.lib.rats_is_peer_limit_reached.restype = c_int
        
        # Advanced connection methods
        self.lib.rats_connect_with_strategy.argtypes = [c_void_p, c_char_p, c_int, c_int]
        self.lib.rats_connect_with_strategy.restype = c_int
        
        self.lib.rats_disconnect_peer_by_id.argtypes = [c_void_p, c_char_p]
        self.lib.rats_disconnect_peer_by_id.restype = c_int
        
        # Binary data operations
        self.lib.rats_send_binary.argtypes = [c_void_p, c_char_p, c_void_p, c_size_t]
        self.lib.rats_send_binary.restype = c_int
        
        self.lib.rats_broadcast_binary.argtypes = [c_void_p, c_void_p, c_size_t]
        self.lib.rats_broadcast_binary.restype = c_int
        
        # JSON operations
        self.lib.rats_send_json.argtypes = [c_void_p, c_char_p, c_char_p]
        self.lib.rats_send_json.restype = c_int
        
        self.lib.rats_broadcast_json.argtypes = [c_void_p, c_char_p]
        self.lib.rats_broadcast_json.restype = c_int
        
        # DHT Discovery
        self.lib.rats_start_dht_discovery.argtypes = [c_void_p, c_int]
        self.lib.rats_start_dht_discovery.restype = c_int
        
        self.lib.rats_stop_dht_discovery.argtypes = [c_void_p]
        self.lib.rats_stop_dht_discovery.restype = None
        
        self.lib.rats_is_dht_running.argtypes = [c_void_p]
        self.lib.rats_is_dht_running.restype = c_int
        
        # Encryption
        self.lib.rats_set_encryption_enabled.argtypes = [c_void_p, c_int]
        self.lib.rats_set_encryption_enabled.restype = c_int
        
        self.lib.rats_is_encryption_enabled.argtypes = [c_void_p]
        self.lib.rats_is_encryption_enabled.restype = c_int
        
        self.lib.rats_get_encryption_key.argtypes = [c_void_p]
        self.lib.rats_get_encryption_key.restype = c_void_p
        
        self.lib.rats_set_encryption_key.argtypes = [c_void_p, c_char_p]
        self.lib.rats_set_encryption_key.restype = c_int
        
        self.lib.rats_generate_encryption_key.argtypes = [c_void_p]
        self.lib.rats_generate_encryption_key.restype = c_void_p
        
        # File Transfer
        self.lib.rats_send_file.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
        self.lib.rats_send_file.restype = c_void_p
        
        self.lib.rats_accept_file_transfer.argtypes = [c_void_p, c_char_p, c_char_p]
        self.lib.rats_accept_file_transfer.restype = c_int
        
        self.lib.rats_reject_file_transfer.argtypes = [c_void_p, c_char_p, c_char_p]
        self.lib.rats_reject_file_transfer.restype = c_int
        
        self.lib.rats_cancel_file_transfer.argtypes = [c_void_p, c_char_p]
        self.lib.rats_cancel_file_transfer.restype = c_int
        
        # GossipSub
        self.lib.rats_is_gossipsub_available.argtypes = [c_void_p]
        self.lib.rats_is_gossipsub_available.restype = c_int
        
        self.lib.rats_subscribe_to_topic.argtypes = [c_void_p, c_char_p]
        self.lib.rats_subscribe_to_topic.restype = c_int
        
        self.lib.rats_unsubscribe_from_topic.argtypes = [c_void_p, c_char_p]
        self.lib.rats_unsubscribe_from_topic.restype = c_int
        
        self.lib.rats_publish_to_topic.argtypes = [c_void_p, c_char_p, c_char_p]
        self.lib.rats_publish_to_topic.restype = c_int
        
        # Callbacks
        self.lib.rats_set_connection_callback.argtypes = [c_void_p, ConnectionCallbackType, c_void_p]
        self.lib.rats_set_connection_callback.restype = None
        
        self.lib.rats_set_string_callback.argtypes = [c_void_p, StringCallbackType, c_void_p]
        self.lib.rats_set_string_callback.restype = None
        
        self.lib.rats_set_binary_callback.argtypes = [c_void_p, BinaryCallbackType, c_void_p]
        self.lib.rats_set_binary_callback.restype = None
        
        self.lib.rats_set_json_callback.argtypes = [c_void_p, JsonCallbackType, c_void_p]
        self.lib.rats_set_json_callback.restype = None
        
        self.lib.rats_set_disconnect_callback.argtypes = [c_void_p, DisconnectCallbackType, c_void_p]
        self.lib.rats_set_disconnect_callback.restype = None
        
        # Logging
        self.lib.rats_set_logging_enabled.argtypes = [c_int]
        self.lib.rats_set_logging_enabled.restype = None
        
        self.lib.rats_set_log_level.argtypes = [c_char_p]
        self.lib.rats_set_log_level.restype = None


# Global instance
_librats = None

def get_librats() -> LibratsCtypes:
    """Get the global librats ctypes instance."""
    global _librats
    if _librats is None:
        _librats = LibratsCtypes()
    return _librats
