"""
Core RatsClient implementation for Python bindings.
"""

import json
import threading
import weakref
from typing import Optional, List, Dict, Any, Callable
from ctypes import c_void_p, c_char_p, create_string_buffer, byref, cast, c_int, string_at

from .ctypes_wrapper import get_librats
from .enums import RatsError as ErrorCode, ConnectionStrategy, LogLevel
from .exceptions import RatsError, check_error
from .callbacks import *


class RatsClient:
    """
    Python wrapper for the librats C client.
    
    This class provides a high-level Python interface to the librats P2P networking library.
    """
    
    def __init__(self, listen_port: int = 0):
        """
        Initialize a new RatsClient.
        
        Args:
            listen_port: Port to listen on for incoming connections (0 for random)
        """
        self._lib = get_librats()
        self._handle = self._lib.lib.rats_create(listen_port)
        if not self._handle:
            raise RatsError("Failed to create RatsClient")
        
        self._listen_port = listen_port
        self._running = False
        self._callbacks_lock = threading.Lock()
        
        # Store Python callbacks to prevent garbage collection
        self._callbacks = {}
        
        # Store C callback functions
        self._c_callbacks = {}
        
        # Weak reference for cleanup
        self._finalizer = weakref.finalize(self, self._cleanup, self._handle, self._lib)
    
    @staticmethod
    def _cleanup(handle, lib):
        """Cleanup function called when object is garbage collected."""
        if handle:
            lib.lib.rats_destroy(handle)
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
    
    def start(self) -> None:
        """
        Start the RatsClient and begin listening for connections.
        
        Raises:
            RatsError: If starting the client fails
        """
        result = self._lib.lib.rats_start(self._handle)
        check_error(result, "Starting client")
        self._running = True
    
    def stop(self) -> None:
        """Stop the RatsClient and close all connections."""
        if self._handle:
            self._lib.lib.rats_stop(self._handle)
            self._running = False
    
    def is_running(self) -> bool:
        """Check if the client is currently running."""
        return self._running
    
    def connect(self, host: str, port: int, 
                strategy: ConnectionStrategy = ConnectionStrategy.AUTO_ADAPTIVE) -> None:
        """
        Connect to a peer.
        
        Args:
            host: Target host/IP address
            port: Target port
            strategy: Connection strategy to use
            
        Raises:
            RatsError: If connection fails
        """
        host_bytes = host.encode('utf-8')
        result = self._lib.lib.rats_connect_with_strategy(
            self._handle, host_bytes, port, strategy.value
        )
        check_error(result, f"Connecting to {host}:{port}")
    
    def disconnect_peer(self, peer_id: str) -> None:
        """
        Disconnect from a specific peer.
        
        Args:
            peer_id: Peer ID to disconnect
            
        Raises:
            RatsError: If disconnection fails
        """
        peer_id_bytes = peer_id.encode('utf-8')
        result = self._lib.lib.rats_disconnect_peer_by_id(self._handle, peer_id_bytes)
        check_error(result, f"Disconnecting peer {peer_id}")
    
    def send_string(self, peer_id: str, message: str) -> None:
        """
        Send a string message to a specific peer.
        
        Args:
            peer_id: Target peer ID
            message: String message to send
            
        Raises:
            RatsError: If sending fails
        """
        peer_id_bytes = peer_id.encode('utf-8')
        message_bytes = message.encode('utf-8')
        result = self._lib.lib.rats_send_string(self._handle, peer_id_bytes, message_bytes)
        check_error(result, f"Sending string to peer {peer_id}")
    
    def send_binary(self, peer_id: str, data: bytes) -> None:
        """
        Send binary data to a specific peer.
        
        Args:
            peer_id: Target peer ID
            data: Binary data to send
            
        Raises:
            RatsError: If sending fails
        """
        peer_id_bytes = peer_id.encode('utf-8')
        result = self._lib.lib.rats_send_binary(
            self._handle, peer_id_bytes, data, len(data)
        )
        check_error(result, f"Sending binary data to peer {peer_id}")
    
    def send_json(self, peer_id: str, data: Dict[str, Any]) -> None:
        """
        Send JSON data to a specific peer.
        
        Args:
            peer_id: Target peer ID
            data: Dictionary to send as JSON
            
        Raises:
            RatsError: If sending fails
        """
        peer_id_bytes = peer_id.encode('utf-8')
        json_bytes = json.dumps(data).encode('utf-8')
        result = self._lib.lib.rats_send_json(self._handle, peer_id_bytes, json_bytes)
        check_error(result, f"Sending JSON to peer {peer_id}")
    
    def broadcast_string(self, message: str) -> int:
        """
        Broadcast a string message to all connected peers.
        
        Args:
            message: String message to broadcast
            
        Returns:
            Number of peers the message was sent to
        """
        message_bytes = message.encode('utf-8')
        return self._lib.lib.rats_broadcast_string(self._handle, message_bytes)
    
    def broadcast_binary(self, data: bytes) -> int:
        """
        Broadcast binary data to all connected peers.
        
        Args:
            data: Binary data to broadcast
            
        Returns:
            Number of peers the data was sent to
        """
        return self._lib.lib.rats_broadcast_binary(self._handle, data, len(data))
    
    def broadcast_json(self, data: Dict[str, Any]) -> int:
        """
        Broadcast JSON data to all connected peers.
        
        Args:
            data: Dictionary to broadcast as JSON
            
        Returns:
            Number of peers the data was sent to
        """
        json_bytes = json.dumps(data).encode('utf-8')
        return self._lib.lib.rats_broadcast_json(self._handle, json_bytes)
    
    def get_peer_count(self) -> int:
        """Get the number of currently connected peers."""
        return self._lib.lib.rats_get_peer_count(self._handle)
    
    def get_our_peer_id(self) -> str:
        """Get our own peer ID."""
        result = self._lib.lib.rats_get_our_peer_id(self._handle)
        if not result:
            return ""
        peer_id = string_at(result).decode('utf-8')
        self._lib.lib.rats_string_free(result)
        return peer_id
    
    def get_connection_statistics(self) -> Dict[str, Any]:
        """Get connection statistics as a dictionary."""
        result = self._lib.lib.rats_get_connection_statistics_json(self._handle)
        if not result:
            return {}
        
        json_str = string_at(result).decode('utf-8')
        self._lib.lib.rats_string_free(result)
        
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return {}
    
    # Peer configuration
    def set_max_peers(self, max_peers: int) -> None:
        """Set maximum number of peers."""
        result = self._lib.lib.rats_set_max_peers(self._handle, max_peers)
        check_error(result, "Setting max peers")
    
    def get_max_peers(self) -> int:
        """Get maximum number of peers."""
        return self._lib.lib.rats_get_max_peers(self._handle)
    
    def is_peer_limit_reached(self) -> bool:
        """Check if peer limit has been reached."""
        return bool(self._lib.lib.rats_is_peer_limit_reached(self._handle))
    
    # DHT Discovery
    def start_dht_discovery(self, dht_port: int = 6881) -> None:
        """Start DHT discovery."""
        result = self._lib.lib.rats_start_dht_discovery(self._handle, dht_port)
        check_error(result, "Starting DHT discovery")
    
    def stop_dht_discovery(self) -> None:
        """Stop DHT discovery."""
        self._lib.lib.rats_stop_dht_discovery(self._handle)
    
    def is_dht_running(self) -> bool:
        """Check if DHT is running."""
        return bool(self._lib.lib.rats_is_dht_running(self._handle))
    
    # Encryption
    def set_encryption_enabled(self, enabled: bool) -> None:
        """Enable or disable encryption."""
        result = self._lib.lib.rats_set_encryption_enabled(self._handle, int(enabled))
        check_error(result, "Setting encryption")
    
    def is_encryption_enabled(self) -> bool:
        """Check if encryption is enabled."""
        return bool(self._lib.lib.rats_is_encryption_enabled(self._handle))
    
    def get_encryption_key(self) -> str:
        """Get the encryption key as hex string."""
        result = self._lib.lib.rats_get_encryption_key(self._handle)
        if not result:
            return ""
        key = string_at(result).decode('utf-8')
        self._lib.lib.rats_string_free(result)
        return key
    
    def set_encryption_key(self, key_hex: str) -> None:
        """Set encryption key from hex string."""
        key_bytes = key_hex.encode('utf-8')
        result = self._lib.lib.rats_set_encryption_key(self._handle, key_bytes)
        check_error(result, "Setting encryption key")
    
    def generate_encryption_key(self) -> str:
        """Generate a new encryption key."""
        result = self._lib.lib.rats_generate_encryption_key(self._handle)
        if not result:
            return ""
        key = string_at(result).decode('utf-8')
        self._lib.lib.rats_string_free(result)
        return key
    
    # File Transfer
    def send_file(self, peer_id: str, file_path: str, 
                  remote_filename: Optional[str] = None) -> str:
        """
        Send a file to a peer.
        
        Args:
            peer_id: Target peer ID
            file_path: Local file path to send
            remote_filename: Optional remote filename
            
        Returns:
            Transfer ID if successful
            
        Raises:
            RatsError: If sending fails
        """
        peer_id_bytes = peer_id.encode('utf-8')
        file_path_bytes = file_path.encode('utf-8')
        remote_filename_bytes = (remote_filename or "").encode('utf-8')
        
        result = self._lib.lib.rats_send_file(
            self._handle, peer_id_bytes, file_path_bytes, remote_filename_bytes
        )
        
        if not result:
            raise RatsError(f"Failed to send file {file_path} to peer {peer_id}")
        
        transfer_id = string_at(result).decode('utf-8')
        self._lib.lib.rats_string_free(result)
        return transfer_id
    
    def accept_file_transfer(self, transfer_id: str, local_path: str) -> None:
        """Accept an incoming file transfer."""
        transfer_id_bytes = transfer_id.encode('utf-8')
        local_path_bytes = local_path.encode('utf-8')
        result = self._lib.lib.rats_accept_file_transfer(
            self._handle, transfer_id_bytes, local_path_bytes
        )
        check_error(result, f"Accepting file transfer {transfer_id}")
    
    def reject_file_transfer(self, transfer_id: str, reason: str = "") -> None:
        """Reject an incoming file transfer."""
        transfer_id_bytes = transfer_id.encode('utf-8')
        reason_bytes = reason.encode('utf-8')
        result = self._lib.lib.rats_reject_file_transfer(
            self._handle, transfer_id_bytes, reason_bytes
        )
        check_error(result, f"Rejecting file transfer {transfer_id}")
    
    def cancel_file_transfer(self, transfer_id: str) -> None:
        """Cancel an active file transfer."""
        transfer_id_bytes = transfer_id.encode('utf-8')
        result = self._lib.lib.rats_cancel_file_transfer(self._handle, transfer_id_bytes)
        check_error(result, f"Cancelling file transfer {transfer_id}")
    
    # GossipSub
    def is_gossipsub_available(self) -> bool:
        """Check if GossipSub is available."""
        return bool(self._lib.lib.rats_is_gossipsub_available(self._handle))
    
    def subscribe_to_topic(self, topic: str) -> None:
        """Subscribe to a GossipSub topic."""
        topic_bytes = topic.encode('utf-8')
        result = self._lib.lib.rats_subscribe_to_topic(self._handle, topic_bytes)
        check_error(result, f"Subscribing to topic {topic}")
    
    def unsubscribe_from_topic(self, topic: str) -> None:
        """Unsubscribe from a GossipSub topic."""
        topic_bytes = topic.encode('utf-8')
        result = self._lib.lib.rats_unsubscribe_from_topic(self._handle, topic_bytes)
        check_error(result, f"Unsubscribing from topic {topic}")
    
    def publish_to_topic(self, topic: str, message: str) -> None:
        """Publish a message to a GossipSub topic."""
        topic_bytes = topic.encode('utf-8')
        message_bytes = message.encode('utf-8')
        result = self._lib.lib.rats_publish_to_topic(self._handle, topic_bytes, message_bytes)
        check_error(result, f"Publishing to topic {topic}")
    
    # Callback management
    def _create_connection_callback(self, callback: ConnectionCallback):
        """Create a C callback wrapper for connection events."""
        def c_callback(user_data, peer_id_ptr):
            if callback and peer_id_ptr:
                peer_id = peer_id_ptr.decode('utf-8')
                try:
                    callback(peer_id)
                except Exception as e:
                    print(f"Error in connection callback: {e}")
        return ConnectionCallbackType(c_callback)
    
    def _create_string_callback(self, callback: StringCallback):
        """Create a C callback wrapper for string messages."""
        def c_callback(user_data, peer_id_ptr, message_ptr):
            if callback and peer_id_ptr and message_ptr:
                peer_id = peer_id_ptr.decode('utf-8')
                message = message_ptr.decode('utf-8')
                try:
                    callback(peer_id, message)
                except Exception as e:
                    print(f"Error in string callback: {e}")
        return StringCallbackType(c_callback)
    
    def _create_binary_callback(self, callback: BinaryCallback):
        """Create a C callback wrapper for binary data."""
        def c_callback(user_data, peer_id_ptr, data_ptr, size):
            if callback and peer_id_ptr and data_ptr and size:
                peer_id = peer_id_ptr.decode('utf-8')
                data_bytes = string_at(data_ptr, size)
                try:
                    callback(peer_id, data_bytes)
                except Exception as e:
                    print(f"Error in binary callback: {e}")
        return BinaryCallbackType(c_callback)
    
    def _create_json_callback(self, callback: JsonCallback):
        """Create a C callback wrapper for JSON messages."""
        def c_callback(user_data, peer_id_ptr, json_ptr):
            if callback and peer_id_ptr and json_ptr:
                peer_id = peer_id_ptr.decode('utf-8')
                json_str = json_ptr.decode('utf-8')
                try:
                    data = json.loads(json_str)
                    callback(peer_id, data)
                except (json.JSONDecodeError, Exception) as e:
                    print(f"Error in JSON callback: {e}")
        return JsonCallbackType(c_callback)
    
    def _create_disconnect_callback(self, callback: DisconnectCallback):
        """Create a C callback wrapper for disconnect events."""
        def c_callback(user_data, peer_id_ptr):
            if callback and peer_id_ptr:
                peer_id = peer_id_ptr.decode('utf-8')
                try:
                    callback(peer_id)
                except Exception as e:
                    print(f"Error in disconnect callback: {e}")
        return DisconnectCallbackType(c_callback)
    
    def set_connection_callback(self, callback: ConnectionCallback) -> None:
        """Set callback for new peer connections."""
        with self._callbacks_lock:
            self._callbacks['connection'] = callback
            if callback:
                c_callback = self._create_connection_callback(callback)
                self._c_callbacks['connection'] = c_callback
                self._lib.lib.rats_set_connection_callback(self._handle, c_callback, None)
            else:
                self._lib.lib.rats_set_connection_callback(self._handle, None, None)
    
    def set_string_callback(self, callback: StringCallback) -> None:
        """Set callback for string messages."""
        with self._callbacks_lock:
            self._callbacks['string'] = callback
            if callback:
                c_callback = self._create_string_callback(callback)
                self._c_callbacks['string'] = c_callback
                self._lib.lib.rats_set_string_callback(self._handle, c_callback, None)
            else:
                self._lib.lib.rats_set_string_callback(self._handle, None, None)
    
    def set_binary_callback(self, callback: BinaryCallback) -> None:
        """Set callback for binary data."""
        with self._callbacks_lock:
            self._callbacks['binary'] = callback
            if callback:
                c_callback = self._create_binary_callback(callback)
                self._c_callbacks['binary'] = c_callback
                self._lib.lib.rats_set_binary_callback(self._handle, c_callback, None)
            else:
                self._lib.lib.rats_set_binary_callback(self._handle, None, None)
    
    def set_json_callback(self, callback: JsonCallback) -> None:
        """Set callback for JSON messages."""
        with self._callbacks_lock:
            self._callbacks['json'] = callback
            if callback:
                c_callback = self._create_json_callback(callback)
                self._c_callbacks['json'] = c_callback
                self._lib.lib.rats_set_json_callback(self._handle, c_callback, None)
            else:
                self._lib.lib.rats_set_json_callback(self._handle, None, None)
    
    def set_disconnect_callback(self, callback: DisconnectCallback) -> None:
        """Set callback for peer disconnections."""
        with self._callbacks_lock:
            self._callbacks['disconnect'] = callback
            if callback:
                c_callback = self._create_disconnect_callback(callback)
                self._c_callbacks['disconnect'] = c_callback
                self._lib.lib.rats_set_disconnect_callback(self._handle, c_callback, None)
            else:
                self._lib.lib.rats_set_disconnect_callback(self._handle, None, None)
    
    # Static logging methods
    @staticmethod
    def set_logging_enabled(enabled: bool) -> None:
        """Enable or disable global logging."""
        lib = get_librats()
        lib.lib.rats_set_logging_enabled(int(enabled))
    
    @staticmethod
    def set_log_level(level: LogLevel) -> None:
        """Set global log level."""
        lib = get_librats()
        level_str = level.name.encode('utf-8')
        lib.lib.rats_set_log_level(level_str)


# The RatsError exception is imported from exceptions module in __init__.py
