"""
High-level :class:`RatsClient` over the librats C ABI (``src/bindings/rats.h``).

A :class:`RatsClient` wraps a single ``rats_t`` node. The lifecycle mirrors the
C contract:

* Register callbacks and enable subsystems **before** :meth:`start`.
  Enabling a subsystem after start raises :class:`RatsAlreadyStartedError`;
  calling a subsystem op before its enable raises :class:`RatsNotEnabledError`.
* Callbacks fire on an internal reactor thread — do not block in them. The
  wrappers here swallow Python exceptions so they never propagate into C.
* All ``CFUNCTYPE`` callback objects are retained on the instance for the
  node's lifetime so they are not garbage-collected while C holds a pointer.
"""

import json
import threading
import weakref
from typing import Any, Dict, List, Optional

from ctypes import byref, c_size_t, c_int, string_at

from .ctypes_wrapper import get_librats, take_string, RatsConfig
from .enums import RatsError as ErrorCode, Security, LogLevel, VersionInfo
from .exceptions import RatsError, RatsConnectionError, check_error
from .callbacks import (
    PeerCallback, MessageCallback, TopicCallback, JsonCallback,
    FileOfferCallback, FileProgressCallback, FileCompleteCallback,
    PeerCallbackType, MessageCallbackType, TopicCallbackType, JsonCallbackType,
    FileOfferCallbackType, FileProgressCallbackType, FileCompleteCallbackType,
)


def _b(s: Optional[str]) -> Optional[bytes]:
    """Encode an optional ``str`` to UTF-8 bytes (``None`` stays ``None``)."""
    return s.encode('utf-8') if s is not None else None


class RatsClient:
    """Pythonic wrapper around a librats node (``rats_t``)."""

    def __init__(
        self,
        listen_port: int = 0,
        *,
        enable_listen: bool = True,
        bind_address: Optional[str] = None,
        security: Security = Security.NOISE,
        data_dir: Optional[str] = None,
        protocol: Optional[str] = None,
        max_peers: int = 0,
    ):
        """Create a node.

        Args:
            listen_port: Inbound TCP port (0 = ephemeral).
            enable_listen: ``False`` makes a dial-only node (no listener).
            bind_address: Bind address; ``None`` → ``"::"`` dual-stack wildcard.
            security: :class:`~librats_py.enums.Security` mode (default Noise).
            data_dir: Persistent state dir; ``None``/"" → ephemeral identity.
            protocol: Handshake app id, e.g. ``"myapp/1.0"``; ``None`` →
                ``"librats/1.0"``. Peers whose protocol differs cannot connect.
            max_peers: Established-peer cap (0 = unlimited).
        """
        self._lib = get_librats()

        cfg: RatsConfig = self._lib.config_default()
        cfg.listen_port = listen_port
        cfg.enable_listen = 1 if enable_listen else 0
        cfg.security = int(security)
        cfg.max_peers = max_peers
        # Keep bytes alive for the duration of the create call.
        self._cfg_keepalive = [
            _b(bind_address), _b(data_dir), _b(protocol),
        ]
        if bind_address is not None:
            cfg.bind_address = self._cfg_keepalive[0]
        if data_dir is not None:
            cfg.data_dir = self._cfg_keepalive[1]
        if protocol is not None:
            cfg.protocol = self._cfg_keepalive[2]

        self._handle = self._lib.lib.rats_create_config(byref(cfg))
        if not self._handle:
            raise RatsError("Failed to create RatsClient node")

        self._running = False
        self._lock = threading.Lock()

        # Retain every CFUNCTYPE object so the GC cannot collect it while the
        # native side still holds the pointer. Keys are stable per-slot.
        self._c_callbacks: Dict[str, Any] = {}

        self._finalizer = weakref.finalize(
            self, self._cleanup, self._handle, self._lib)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    @staticmethod
    def _cleanup(handle, lib):
        if handle:
            lib.lib.rats_destroy(handle)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

    def start(self) -> None:
        """Start the node. Raises on bind failure or if already started."""
        check_error(self._lib.lib.rats_start(self._handle), "Starting node")
        self._running = True

    def stop(self) -> None:
        """Stop the node and close all connections (idempotent)."""
        if self._handle and self._running:
            self._lib.lib.rats_stop(self._handle)
            self._running = False

    def is_running(self) -> bool:
        """Return whether :meth:`start` has been called and not stopped."""
        return self._running

    def destroy(self) -> None:
        """Explicitly destroy the node (otherwise destroyed on GC)."""
        self._finalizer()
        self._handle = None

    # ------------------------------------------------------------------ #
    # Identity / info
    # ------------------------------------------------------------------ #
    @property
    def listen_port(self) -> int:
        """The actual port the node is listening on."""
        return self._lib.lib.rats_listen_port(self._handle)

    def get_listen_port(self) -> int:
        return self.listen_port

    @property
    def local_id(self) -> str:
        """Our self-certifying peer id (64-char lowercase hex)."""
        return take_string(self._lib, self._lib.lib.rats_local_id(self._handle))

    def get_local_id(self) -> str:
        return self.local_id

    @property
    def protocol(self) -> str:
        """Application protocol id bound into the handshake (e.g. ``"librats/1.0"``)."""
        return take_string(self._lib, self._lib.lib.rats_protocol(self._handle))

    # ------------------------------------------------------------------ #
    # Connections / peers
    # ------------------------------------------------------------------ #
    def connect(self, host: str, port: int) -> None:
        """Dial a peer at ``host:port`` (best-effort; queued)."""
        check_error(
            self._lib.lib.rats_connect(self._handle, _b(host), port),
            f"Connecting to {host}:{port}")

    def peer_count(self) -> int:
        """Number of currently-connected peers."""
        return self._lib.lib.rats_peer_count(self._handle)

    def get_peer_count(self) -> int:
        return self.peer_count()

    def set_max_peers(self, max_peers: int) -> None:
        """Set the established-peer cap (0 = unlimited)."""
        self._lib.lib.rats_set_max_peers(self._handle, max_peers)

    def get_max_peers(self) -> int:
        """Get the established-peer cap."""
        return self._lib.lib.rats_max_peers(self._handle)

    def peer_ids(self) -> List[str]:
        """Hex ids of currently-connected peers."""
        count = c_size_t()
        arr = self._lib.lib.rats_peer_ids(self._handle, byref(count))
        if not arr or count.value == 0:
            return []
        try:
            result = []
            for i in range(count.value):
                ptr = arr[i]
                if ptr:
                    result.append(string_at(ptr).decode('utf-8', errors='replace'))
            return result
        finally:
            self._lib.lib.rats_free_peer_ids(arr, count.value)

    def get_peer_ids(self) -> List[str]:
        return self.peer_ids()

    # ------------------------------------------------------------------ #
    # Raw channel messaging
    # ------------------------------------------------------------------ #
    def send(self, peer_id: str, channel: str, data: bytes) -> None:
        """Send raw ``data`` on a named ``channel`` to one peer."""
        check_error(
            self._lib.lib.rats_send(self._handle, _b(peer_id), _b(channel),
                                    data, len(data)),
            f"Sending on channel {channel} to {peer_id}")

    def broadcast(self, channel: str, data: bytes) -> None:
        """Broadcast raw ``data`` on a named ``channel`` to all peers."""
        check_error(
            self._lib.lib.rats_broadcast(self._handle, _b(channel), data, len(data)),
            f"Broadcasting on channel {channel}")

    def on(self, channel: str, callback: MessageCallback) -> None:
        """Register a handler for raw messages on ``channel``.

        ``callback(peer_id: str, data: bytes)``. Register before :meth:`start`.
        """
        def trampoline(user, peer_id_ptr, data_ptr, length):
            try:
                peer_id = peer_id_ptr.decode('utf-8') if peer_id_ptr else ""
                data = string_at(data_ptr, length) if (data_ptr and length) else b""
                callback(peer_id, data)
            except Exception as exc:  # never propagate into C
                _report(exc, "message callback")
        c_cb = MessageCallbackType(trampoline)
        self._c_callbacks[f"on:{channel}"] = c_cb
        check_error(
            self._lib.lib.rats_on(self._handle, _b(channel), c_cb, None),
            f"Registering channel handler {channel}")

    # ------------------------------------------------------------------ #
    # Peer connect / disconnect events
    # ------------------------------------------------------------------ #
    def on_peer_connected(self, callback: PeerCallback) -> None:
        """Register a ``callback(peer_id: str)`` for new peer connections."""
        self._register_peer_cb("connected", "rats_on_peer_connected", callback)

    def on_peer_disconnected(self, callback: PeerCallback) -> None:
        """Register a ``callback(peer_id: str)`` for peer disconnections."""
        self._register_peer_cb("disconnected", "rats_on_peer_disconnected", callback)

    def _register_peer_cb(self, slot: str, c_func_name: str, callback: PeerCallback):
        def trampoline(user, peer_id_ptr):
            try:
                callback(peer_id_ptr.decode('utf-8') if peer_id_ptr else "")
            except Exception as exc:
                _report(exc, f"peer {slot} callback")
        c_cb = PeerCallbackType(trampoline)
        self._c_callbacks[f"peer:{slot}"] = c_cb
        check_error(
            getattr(self._lib.lib, c_func_name)(self._handle, c_cb, None),
            f"Registering peer {slot} handler")

    # ------------------------------------------------------------------ #
    # Discovery / port mapping subsystems (enable before start)
    # ------------------------------------------------------------------ #
    def enable_dht(self, dht_port: int = 0, discovery_key: Optional[str] = None) -> None:
        """Enable DHT discovery. ``dht_port`` 0 = ephemeral."""
        check_error(
            self._lib.lib.rats_enable_dht(self._handle, dht_port, _b(discovery_key)),
            "Enabling DHT")

    def enable_mdns(self) -> None:
        """Enable local-network mDNS discovery."""
        check_error(self._lib.lib.rats_enable_mdns(self._handle), "Enabling mDNS")

    def enable_port_mapping(self, enable_upnp: bool = True,
                            enable_natpmp: bool = True) -> None:
        """Enable automatic NAT port forwarding (UPnP IGD + NAT-PMP)."""
        check_error(
            self._lib.lib.rats_enable_port_mapping(
                self._handle, 1 if enable_upnp else 0, 1 if enable_natpmp else 0),
            "Enabling port mapping")

    # ------------------------------------------------------------------ #
    # Pub/sub (GossipSub)
    # ------------------------------------------------------------------ #
    def enable_pubsub(self) -> None:
        """Enable the pub/sub (GossipSub) subsystem. Call before start()."""
        check_error(self._lib.lib.rats_enable_pubsub(self._handle), "Enabling pubsub")

    def subscribe(self, topic: str, callback: TopicCallback) -> None:
        """Subscribe to ``topic``; ``callback(peer_id, topic, data: bytes)``."""
        def trampoline(user, peer_id_ptr, topic_ptr, data_ptr, length):
            try:
                peer_id = peer_id_ptr.decode('utf-8') if peer_id_ptr else ""
                top = topic_ptr.decode('utf-8') if topic_ptr else ""
                data = string_at(data_ptr, length) if (data_ptr and length) else b""
                callback(peer_id, top, data)
            except Exception as exc:
                _report(exc, "topic callback")
        c_cb = TopicCallbackType(trampoline)
        self._c_callbacks[f"sub:{topic}"] = c_cb
        check_error(
            self._lib.lib.rats_subscribe(self._handle, _b(topic), c_cb, None),
            f"Subscribing to {topic}")

    def unsubscribe(self, topic: str) -> None:
        """Unsubscribe from ``topic``."""
        check_error(
            self._lib.lib.rats_unsubscribe(self._handle, _b(topic)),
            f"Unsubscribing from {topic}")
        self._c_callbacks.pop(f"sub:{topic}", None)

    def publish(self, topic: str, data: bytes) -> None:
        """Publish raw ``data`` to ``topic``."""
        check_error(
            self._lib.lib.rats_publish(self._handle, _b(topic), data, len(data)),
            f"Publishing to {topic}")

    # ------------------------------------------------------------------ #
    # Typed JSON messaging
    # ------------------------------------------------------------------ #
    def enable_json(self) -> None:
        """Enable the typed JSON messaging subsystem. Call before start()."""
        check_error(self._lib.lib.rats_enable_json(self._handle), "Enabling JSON")

    def on_json(self, type_name: str, callback: JsonCallback) -> None:
        """Register a handler for JSON messages of ``type_name``.

        ``callback(peer_id: str, payload)`` where ``payload`` is parsed JSON.
        Additive: multiple handlers may coexist for a type.
        """
        self._register_json_cb("rats_on_json", type_name, callback, once=False)

    def once_json(self, type_name: str, callback: JsonCallback) -> None:
        """Like :meth:`on_json` but the handler fires at most once."""
        self._register_json_cb("rats_once_json", type_name, callback, once=True)

    def off_json(self, type_name: str) -> None:
        """Remove JSON handlers for ``type_name``."""
        check_error(
            self._lib.lib.rats_off_json(self._handle, _b(type_name)),
            f"Removing JSON handler {type_name}")
        # Drop any retained trampolines for this type.
        for key in [k for k in self._c_callbacks
                    if k.startswith(f"json:{type_name}:")]:
            self._c_callbacks.pop(key, None)

    def _register_json_cb(self, c_func_name, type_name, callback, once):
        def trampoline(user, peer_id_ptr, json_ptr):
            try:
                peer_id = peer_id_ptr.decode('utf-8') if peer_id_ptr else ""
                payload = None
                if json_ptr:
                    text = json_ptr.decode('utf-8')
                    payload = json.loads(text) if text else None
                callback(peer_id, payload)
            except Exception as exc:
                _report(exc, "json callback")
        c_cb = JsonCallbackType(trampoline)
        # Additive registration: use a unique key so multiple handlers survive.
        key = f"json:{type_name}:{id(callback)}"
        self._c_callbacks[key] = c_cb
        check_error(
            getattr(self._lib.lib, c_func_name)(self._handle, _b(type_name), c_cb, None),
            f"Registering JSON handler {type_name}")

    def send_json(self, peer_id: str, type_name: str, payload: Any) -> None:
        """Send a typed JSON message to one peer. ``payload`` is JSON-encoded."""
        text = payload if isinstance(payload, str) else json.dumps(payload)
        check_error(
            self._lib.lib.rats_send_json(self._handle, _b(peer_id),
                                         _b(type_name), _b(text)),
            f"Sending JSON {type_name} to {peer_id}")

    def broadcast_json(self, type_name: str, payload: Any) -> None:
        """Broadcast a typed JSON message to all peers."""
        text = payload if isinstance(payload, str) else json.dumps(payload)
        check_error(
            self._lib.lib.rats_broadcast_json(self._handle, _b(type_name), _b(text)),
            f"Broadcasting JSON {type_name}")

    # ------------------------------------------------------------------ #
    # File transfer
    # ------------------------------------------------------------------ #
    def enable_file_transfer(self, temp_dir: Optional[str] = None) -> None:
        """Enable the file-transfer subsystem. ``temp_dir`` holds partials."""
        check_error(
            self._lib.lib.rats_enable_file_transfer(self._handle, _b(temp_dir)),
            "Enabling file transfer")

    def on_file_offer(self, callback: FileOfferCallback) -> None:
        """Register an incoming-offer handler.

        ``callback(peer_id, transfer_id, name, size, is_directory)``. Respond
        with :meth:`accept_file` or :meth:`reject_file`.
        """
        def trampoline(user, peer_id_ptr, transfer_id, name_ptr, size, is_dir):
            try:
                peer_id = peer_id_ptr.decode('utf-8') if peer_id_ptr else ""
                name = name_ptr.decode('utf-8') if name_ptr else ""
                callback(peer_id, int(transfer_id), name, int(size), bool(is_dir))
            except Exception as exc:
                _report(exc, "file offer callback")
        c_cb = FileOfferCallbackType(trampoline)
        self._c_callbacks["file:offer"] = c_cb
        check_error(
            self._lib.lib.rats_on_file_offer(self._handle, c_cb, None),
            "Registering file offer handler")

    def on_file_progress(self, callback: FileProgressCallback) -> None:
        """Register a progress handler.

        ``callback(transfer_id, peer_id, bytes_transferred, total_bytes, status)``
        where ``status`` is a :class:`~librats_py.enums.FileTransferStatus`.
        """
        def trampoline(user, transfer_id, peer_id_ptr, done, total, status):
            try:
                peer_id = peer_id_ptr.decode('utf-8') if peer_id_ptr else ""
                callback(int(transfer_id), peer_id, int(done), int(total), int(status))
            except Exception as exc:
                _report(exc, "file progress callback")
        c_cb = FileProgressCallbackType(trampoline)
        self._c_callbacks["file:progress"] = c_cb
        check_error(
            self._lib.lib.rats_on_file_progress(self._handle, c_cb, None),
            "Registering file progress handler")

    def on_file_complete(self, callback: FileCompleteCallback) -> None:
        """Register a completion handler ``callback(transfer_id, success, path)``."""
        def trampoline(user, transfer_id, success, path_ptr):
            try:
                path = path_ptr.decode('utf-8') if path_ptr else ""
                callback(int(transfer_id), bool(success), path)
            except Exception as exc:
                _report(exc, "file complete callback")
        c_cb = FileCompleteCallbackType(trampoline)
        self._c_callbacks["file:complete"] = c_cb
        check_error(
            self._lib.lib.rats_on_file_complete(self._handle, c_cb, None),
            "Registering file complete handler")

    def send_file(self, peer_id: str, path: str) -> int:
        """Offer a file to ``peer_id``. Returns the transfer id (0 on failure)."""
        transfer_id = self._lib.lib.rats_send_file(self._handle, _b(peer_id), _b(path))
        if transfer_id == 0:
            raise RatsError(f"Failed to send file {path} to {peer_id}",
                            ErrorCode.NO_SUCH_PEER)
        return int(transfer_id)

    def send_directory(self, peer_id: str, dir_path: str) -> int:
        """Offer a directory tree to ``peer_id``. Returns the transfer id."""
        transfer_id = self._lib.lib.rats_send_directory(
            self._handle, _b(peer_id), _b(dir_path))
        if transfer_id == 0:
            raise RatsError(f"Failed to send directory {dir_path} to {peer_id}",
                            ErrorCode.NO_SUCH_PEER)
        return int(transfer_id)

    def accept_file(self, peer_id: str, transfer_id: int, dest_path: str) -> None:
        """Accept an offered transfer, writing to ``dest_path``."""
        check_error(
            self._lib.lib.rats_accept_file(self._handle, _b(peer_id),
                                           transfer_id, _b(dest_path)),
            f"Accepting transfer {transfer_id}")

    def reject_file(self, peer_id: str, transfer_id: int) -> None:
        """Reject an offered transfer."""
        check_error(
            self._lib.lib.rats_reject_file(self._handle, _b(peer_id), transfer_id),
            f"Rejecting transfer {transfer_id}")

    def cancel_file(self, peer_id: str, transfer_id: int) -> None:
        """Cancel a live transfer (either side)."""
        check_error(
            self._lib.lib.rats_cancel_file(self._handle, _b(peer_id), transfer_id),
            f"Cancelling transfer {transfer_id}")

    def pause_file(self, peer_id: str, transfer_id: int) -> None:
        """Pause a live transfer."""
        check_error(
            self._lib.lib.rats_pause_file(self._handle, _b(peer_id), transfer_id),
            f"Pausing transfer {transfer_id}")

    def resume_file(self, peer_id: str, transfer_id: int) -> None:
        """Resume a paused transfer."""
        check_error(
            self._lib.lib.rats_resume_file(self._handle, _b(peer_id), transfer_id),
            f"Resuming transfer {transfer_id}")

    # ------------------------------------------------------------------ #
    # Liveness (ping/RTT)
    # ------------------------------------------------------------------ #
    def enable_ping(self) -> None:
        """Enable periodic ping/pong RTT probing. Call before start()."""
        check_error(self._lib.lib.rats_enable_ping(self._handle), "Enabling ping")

    def peer_rtt_ms(self, peer_id: str) -> int:
        """Last measured RTT to a peer in ms, or -1 if unknown."""
        return int(self._lib.lib.rats_peer_rtt_ms(self._handle, _b(peer_id)))

    # ------------------------------------------------------------------ #
    # Automatic reconnection
    # ------------------------------------------------------------------ #
    def enable_reconnect(self) -> None:
        """Enable the reconnection subsystem. Call before start()."""
        check_error(self._lib.lib.rats_enable_reconnect(self._handle),
                    "Enabling reconnect")

    def add_reconnect(self, host: str, port: int) -> None:
        """Keep ``host:port`` connected (re-dialed on drop)."""
        check_error(
            self._lib.lib.rats_add_reconnect(self._handle, _b(host), port),
            f"Adding reconnect target {host}:{port}")

    def remove_reconnect(self, host: str, port: int) -> None:
        """Stop reconnecting to ``host:port``."""
        check_error(
            self._lib.lib.rats_remove_reconnect(self._handle, _b(host), port),
            f"Removing reconnect target {host}:{port}")

    # ------------------------------------------------------------------ #
    # Logging (process-global)
    # ------------------------------------------------------------------ #
    @staticmethod
    def set_log_level(level: LogLevel) -> None:
        """Set the process-global log verbosity."""
        get_librats().lib.rats_set_log_level(int(level))

    @staticmethod
    def set_log_file(path: Optional[str]) -> None:
        """Mirror logs to ``path`` (``None``/"" disables file logging)."""
        get_librats().lib.rats_set_log_file(_b(path))

    # ------------------------------------------------------------------ #
    # Library info (process-global)
    # ------------------------------------------------------------------ #
    @staticmethod
    def get_version_string() -> str:
        """Library version string, e.g. ``"1.2.3"`` (static; not freed)."""
        ptr = get_librats().lib.rats_version_string()
        return ptr.decode('utf-8') if ptr else ""

    @staticmethod
    def get_version() -> VersionInfo:
        """Detailed library version components."""
        lib = get_librats()
        major, minor, patch, build = c_int(), c_int(), c_int(), c_int()
        lib.lib.rats_version(byref(major), byref(minor), byref(patch), byref(build))
        return VersionInfo(major.value, minor.value, patch.value, build.value)

    @staticmethod
    def get_git_describe() -> str:
        """Git describe of the build (static; not freed)."""
        ptr = get_librats().lib.rats_git_describe()
        return ptr.decode('utf-8') if ptr else ""

    @staticmethod
    def get_abi() -> int:
        """Packed ABI id ``(major<<16)|(minor<<8)|patch``."""
        return get_librats().lib.rats_abi()

    @staticmethod
    def error_str(error_code: int) -> str:
        """Static human-readable name for a ``rats_error_t`` code."""
        ptr = get_librats().lib.rats_error_str(int(error_code))
        return ptr.decode('utf-8') if ptr else ""


def _report(exc: Exception, where: str) -> None:
    """Log an exception raised inside a reactor-thread callback (never reraise)."""
    import sys
    print(f"[librats_py] error in {where}: {exc!r}", file=sys.stderr)
