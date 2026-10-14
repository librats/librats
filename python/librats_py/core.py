"""
:class:`RatsNode` — one librats node, over the C ABI (``src/librats/bindings/rats.h``).

On its own a node is secure transport plus raw messaging on named channels;
discovery, NAT traversal, pub/sub, JSON messaging, file transfer, ping and
reconnection are subsystems enabled before :meth:`RatsNode.start`.

Callbacks run on a librats reactor thread. Each one is wrapped so that an
exception raised in it is printed to stderr instead of unwinding into C, and
every ``CFUNCTYPE`` object is kept for the node's lifetime: the C side may hold
the pointer until the node is destroyed.
"""

import json
import sys
import weakref
from ctypes import byref, c_int, c_size_t, c_uint64, string_at
from typing import Any, Callable, List, Optional

from .ctypes_wrapper import (
    RatsBtConfig, RatsConfig, RatsFileProgress, RatsPathStats, RatsPeerInfo, get_librats,
)
from .enums import (
    BtEncryption, CloseReason, Congestion, Direction, FileProgress, FileTransferStatus,
    LogLevel, NatMapping, PathStats, PeerInfo, RatsError as ErrorCode, Security, Transport,
    TransportMask, VersionInfo,
)
from .exceptions import RatsError, RatsInvalidArgError, check_error
from .callbacks import (
    DialFailedCallback, DialFailedCallbackType, DisconnectCallback, DisconnectCallbackType,
    FileCompleteCallback, FileCompleteCallbackType, FileOfferCallback, FileOfferCallbackType,
    FileProgressCallback, FileProgressCallbackType, JsonCallback, JsonCallbackType,
    MessageCallback, MessageCallbackType, PathCallback, PathCallbackType, PeerCallback,
    PeerCallbackType, TopicCallback, TopicCallbackType,
)


def _b(s: Optional[str]) -> Optional[bytes]:
    return s.encode('utf-8') if s is not None else None


def _s(b: Optional[bytes]) -> str:
    return b.decode('utf-8', errors='replace') if b else ""


def _bytes(ptr, length: int) -> bytes:
    return string_at(ptr, length) if ptr and length else b""


def _report(exc: BaseException, where: str) -> None:
    print(f"[librats_py] exception in {where} callback: {exc!r}", file=sys.stderr)


def _guard(where: str, fn: Callable) -> Callable:
    """Wrap a trampoline so a Python exception never unwinds into C."""
    def call(*args):
        try:
            fn(*args)
        except BaseException as exc:  # noqa: B902 — nothing may cross into C
            _report(exc, where)
    return call


def _path_stats(c: RatsPathStats) -> PathStats:
    return PathStats(
        bandwidth_bps=c.bandwidth_bps, app_limited=bool(c.app_limited),
        pacing_bps=c.pacing_bps, srtt_us=c.srtt_us, min_rtt_us=c.min_rtt_us,
        queued_bytes=c.queued_bytes, bytes_in_flight=c.bytes_in_flight, loss=c.loss,
        bytes_delivered=c.bytes_delivered, bytes_lost=c.bytes_lost,
        live_sent=c.live_sent, live_expired=c.live_expired,
        live_repair_bytes=c.live_repair_bytes)


def _string_list(lib, fn, handle) -> List[str]:
    count = c_size_t()
    arr = fn(handle, byref(count))
    if not arr:
        return []
    try:
        return [_s(arr[i]) for i in range(count.value)]
    finally:
        lib.rats_strings_free(arr, count.value)


class RatsNode:
    """A librats node.

    Every keyword maps to a ``rats_config_t`` field; leaving one out keeps the
    library default. Use it as a context manager to have it destroyed on exit::

        with RatsNode(8080, protocol="myapp/1.0") as node:
            node.on("chat", lambda peer, data: print(peer, data))
            node.start()
    """

    def __init__(
        self,
        listen_port: int = 0,
        *,
        protocol: Optional[str] = None,
        data_dir: Optional[str] = None,
        security: Security = Security.NOISE,
        bind_address: Optional[str] = None,
        dial_only: bool = False,
        max_peers: int = 0,
        transports: TransportMask = TransportMask.NONE,
        preferred_transport: Transport = Transport.UDP,
        transport_fallback_ms: int = 0,
        send_queue_limit: int = 0,
        path_sample_ms: int = 0,
        congestion_control: Congestion = Congestion.BBR,
        udp_receive_window: int = 0,
        udp_receive_budget: int = 0,
        udp_offload: bool = True,
        reactor_threads: int = 0,
        network_monitor: bool = True,
    ):
        """Create a node; no socket is opened until :meth:`start`.

        Args:
            listen_port: Port both transports listen on; 0 = ephemeral.
            protocol: App id bound into the handshake, e.g. ``"myapp/1.0"``;
                peers with a different one cannot connect. Default ``"librats/1.0"``.
            data_dir: Directory for persistent state (identity, DHT routing
                table, reconnect list). Without it the identity is new every run.
            security: :class:`Security`; Noise by default.
            bind_address: Interface to listen on; default ``"::"``, dual-stack.
            dial_only: No listener: outbound connections only.
            max_peers: Cap on established peers, enforced on inbound; 0 = none.
            transports: :class:`TransportMask` of transports to run; NONE = both.
            preferred_transport: Tried first by a dial; UDP by default.
            transport_fallback_ms: How long the preferred transport dials alone
                before the other is raced; 0 = 1200, :data:`FALLBACK_NEVER` = never.
            send_queue_limit: Bytes a peer's queue may hold before a sender that
                keeps going has it dropped (``CloseReason.SLOW_CONSUMER``);
                :meth:`peer_writable` turns False at a quarter of it. Not a
                message size limit. 0 = 8 MiB.
            path_sample_ms: How often each peer's path is sampled for
                :meth:`path_stats`; 0 = only while an :meth:`on_peer_path`
                callback is registered, every 100 ms.
            congestion_control: :class:`Congestion` of every UDP connection.
            udp_receive_window: Ceiling one UDP connection's flow-control window
                grows to (it starts at 1 MiB); 0 = 16 MiB.
            udp_receive_budget: Bytes all UDP connections together may hold out of
                order; 0 = 64 MiB.
            udp_offload: Use the kernel's UDP segmentation offload where present.
            reactor_threads: I/O threads; 0 = 1.
            network_monitor: Watch the host for interface and address changes.

        Raises:
            RatsInvalidArgError: the config is impossible (no transport, or
                TCP preferred while it is turned off).
        """
        self._lib = get_librats().lib
        self._handle = None
        self._running = False
        # Every CFUNCTYPE handed to C, kept until the node is destroyed.
        self._thunks: List[Any] = []

        cfg = RatsConfig()
        cfg.protocol = _b(protocol)
        cfg.data_dir = _b(data_dir)
        cfg.security = int(security)
        cfg.listen_port = listen_port
        cfg.bind_address = _b(bind_address)
        cfg.dial_only = int(dial_only)
        cfg.max_peers = max_peers
        cfg.transports = int(transports)
        cfg.preferred_transport = int(preferred_transport)
        cfg.transport_fallback_ms = transport_fallback_ms
        cfg.send_queue_limit = send_queue_limit
        cfg.path_sample_ms = path_sample_ms
        cfg.congestion_control = int(congestion_control)
        cfg.udp_receive_window = udp_receive_window
        cfg.udp_receive_budget = udp_receive_budget
        cfg.disable_udp_offload = int(not udp_offload)
        cfg.reactor_threads = reactor_threads
        cfg.disable_network_monitor = int(not network_monitor)

        handle = self._lib.rats_create(byref(cfg))
        if not handle:
            raise RatsInvalidArgError(
                "rats_create refused the config: no transport, a contradictory "
                "transport choice, an out-of-range value, or an unreadable data_dir")
        self._handle = handle
        self._finalizer = weakref.finalize(self, self._lib.rats_destroy, handle)

    # ------------------------------------------------------------------ lifecycle

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()
        return False

    @property
    def _h(self):
        # The C ABI does not check its handle: a call after destroy() would crash.
        if self._handle is None:
            raise RatsError("the node has been destroyed", ErrorCode.INVALID_ARG)
        return self._handle

    def start(self) -> None:
        """Open the sockets and start every enabled subsystem.

        Raises :class:`RatsBindError` if the listen port is taken.
        """
        check_error(self._lib.rats_start(self._h), "start")
        self._running = True

    def stop(self) -> None:
        """Close every connection and stop. Idempotent."""
        if self._handle is not None:
            self._lib.rats_stop(self._handle)
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    def destroy(self) -> None:
        """Stop and free the native node now rather than at garbage collection.

        Idempotent; every other method raises afterwards.
        """
        if self._handle is not None:
            self._finalizer()
            self._handle = None
        self._running = False

    # ------------------------------------------------------------------ this node

    @property
    def local_id(self) -> str:
        """Our peer id, 64 lowercase hex characters."""
        return _s(self._lib.rats_local_id(self._h))

    @property
    def protocol(self) -> str:
        """The protocol bound into the handshake."""
        return _s(self._lib.rats_protocol(self._h))

    @property
    def listen_port(self) -> int:
        """The bound listen port (the real one when 0 was asked for); 0 before start."""
        return self._lib.rats_listen_port(self._h)

    @property
    def transports(self) -> TransportMask:
        """Transports actually running; NONE when not running.

        Can be narrower than asked for: a UDP socket that cannot be bound leaves
        the node TCP-only rather than failing to start.
        """
        return TransportMask(self._lib.rats_transports(self._h))

    @property
    def nat_mapping(self) -> NatMapping:
        """What the mesh has shown about this node's NAT, from where UDP peers
        report seeing its socket."""
        return NatMapping(self._lib.rats_nat_mapping(self._h))

    @property
    def observed_addresses(self) -> List[str]:
        """Our own addresses as peers report seeing us (``"ip:port"``)."""
        return _string_list(self._lib, self._lib.rats_observed_addresses, self._h)

    # ---------------------------------------------------------------------- peers

    def connect(self, host: str, port: int) -> None:
        """Dial ``host:port`` (a literal or a hostname). Needs a started node.

        Non-blocking: success arrives at :meth:`on_peer_connected`, failure at
        :meth:`on_dial_failed`.
        """
        check_error(self._lib.rats_connect(self._h, _b(host), port), f"connect to {host}:{port}")

    def disconnect(self, peer_id: str) -> None:
        """Close the connection to a peer. Raises :class:`RatsNoSuchPeerError`."""
        check_error(self._lib.rats_disconnect(self._h, _b(peer_id)), f"disconnect {peer_id}")

    @property
    def peer_count(self) -> int:
        return self._lib.rats_peer_count(self._h)

    @property
    def peer_ids(self) -> List[str]:
        """Ids of the connected peers."""
        return _string_list(self._lib, self._lib.rats_peer_ids, self._h)

    def peer_info(self, peer_id: str) -> Optional[PeerInfo]:
        """What the node knows about a connected peer, or ``None`` if it is not."""
        out = RatsPeerInfo()
        err = self._lib.rats_peer_info(self._h, _b(peer_id), byref(out))
        if err == ErrorCode.NO_SUCH_PEER:
            return None
        check_error(err, f"peer_info {peer_id}")
        return PeerInfo(transport=Transport(out.transport),
                        transports=TransportMask(out.transports),
                        direction=Direction(out.direction),
                        address=_s(out.address))

    @property
    def max_peers(self) -> int:
        """Cap on established peers (0 = unlimited). Can be changed while running."""
        return self._lib.rats_max_peers(self._h)

    @max_peers.setter
    def max_peers(self, value: int) -> None:
        self._lib.rats_set_max_peers(self._h, value)

    # ------------------------------------------------------------------ messaging

    def send(self, peer_id: str, channel: str, data: bytes, lifetime_ms: int = 0) -> None:
        """Queue ``data`` for one peer on a named channel.

        Returning means queued, not arrived. ``lifetime_ms`` 0 is reliable and in
        order with everything else this node sends on its channels. Non-zero
        makes it a live message, worth delivering only within that many ms
        (:data:`LIVE_MAX_LIFETIME_MS` at most, :data:`LIVE_MAX_PAYLOAD` bytes at
        most): repaired while it can still arrive in time, dropped whole once it
        cannot, never delivered partly or twice, and ordered with nothing. The
        receiver's :meth:`on` handler is the same either way.

        If you send in bulk, ask :meth:`peer_writable` after each send.
        Raises :class:`RatsNoSuchPeerError` if the peer is not connected.
        """
        data = bytes(data)
        check_error(self._lib.rats_send(self._h, _b(peer_id), _b(channel), data, len(data),
                                        lifetime_ms),
                    f"send on '{channel}' to {peer_id}")

    def broadcast(self, channel: str, data: bytes, lifetime_ms: int = 0) -> None:
        """:meth:`send` to every connected peer."""
        data = bytes(data)
        check_error(self._lib.rats_broadcast(self._h, _b(channel), data, len(data), lifetime_ms),
                    f"broadcast on '{channel}'")

    def peer_writable(self, peer_id: str) -> bool:
        """Whether the peer's send queue has room (False also when not connected).

        False means stop: what you sent was queued, but keep adding and the peer
        is dropped with ``CloseReason.SLOW_CONSUMER``. Resume on
        :meth:`on_peer_writable`, or poll this. Bytes just handed to :meth:`send`
        are counted, so asking right after a send is exact.
        """
        return bool(self._lib.rats_peer_writable(self._h, _b(peer_id)))

    def path_stats(self, peer_id: str) -> Optional[PathStats]:
        """The latest path sample for a peer, or ``None`` if it is not connected or
        nothing was sampled yet (sampling needs ``path_sample_ms`` or an
        :meth:`on_peer_path` callback)."""
        out = RatsPathStats()
        err = self._lib.rats_path_stats(self._h, _b(peer_id), byref(out))
        if err == ErrorCode.NO_SUCH_PEER:
            return None
        check_error(err, f"path_stats {peer_id}")
        return _path_stats(out)

    # ------------------------------------------------- callbacks (before start)

    def _keep(self, thunk):
        self._thunks.append(thunk)
        return thunk

    def on_peer_connected(self, callback: PeerCallback) -> None:
        """``callback(peer_id)`` when a peer connects."""
        thunk = self._keep(PeerCallbackType(_guard(
            "peer connected", lambda _u, pid: callback(_s(pid)))))
        check_error(self._lib.rats_on_peer_connected(self._h, thunk, None), "on_peer_connected")

    def on_peer_disconnected(self, callback: DisconnectCallback) -> None:
        """``callback(peer_id, reason: CloseReason)`` when a peer goes.

        Branch on the reason: a peer that left is one to redial, while
        ``SLOW_CONSUMER`` means this node sent faster than the link drained, and
        redialing only repeats it.
        """
        thunk = self._keep(DisconnectCallbackType(_guard(
            "peer disconnected", lambda _u, pid, why: callback(_s(pid), CloseReason(why)))))
        check_error(self._lib.rats_on_peer_disconnected(self._h, thunk, None),
                    "on_peer_disconnected")

    def on_dial_failed(self, callback: DialFailedCallback) -> None:
        """``callback(address)`` when a dial to a numeric address failed over every
        transport tried — one made by :meth:`connect` or by a discovery
        subsystem. A dial by hostname is not reported."""
        thunk = self._keep(DialFailedCallbackType(_guard(
            "dial failed", lambda _u, addr: callback(_s(addr)))))
        check_error(self._lib.rats_on_dial_failed(self._h, thunk, None), "on_dial_failed")

    def on_peer_writable(self, callback: PeerCallback) -> None:
        """``callback(peer_id)`` when a peer whose queue had filled has room again."""
        thunk = self._keep(PeerCallbackType(_guard(
            "peer writable", lambda _u, pid: callback(_s(pid)))))
        check_error(self._lib.rats_on_peer_writable(self._h, thunk, None), "on_peer_writable")

    def on_peer_path(self, callback: PathCallback) -> None:
        """``callback(peer_id, stats: PathStats)`` for every connected peer, every
        ``path_sample_ms`` (100 ms if 0). Registering turns sampling on; it runs
        once per peer per interval, so keep it cheap."""
        thunk = self._keep(PathCallbackType(_guard(
            "peer path", lambda _u, pid, st: callback(
                _s(pid), _path_stats(RatsPathStats.from_address(st))))))
        check_error(self._lib.rats_on_peer_path(self._h, thunk, None), "on_peer_path")

    def on(self, channel: str, callback: MessageCallback) -> None:
        """``callback(peer_id, data: bytes)`` for messages on a named channel."""
        thunk = self._keep(MessageCallbackType(_guard(
            f"'{channel}' message", lambda _u, pid, data, n: callback(_s(pid), _bytes(data, n)))))
        check_error(self._lib.rats_on(self._h, _b(channel), thunk, None), f"on('{channel}')")

    # --------------------------------------------------- discovery (before start)

    def enable_dht(self, dht_port: int = 0, discovery_key: Optional[str] = None) -> None:
        """Mainline DHT: announce and search a key, dialing the peers found.

        ``discovery_key`` defaults to the node's protocol, so only nodes that
        could handshake find each other.
        """
        check_error(self._lib.rats_enable_dht(self._h, dht_port, _b(discovery_key)), "enable_dht")

    def enable_mdns(self) -> None:
        """mDNS discovery on the local network."""
        check_error(self._lib.rats_enable_mdns(self._h), "enable_mdns")

    def enable_peer_exchange(self) -> None:
        """Connected peers trade the addresses of peers they hold, so one contact
        is enough to find the rest of the mesh."""
        check_error(self._lib.rats_enable_peer_exchange(self._h), "enable_peer_exchange")

    # ----------------------------------------------- NAT traversal (before start)

    def enable_port_mapping(self, upnp: bool = True, natpmp: bool = True) -> None:
        """Ask the router to forward the listen port (UPnP IGD and/or NAT-PMP)."""
        check_error(self._lib.rats_enable_port_mapping(self._h, int(upnp), int(natpmp)),
                    "enable_port_mapping")

    def enable_hole_punch(self, serve_rendezvous: bool = True) -> None:
        """UDP hole punching through a peer both sides share. Every node involved
        needs it; ``serve_rendezvous`` also passes other peers' rendezvous along
        (a few dozen bytes per punch) — a mesh where nobody does cannot punch."""
        check_error(self._lib.rats_enable_hole_punch(self._h, int(serve_rendezvous)),
                    "enable_hole_punch")

    def punch_peer(self, peer_id: str) -> None:
        """Start punching to a peer; success arrives at :meth:`on_peer_connected`.

        Raises :class:`RatsDeclinedError` when already connected, already
        punching, or no external endpoint of our own is known yet (that takes at
        least one UDP peer).
        """
        check_error(self._lib.rats_punch_peer(self._h, _b(peer_id)), f"punch {peer_id}")

    def enable_relay(self, serve: bool = False) -> None:
        """Reach a peer nothing else can, through a node both ends are connected to.

        Encryption stays end to end; :meth:`peer_info` reports ``Transport.RELAY``.
        ``serve`` also carries OTHER peers' connections, which costs this node
        their bandwidth. With hole punching enabled too, a punch that cannot work
        falls back to a relay by itself, and a relayed peer is upgraded to a
        direct connection when a later punch succeeds.
        """
        check_error(self._lib.rats_enable_relay(self._h, int(serve)), "enable_relay")

    def connect_via_relay(self, peer_id: str) -> None:
        """Start a relayed connection; success arrives at :meth:`on_peer_connected`.

        Raises :class:`RatsDeclinedError` when already connected, already trying
        or cooling down, or no connected peer could carry it.
        """
        check_error(self._lib.rats_connect_via_relay(self._h, _b(peer_id)),
                    f"connect_via_relay {peer_id}")

    # -------------------------------------------------------------------- pub/sub

    def enable_pubsub(self) -> None:
        """GossipSub topics. Enable before start."""
        check_error(self._lib.rats_enable_pubsub(self._h), "enable_pubsub")

    def subscribe(self, topic: str, callback: TopicCallback) -> None:
        """``callback(peer_id, topic, data: bytes)``. One handler per topic: a second
        subscribe replaces the first."""
        thunk = self._keep(TopicCallbackType(_guard(
            f"topic '{topic}'",
            lambda _u, pid, t, data, n: callback(_s(pid), _s(t), _bytes(data, n)))))
        check_error(self._lib.rats_subscribe(self._h, _b(topic), thunk, None),
                    f"subscribe '{topic}'")

    def unsubscribe(self, topic: str) -> None:
        check_error(self._lib.rats_unsubscribe(self._h, _b(topic)), f"unsubscribe '{topic}'")

    def publish(self, topic: str, data: bytes) -> None:
        """Publish to every subscriber of the topic."""
        data = bytes(data)
        check_error(self._lib.rats_publish(self._h, _b(topic), data, len(data)),
                    f"publish '{topic}'")

    # -------------------------------------------------------------- JSON messages

    def enable_json(self) -> None:
        """Typed messages carrying a JSON document. Enable before start."""
        check_error(self._lib.rats_enable_json(self._h), "enable_json")

    def _json_thunk(self, type_name: str, callback: JsonCallback):
        return self._keep(JsonCallbackType(_guard(
            f"JSON '{type_name}'", lambda _u, pid, text: callback(_s(pid), json.loads(text)))))

    def on_json(self, type_name: str, callback: JsonCallback) -> None:
        """``callback(peer_id, value)`` for messages of ``type_name``, ``value``
        parsed from JSON. Adds a handler; may be called while running."""
        check_error(self._lib.rats_on_json(self._h, _b(type_name),
                                           self._json_thunk(type_name, callback), None),
                    f"on_json '{type_name}'")

    def once_json(self, type_name: str, callback: JsonCallback) -> None:
        """Like :meth:`on_json`; the handler is removed after its first message."""
        check_error(self._lib.rats_once_json(self._h, _b(type_name),
                                             self._json_thunk(type_name, callback), None),
                    f"once_json '{type_name}'")

    def off_json(self, type_name: str) -> None:
        """Remove every handler of ``type_name``."""
        check_error(self._lib.rats_off_json(self._h, _b(type_name)), f"off_json '{type_name}'")

    def send_json(self, peer_id: str, type_name: str, value: Any) -> None:
        """Send ``value``, encoded with :func:`json.dumps`, to one peer."""
        check_error(self._lib.rats_send_json(self._h, _b(peer_id), _b(type_name),
                                             _b(json.dumps(value))),
                    f"send_json '{type_name}' to {peer_id}")

    def broadcast_json(self, type_name: str, value: Any) -> None:
        """:meth:`send_json` to every connected peer."""
        check_error(self._lib.rats_broadcast_json(self._h, _b(type_name), _b(json.dumps(value))),
                    f"broadcast_json '{type_name}'")

    # -------------------------------------------------------------- file transfer

    def enable_file_transfer(self, temp_dir: Optional[str] = None) -> None:
        """Push-style file transfer. ``temp_dir`` holds partial downloads (default
        the working directory). Enable and set its callbacks before start."""
        check_error(self._lib.rats_enable_file_transfer(self._h, _b(temp_dir)),
                    "enable_file_transfer")

    def on_file_offer(self, callback: FileOfferCallback) -> None:
        """``callback(peer_id, transfer_id, name, size, is_directory)`` for each
        incoming offer; answer with :meth:`accept_file` or :meth:`reject_file`.
        One handler: a second call replaces the first."""
        thunk = self._keep(FileOfferCallbackType(_guard(
            "file offer", lambda _u, pid, tid, name, size, is_dir: callback(
                _s(pid), int(tid), _s(name), int(size), bool(is_dir)))))
        check_error(self._lib.rats_on_file_offer(self._h, thunk, None), "on_file_offer")

    def on_file_progress(self, callback: FileProgressCallback) -> None:
        """``callback(progress: FileProgress)`` as transfers move, both directions."""
        def trampoline(_u, ptr):
            c = RatsFileProgress.from_address(ptr)
            callback(FileProgress(
                transfer_id=c.transfer_id, peer_id=_s(c.peer_id),
                direction=Direction(c.direction), status=FileTransferStatus(c.status),
                bytes_transferred=c.bytes_transferred, total_bytes=c.total_bytes,
                files_completed=c.files_completed, total_files=c.total_files,
                rate_bytes_per_sec=c.rate_bytes_per_sec))
        thunk = self._keep(FileProgressCallbackType(_guard("file progress", trampoline)))
        check_error(self._lib.rats_on_file_progress(self._h, thunk, None), "on_file_progress")

    def on_file_complete(self, callback: FileCompleteCallback) -> None:
        """``callback(peer_id, transfer_id, success, path)`` when a transfer ends."""
        thunk = self._keep(FileCompleteCallbackType(_guard(
            "file complete", lambda _u, pid, tid, ok, path: callback(
                _s(pid), int(tid), bool(ok), _s(path)))))
        check_error(self._lib.rats_on_file_complete(self._h, thunk, None), "on_file_complete")

    def send_file(self, peer_id: str, path: str) -> int:
        """Offer a file to a connected peer; returns the transfer id.

        Raises RatsNoSuchPeerError if the peer is not connected and
        RatsNotFoundError if the file cannot be read.
        """
        tid = c_uint64(0)
        check_error(self._lib.rats_send_file(self._h, _b(peer_id), _b(path), byref(tid)),
                    "send_file")
        return tid.value

    def send_directory(self, peer_id: str, path: str) -> int:
        """Offer a directory tree; returns and raises as send_file()."""
        tid = c_uint64(0)
        check_error(self._lib.rats_send_directory(self._h, _b(peer_id), _b(path), byref(tid)),
                    "send_directory")
        return tid.value

    def accept_file(self, peer_id: str, transfer_id: int, dest_path: str) -> None:
        """Accept an offer: ``dest_path`` is the file to write for a file, the
        directory to fill for a directory."""
        check_error(self._lib.rats_accept_file(self._h, _b(peer_id), transfer_id, _b(dest_path)),
                    f"accept_file {transfer_id}")

    def reject_file(self, peer_id: str, transfer_id: int) -> None:
        check_error(self._lib.rats_reject_file(self._h, _b(peer_id), transfer_id),
                    f"reject_file {transfer_id}")

    def cancel_file(self, peer_id: str, transfer_id: int) -> None:
        """Cancel a transfer from either side. Raises :class:`RatsNotFoundError`."""
        check_error(self._lib.rats_cancel_file(self._h, _b(peer_id), transfer_id),
                    f"cancel_file {transfer_id}")

    def pause_file(self, peer_id: str, transfer_id: int) -> None:
        check_error(self._lib.rats_pause_file(self._h, _b(peer_id), transfer_id),
                    f"pause_file {transfer_id}")

    def resume_file(self, peer_id: str, transfer_id: int) -> None:
        check_error(self._lib.rats_resume_file(self._h, _b(peer_id), transfer_id),
                    f"resume_file {transfer_id}")

    # ----------------------------------------------------------- ping, reconnect

    def enable_ping(self) -> None:
        """Round-trip probing of every peer. Enable before start."""
        check_error(self._lib.rats_enable_ping(self._h), "enable_ping")

    def peer_rtt_ms(self, peer_id: str) -> Optional[int]:
        """Last measured round trip to a peer in ms; ``None`` if unknown."""
        rtt = self._lib.rats_peer_rtt_ms(self._h, _b(peer_id))
        return None if rtt < 0 else rtt

    def enable_reconnect(self) -> None:
        """Redial dropped peers with backoff; with ``data_dir`` the list survives
        restarts. Enable before start."""
        check_error(self._lib.rats_enable_reconnect(self._h), "enable_reconnect")

    def add_reconnect(self, host: str, port: int) -> None:
        """Keep an address connected. May be called while running."""
        check_error(self._lib.rats_add_reconnect(self._h, _b(host), port),
                    f"add_reconnect {host}:{port}")

    def remove_reconnect(self, host: str, port: int) -> None:
        """Stop keeping an address connected and forget it."""
        check_error(self._lib.rats_remove_reconnect(self._h, _b(host), port),
                    f"remove_reconnect {host}:{port}")

    # ----------------------------------------------------------------- BitTorrent

    def enable_bittorrent(
        self,
        listen_port: int = 0,
        download_path: Optional[str] = None,
        *,
        outgoing_encryption: BtEncryption = BtEncryption.ENABLED,
        incoming_encryption: BtEncryption = BtEncryption.ENABLED,
        outgoing_utp: bool = True,
        incoming_utp: bool = True,
    ) -> None:
        """A BitTorrent client beside the node. Only in libraries built with
        ``RATS_SEARCH_FEATURES`` (else :class:`RatsNotEnabledError`). It runs its
        own sockets; enable the DHT first and it shares the node's."""
        cfg = RatsBtConfig()
        cfg.listen_port = listen_port
        cfg.download_path = _b(download_path)
        cfg.outgoing_encryption = int(outgoing_encryption)
        cfg.incoming_encryption = int(incoming_encryption)
        cfg.disable_outgoing_utp = int(not outgoing_utp)
        cfg.disable_incoming_utp = int(not incoming_utp)
        check_error(self._lib.rats_enable_bittorrent(self._h, byref(cfg)), "enable_bittorrent")

    def bt_add_magnet(self, magnet_uri: str, save_path: Optional[str] = None) -> None:
        """Start a download from a magnet link. Needs a started node."""
        check_error(self._lib.rats_bt_add_magnet(self._h, _b(magnet_uri), _b(save_path)),
                    "bt_add_magnet")

    def bt_add_torrent_file(self, torrent_path: str, save_path: Optional[str] = None) -> None:
        """Start a download from a .torrent file. Needs a started node."""
        check_error(self._lib.rats_bt_add_torrent_file(self._h, _b(torrent_path), _b(save_path)),
                    f"bt_add_torrent_file {torrent_path!r}")

    def bt_remove_torrent(self, info_hash_hex: str) -> None:
        """Remove a torrent by its 40-char hex info-hash; downloaded files stay."""
        check_error(self._lib.rats_bt_remove_torrent(self._h, _b(info_hash_hex)),
                    f"bt_remove_torrent {info_hash_hex}")


# --------------------------------------------------------------- process-wide

def set_log_level(level: LogLevel) -> None:
    get_librats().lib.rats_set_log_level(int(level))


def set_log_file(path: Optional[str]) -> None:
    """Also write logs to ``path``; ``None`` or ``""`` stops file logging."""
    get_librats().lib.rats_set_log_file(_b(path))


def version() -> str:
    """Library version, e.g. ``"1.2.3"``."""
    return _s(get_librats().lib.rats_version_string())


def version_info() -> VersionInfo:
    parts = [c_int() for _ in range(4)]
    get_librats().lib.rats_version(*(byref(p) for p in parts))
    return VersionInfo(*(p.value for p in parts))


def git_describe() -> str:
    """``git describe`` of the build, e.g. ``"v1.2.3-4-gabcdef"``."""
    return _s(get_librats().lib.rats_git_describe())


def abi() -> int:
    """``(major << 16) | (minor << 8) | patch``."""
    return get_librats().lib.rats_abi()


def error_str(code: int) -> str:
    """Name of a ``rats_error_t`` code, e.g. ``"RATS_ERR_DECLINED"``."""
    return _s(get_librats().lib.rats_error_str(int(code)))
