#pragma once

/**
 * @file node.h
 * @brief The public entry point: a thin facade that wires the layers together.
 *
 * Node owns the reactor pool, the security provider, the peer table and the
 * message router, and it IS the ConnectionDelegate the reactors report to. It is
 * deliberately thin — it composes the layers and exposes a small async API; the
 * logic lives in those layers, not here.
 *
 * Threading: connect/send/broadcast are non-blocking and thread-safe — they post
 * work to the owning reactor. Event callbacks (on_peer_connected / on(channel,…)
 * / on_peer_disconnected) run on a reactor thread; register them before start().
 *
 * ── What a bare Node does, and what it does NOT ──────────────────────────────
 * A Node on its own is just the secure transport core. Out of the box it gives you:
 *   - an encrypted transport (Noise_XX, or plaintext per NodeConfig::security),
 *     with a self-certifying PeerId and the app protocol bound into the handshake,
 *     over EITHER wire: TCP, or the library's reliable stream over UDP. Both are
 *     offered by default on the same port, and a dial tries the preferred one
 *     (UDP, the better fit for P2P) and races the other after a short delay;
 *   - manual dialing: connect(host, port) / connect(Address) — it never discovers
 *     peers by itself;
 *   - the peer table + admission limit: peers(), peer(), peer_count(), max_peers;
 *   - raw channel messaging: send(to, channel, bytes) / broadcast(channel, bytes)
 *     / on(channel, …);
 *   - peer connect/disconnect events and the node-scoped EventBus + ServiceRegistry;
 *   - host network-change detection (NetworkChanged on the EventBus), if enabled;
 *   - identity persistence (NodeConfig::data_dir → identity.key).
 *
 * Everything else is an opt-in Subsystem you attach with add_subsystem() BEFORE
 * start(): peer discovery (DhtDiscovery, MdnsDiscovery), pub/sub (PubSub), typed
 * JSON messaging (MessageJson), file transfer (FileTransfer), liveness
 * (PingService), NAT port mapping (PortMappingService), automatic reconnection
 * (ReconnectionService), distributed storage (StorageManager). None of these are
 * wired by default — a bare Node neither discovers peers nor reconnects on its own;
 * the application composes exactly the capabilities it wants. This is deliberate:
 * the node stays a small, predictable core, and you pay only for what you attach.
 */

#include "librats/util/rats_export.h"
#include "librats/transport/connection.h"      // ConnectionDelegate
#include "librats/transport/reactor_pool.h"
#include "librats/core/address.h"
#include "librats/peer/peer_table.h"
#include "librats/peer/peer_id.h"
#include "librats/peer/peer_info.h"
#include "librats/security/identity.h"
#include "librats/security/handshaker.h"  // SecurityProvider
#include "librats/node/circuit_service.h"
#include "librats/node/config.h"
#include "librats/node/dial_service.h"
#include "librats/node/dialer.h"
#include "librats/node/nat_status.h"
#include "librats/node/node_context.h"    // NodeContext, EventBus, ServiceRegistry
#include "librats/peer/peer.h"
#include "librats/node/peer_network.h"
#include "librats/wire/message_router.h"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

namespace librats {

class NetworkMonitor;  // util/network_monitor.h — owned via unique_ptr, included in node.cpp
class MessageJson;     // subsystems/message_json.h — reached via json() (json.h stays out of node.h)

class RATS_API Node final : public ConnectionDelegate,
                            public PeerNetwork,
                            public DialService,
                            public CircuitService {
public:
    /// Construct a node from its configuration (see NodeConfig). This only loads
    /// the identity and prepares the layers; no socket is opened until start().
    explicit Node(NodeConfig config);
    /// Stops the node if still running, then releases all resources.
    ~Node() override;

    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;

    /// Attach a subsystem (DHT, GossipSub, PingService…). Call before start();
    /// the node owns it (single ownership), gives it a PeerNetwork on start(), and
    /// stops it on stop(). Returns a non-owning pointer to the just-added subsystem
    /// so the caller can drive its API without a separate get()/move dance — valid
    /// for the node's lifetime:
    ///   auto* files = node.add_subsystem(std::make_unique<FileTransfer>("./dl"));
    template <class T>
    T* add_subsystem(std::unique_ptr<T> subsystem) {
        static_assert(std::is_base_of<Subsystem, T>::value, "T must derive from Subsystem");
        T* raw = subsystem.get();
        subsystems_.push_back(std::move(subsystem));  // upcast to unique_ptr<Subsystem>
        return raw;
    }

    /// Bring the node up: open the listener (if enabled), start the reactor pool,
    /// then start every attached subsystem. Register callbacks and attach
    /// subsystems BEFORE calling this.
    /// @return true on success; false if the listener could not bind.
    bool start();
    /// Tear the node down: stop subsystems (reverse order), close all
    /// connections, and join the reactor pool. Safe to call once; idempotent.
    void stop();

    /// Our self-certifying peer identity (the public key peers authenticate).
    const PeerId& local_id() const noexcept override { return identity_.id; }
    /// The bound listen port (the actual port when the config requested 0). Both
    /// transports share it, so one advertised address is dialable over either.
    uint16_t      listen_port() const noexcept override { return listen_port_; }

    /// Transports this node is actually running, as a PeerTransports bitmask.
    /// May be narrower than the config asked for — a UDP socket that could not be
    /// bound leaves the node TCP-only rather than failing to start.
    uint8_t       transports() const noexcept override { return transports_; }

    /// Application protocol identity bound into the handshake (see NodeConfig).
    const std::string& protocol() const noexcept override { return config_.protocol; }

    // — node-scoped coordination, shared by subsystems and the app (see NodeContext) —
    //   events()   : fire-and-forget notifications, one→many (host events, …)
    //   services() : targeted synchronous calls by capability interface, one→one
    EventBus&        events()   noexcept { return events_; }
    ServiceRegistry& services() noexcept { return services_; }

    // — connections —
    /// Dial a peer. Non-blocking: the connection (transport + handshake) completes
    /// asynchronously and surfaces via on_peer_connected. A duplicate or
    /// self-connection is detected and dropped after the handshake.
    ///
    /// The transport is chosen by the dialer (see node/dialer.h): the preferred
    /// one first, the other raced in after NodeConfig::transport_fallback_ms if
    /// the first has not come up. Whichever completes its handshake first wins.
    void connect(const Address& address) override;
    /// @copydoc connect(const Address&)
    void connect(const std::string& host, uint16_t port);

    /// Number of currently-established peers.
    size_t                  peer_count() const noexcept { return peers_.size(); }
    /// Snapshot of all established peers (id, addresses, direction, timing).
    std::vector<PeerInfo>   peers() const override { return peers_.snapshot(); }
    /// Handle to a connected peer by id, or std::nullopt if not connected.
    std::optional<Peer> peer(const PeerId& id);

    /// Our own addresses as remote peers reported observing us at — their observed
    /// IP paired with our listen port. De-duplicated and bounded; populated as
    /// peers send their identify message. Useful for NAT awareness / advertising.
    std::vector<Address> observed_addresses() const;

    /// What the mesh has shown about our own side of the NAT, from the endpoints
    /// datagram peers report observing our shared UDP socket at (see nat_status.h).
    /// Also published in services() as ExternalAddressService, which is how a
    /// NAT-traversal subsystem reaches it.
    const NatStatus& nat_status() const noexcept { return nat_status_; }

    // — DialService: dial one endpoint over one wire, bypassing the transport race
    //   (see node/dial_service.h; used by hole punching) —
    bool dial_direct(const Address& addr, TransportKind kind,
                     const DialProfile& profile) override;

    // — CircuitService: make a relayed byte stream an ordinary peer connection
    //   (see node/circuit_service.h; used by the relay module) —
    std::optional<PeerRoute> adopt_circuit(const PeerId& carrier, std::unique_ptr<Link> link,
                                           ConnRole role, bool connected) override;
    void                     wake_circuit(PeerRoute route, uint32_t events) override;
    void                     close_circuit(PeerRoute route, CloseReason reason) override;

    // — peer admission limit (0 = unlimited; guards inbound, not our own dials) —
    size_t max_peers() const noexcept { return max_peers_.load(std::memory_order_relaxed); }
    void   set_max_peers(size_t n) noexcept { max_peers_.store(n, std::memory_order_relaxed); }
    bool   peer_limit_reached() const noexcept {
        const size_t cap = max_peers_.load(std::memory_order_relaxed);
        return cap != 0 && peers_.size() >= cap;
    }

    // — application messaging (raw bytes on a named channel) —
    /// Send raw bytes to one peer on a named channel. Non-blocking; the payload
    /// is copied into the peer's send queue. No-op if the peer is not connected.
    /// @param to      destination peer id
    /// @param channel application channel name (interned to a 16-bit id)
    /// @param payload message bytes (copied)
    /// @return whether that peer's queue still has room. <b>False means stop</b>:
    ///         this message is queued like any other, but the queue is past its
    ///         low-water mark, and an application that keeps going regardless
    ///         will eventually have the peer dropped as a slow consumer. Wait for
    ///         on_peer_writable instead. Also false if the peer is not connected.
    ///
    ///         "Stop" is meant literally, and yielding is part of it: the mark is
    ///         re-tested inside the reactor task this call hands off to, and it is
    ///         that test which flips the peer to unwritable and later raises
    ///         on_peer_writable. A caller that answers a false by looping straight
    ///         back into send() therefore starves the very thread that would tell
    ///         it to stop — the queue keeps growing while the signal it is waiting
    ///         for never gets a turn to be produced.
    bool send(const PeerId& to, std::string_view channel, ByteView payload);
    /// Send raw bytes on a named channel to every connected peer.
    /// @return whether *every* one of them still has room — a fan-out can only
    ///         usefully be paced by its slowest recipient.
    ///
    /// Coarser than send(): the answer is the reactors' view as they last left
    /// it and does not count what this call has just handed over, because a
    /// broadcast is dispatched per reactor rather than per peer. Good enough to
    /// pace a periodic fan-out; when precise backpressure matters — a file
    /// transfer, a large stream — address peers individually with send().
    bool broadcast(std::string_view channel, ByteView payload);

    /// Whether a peer's send queue has room for more. False for a peer that is
    /// not connected.
    ///
    /// The same question send() answers, asked without sending anything: it
    /// weighs both halves of what the peer is carrying — the bytes the reactor
    /// has queued, and the bytes a caller has handed to send() that the reactor
    /// has not taken up yet. So it is safe to poll: a caller that has just filled
    /// the queue in a tight loop keeps being told "no room" until the reactor has
    /// actually looked at what it was given, rather than being told "go on"
    /// because nothing observable has changed yet.
    ///
    /// It stays a hint about a queue that drains as it is read, so the ordinary
    /// flow is unchanged: the signal to stop is the return of send(), and the
    /// signal to resume is on_peer_writable. This is for a caller that must wait
    /// for room on a thread of its own — the event alone cannot serve it, because
    /// a queue that filled *only* with bytes still in transit never crossed
    /// anything on the connection and so raises no event when they drain.
    bool peer_writable(const PeerId& id) const override;

    // — events (register before start(); invoked on a reactor thread). Multiple
    //   listeners are supported, so subsystems and the app can both subscribe. —
    /// Subscribe to peer-connected events. The handler runs on a reactor thread.
    void on_peer_connected(PeerNetwork::PeerEventHandler cb) override { peer_connected_.push_back(std::move(cb)); }
    /// Subscribe to peer-disconnected events. The handler runs on a reactor thread.
    void on_peer_disconnected(PeerNetwork::PeerDisconnectHandler cb) override { peer_disconnected_.push_back(std::move(cb)); }
    /// Subscribe to failed-outbound-dial events. The handler runs on a reactor thread.
    void on_dial_failed(PeerNetwork::DialFailedHandler cb) override { dial_failed_.push_back(std::move(cb)); }
    /// Subscribe to "this peer can be written to again" — fired when a peer whose
    /// send queue had filled past its mark has drained back under it. The other
    /// half of send() returning false; an application that never checks that
    /// return never needs this. The handler runs on a reactor thread.
    void on_peer_writable(PeerNetwork::PeerEventHandler cb) override { peer_writable_.push_back(std::move(cb)); }
    /// Register a handler for inbound messages on a named channel. Additive:
    /// multiple handlers may coexist. The handler runs on a reactor thread.
    void on(std::string_view channel, MessageRouter::Handler cb) { router_.on_channel(channel, std::move(cb)); }

    // — typed lookup of an attached subsystem (nullptr if none of that type) —
    //   reaches a module's own API without threading a pointer from add_subsystem:
    //     if (auto* j = node.json()) j->on("chat", …);
    template <class T>
    T* subsystem() noexcept {
        for (auto& s : subsystems_) if (auto* p = dynamic_cast<T*>(s.get())) return p;
        return nullptr;
    }
    /// The JSON messaging module if one was attached (add_subsystem<MessageJson>),
    /// else nullptr. Convenience over subsystem<MessageJson>(); defined in node.cpp.
    MessageJson* json() noexcept;

    // — PeerNetwork (for subsystems) —
    bool                send(const PeerId& to, MessageType type, ByteView payload) override;
    bool                broadcast(MessageType type, ByteView payload) override;
    std::vector<PeerId> connected_peers() const override;
    void                on(MessageType type, PeerNetwork::MessageHandler cb) override { router_.on_type(type, std::move(cb)); }

private:
    friend class Peer;

    // ConnectionDelegate (reactor thread)
    bool admit_inbound() override;
    void on_established(Connection& conn) override;
    void on_frame(Connection& conn, const Frame& frame) override;
    void on_closed(Connection& conn, CloseReason reason) override;
    void on_writable_changed(Connection& conn, bool writable) override;
    void on_dial_aborted(uint8_t reactor_index, ConnId id,
                         const std::string& host, uint16_t port) override;

    /// Open the listeners the config asks for, keeping both transports on one
    /// port. Sets listen_socket_/udp_socket_/listen_port_/transports_.
    bool open_listeners();
    /// Report a target every dial attempt failed on (called by the Dialer).
    void report_dial_failed(const std::string& host, uint16_t port);

    Peer make_peer(const PeerId& id, PeerRoute route) { return Peer(id, route, *this); }
    void route_send(PeerRoute route, FrameHeader header, Bytes payload,
                    std::shared_ptr<std::atomic<size_t>> owed = nullptr);
    /// Bytes a peer may have queued (in the connection) or in transit to its
    /// reactor before send() starts answering "no room". Derived from the same
    /// config knob that sets the hard limit, so the two cannot drift apart.
    size_t send_low_water() const noexcept;
    void route_close(PeerRoute route);

    // — identify: how peers learn each other's dialable addresses (reactor thread) —
    void                 send_identify(Connection& conn);            ///< on establish
    void                 handle_identify(Connection& conn, const Frame& frame);  ///< Control frame
    std::vector<Address> advertised_addresses() const;              ///< our dialable addrs (sent in identify)
    void                 rebuild_advertised_addresses(const std::vector<std::string>& local_ips);
    void                 record_observed_address(const Address& addr);
    /// Whether `addr` is an endpoint this node holds itself — i.e. a peer reporting
    /// it saw us there saw no NAT in between. Compares against the advertised set.
    bool                 is_own_endpoint(const Address& addr) const;

    void start_network_monitor();   ///< spin up the monitor + maintenance thread
    void stop_network_monitor();    ///< stop the monitor, drain + join maintenance
    void maintenance_loop();        ///< off-monitor thread: emits NetworkChanged

    NodeConfig                        config_;
    Identity                          identity_;
    std::unique_ptr<SecurityProvider> security_;
    PeerTable                     peers_;
    MessageRouter                     router_;
    EventBus                          events_;      ///< host/cross-module notifications
    ServiceRegistry                   services_;    ///< capability lookup between modules
    std::unique_ptr<ReactorPool>      reactors_;
    std::unique_ptr<Dialer>           dialer_;      ///< transport choice + fallback race

    std::vector<std::unique_ptr<Subsystem>> subsystems_;

    // Host network-change watch. The monitor signals on its own thread; the
    // maintenance thread does the (possibly blocking) EventBus emit off it, so
    // subscribers may run slow recovery without stalling change detection.
    std::unique_ptr<NetworkMonitor> monitor_;
    std::thread                     maintenance_thread_;
    std::mutex                      maintenance_mutex_;
    std::condition_variable         maintenance_cv_;
    std::vector<std::string>        pending_addresses_;
    bool                            maintenance_pending_ = false;
    bool                            maintenance_stop_    = false;

    socket_t            listen_socket_ = RATS_INVALID_SOCKET;  ///< TCP listener
    socket_t            udp_socket_    = RATS_INVALID_SOCKET;  ///< shared datagram socket
    uint16_t            listen_port_   = 0;   ///< bound by both transports
    uint8_t             transports_    = 0;   ///< PeerTransports bitmask actually running
    std::atomic<bool>   running_{false};
    std::atomic<size_t> max_peers_{0};  ///< established-peer cap; 0 = unlimited

    std::vector<PeerNetwork::PeerEventHandler>      peer_connected_;
    std::vector<PeerNetwork::PeerDisconnectHandler> peer_disconnected_;
    std::vector<PeerNetwork::DialFailedHandler>     dial_failed_;
    std::vector<PeerNetwork::PeerEventHandler>      peer_writable_;

    // Our own addresses as peers observe us (their reported IP + our listen port).
    mutable std::mutex   observed_mutex_;
    std::vector<Address> observed_addresses_;

    // The datagram half of the same knowledge, which is a different thing: what a
    // peer sees on a UDP link is our NAT's mapping of the one shared socket, port
    // included, and several peers' views of it are what say whether that mapping is
    // stable enough to punch through. Published as ExternalAddressService.
    NatStatus            nat_status_;

    // The dialable addresses we advertise to peers in identify. Derived from local
    // interfaces (and, in future, promoted observed addresses). Rebuilt once at
    // start() and on NetworkMonitor changes — never re-enumerated per connection,
    // since interface enumeration is a syscall and the send path is hot.
    mutable std::mutex   advertised_mutex_;
    std::vector<Address> advertised_addresses_;
};

} // namespace librats
