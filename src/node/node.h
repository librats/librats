#pragma once

/**
 * @file node.h
 * @brief The public entry point: a thin facade that wires the layers together.
 *
 * Node owns the reactor pool, the security provider, the peer directory and the
 * message router, and it IS the ConnectionDelegate the reactors report to. It is
 * deliberately thin — it composes the layers and exposes a small async API; the
 * logic lives in those layers, not here. (Contrast the old RatsClient, which was
 * all of them at once behind ~250 methods.)
 *
 * Threading: connect/send/broadcast are non-blocking and thread-safe — they post
 * work to the owning reactor. Event callbacks (on_peer_connected / on_message /
 * on_peer_disconnected) run on a reactor thread; register them before start().
 *
 * ── What a bare Node does, and what it does NOT ──────────────────────────────
 * A Node on its own is just the secure transport core. Out of the box it gives you:
 *   - an encrypted TCP transport (Noise_XX, or plaintext per NodeConfig::security),
 *     with a self-certifying PeerId and the app protocol bound into the handshake;
 *   - manual dialing: connect(host, port) / connect(Address) — it never discovers
 *     peers by itself;
 *   - the peer directory + admission limit: peers(), peer(), peer_count(), max_peers;
 *   - raw channel messaging: send(to, channel, bytes) / broadcast(channel, bytes)
 *     / on_message(channel, …);
 *   - peer connect/disconnect events and the node-scoped EventBus + ServiceRegistry;
 *   - host network-change detection (NetworkChanged on the EventBus), if enabled;
 *   - identity persistence (NodeConfig::data_dir → identity.key).
 *
 * Everything else is an opt-in Subsystem you attach with add_subsystem() BEFORE
 * start(): peer discovery (DhtDiscovery, MdnsDiscovery), pub/sub (PubSub), typed
 * JSON messaging (MessageExchange), file transfer (FileTransfer), liveness
 * (PingService), NAT port mapping (PortMappingService), automatic reconnection
 * (ReconnectionService), distributed storage (StorageManager). None of these are
 * wired by default — a bare Node neither discovers peers nor reconnects on its own;
 * the application composes exactly the capabilities it wants. This is deliberate:
 * the node stays a small, predictable core, and you pay only for what you attach.
 */

#include "transport/connection.h"      // ConnectionDelegate
#include "transport/reactor_pool.h"
#include "core/address.h"
#include "peer/peer_table.h"
#include "peer/peer_id.h"
#include "peer/peer_info.h"
#include "security/identity.h"
#include "security/handshaker.h"  // SecurityProvider
#include "node/config.h"
#include "node/node_context.h"    // NodeContext, EventBus, ServiceRegistry
#include "peer/peer.h"
#include "node/peer_network.h"
#include "wire/message_router.h"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace librats {

class NetworkMonitor;  // util/network_monitor.h — owned via unique_ptr, included in node.cpp

class Node final : public ConnectionDelegate, public PeerNetwork {
public:
    explicit Node(NodeConfig config);
    ~Node() override;

    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;

    /// Attach a subsystem (DHT, GossipSub, PingService…). Call before start();
    /// the node owns it, gives it a PeerNetwork on start(), and stops it on stop().
    void add_subsystem(std::unique_ptr<Subsystem> subsystem);

    bool start();
    void stop();

    const PeerId& local_id() const noexcept override { return identity_.id; }
    uint16_t      listen_port() const noexcept override { return listen_port_; }

    /// Application protocol identity bound into the handshake (see NodeConfig).
    const std::string& protocol_name() const noexcept { return config_.protocol_name; }
    const std::string& protocol_version() const noexcept { return config_.protocol_version; }

    // — node-scoped coordination, shared by subsystems and the app (see NodeContext) —
    //   events()   : fire-and-forget notifications, one→many (host events, …)
    //   services() : targeted synchronous calls by capability interface, one→one
    EventBus&        events()   noexcept { return events_; }
    ServiceRegistry& services() noexcept { return services_; }

    // — connections —
    void connect(const Address& address) override;
    void connect(const std::string& host, uint16_t port);

    size_t                  peer_count() const noexcept { return directory_.size(); }
    std::vector<PeerInfo>   peers() const override { return directory_.snapshot(); }
    std::optional<Peer> peer(const PeerId& id);

    /// Our own addresses as remote peers reported observing us at — their observed
    /// IP paired with our listen port. De-duplicated and bounded; populated as
    /// peers send their identify message. Useful for NAT awareness / advertising.
    std::vector<Address> observed_addresses() const;

    // — peer admission limit (0 = unlimited; guards inbound, not our own dials) —
    size_t max_peers() const noexcept { return max_peers_.load(std::memory_order_relaxed); }
    void   set_max_peers(size_t n) noexcept { max_peers_.store(n, std::memory_order_relaxed); }
    bool   peer_limit_reached() const noexcept {
        const size_t cap = max_peers_.load(std::memory_order_relaxed);
        return cap != 0 && directory_.size() >= cap;
    }

    // — application messaging —
    void send(const PeerId& to, std::string_view channel, ByteView payload);
    void broadcast(std::string_view channel, ByteView payload);

    // — events (register before start(); invoked on a reactor thread). Multiple
    //   listeners are supported, so subsystems and the app can both subscribe. —
    void on_peer_connected(PeerNetwork::PeerEventHandler cb) override { peer_connected_.push_back(std::move(cb)); }
    void on_peer_disconnected(PeerNetwork::PeerDisconnectHandler cb) override { peer_disconnected_.push_back(std::move(cb)); }
    void on_message(std::string_view channel, MessageRouter::Handler cb) { router_.on_channel(channel, std::move(cb)); }

    // — PeerNetwork (for subsystems) —
    void                send(const PeerId& to, MessageType type, ByteView payload) override;
    void                broadcast(MessageType type, ByteView payload) override;
    std::vector<PeerId> connected_peers() const override;
    void                on_message(MessageType type, PeerNetwork::MessageHandler cb) override { router_.on_type(type, std::move(cb)); }

private:
    friend class Peer;

    // ConnectionDelegate (reactor thread)
    bool admit_inbound() override;
    void on_established(Connection& conn) override;
    void on_frame(Connection& conn, const Frame& frame) override;
    void on_closed(Connection& conn, CloseReason reason) override;

    Peer make_peer(const PeerId& id, PeerRoute route) { return Peer(id, route, *this); }
    void route_send(PeerRoute route, FrameHeader header, Bytes payload);
    void route_close(PeerRoute route);

    // — identify: how peers learn each other's dialable addresses (reactor thread) —
    void                 send_identify(Connection& conn);            ///< on establish
    void                 handle_identify(Connection& conn, const Frame& frame);  ///< Control frame
    std::vector<Address> advertised_addresses() const;              ///< our dialable addrs (sent in identify)
    void                 rebuild_advertised_addresses(const std::vector<std::string>& local_ips);
    void                 record_observed_address(const Address& addr);

    void start_network_monitor();   ///< spin up the monitor + maintenance thread
    void stop_network_monitor();    ///< stop the monitor, drain + join maintenance
    void maintenance_loop();        ///< off-monitor thread: emits NetworkChanged

    NodeConfig                        config_;
    Identity                          identity_;
    std::unique_ptr<SecurityProvider> security_;
    PeerTable                     directory_;
    MessageRouter                     router_;
    EventBus                          events_;      ///< host/cross-module notifications
    ServiceRegistry                   services_;    ///< capability lookup between modules
    std::unique_ptr<ReactorPool>      reactors_;

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

    socket_t            listen_socket_ = INVALID_SOCKET_VALUE;
    uint16_t            listen_port_   = 0;
    std::atomic<bool>   running_{false};
    std::atomic<size_t> max_peers_{0};  ///< established-peer cap; 0 = unlimited

    std::vector<PeerNetwork::PeerEventHandler>      peer_connected_;
    std::vector<PeerNetwork::PeerDisconnectHandler> peer_disconnected_;

    // Our own addresses as peers observe us (their reported IP + our listen port).
    mutable std::mutex   observed_mutex_;
    std::vector<Address> observed_addresses_;

    // The dialable addresses we advertise to peers in identify. Derived from local
    // interfaces (and, in future, promoted observed addresses). Rebuilt once at
    // start() and on NetworkMonitor changes — never re-enumerated per connection,
    // since interface enumeration is a syscall and the send path is hot.
    mutable std::mutex   advertised_mutex_;
    std::vector<Address> advertised_addresses_;
};

} // namespace librats
