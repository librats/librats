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
 */

#include "core/connection.h"      // ConnectionDelegate
#include "core/reactor_pool.h"
#include "net/address.h"
#include "net/peer_directory.h"
#include "net/peer_id.h"
#include "net/peer_info.h"
#include "security/identity.h"
#include "security/handshaker.h"  // SecurityProvider
#include "node/config.h"
#include "node/peer.h"
#include "node/peer_network.h"
#include "node/message_router.h"

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace librats {

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
    uint16_t      listen_port() const noexcept { return listen_port_; }

    // — connections —
    void connect(const Address& address);
    void connect(const std::string& host, uint16_t port);

    size_t                  peer_count() const noexcept { return directory_.size(); }
    std::vector<PeerInfo>   peers() const { return directory_.snapshot(); }
    std::optional<PeerHandle> peer(const PeerId& id);

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
    friend class PeerHandle;

    // ConnectionDelegate (reactor thread)
    void on_established(Connection& conn) override;
    void on_frame(Connection& conn, const Frame& frame) override;
    void on_closed(Connection& conn, CloseReason reason) override;

    PeerHandle make_peer(const PeerId& id, PeerRoute route) { return PeerHandle(id, route, *this); }
    void route_send(PeerRoute route, FrameHeader header, Bytes payload);
    void route_close(PeerRoute route);

    NodeConfig                        config_;
    Identity                          identity_;
    std::unique_ptr<SecurityProvider> security_;
    PeerDirectory                     directory_;
    MessageRouter                     router_;
    std::unique_ptr<ReactorPool>      reactors_;

    std::vector<std::unique_ptr<Subsystem>> subsystems_;

    socket_t          listen_socket_ = INVALID_SOCKET_VALUE;
    uint16_t          listen_port_   = 0;
    std::atomic<bool> running_{false};

    std::vector<PeerNetwork::PeerEventHandler>      peer_connected_;
    std::vector<PeerNetwork::PeerDisconnectHandler> peer_disconnected_;
};

} // namespace librats
