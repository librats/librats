#include "node/node.h"
#include "security/noise_security.h"
#include "security/plaintext_security.h"
#include "logger.h"

#include <memory>
#include <utility>

namespace librats {

namespace {
std::unique_ptr<SecurityProvider> make_security(NodeConfig::Security kind, const Identity& id) {
    if (kind == NodeConfig::Security::Noise)
        return std::make_unique<NoiseSecurity>(id);
    return std::make_unique<PlaintextSecurity>(id);
}
} // namespace

Node::Node(NodeConfig config)
    : config_(std::move(config)),
      identity_(Identity::generate()),
      security_(make_security(config_.security, identity_)),
      reactors_(std::make_unique<ReactorPool>(config_.reactor_threads, *this, *security_)) {}

Node::~Node() {
    stop();
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

bool Node::start() {
    if (running_.exchange(true)) return false;
    init_socket_library();

    if (config_.enable_listen) {
        listen_socket_ = create_tcp_server(config_.listen_port, 128, config_.bind_address,
                                           AddressFamily::IPv4);
        if (!is_valid_socket(listen_socket_)) {
            LOG_ERROR("node", "Failed to listen on " << config_.bind_address << ":" << config_.listen_port);
            running_.store(false);
            return false;
        }
        listen_port_ = static_cast<uint16_t>(get_bound_port(listen_socket_));
        reactors_->listen(listen_socket_);
    }

    reactors_->start();
    LOG_INFO("node", "Node " << identity_.id.short_hex() << " started on port " << listen_port_
             << " (" << reactors_->size() << " reactor(s))");
    return true;
}

void Node::stop() {
    if (!running_.exchange(false)) return;
    reactors_->stop();  // joins reactor threads; closes all connections
}

// ── Connections ─────────────────────────────────────────────────────────────

void Node::connect(const Address& address) { connect(address.host, address.port); }

void Node::connect(const std::string& host, uint16_t port) {
    reactors_->pick().connect(host, port);
}

std::optional<PeerHandle> Node::peer(const PeerId& id) {
    auto route = directory_.route(id);
    if (!route) return std::nullopt;
    return make_peer(id, *route);
}

// ── Application messaging ────────────────────────────────────────────────────

void Node::send(const PeerId& to, std::string_view channel, ByteView payload) {
    auto route = directory_.route(to);
    if (!route) return;
    route_send(*route, FrameHeader{MessageType::App, 0, MessageRouter::channel_id(channel)},
               payload.to_bytes());
}

void Node::broadcast(std::string_view channel, ByteView payload) {
    auto data = std::make_shared<const Bytes>(payload.to_bytes());
    FrameHeader header{MessageType::App, 0, MessageRouter::channel_id(channel)};
    reactors_->for_each([&](Reactor& r) { r.broadcast(header, data); });
}

// ── PeerNetwork (subsystems) ─────────────────────────────────────────────────

void Node::send(const PeerId& to, MessageType type, ByteView payload) {
    auto route = directory_.route(to);
    if (!route) return;
    route_send(*route, FrameHeader{type, 0, 0}, payload.to_bytes());
}

void Node::broadcast(MessageType type, ByteView payload) {
    auto data = std::make_shared<const Bytes>(payload.to_bytes());
    FrameHeader header{type, 0, 0};
    reactors_->for_each([&](Reactor& r) { r.broadcast(header, data); });
}

std::vector<PeerId> Node::connected_peers() const {
    std::vector<PeerId> ids;
    for (const auto& info : directory_.snapshot()) ids.push_back(info.id);
    return ids;
}

// ── Routed send/close (used by Node and Peer) ───────────────────────────────

void Node::route_send(PeerRoute route, FrameHeader header, Bytes payload) {
    Reactor& reactor = reactors_->by_index(route.reactor);
    ConnId conn = route.conn;
    auto data = std::make_shared<Bytes>(std::move(payload));
    reactor.execute([&reactor, conn, header, data] {
        if (auto* c = reactor.find(conn)) c->send(header, ByteView(*data));
    });
}

void Node::route_close(PeerRoute route) {
    reactors_->by_index(route.reactor).close(route.conn, CloseReason::LocalClose);
}

// ── ConnectionDelegate (reactor thread) ─────────────────────────────────────

void Node::on_established(Connection& conn) {
    PeerInfo info;
    info.id        = conn.remote_id();
    info.direction = conn.role();

    PeerRoute route{conn.reactor_index(), conn.id()};
    directory_.add(info, route);

    if (on_peer_connected_) on_peer_connected_(make_peer(conn.remote_id(), route));
}

void Node::on_frame(Connection& conn, const Frame& frame) {
    PeerHandle peer = make_peer(conn.remote_id(), PeerRoute{conn.reactor_index(), conn.id()});
    if (!router_.dispatch(peer, frame)) {
        LOG_DEBUG("node", "No handler for frame from " << conn.remote_id().short_hex()
                  << " (type " << static_cast<int>(frame.header.type)
                  << ", channel " << frame.header.channel << ")");
    }
}

void Node::on_closed(Connection& conn, CloseReason reason) {
    // Only peers that actually established were registered.
    if (conn.remote_id().is_zero()) return;

    directory_.remove(conn.remote_id());
    if (on_peer_disconnected_) on_peer_disconnected_(conn.remote_id());
    (void)reason;
}

// ── Peer handle methods (defined here for the full Node type) ────────────────

void PeerHandle::send(std::string_view channel, ByteView payload) const {
    node_->route_send(route_, FrameHeader{MessageType::App, 0, MessageRouter::channel_id(channel)},
                      payload.to_bytes());
}

void PeerHandle::disconnect() const {
    node_->route_close(route_);
}

std::optional<PeerInfo> PeerHandle::info() const {
    return node_->directory_.info(id_);
}

} // namespace librats
