#include "node/node.h"
#include "security/noise_security.h"
#include "security/plaintext_security.h"
#include "util/fs.h"
#include "util/logger.h"

#include <cstring>
#include <memory>
#include <utility>

namespace librats {

namespace {

std::unique_ptr<SecurityProvider> make_security(NodeConfig::Security kind, const Identity& id) {
    if (kind == NodeConfig::Security::Noise)
        return std::make_unique<NoiseSecurity>(id);
    return std::make_unique<PlaintextSecurity>(id);
}

// Load a persisted identity from <data_dir>/identity.key, or generate one and
// save it. An empty data_dir means ephemeral (fresh identity each run).
Identity load_or_create_identity(const std::string& data_dir) {
    if (data_dir.empty()) return Identity::generate();

    const std::string key_path = combine_paths(data_dir, "identity.key");

    size_t size = 0;
    void* data = read_file_binary(key_path.c_str(), &size);
    if (data) {
        if (size == rats::NOISE_DH_SIZE) {
            uint8_t priv[rats::NOISE_DH_SIZE];
            std::memcpy(priv, data, rats::NOISE_DH_SIZE);
            free_file_buffer(data);
            return Identity::from_private_key(priv);
        }
        free_file_buffer(data);  // malformed key file → regenerate
        LOG_WARN("node", "Ignoring malformed identity key at " << key_path);
    }

    Identity identity = Identity::generate();
    create_directories(data_dir.c_str());
    if (!create_file_binary(key_path.c_str(), identity.static_keypair.private_key, rats::NOISE_DH_SIZE))
        LOG_WARN("node", "Failed to persist identity key to " << key_path);
    return identity;
}

} // namespace

Node::Node(NodeConfig config)
    : config_(std::move(config)),
      identity_(load_or_create_identity(config_.data_dir)),
      security_(make_security(config_.security, identity_)),
      reactors_(std::make_unique<ReactorPool>(config_.reactor_threads, *this, *security_)) {
    max_peers_.store(config_.max_peers, std::memory_order_relaxed);
}

Node::~Node() {
    stop();
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

void Node::add_subsystem(std::unique_ptr<Subsystem> subsystem) {
    subsystems_.push_back(std::move(subsystem));
}

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

    // Attach subsystems (registers their message handlers) BEFORE any reactor
    // thread runs, so the router is fully built with no concurrent writes.
    for (auto& s : subsystems_) s->attach(*this);

    reactors_->start();

    for (auto& s : subsystems_) s->start();

    LOG_INFO("node", "Node " << identity_.id.short_hex() << " started on port " << listen_port_
             << " (" << reactors_->size() << " reactor(s), " << subsystems_.size() << " subsystem(s))");
    return true;
}

void Node::stop() {
    if (!running_.exchange(false)) return;
    for (auto& s : subsystems_) s->stop();  // stop subsystem threads first
    reactors_->stop();                      // then join reactors; close connections
}

// ── Connections ─────────────────────────────────────────────────────────────

void Node::connect(const Address& address) { connect(address.ip, address.port); }

void Node::connect(const std::string& host, uint16_t port) {
    reactors_->pick().connect(host, port);
}

std::optional<Peer> Node::peer(const PeerId& id) {
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

bool Node::admit_inbound() {
    // Coarse gate at accept time: refuse new inbound when at capacity, before any
    // handshake cost. The exact per-peer cap (which can tell a reconnect of a
    // known peer from a brand-new one) is enforced in on_established below.
    const size_t cap = max_peers_.load(std::memory_order_relaxed);
    return cap == 0 || directory_.size() < cap;
}

void Node::on_established(Connection& conn) {
    // Reject self-connections: a self-certifying handshake against our own
    // listener yields our own id. (Common once DHT/discovery starts dialing.)
    if (conn.remote_id() == identity_.id) {
        reactors_->by_index(conn.reactor_index()).close(conn.id(), CloseReason::LocalClose);
        return;
    }

    // Peer-limit backstop. Inbound handshakes that raced past admit_inbound()
    // before the cap was hit are rejected here, now that we know the remote id.
    // A reconnect/duplicate of an already-known peer does not grow the count, so
    // it is allowed through (the directory tie-break supersedes the old link).
    // Our own outbound dials are intentional and never rejected.
    const size_t cap = max_peers_.load(std::memory_order_relaxed);
    if (cap != 0 && conn.role() == ConnRole::Inbound &&
        directory_.size() >= cap && !directory_.contains(conn.remote_id())) {
        LOG_DEBUG("node", "Rejecting inbound peer " << conn.remote_id().short_hex()
                  << "; peer limit (" << cap << ") reached");
        reactors_->by_index(conn.reactor_index()).close(conn.id(), CloseReason::PeerLimit);
        return;
    }

    PeerInfo info;
    info.id        = conn.remote_id();
    info.direction = conn.role();
    if (conn.has_dial_address())  // outbound: remember the address we dialed
        info.addresses.push_back(Address{conn.dial_host(), conn.dial_port()});

    const PeerRoute route{conn.reactor_index(), conn.id()};
    // Symmetric tie-break for a simultaneous cross-connect: both peers keep the
    // link initiated by the smaller id, so they converge on the same connection.
    const bool prefer_outbound = identity_.id < conn.remote_id();
    const auto outcome = directory_.add(info, route, prefer_outbound);

    // Tear down the loser of a duplicate/cross-connect race so it can't linger
    // holding an fd. Its on_closed is a no-op: the directory no longer maps its
    // route, so it neither evicts the survivor nor fires a spurious disconnect.
    if (outcome.close)
        reactors_->by_index(outcome.close->reactor).close(outcome.close->conn, CloseReason::DuplicateConn);

    // Fire "connected" only on the 0→1 transition. A reconnect/duplicate that
    // merely swapped the live route keeps the peer connected from the app's view.
    if (outcome.result == PeerTable::AddResult::NewPeer) {
        Peer handle = make_peer(conn.remote_id(), route);
        for (auto& cb : peer_connected_) cb(handle);
    }
}

void Node::on_frame(Connection& conn, const Frame& frame) {
    Peer peer = make_peer(conn.remote_id(), PeerRoute{conn.reactor_index(), conn.id()});
    if (!router_.dispatch(peer, frame)) {
        LOG_DEBUG("node", "No handler for frame from " << conn.remote_id().short_hex()
                  << " (type " << static_cast<int>(frame.header.type)
                  << ", channel " << frame.header.channel << ")");
    }
}

void Node::on_closed(Connection& conn, CloseReason reason) {
    // Only peers that actually established were registered.
    if (conn.remote_id().is_zero()) return;

    const PeerId    id = conn.remote_id();
    const PeerRoute route{conn.reactor_index(), conn.id()};

    // Disconnect fires only for the connection currently registered for this peer.
    // A loser of a duplicate race (or a rejected self-connection) is not mapped
    // under its route, so removing it is a no-op and must NOT surface a disconnect
    // for a peer that is still connected over the surviving link.
    if (!directory_.remove(id, route)) return;
    for (auto& cb : peer_disconnected_) cb(id);
    (void)reason;
}

// ── Peer handle methods (defined here for the full Node type) ────────────────

void Peer::send(std::string_view channel, ByteView payload) const {
    node_->route_send(route_, FrameHeader{MessageType::App, 0, MessageRouter::channel_id(channel)},
                      payload.to_bytes());
}

void Peer::disconnect() const {
    node_->route_close(route_);
}

std::optional<PeerInfo> Peer::info() const {
    return node_->directory_.info(id_);
}

} // namespace librats
