#include "node/node.h"
#include "node/host_events.h"
#include "node/identify.h"
#include "subsystems/message_json.h"
#include "security/noise_security.h"
#include "security/plaintext_security.h"
#include "util/fs.h"
#include "util/logger.h"
#include "util/network_monitor.h"
#include "util/network_utils.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <utility>

namespace librats {

namespace {

// Pick the listen socket's address family from the bind address:
//   - empty or "::"  → DualStack wildcard: one IPv6 socket that also accepts IPv4
//                      (IPv4-mapped), so the node is reachable over both families.
//   - other IPv6 literal (contains ':') → IPv6-only, bound to that interface.
//   - IPv4 literal / hostname → IPv4.
// A specific (non-wildcard) address pins a single interface, so dual-stack only
// applies to the wildcard cases where binding both families is meaningful.
AddressFamily family_for_bind(const std::string& bind_address) {
    if (bind_address.empty() || bind_address == "::") return AddressFamily::DualStack;
    if (bind_address.find(':') != std::string::npos)   return AddressFamily::IPv6;
    return AddressFamily::IPv4;
}

// A wildcard/empty IP is never a dialable endpoint; filter it out of identify.
bool is_unspecified_ip(const std::string& ip) {
    return ip.empty() || ip == "0.0.0.0" || ip == "::";
}

std::unique_ptr<SecurityProvider> make_security(const NodeConfig& cfg, const Identity& id) {
    if (cfg.security == NodeConfig::Security::Noise)
        return std::make_unique<NoiseSecurity>(id, cfg.protocol_name, cfg.protocol_version);
    return std::make_unique<PlaintextSecurity>(id, cfg.protocol_name, cfg.protocol_version);
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
      security_(make_security(config_, identity_)),
      reactors_(std::make_unique<ReactorPool>(config_.reactor_threads, *this, *security_)) {
    max_peers_.store(config_.max_peers, std::memory_order_relaxed);
}

Node::~Node() {
    stop();
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

MessageJson* Node::json() noexcept { return subsystem<MessageJson>(); }

bool Node::start() {
    if (running_.exchange(true)) return false;
    init_socket_library();

    if (config_.enable_listen) {
        listen_socket_ = create_tcp_server(config_.listen_port, 128, config_.bind_address,
                                           family_for_bind(config_.bind_address));
        if (!is_valid_socket(listen_socket_)) {
            LOG_ERROR("node", "Failed to listen on " << config_.bind_address << ":" << config_.listen_port);
            running_.store(false);
            return false;
        }
        listen_port_ = static_cast<uint16_t>(get_bound_port(listen_socket_));
        reactors_->listen(listen_socket_);
    }

    // Compute our advertised addresses once; the network monitor refreshes them
    // on change. Done here (not per-connection) so the send path stays syscall-free.
    rebuild_advertised_addresses(network_utils::get_local_interface_addresses());

    // Attach subsystems (registers their message handlers, event subscriptions
    // and service providers) BEFORE any reactor thread runs, so the router and the
    // event/service tables are fully built with no concurrent writes.
    NodeContext ctx{*this, events_, services_};
    for (auto& s : subsystems_) s->attach(ctx);

    reactors_->start();

    for (auto& s : subsystems_) s->start();

    start_network_monitor();

    LOG_INFO("node", "Node " << identity_.id.short_hex() << " started on port " << listen_port_
             << " (" << reactors_->size() << " reactor(s), " << subsystems_.size() << " subsystem(s))");
    return true;
}

void Node::stop() {
    if (!running_.exchange(false)) return;
    stop_network_monitor();                 // no more NetworkChanged after this
    // Stop subsystems in reverse attach order, so a subsystem that depends on an
    // earlier one (e.g. Bittorrent borrowing DhtDiscovery's DhtClient) tears down
    // before the dependency it borrowed is itself stopped and destroyed.
    for (auto it = subsystems_.rbegin(); it != subsystems_.rend(); ++it) (*it)->stop();
    reactors_->stop();                      // then join reactors; close connections
    LOG_INFO("node", "Node " << identity_.id.short_hex() << " stopped");
}

// ── Host network-change watch ────────────────────────────────────────────────
//
// One monitor, many reactors: the NetworkMonitor detects a change on its own
// thread and hands the new address set to the maintenance thread, which performs
// the (possibly slow) EventBus emit. Subscribers — PortMappingService, DhtDiscovery,
// … — react independently without the monitor knowing they exist.

void Node::start_network_monitor() {
    if (!config_.enable_network_monitor) return;

    maintenance_stop_ = false;
    maintenance_thread_ = std::thread([this] { maintenance_loop(); });

    monitor_ = std::make_unique<NetworkMonitor>();
    monitor_->start([this](const std::vector<std::string>& addresses) {
        // Runs on the monitor thread; just hand off and return promptly. Coalesces:
        // a burst collapses to one emit carrying the latest address set.
        {
            std::lock_guard<std::mutex> lock(maintenance_mutex_);
            pending_addresses_   = addresses;
            maintenance_pending_ = true;
        }
        maintenance_cv_.notify_one();
    });
}

void Node::stop_network_monitor() {
    monitor_.reset();  // joins the monitor thread → no further hand-offs

    {
        std::lock_guard<std::mutex> lock(maintenance_mutex_);
        maintenance_stop_ = true;
    }
    maintenance_cv_.notify_one();
    if (maintenance_thread_.joinable()) maintenance_thread_.join();
}

void Node::maintenance_loop() {
    for (;;) {
        std::vector<std::string> addresses;
        {
            std::unique_lock<std::mutex> lock(maintenance_mutex_);
            maintenance_cv_.wait(lock, [this] { return maintenance_pending_ || maintenance_stop_; });
            if (maintenance_stop_) return;
            maintenance_pending_ = false;
            addresses = std::move(pending_addresses_);
        }
        LOG_INFO("node", "Network change: " << addresses.size()
                 << " local address(es); notifying subsystems");
        rebuild_advertised_addresses(addresses);  // keep identify's advertised set fresh
        events_.emit(NetworkChanged{std::move(addresses)});
    }
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
        LOG_INFO("node", "Peer " << conn.remote_id().short_hex() << " connected ("
                 << (conn.role() == ConnRole::Inbound ? "inbound" : "outbound") << ")");
        Peer handle = make_peer(conn.remote_id(), route);
        for (auto& cb : peer_connected_) cb(handle);
    }

    // Tell the peer how to reach us, and what address we see it at. Skipped for a
    // rejected duplicate (its connection was just closed above); sent on the
    // surviving link otherwise — including the winner of a cross-connect race.
    if (outcome.result != PeerTable::AddResult::Rejected)
        send_identify(conn);
}

void Node::on_frame(Connection& conn, const Frame& frame) {
    // Control is the node's own plane (identify); it never reaches the app router.
    if (frame.header.type == MessageType::Control) {
        handle_identify(conn, frame);
        return;
    }
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
    LOG_INFO("node", "Peer " << id.short_hex() << " disconnected (" << to_string(reason) << ")");
    for (auto& cb : peer_disconnected_) cb(id);
}

// ── Identify: dialable-address discovery (reactor thread) ────────────────────
//
// A TCP socket only exposes a peer's ephemeral source port, so an inbound peer's
// dialable address is unknowable from the connection alone. Right after the
// handshake each side sends a Control/identify frame; the receiver pairs the
// peer's advertised listen port with the IP it sees to recover the dialable
// address, and learns its own public address from the peer's observation.

void Node::send_identify(Connection& conn) {
    IdentifyMessage msg;
    msg.listen_port = listen_port_;
    msg.addresses   = advertised_addresses();
    const std::string seen_ip = conn.remote_ip();
    if (!is_unspecified_ip(seen_ip))
        msg.observed = Address{seen_ip, 0};  // port is the peer's ephemeral; IP is what matters

    const Bytes payload = msg.encode();
    conn.send(FrameHeader{MessageType::Control, 0, 0}, ByteView(payload));
}

void Node::handle_identify(Connection& conn, const Frame& frame) {
    const auto msg = IdentifyMessage::decode(frame.payload);
    if (!msg) {
        LOG_DEBUG("node", "Ignoring malformed identify from " << conn.remote_id().short_hex());
        return;
    }

    // The peer's dialable addresses: the address we see it at paired with its
    // advertised listen port (the linchpin for inbound peers), plus any extra
    // addresses it self-advertised. PeerTable de-duplicates and caps the set.
    std::vector<Address> candidates;
    const std::string seen_ip = conn.remote_ip();
    if (msg->listen_port != 0 && !is_unspecified_ip(seen_ip))
        candidates.push_back(Address{seen_ip, msg->listen_port});
    for (const Address& a : msg->addresses)
        if (a.port != 0 && !is_unspecified_ip(a.ip))
            candidates.push_back(a);

    if (!candidates.empty()) {
        const PeerRoute route{conn.reactor_index(), conn.id()};
        const auto added = directory_.add_addresses(conn.remote_id(), route, candidates);
        if (!added.empty())
            LOG_DEBUG("node", "Learned " << added.size() << " address(es) for peer "
                      << conn.remote_id().short_hex() << " (e.g. " << added.front().to_string() << ")");
    }

    // Learn our own public address: pair the IP the peer saw us at with OUR listen
    // port (its observed port is our ephemeral source port, not dialable).
    if (msg->observed && listen_port_ != 0 && !is_unspecified_ip(msg->observed->ip))
        record_observed_address(Address{msg->observed->ip, listen_port_});
}

std::vector<Address> Node::advertised_addresses() const {
    std::lock_guard<std::mutex> lock(advertised_mutex_);
    return advertised_addresses_;  // hot path: just hand back the stored snapshot
}

void Node::rebuild_advertised_addresses(const std::vector<std::string>& local_ips) {
    // Pair each local interface IP with our listen port. A non-listening node has
    // nothing dialable to advertise. Called off the hot path: once at start() and
    // again whenever the NetworkMonitor reports the interface set changed.
    std::vector<Address> fresh;
    if (listen_port_ != 0) {
        for (const std::string& ip : local_ips) {
            if (is_unspecified_ip(ip)) continue;
            fresh.push_back(Address{ip, listen_port_});
            if (fresh.size() >= IdentifyMessage::kMaxAddresses) break;
        }
    }
    std::lock_guard<std::mutex> lock(advertised_mutex_);
    advertised_addresses_ = std::move(fresh);
}

void Node::record_observed_address(const Address& addr) {
    std::lock_guard<std::mutex> lock(observed_mutex_);
    if (std::find(observed_addresses_.begin(), observed_addresses_.end(), addr) != observed_addresses_.end())
        return;
    if (observed_addresses_.size() >= 16) return;  // bound (NAT remap churn / hostile peers)
    observed_addresses_.push_back(addr);
    LOG_DEBUG("node", "Observed own address " << addr.to_string() << " (reported by a peer)");
}

std::vector<Address> Node::observed_addresses() const {
    std::lock_guard<std::mutex> lock(observed_mutex_);
    return observed_addresses_;
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
