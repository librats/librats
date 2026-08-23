#include "librats/node/node.h"
#include "librats/node/host_events.h"
#include "librats/node/identify.h"
#include "librats/subsystems/message_json.h"
#include "librats/security/noise_security.h"
#include "librats/security/plaintext_security.h"
#include "librats/util/fs.h"
#include "librats/util/logger.h"
#include "librats/util/network_monitor.h"
#include "librats/util/network_utils.h"

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
        return std::make_unique<NoiseSecurity>(id, cfg.protocol);
    return std::make_unique<PlaintextSecurity>(id, cfg.protocol);
}

// Load a persisted identity from <data_dir>/identity.key, or generate one and
// save it. An empty data_dir means ephemeral (fresh identity each run).
Identity load_or_create_identity(const std::string& data_dir) {
    if (data_dir.empty()) return Identity::generate();

    const std::string key_path = combine_paths(data_dir, "identity.key");

    size_t size = 0;
    void* data = read_file_binary(key_path.c_str(), &size);
    if (data) {
        if (size == librats::NOISE_DH_SIZE) {
            uint8_t priv[librats::NOISE_DH_SIZE];
            std::memcpy(priv, data, librats::NOISE_DH_SIZE);
            free_file_buffer(data);
            return Identity::from_private_key(priv);
        }
        free_file_buffer(data);  // malformed key file → regenerate
        LOG_WARN("node", "Ignoring malformed identity key at " << key_path);
    }

    Identity identity = Identity::generate();
    create_directories(data_dir.c_str());
    if (!create_file_binary(key_path.c_str(), identity.static_keypair.private_key, librats::NOISE_DH_SIZE))
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

    DialPolicy policy;
    policy.preferred      = config_.preferred_transport;
    policy.allow_tcp      = config_.enable_tcp;
    policy.allow_udp      = config_.enable_udp;
    policy.fallback_delay = std::chrono::milliseconds(config_.transport_fallback_ms);
    dialer_ = std::make_unique<Dialer>(*reactors_, policy,
                                       [this](const std::string& host, uint16_t port) {
                                           report_dial_failed(host, port);
                                       });

    // Published here rather than in start(): a subsystem resolves what it needs
    // during attach(), which runs before start(), and both of these are node state
    // that exists from construction. Neither extends Node's public surface — they
    // are narrow capabilities a module asks for by interface (see
    // node/dial_service.h, node/nat_status.h).
    services_.provide<DialService>(this);
    services_.provide<CircuitService>(this);
    services_.provide<ExternalAddressService>(&nat_status_);
}

Node::~Node() {
    stop();
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

MessageJson* Node::json() noexcept { return subsystem<MessageJson>(); }

bool Node::open_listeners() {
    // Attempts at finding a port that is free for BOTH transports. A clash
    // between the two is unlikely (TCP and UDP have separate port spaces) but it
    // is not impossible, and silently landing on mismatched ports would make
    // every address this node advertises half-wrong. The same attempts cover a
    // configured port that some other process already holds: attempt N tries
    // listen_port + N, so one squatter on the default port does not leave the
    // host without a node.
    constexpr int kBindAttempts = 5;

    const AddressFamily family = family_for_bind(config_.bind_address);
    const bool listen_tcp = config_.enable_listen && config_.enable_tcp;
    const bool listen_udp = config_.enable_listen && config_.enable_udp;

    if (config_.enable_listen && !listen_tcp && !listen_udp) {
        LOG_ERROR("node", "enable_listen is set but neither transport is enabled");
        return false;
    }

    if (!config_.enable_listen) {
        // Dial-only. TCP needs no socket up front, but the datagram transport
        // still wants its one shared socket — that single socket is what gives
        // every peer one NAT mapping instead of one each. It just does not need a
        // predictable port, since nobody dials us.
        if (!config_.enable_udp) return true;
        udp_socket_ = create_udp_socket(0, config_.bind_address, family);
        if (!is_valid_socket(udp_socket_))
            LOG_WARN("node", "Could not open a UDP socket; dials will fall back to TCP");
        else
            reactors_->listen_udp(udp_socket_, family);
        return true;
    }

    for (int attempt = 0; attempt < kBindAttempts; ++attempt) {
        socket_t udp  = RATS_INVALID_SOCKET;
        socket_t tcp  = RATS_INVALID_SOCKET;

        // Walk upward from the configured port; an ephemeral one is re-requested
        // as 0 each time, since the kernel picks a different port on its own.
        const int candidate = config_.listen_port == 0 ? 0 : config_.listen_port + attempt;
        if (candidate > 65535) break;
        uint16_t port = static_cast<uint16_t>(candidate);

        // Which socket names the port, and which one has to accept the name.
        //
        // Whichever binds second is the one that can be refused: the kernel only
        // ever hands out a port that is free for the protocol it is allocating
        // for, and the two protocols have separate port spaces. So the order is a
        // choice of which refusal to face, and the sides are not symmetric.
        //
        // The stream socket names it first, because the scarcity is on its side.
        // Both draw from the same ephemeral range, but every outbound TCP
        // connection on the host holds a source port in it, and goes on holding
        // it through TIME_WAIT after it closes; a busy machine keeps tens of
        // thousands there, and nearly nothing competes for the UDP half of the
        // same range. Letting UDP name the port and then demanding TCP match it
        // is a bet against that crowd, and under load it loses often enough to
        // fail a node's start outright.
        //
        // That reasoning is about a port being *taken*, though, and on Windows
        // the usual refusal is a port being *reserved* — the blocks Hyper-V,
        // WinNAT and WSL2 carve out of the ephemeral range, which are not the
        // same blocks for the two protocols. Against a reservation, retrying the
        // same way barely moves: Windows hands out ephemeral ports in ascending
        // order while a reserved block is contiguous and can be hundreds wide, so
        // each retry lands one port further into the same hole. A retry therefore
        // swaps the roles rather than repeating them — an ephemeral bind on the
        // refused side steps clear of that side's reservations in one move, since
        // the kernel never allocates out of them. Only worth doing when the port
        // is ours to choose, and never on the last attempt, so running out of
        // attempts still ends on the conservative order.
        const bool udp_names_port = listen_tcp && listen_udp && port == 0
                                    && attempt % 2 == 1 && attempt + 1 < kBindAttempts;
        if (udp_names_port) {
            udp = create_udp_socket(0, config_.bind_address, family);
            // Failing on a port the kernel picked itself is not a failure another
            // port would fix, so there is nothing to walk to: leave the datagram
            // socket to the usual path below and let TCP name the port after all.
            if (is_valid_socket(udp))
                port = static_cast<uint16_t>(get_bound_port(udp));
        }

        if (listen_tcp) {
            tcp = create_tcp_server(port, 128, config_.bind_address, family);
            if (!is_valid_socket(tcp)) {
                // A port that is taken, or that Windows keeps reserved, is the
                // bind failure another port can answer. Every other one — no
                // permission for a privileged port, a bind address that is not on
                // this host, IPv6 switched off — fails identically on all 65535 of
                // them, and walking the range would only bury the real error under
                // four more copies of it.
                const bool retry = last_error_was_port_unavailable()
                                   && attempt + 1 < kBindAttempts;
                if (is_valid_socket(udp)) close_socket(udp);
                if (retry) {
                    LOG_WARN("node", "TCP port " << port << " is unavailable, trying another");
                    continue;
                }
                LOG_ERROR("node", "Failed to listen on "
                          << config_.bind_address << ":" << port);
                return false;
            }
            if (port == 0) port = static_cast<uint16_t>(get_bound_port(tcp));
        }

        // Skipped when the datagram socket already has the port: it named it.
        if (listen_udp && !is_valid_socket(udp)) {
            udp = create_udp_socket(port, config_.bind_address, family);
            if (is_valid_socket(udp)) {
                if (port == 0) port = static_cast<uint16_t>(get_bound_port(udp));
            } else if (listen_tcp) {
                // Worth another attempt only for a port another port would fix,
                // and only while the next attempt would actually move: both the
                // ephemeral case and the configured one land on a different port
                // next time round. Windows makes this path the common one — its
                // reserved ranges differ between TCP and UDP, so a port the stream
                // socket was handed can be refused to the datagram one.
                if (last_error_was_port_unavailable() && attempt + 1 < kBindAttempts) {
                    close_socket(tcp);
                    continue;
                }
                // Out of attempts, or a failure no other port would fix: the node
                // still has a working transport, so it runs on that one rather
                // than refusing to start.
                LOG_WARN("node", "UDP port " << port << " unavailable; this node runs TCP-only");
            } else {
                // UDP-only node: nothing to fall back to, so an unavailable port
                // is walked past exactly as it is for TCP above.
                if (last_error_was_port_unavailable() && attempt + 1 < kBindAttempts) {
                    LOG_WARN("node", "UDP port " << port << " is unavailable, trying another");
                    continue;
                }
                LOG_ERROR("node", "Failed to listen on UDP "
                          << config_.bind_address << ":" << port);
                return false;
            }
        }

        if (config_.listen_port != 0 && port != config_.listen_port) {
            LOG_WARN("node", "Configured port " << config_.listen_port
                     << " was unavailable; listening on " << port << " instead");
        }

        listen_socket_ = tcp;
        udp_socket_    = udp;
        listen_port_   = port;
        if (is_valid_socket(tcp)) {
            reactors_->listen(tcp);
            transports_ |= PeerTransportTcp;
        }
        if (is_valid_socket(udp)) {
            reactors_->listen_udp(udp, family);
            transports_ |= PeerTransportUdp;
        }
        return true;
    }

    // Reached only by running the port range off its end; the last attempt does
    // not retry, it settles for the transport it has.
    LOG_ERROR("node", "No free port found from " << config_.listen_port
              << " upward for " << config_.bind_address);
    return false;
}

bool Node::start() {
    if (running_.exchange(true)) return false;
    init_socket_library();

    dialer_->start();  // a node may be restarted; clear any state from the last run

    if (!open_listeners()) {
        running_.store(false);
        return false;
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
             << " (" << ((transports_ & PeerTransportTcp) ? "tcp" : "")
             << ((transports_ == (PeerTransportTcp | PeerTransportUdp)) ? "+" : "")
             << ((transports_ & PeerTransportUdp) ? "udp" : "")
             << ", " << reactors_->size() << " reactor(s), "
             << subsystems_.size() << " subsystem(s))");
    return true;
}

void Node::stop() {
    if (!running_.exchange(false)) return;
    dialer_->stop();                        // no more fallback attempts get started
    stop_network_monitor();                 // no more NetworkChanged after this
    // Stop subsystems in reverse attach order, so a subsystem that depends on an
    // earlier one (e.g. Bittorrent borrowing DhtDiscovery's DhtClient) tears down
    // before the dependency it borrowed is itself stopped and destroyed.
    for (auto it = subsystems_.rbegin(); it != subsystems_.rend(); ++it) (*it)->stop();
    reactors_->stop();                      // then join reactors; close connections
    // The listen sockets are owned by us, not the reactors — close them here,
    // after the reactor threads have joined (so nothing is still polling them), to
    // release the bound port immediately on stop() rather than leaking it until
    // destruction.
    if (is_valid_socket(listen_socket_)) {
        close_socket(listen_socket_);
        listen_socket_ = RATS_INVALID_SOCKET;
    }
    if (is_valid_socket(udp_socket_)) {
        close_socket(udp_socket_);
        udp_socket_ = RATS_INVALID_SOCKET;
    }
    transports_ = 0;
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
        // Every external endpoint we learned was a mapping made by the path that
        // just changed underneath us. Holding on to it would aim a punch at a port
        // that no longer exists; peers re-report as their links come back.
        nat_status_.reset();
        events_.emit(NetworkChanged{std::move(addresses)});
    }
}

// ── Connections ─────────────────────────────────────────────────────────────

void Node::connect(const Address& address) { connect(address.ip.to_string(), address.port); }

void Node::connect(const std::string& host, uint16_t port) {
    // The dialer owns the transport choice: preferred first, the other raced in
    // after the fallback delay, loser dropped. See node/dialer.h.
    dialer_->dial(host, port);
}

bool Node::dial_direct(const Address& addr, TransportKind kind, const DialProfile& profile) {
    if (!addr.is_valid()) return false;
    if (kind == TransportKind::Udp && !reactors_->has_udp()) return false;
    if (kind == TransportKind::Tcp && !config_.enable_tcp)   return false;
    // A relayed circuit is not dialed: it is negotiated with a third node and then
    // adopted (see node/circuit_service.h). There is no address to aim at here.
    if (kind == TransportKind::Relay) return false;

    // Straight to the reactor, deliberately around the Dialer: this dial is not a
    // race and must not become one (see node/dial_service.h). The Dialer is left
    // unaware of it, which is exactly right — its bookkeeping is keyed by
    // (reactor, conn) and simply does not match, so the connection's later
    // established/closed reports are no-ops there rather than corrections.
    const ConnId id = reactors_->pick(kind).connect(addr.ip.to_string(), addr.port, kind, profile);
    return id != kInvalidConnId;
}

// ── CircuitService: a relayed byte stream becomes a peer connection ─────────

std::optional<PeerRoute> Node::adopt_circuit(const PeerId& carrier, std::unique_ptr<Link> link,
                                             ConnRole role, bool connected) {
    if (!link) return std::nullopt;

    // The carrier has to still be a peer: it is the only thing this circuit's bytes
    // can travel through, and a connection whose carrier is already gone would
    // simply sit there until the establish deadline reaped it.
    const auto carrier_route = peers_.route(carrier);
    if (!carrier_route) return std::nullopt;

    // Inbound circuits go through the same admission gate as an accepted socket.
    // A relayed connection is cheaper for whoever opens it than a direct one — no
    // NAT to get through, someone else's bandwidth — so if anything it deserves the
    // gate more, not less.
    if (role == ConnRole::Inbound && !admit_inbound()) return std::nullopt;

    Reactor& reactor = reactors_->by_index(carrier_route->reactor);
    // Same reactor as the carrier, which is the whole point: every byte of this
    // circuit arrives on the carrier's connection and leaves through it, so the two
    // share a thread and the relayed path needs no locks and no hand-offs.
    const ConnId id = reactor.reserve_conn_id();
    reactor.adopt_link(id, std::move(link), role, connected);
    return PeerRoute{carrier_route->reactor, id};
}

void Node::wake_circuit(PeerRoute route, uint32_t events) {
    reactors_->by_index(route.reactor).wake(route.conn, events);
}

void Node::close_circuit(PeerRoute route, CloseReason reason) {
    reactors_->by_index(route.reactor).close(route.conn, reason);
}

void Node::report_dial_failed(const std::string& host, uint16_t port) {
    // Only a numeric target can be handed on as an Address; a dial by hostname has
    // no dialable Address to report (peers cannot use our resolver), and the
    // subscribers of this event — a reconnection policy, say — deal in addresses.
    const auto ip = IpAddress::parse(host);
    if (!ip) return;
    const Address addr{*ip, port};
    for (auto& cb : dial_failed_) cb(addr);
}

std::optional<Peer> Node::peer(const PeerId& id) {
    auto route = peers_.route(id);
    if (!route) return std::nullopt;
    return make_peer(id, *route);
}

// ── Application messaging ────────────────────────────────────────────────────

bool Node::send(const PeerId& to, std::string_view channel, ByteView payload) {
    // Route and writability in one lookup. The answer is the queue's state as of
    // now rather than after this message lands — the send itself is handed to the
    // owning reactor and completes there — which is all a backpressure hint can
    // ever be, and is enough: it is the *previous* messages that filled the queue.
    auto dest = peers_.destination(to);
    if (!dest) return false;
    // Charged before the hand-off and discharged by the reactor task, so a caller
    // in a tight loop is answered on what it has actually offered rather than on
    // what the reactor has managed to look at so far.
    const size_t in_transit =
        dest->owed->fetch_add(payload.size(), std::memory_order_relaxed) + payload.size();
    route_send(dest->route, FrameHeader{MessageType::App, 0, MessageRouter::channel_id(channel)},
               payload.to_bytes(), dest->owed);
    return dest->writable && in_transit <= send_low_water();
}

bool Node::peer_writable(const PeerId& id) const {
    const auto dest = peers_.destination(id);
    return dest && dest->writable;
}

bool Node::broadcast(std::string_view channel, ByteView payload) {
    auto data = std::make_shared<const Bytes>(payload.to_bytes());
    FrameHeader header{MessageType::App, 0, MessageRouter::channel_id(channel)};
    reactors_->for_each([&](Reactor& r) { r.broadcast(header, data); });
    return peers_.all_writable();
}

// ── PeerNetwork (subsystems) ─────────────────────────────────────────────────

bool Node::send(const PeerId& to, MessageType type, ByteView payload) {
    auto dest = peers_.destination(to);
    if (!dest) return false;
    const size_t in_transit =
        dest->owed->fetch_add(payload.size(), std::memory_order_relaxed) + payload.size();
    route_send(dest->route, FrameHeader{type, 0, 0}, payload.to_bytes(), dest->owed);
    return dest->writable && in_transit <= send_low_water();
}

bool Node::broadcast(MessageType type, ByteView payload) {
    auto data = std::make_shared<const Bytes>(payload.to_bytes());
    FrameHeader header{type, 0, 0};
    reactors_->for_each([&](Reactor& r) { r.broadcast(header, data); });
    return peers_.all_writable();
}

std::vector<PeerId> Node::connected_peers() const {
    std::vector<PeerId> ids;
    for (const auto& info : peers_.snapshot()) ids.push_back(info.id);
    return ids;
}

// ── Routed send/close (used by Node and Peer) ───────────────────────────────

void Node::route_send(PeerRoute route, FrameHeader header, Bytes payload,
                      std::shared_ptr<std::atomic<size_t>> owed) {
    Reactor& reactor = reactors_->by_index(route.reactor);
    ConnId conn = route.conn;
    auto data = std::make_shared<Bytes>(std::move(payload));
    const size_t weight = data->size();
    reactor.execute([&reactor, conn, header, data, owed, weight] {
        // Discharged whether or not the connection is still there, and *before*
        // the frame is queued rather than after: from here on these bytes are
        // counted by the send queue instead, and the connection weighs both
        // together (Connection::backlog). Discharging afterwards would leave a
        // window where they were counted twice — and, worse, one where they were
        // counted by neither, which is what an opening must never be reported on.
        if (owed) owed->fetch_sub(weight, std::memory_order_relaxed);
        if (auto* c = reactor.find(conn)) c->send(header, ByteView(*data));
    });
}

size_t Node::send_low_water() const noexcept {
    const size_t limit = config_.send_queue_limit != 0 ? config_.send_queue_limit
                                                       : Connection::kDefaultSendHighWater;
    return limit / 4;
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
    return cap == 0 || peers_.size() < cap;
}

void Node::on_established(Connection& conn) {
    if (config_.send_queue_limit != 0) conn.set_send_high_water(config_.send_queue_limit);

    // Settle the dial race first: this attempt won its target, so any sibling
    // attempt over the other transport is redundant and gets cancelled — unless it
    // has established too, in which case it arrives here as an ordinary duplicate
    // and the peer table decides between them (see dialer.h). Done before
    // the checks below so a self-connection or a rejected duplicate still counts
    // as "this dial resolved" rather than leaving the race running.
    if (conn.role() == ConnRole::Outbound)
        dialer_->on_established(PeerRoute{conn.reactor_index(), conn.id()});

    // Reject self-connections: a self-certifying handshake against our own
    // listener yields our own id. (Common once DHT/discovery starts dialing.)
    if (conn.remote_id() == identity_.id) {
        reactors_->by_index(conn.reactor_index()).close(conn.id(), CloseReason::LocalClose);
        return;
    }

    // Peer-limit backstop. Inbound handshakes that raced past admit_inbound()
    // before the cap was hit are rejected here, now that we know the remote id.
    // A reconnect/duplicate of an already-known peer does not grow the count, so
    // it is allowed through (the peer-table tie-break supersedes the old link).
    // Our own outbound dials are intentional and never rejected.
    const size_t cap = max_peers_.load(std::memory_order_relaxed);
    if (cap != 0 && conn.role() == ConnRole::Inbound &&
        peers_.size() >= cap && !peers_.contains(conn.remote_id())) {
        LOG_DEBUG("node", "Rejecting inbound peer " << conn.remote_id().short_hex()
                  << "; peer limit (" << cap << ") reached");
        reactors_->by_index(conn.reactor_index()).close(conn.id(), CloseReason::PeerLimit);
        return;
    }

    PeerInfo info;
    info.id        = conn.remote_id();
    info.direction = conn.role();
    info.transport = conn.transport();
    // Outbound: remember the address we dialed — but only if it was a numeric IP.
    // A dial-by-hostname target isn't a dialable Address (peers can't use our name),
    // and the resolved IP is re-learned via identify anyway.
    if (conn.has_dial_address())
        if (auto ip = IpAddress::parse(conn.dial_host()))
            info.addresses.push_back(Address{*ip, conn.dial_port()});

    const PeerRoute route{conn.reactor_index(), conn.id()};
    // Symmetric tie-break for a simultaneous cross-connect: both peers keep the
    // link initiated by the smaller id, so they converge on the same connection.
    const bool prefer_outbound = identity_.id < conn.remote_id();
    const auto outcome = peers_.add(info, route, prefer_outbound);

    // Tear down the loser of a duplicate/cross-connect race so it can't linger
    // holding an fd. Its on_closed is a no-op: the peer table no longer maps its
    // route, so it neither evicts the survivor nor fires a spurious disconnect.
    if (outcome.close)
        reactors_->by_index(outcome.close->reactor).close(outcome.close->conn, CloseReason::DuplicateConn);

    // Hand the peer's in-transit counter to the connection that now carries its
    // traffic, so the send queue's marks weigh what callers have offered as well
    // as what is already queued — the two halves of one backlog, and the reason a
    // caller told "no room" is always the one told when the room comes back. The
    // route check keeps the loser of a race off the survivor's counter.
    if (const auto dest = peers_.destination(conn.remote_id()); dest && dest->route == route)
        conn.set_in_transit(dest->owed);

    // Fire "connected" only on the 0→1 transition. A reconnect/duplicate that
    // merely swapped the live route keeps the peer connected from the app's view.
    if (outcome.result == PeerTable::AddResult::NewPeer) {
        LOG_INFO("node", "Peer " << conn.remote_id().short_hex() << " connected ("
                 << (conn.role() == ConnRole::Inbound ? "inbound" : "outbound")
                 << " over " << to_string(conn.transport()) << ")");
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
    // Tell the dial race this attempt is out. If it was the last one and none
    // succeeded, the dialer reports the target as failed — a redial policy
    // (ReconnectionService) needs to know its in-flight dial resolved, or it would
    // wait out a timeout before retrying. The dialer coalesces that into exactly
    // one report per target, however many transports were raced.
    if (conn.role() == ConnRole::Outbound)
        dialer_->on_closed(PeerRoute{conn.reactor_index(), conn.id()});

    // Only peers that actually established were registered.
    if (conn.remote_id().is_zero()) return;

    const PeerId    id = conn.remote_id();
    const PeerRoute route{conn.reactor_index(), conn.id()};

    // Disconnect fires only for the connection currently registered for this peer.
    // A loser of a duplicate race (or a rejected self-connection) is not mapped
    // under its route, so removing it is a no-op and must NOT surface a disconnect
    // for a peer that is still connected over the surviving link.
    if (!peers_.remove(id, route)) return;
    // What this peer told us about our external endpoint went with it: the mapping
    // it observed may well have been made for its link alone, and keeping it would
    // let a long-gone peer keep voting on how our NAT behaves.
    nat_status_.forget(id);
    LOG_INFO("node", "Peer " << id.short_hex() << " disconnected (" << to_string(reason) << ")");
    for (auto& cb : peer_disconnected_) cb(id);
}

void Node::on_writable_changed(Connection& conn, bool writable) {
    // Only an established peer has a table entry to record this against; a
    // connection still handshaking cannot be sent to anyway.
    if (conn.remote_id().is_zero()) return;
    const PeerRoute route{conn.reactor_index(), conn.id()};
    peers_.set_writable(conn.remote_id(), route, writable);

    // Only the opening is worth waking anyone for. "You have filled up" is
    // already answered by send() returning false at the moment it happens, so an
    // event for it would tell the caller what it has just been told.
    if (!writable) return;
    Peer handle = make_peer(conn.remote_id(), route);
    for (auto& cb : peer_writable_) cb(handle);
}

void Node::on_dial_aborted(uint8_t reactor_index, ConnId id,
                           const std::string& /*host*/, uint16_t /*port*/) {
    // The attempt died before there was ever a Connection (unresolvable host, no
    // socket). It resolves exactly like a connection that closed without
    // establishing, so the dialer can move on to the next transport at once.
    dialer_->on_closed(PeerRoute{reactor_index, id});
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
    // Both transports share listen_port_, so which of them a peer may dial there
    // is a property of the node, not of the address — say it once, here.
    msg.transports  = transports_;
    const IpAddress seen_ip = conn.remote_ip();
    if (!seen_ip.is_any()) {
        // The port we saw the peer at is worth reporting on exactly one of the two
        // wires. On TCP it is an ephemeral port its OS picked for this one outbound
        // socket and tells the peer nothing it can use. On a datagram link every
        // peer shares ONE socket, so that port is what the peer's NAT mapped that
        // socket to — the port a third party has to aim at to reach it, and the
        // only thing a hole punch can be pointed at. So: report it there, and only
        // there. A zero port keeps the old meaning ("IP only"), which is what an
        // older peer already expects and what TCP still sends.
        uint16_t seen_port = 0;
        if (conn.transport() == TransportKind::Udp)
            if (const auto endpoint = conn.remote_endpoint()) seen_port = endpoint->port;
        msg.observed = Address{seen_ip, seen_port};
    }

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
    const PeerRoute identify_route{conn.reactor_index(), conn.id()};
    const IpAddress seen_ip = conn.remote_ip();
    if (msg->transports != 0) {
        peers_.set_supported_transports(conn.remote_id(), identify_route, msg->transports);
        // ...and tell the dialer, which is the half that actually saves anything:
        // without it every later dial to this address pays the fallback delay again
        // to rediscover what we are being told right here. Only addresses this node
        // can vouch for are recorded — the one we dialed ourselves, and the IP we
        // observe the peer at paired with the listen port it claims. The addresses
        // in msg->addresses are the peer's unverified word about where *anyone*
        // lives, so letting them carry a transports mask would let one peer set the
        // dial order for somebody else's address.
        if (conn.has_dial_address())
            dialer_->remember(conn.dial_host(), conn.dial_port(), msg->transports);
        if (msg->listen_port != 0 && !seen_ip.is_any())
            dialer_->remember(seen_ip.to_string(), msg->listen_port, msg->transports);
    }

    std::vector<Address> candidates;
    if (msg->listen_port != 0 && !seen_ip.is_any())
        candidates.push_back(Address{seen_ip, msg->listen_port});
    for (const Address& a : msg->addresses)
        if (a.port != 0 && !a.ip.is_any())
            candidates.push_back(a);

    if (!candidates.empty()) {
        const auto added = peers_.add_addresses(conn.remote_id(), identify_route, candidates);
        if (!added.empty())
            LOG_DEBUG("node", "Learned " << added.size() << " address(es) for peer "
                      << conn.remote_id().short_hex() << " (e.g. " << added.front().to_string() << ")");
    }

    // Learn our own public address: pair the IP the peer saw us at with OUR listen
    // port, since on TCP its observed port is our ephemeral source port and is not
    // dialable.
    if (msg->observed && !msg->observed->ip.is_any()) {
        if (listen_port_ != 0)
            record_observed_address(Address{msg->observed->ip, listen_port_});

        // A datagram peer reports the port as well, and there it is not ephemeral:
        // it is what a NAT mapped our one shared socket to. That endpoint — not the
        // listen port, which a NAT is under no obligation to preserve — is what a
        // third peer would have to aim at, so it is kept apart from the address set
        // above and classified across peers (see node/nat_status.h).
        if (conn.transport() == TransportKind::Udp && msg->observed->port != 0)
            nat_status_.record_udp_observation(conn.remote_id(), *msg->observed,
                                               is_own_endpoint(*msg->observed));
    }
}

bool Node::is_own_endpoint(const Address& addr) const {
    std::lock_guard<std::mutex> lock(advertised_mutex_);
    // The advertised set is every local interface IP paired with our listen port —
    // so a match means the peer reached us without anything rewriting the endpoint
    // on the way, i.e. there is no NAT between us.
    return std::find(advertised_addresses_.begin(), advertised_addresses_.end(), addr) !=
           advertised_addresses_.end();
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
    return node_->peers_.info(id_);
}

} // namespace librats
