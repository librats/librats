#include "librats.h"
#include "librats_log_macros.h"
#include "sha1.h"

namespace librats {

// =========================================================================
// Peer Discovery Methods
// =========================================================================

bool RatsClient::start_dht_discovery(int dht_port) {
    if (dht_client_ && dht_client_->is_running()) {
        LOG_CLIENT_WARN("DHT discovery is already running");
        return true;
    }

    LOG_CLIENT_INFO("Starting DHT discovery on port " << dht_port <<
                   (bind_address_.empty() ? "" : " bound to " + bind_address_));

    auto bootstrap_nodes = DhtClient::get_default_bootstrap_nodes();

    // IPv4 DHT (also shared with the BitTorrent subsystem) - required.
    dht_client_ = std::make_unique<DhtClient>(dht_port, bind_address_, data_directory_, AddressFamily::IPv4);
    if (!dht_client_->start()) {
        LOG_CLIENT_ERROR("Failed to start IPv4 DHT client");
        dht_client_.reset();
        return false;
    }
    if (!dht_client_->bootstrap(bootstrap_nodes)) {
        LOG_CLIENT_WARN("Failed to bootstrap IPv4 DHT");
    }

    // IPv6 DHT - best effort. Shares the same port via a V6ONLY socket. If the host has
    // no usable IPv6 stack, socket creation fails and we simply run IPv4-only.
    dht_client_v6_ = std::make_unique<DhtClient>(dht_port, bind_address_, data_directory_, AddressFamily::IPv6);
    if (dht_client_v6_->start()) {
        if (!dht_client_v6_->bootstrap(bootstrap_nodes)) {
            LOG_CLIENT_WARN("Failed to bootstrap IPv6 DHT");
        }
        LOG_CLIENT_INFO("IPv6 DHT client started");
    } else {
        LOG_CLIENT_INFO("IPv6 DHT unavailable on this host, running IPv4-only");
        dht_client_v6_.reset();
    }

    // Forward the DHT's UDP port through the router, in addition to the TCP peer
    // port mapped at start(). Like libtorrent (which maps both the TCP listen port
    // and the UDP DHT/uTP port per listen socket), this makes the node reachable by
    // inbound DHT traffic behind NAT. No-op when port mapping is disabled; the
    // mapping uses external==internal so outgoing queries and inbound packets share
    // one public port. The backends wake their workers to install it immediately.
    // Use the *actual* bound port: start() may have fallen back to an ephemeral one
    // when the requested dht_port was taken.
    uint16_t bound_dht_port = dht_client_->get_port();
    if (bound_dht_port != 0) {
        add_port_mapping(PortMapProtocol::UDP, bound_dht_port);
    }

    // Start automatic peer discovery (this thread also performs the best-effort STUN probe
    // that derives our BEP 42 node ID — see automatic_discovery_loop).
    start_automatic_peer_discovery();

    LOG_CLIENT_INFO("DHT discovery started successfully");
    return true;
}

void RatsClient::stop_dht_discovery() {
    if (!dht_client_ && !dht_client_v6_) {
        return;
    }

    LOG_CLIENT_INFO("Stopping DHT discovery");

    // Stop automatic peer discovery
    stop_automatic_peer_discovery();

    if (dht_client_) {
        dht_client_->stop();
        dht_client_.reset();
    }
    if (dht_client_v6_) {
        dht_client_v6_->stop();
        dht_client_v6_.reset();
    }
    LOG_CLIENT_INFO("DHT discovery stopped");
}

bool RatsClient::find_peers_by_hash(const std::string& content_hash, std::function<void(const std::vector<std::string>&)> callback) {
    if (!is_dht_running()) {
        LOG_CLIENT_ERROR("DHT client not running");
        return false;
    }

    if (content_hash.length() != CONTENT_HASH_HEX_LENGTH) {
        LOG_CLIENT_ERROR("Invalid content hash length: " << content_hash.length() << " (expected " << CONTENT_HASH_HEX_LENGTH << ")");
        return false;
    }

    LOG_CLIENT_INFO("Finding peers for content hash: " << content_hash);

    InfoHash info_hash = hex_to_node_id(content_hash);

    // Shared wrapper: discovered peers (IPv4 or IPv6) are delivered through the same callback.
    PeerDiscoveryCallback peer_callback = [callback](const std::vector<Peer>& peers, const InfoHash&) {
        std::vector<std::string> peer_addresses;
        peer_addresses.reserve(peers.size());
        for (const auto& peer : peers) {
            peer_addresses.emplace_back(peer.ip + ":" + std::to_string(peer.port));
        }
        if (callback) {
            callback(peer_addresses);
        }
    };

    // Fan out to both Kademlia networks; succeed if at least one accepts the search.
    bool started = false;
    if (dht_client_ && dht_client_->is_running()) {
        started |= dht_client_->find_peers(info_hash, peer_callback);
    }
    if (dht_client_v6_ && dht_client_v6_->is_running()) {
        started |= dht_client_v6_->find_peers(info_hash, peer_callback);
    }
    return started;
}

bool RatsClient::announce_for_hash(const std::string& content_hash, uint16_t port,
                                   std::function<void(const std::vector<std::string>&)> callback) {
    if (!is_dht_running()) {
        LOG_CLIENT_ERROR("DHT client not running");
        return false;
    }

    if (content_hash.length() != CONTENT_HASH_HEX_LENGTH) {
        LOG_CLIENT_ERROR("Invalid content hash length: " << content_hash.length() << " (expected " << CONTENT_HASH_HEX_LENGTH << ")");
        return false;
    }

    if (port == 0) {
        port = listen_port_;
    }

    LOG_CLIENT_INFO("Announcing for content hash: " << content_hash << " on port " << port
                   << (callback ? " with peer callback" : ""));

    InfoHash info_hash = hex_to_node_id(content_hash);

    // Create wrapper callback that converts Peer to string addresses (if callback provided)
    PeerDiscoveryCallback peer_callback = nullptr;
    if (callback) {
        peer_callback = [callback](const std::vector<Peer>& peers, const InfoHash& hash) {
            std::vector<std::string> peer_addresses;
            peer_addresses.reserve(peers.size());
            for (const auto& peer : peers) {
                peer_addresses.push_back(peer.ip + ":" + std::to_string(peer.port));
            }
            callback(peer_addresses);
        };
    }

    // Announce on both Kademlia networks so IPv4 and IPv6 peers can both find us.
    bool started = false;
    if (dht_client_ && dht_client_->is_running()) {
        started |= dht_client_->announce_peer(info_hash, port, peer_callback);
    }
    if (dht_client_v6_ && dht_client_v6_->is_running()) {
        started |= dht_client_v6_->announce_peer(info_hash, port, peer_callback);
    }
    return started;
}

bool RatsClient::is_dht_running() const {
    return (dht_client_ && dht_client_->is_running()) ||
           (dht_client_v6_ && dht_client_v6_->is_running());
}

size_t RatsClient::get_dht_routing_table_size() const {
    size_t total = 0;
    if (dht_client_) {
        total += dht_client_->get_routing_table_size();
    }
    if (dht_client_v6_) {
        total += dht_client_v6_->get_routing_table_size();
    }
    return total;
}

void RatsClient::handle_dht_peer_discovery(const std::vector<Peer>& peers, const InfoHash& info_hash) {
    LOG_CLIENT_INFO("DHT discovered " << peers.size() << " peers for info hash: " << node_id_to_hex(info_hash));
    
    // Auto-connect to discovered peers
    for (const auto& peer : peers) {
        if (!can_connect_to_peer(peer.ip, peer.port)) {
            continue;
        }
        
        LOG_CLIENT_DEBUG("Attempting to connect to discovered peer: " << peer.ip << ":" << peer.port);
        
        // Try to connect to the peer (non-blocking, managed thread for graceful shutdown)
        add_managed_thread(std::thread([this, peer]() {
            if (connect_to_peer(peer.ip, peer.port)) {
                LOG_CLIENT_INFO("Successfully connected to DHT discovered peer: " << peer.ip << ":" << peer.port);
            } else {
                LOG_CLIENT_DEBUG("Failed to connect to DHT discovered peer: " << peer.ip << ":" << peer.port);
            }
        }), "dht-connect-" + peer.ip);
    }
}

void RatsClient::start_automatic_peer_discovery() {
    if (auto_discovery_running_.load()) {
        LOG_CLIENT_WARN("Automatic peer discovery is already running");
        return;
    }
    
    LOG_CLIENT_INFO("Starting automatic rats peer discovery");
    auto_discovery_running_.store(true);
    auto_discovery_thread_ = std::thread(&RatsClient::automatic_discovery_loop, this);
}

void RatsClient::stop_automatic_peer_discovery() {
    if (!auto_discovery_running_.load()) {
        return;
    }
    
    LOG_CLIENT_INFO("Stopping automatic peer discovery");
    auto_discovery_running_.store(false);
    
    if (auto_discovery_thread_.joinable()) {
        auto_discovery_thread_.join();
    }
    
    LOG_CLIENT_INFO("Automatic peer discovery stopped");
}

bool RatsClient::is_automatic_discovery_running() const {
    return auto_discovery_running_.load();
}

std::chrono::seconds RatsClient::calculate_discovery_interval() const {
    int peer_count = get_peer_count();
    
    // No peers - aggressive discovery
    if (peer_count == 0) {
        return std::chrono::seconds(15);
    }
    
    // Calculate fill ratio
    float fill_ratio = static_cast<float>(peer_count) / static_cast<float>(max_peers_);
    
    // Graduated intervals based on fill ratio
    if (fill_ratio < 0.25f) {
        // Less than 25% full - still fairly aggressive
        return std::chrono::seconds(60);       // 1 minute
    } else if (fill_ratio < 0.50f) {
        // 25-50% full - moderate
        return std::chrono::seconds(180);      // 3 minutes
    } else if (fill_ratio < 0.75f) {
        // 50-75% full - relaxed
        return std::chrono::seconds(600);      // 10 minutes
    } else {
        // 75-100% full - very relaxed (mostly just re-announcing)
        return std::chrono::seconds(1800);     // 30 minutes
    }
}

void RatsClient::automatic_discovery_loop() {
    LOG_CLIENT_INFO("Automatic peer discovery loop started");

    // Best-effort: discover our public IP via STUN and derive a BEP 42 node ID from it BEFORE
    // the initial bootstrap delay below. The DHT starts receiving KRPC responses (each carrying
    // our address in the "ip" field) immediately on bootstrap, and that in-DHT vote can reach
    // EXTERNAL_IP_VOTE_THRESHOLD within a few seconds. Probing STUN first lets set_external_ip()
    // adopt the address and regenerate the node ID up front, so the DHT bootstraps under the
    // correct ID and the ip-field voting silently confirms the already-adopted address instead
    // of racing it to consensus. The voting remains the fallback when STUN is unavailable or the
    // address later changes.
    //
    // This runs on the discovery thread (not a standalone one) on purpose: stop_dht_discovery()
    // joins this thread via stop_automatic_peer_discovery() BEFORE resetting the DHT clients, so
    // set_external_ip() can never touch a destroyed DhtClient.
    if (auto_discovery_running_.load() && running_.load()) {
        auto mapped = discover_public_address("stun.l.google.com", 19302, 4000);
        if (mapped) {
            // set_external_ip validates the address family, so feeding both instances is safe:
            // only the matching-family DHT adopts it. (A default IPv4 STUN server yields an IPv4
            // address; the IPv6 node ID is learned organically from IPv6 DHT responses.)
            if (dht_client_) {
                dht_client_->set_external_ip(mapped->address);
            }
            if (dht_client_v6_) {
                dht_client_v6_->set_external_ip(mapped->address);
            }
        }
    }

    // Initial delay to let DHT bootstrap
    {
        std::unique_lock<std::mutex> lock(shutdown_mutex_);
        if (shutdown_cv_.wait_for(lock, std::chrono::seconds(INITIAL_DISCOVERY_DELAY_SECONDS), [this] { return !auto_discovery_running_.load() || !running_.load(); })) {
            LOG_CLIENT_INFO("Automatic peer discovery loop stopped during initial delay");
            return;
        }
    }

    // Announce immediately - this also discovers peers during traversal
    announce_rats_peer();

    auto last_announce = std::chrono::steady_clock::now();
    
    while (auto_discovery_running_.load()) {
        auto now = std::chrono::steady_clock::now();
        
        // Announce combines both announcing our presence and discovering peers
        // Interval scales based on peer count: aggressive when empty, relaxed when nearly full
        auto interval = calculate_discovery_interval();
        
        if (now - last_announce >= interval) {
            LOG_CLIENT_DEBUG("Discovery interval: " << interval.count() << "s (peers: " 
                            << get_peer_count() << "/" << max_peers_ << ")");
            announce_rats_peer();
            last_announce = now;
        }
        
        // Use conditional variable for responsive shutdown
        {
            std::unique_lock<std::mutex> lock(shutdown_mutex_);
            if (shutdown_cv_.wait_for(lock, std::chrono::milliseconds(500), [this] { return !auto_discovery_running_.load() || !running_.load(); })) {
                break;
            }
        }
    }
    
    LOG_CLIENT_INFO("Automatic peer discovery loop stopped");
}

void RatsClient::announce_rats_peer() {
    if (!dht_client_ || !dht_client_->is_running()) {
        LOG_CLIENT_WARN("DHT client not running, cannot announce peer");
        return;
    }
    
    std::string discovery_hash = get_discovery_hash();

    // Advertise the mapped public TCP port when UPnP/NAT-PMP has established one,
    // so WAN peers connect to (external_ip, external_port) rather than our NATed
    // local listen port. Falls back to listen_port_ when no mapping is active.
    // (Mirrors libtorrent feeding the port-mapping result into what it announces.)
    uint16_t announce_port = get_advertised_port();
    LOG_CLIENT_INFO("Announcing peer for discovery hash: " << discovery_hash << " on port " << announce_port);

    InfoHash info_hash = hex_to_node_id(discovery_hash);

    // Skip only if every running DHT network already has this announce in flight.
    // (announce_peer() also dedups internally, so this is just to avoid redundant work.)
    bool v4_busy = !dht_client_ || !dht_client_->is_running() || dht_client_->is_announce_active(info_hash);
    bool v6_busy = !dht_client_v6_ || !dht_client_v6_->is_running() || dht_client_v6_->is_announce_active(info_hash);
    if (v4_busy && v6_busy) {
        LOG_CLIENT_WARN("Announce already in progress for info hash: " << node_id_to_hex(info_hash));
        return;
    }
    
    // Use announce with callback - combines announce and find_peers in one traversal
    // Peers discovered during traversal will be returned through the callback
    if (announce_for_hash(discovery_hash, announce_port, [this, info_hash](const std::vector<std::string>& peer_addresses) {
        LOG_CLIENT_INFO("Announce discovered " << peer_addresses.size() << " peers during traversal");
        
        // Convert peer addresses to Peer objects for handle_dht_peer_discovery()
        std::vector<Peer> peers;
        peers.reserve(peer_addresses.size());
        for (const auto& peer_address : peer_addresses) {
            std::string ip;
            int port;
            if (parse_address_string(peer_address, ip, port)) {
                peers.push_back(Peer(ip, port));
            }
        }
        
        // Auto-connect to discovered peers
        if (!peers.empty()) {
            handle_dht_peer_discovery(peers, info_hash);
        }
    })) {
        LOG_CLIENT_DEBUG("Successfully started announce with peer discovery for discovery hash");
    } else {
        LOG_CLIENT_WARN("Failed to announce peer for discovery");
    }
}

std::string RatsClient::get_discovery_hash() const {
    std::lock_guard<std::mutex> lock(protocol_config_mutex_);
    // Generate discovery hash based on current protocol configuration
    std::string discovery_string = custom_protocol_name_ + "_peer_discovery_v" + custom_protocol_version_;
    return SHA1::hash(discovery_string);
}

std::string RatsClient::get_rats_peer_discovery_hash() {
    // Well-known hash for rats peer discovery
    // Compute SHA1 hash of "rats_peer_discovery_v1.0"
    return SHA1::hash("rats_peer_discovery_v1.0");
}

}