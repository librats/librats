#include "subsystems/dht_discovery.h"
#include "node/node_context.h"
#include "node/host_events.h"
#include "nat/stun.h"
#include "sha1.h"
#include "util/fs.h"
#include "util/logger.h"

namespace librats {

namespace {
int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

// A couple of well-known public STUN servers, tried in order. Kept short so a
// total-outage startup costs at most a few timeouts before we fall back to voting.
std::vector<HostEndpoint> default_stun_servers() {
    return { HostEndpoint("stun.l.google.com", 19302), HostEndpoint("stun1.l.google.com", 19302) };
}

// The configured bind literal only applies to its own family; the other family
// binds the wildcard. An empty config means wildcard for both.
std::string bind_for(const std::string& cfg, bool want_v6) {
    if (cfg.empty()) return "";
    const bool cfg_is_v6 = cfg.find(':') != std::string::npos;
    return (cfg_is_v6 == want_v6) ? cfg : "";
}
} // namespace

InfoHash DhtDiscovery::hash_for_key(const std::string& key) {
    const std::string hex = SHA1::hash(key);  // 40 hex chars
    InfoHash hash{};
    for (size_t i = 0; i < hash.size() && (2 * i + 1) < hex.size(); ++i)
        hash[i] = static_cast<uint8_t>((hex_val(hex[2 * i]) << 4) | hex_val(hex[2 * i + 1]));
    return hash;
}

DhtDiscovery::DhtDiscovery(Config config)
    : config_(std::move(config)) {}  // hash_ is resolved in attach() (may depend on the node protocol)

DhtDiscovery::~DhtDiscovery() { stop(); }

void DhtDiscovery::attach(NodeContext& ctx) {
    network_ = &ctx.network;
    // Namespace discovery by the node's protocol unless an explicit key overrides
    // it: peers of the same app/version announce/search the same hash, and ones with
    // a different protocol (which couldn't complete a handshake anyway) never meet in
    // the DHT. A non-empty discovery_key opts into a custom, protocol-independent net.
    const std::string& key = config_.discovery_key.empty() ? network_->protocol()
                                                           : config_.discovery_key;
    hash_ = hash_for_key(key);
    // Publish the DHT as a borrowable capability so a sibling subsystem (e.g.
    // Bittorrent) can share this Kademlia node instead of running a second one.
    ctx.services.provide<DhtService>(this);
    // A host network change means our public endpoint may have moved. Re-probe it
    // via STUN and re-announce so the DHT advertises our current reachable address
    // rather than the previous network's. We only flag + wake here (cheap, on the
    // node's maintenance thread); the actual STUN runs on our own loop thread.
    ctx.events.on<NetworkChanged>([this](const NetworkChanged&) {
        recover_pending_.store(true);
        wake_.notify_all();
    });
}

std::unique_ptr<DhtClient> DhtDiscovery::make_client(AddressFamily family) {
    const bool v6 = (family == AddressFamily::IPv6);
    const char* label = v6 ? "IPv6" : "IPv4";

    auto client = std::make_unique<DhtClient>(config_.dht_port, bind_for(config_.bind_address, v6),
                                              config_.data_dir, family);
    if (!client->start()) {
        LOG_WARN("dht-discovery", label << " DHT client failed to start (skipping this family)");
        return nullptr;
    }

    const std::vector<HostEndpoint> nodes =
        config_.bootstrap_nodes.empty() ? DhtClient::get_default_bootstrap_nodes() : config_.bootstrap_nodes;
    if (!nodes.empty()) client->bootstrap(nodes);

    LOG_INFO("dht-discovery", label << " DHT on UDP port " << client->get_port());
    return client;
}

void DhtDiscovery::start() {
    if (running_.exchange(true)) return;

    // Make sure the routing-table directory exists before the clients try to use it.
    if (!config_.data_dir.empty()) create_directories(config_.data_dir.c_str());

    if (config_.enable_ipv4) dht_  = make_client(AddressFamily::IPv4);
    if (config_.enable_ipv6) dht6_ = make_client(AddressFamily::IPv6);

    if (!dht_ && !dht6_) {
        LOG_ERROR("dht-discovery", "Failed to start DHT client on any address family");
        running_.store(false);
        return;
    }

    thread_ = std::thread(&DhtDiscovery::loop, this);
    LOG_INFO("dht-discovery", "Started (" << (dht_ ? "IPv4" : "") << (dht_ && dht6_ ? "+" : "")
             << (dht6_ ? "IPv6" : "") << "), hash key '" << config_.discovery_key << "'");
}

void DhtDiscovery::stop() {
    if (!running_.exchange(false)) return;
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
    if (dht_)  { dht_->stop();  dht_.reset(); }
    if (dht6_) { dht6_->stop(); dht6_.reset(); }
}

bool DhtDiscovery::is_running() const {
    return running_.load() && ((dht_ && dht_->is_running()) || (dht6_ && dht6_->is_running()));
}

uint16_t DhtDiscovery::dht_port() const { return dht_ ? static_cast<uint16_t>(dht_->get_port()) : 0; }

uint16_t DhtDiscovery::dht_port_v6() const { return dht6_ ? static_cast<uint16_t>(dht6_->get_port()) : 0; }

std::string DhtDiscovery::external_address() const {
    // The IPv4 reflexive address is the public-facing one most callers expect;
    // fall back to the IPv6 client's view if only that family is up.
    if (dht_) {
        std::string a = dht_->get_external_address();
        if (!a.empty()) return a;
    }
    return dht6_ ? dht6_->get_external_address() : "";
}

// Discover our reflexive (public) address via STUN and feed it to the DHT so the
// node id is BEP-42-correct from the start instead of waiting for "ip" voting.
// Runs on the loop thread; stop() joins that thread before resetting dht_, so the
// dht_ access here can never touch a freed client.
void DhtDiscovery::probe_external_ip() {
    std::vector<HostEndpoint> servers = config_.stun_servers.empty() ? default_stun_servers()
                                                                      : config_.stun_servers;
    StunClient stun;
    const int timeout = static_cast<int>(config_.stun_timeout.count());
    for (const HostEndpoint& s : servers) {
        if (!running_.load()) return;  // stopping; don't keep probing
        StunResult r = stun.binding_request(s.host, s.port, timeout);
        if (r.success && r.mapped_address) {
            const std::string& ip = r.mapped_address->address;
            LOG_INFO("dht-discovery", "STUN reflexive address " << ip << " (via " << s.host << ":" << s.port << ")");
            // Feed it to whichever clients are up; each ignores it if it's not a
            // public address of its own family (e.g. a v4 reflexive on the v6 client).
            if (running_.load()) for_each_client([&](DhtClient& c) { c.set_external_ip(ip); });
            return;
        }
    }
    LOG_DEBUG("dht-discovery", "STUN external-IP discovery failed; relying on DHT ip voting");
}

void DhtDiscovery::loop() {
    if (config_.discover_external_ip) probe_external_ip();

    auto last_announce = std::chrono::steady_clock::now() - config_.announce_interval;
    while (running_.load()) {
        // Network changed: re-learn our public IP and force an immediate re-announce.
        if (recover_pending_.exchange(false)) {
            LOG_INFO("dht-discovery", "Network changed — re-probing STUN and re-announcing");
            if (config_.discover_external_ip) probe_external_ip();
            last_announce = std::chrono::steady_clock::now() - config_.announce_interval;
        }

        const auto now = std::chrono::steady_clock::now();
        auto deliver = [this](const std::vector<Address>& peers, const InfoHash& h) { on_peers(peers, h); };
        if (now - last_announce >= config_.announce_interval) {
            // announce_peer runs a get_peers traversal and announces on completion, so it
            // discovers peers itself — feed them to on_peers and skip the separate
            // find_peers this cycle, otherwise we'd run two identical traversals per hash
            // (every node queried twice). find_peers covers the faster search cadence in
            // between announces.
            for_each_client([&](DhtClient& c) { c.announce_peer(hash_, network_->listen_port(), deliver); });
            last_announce = now;
        } else {
            for_each_client([&](DhtClient& c) { c.find_peers(hash_, deliver); });
        }

        std::unique_lock<std::mutex> lock(wait_mutex_);
        wake_.wait_for(lock, config_.search_interval,
                       [this] { return !running_.load() || recover_pending_.load(); });
    }
}

void DhtDiscovery::on_peers(const std::vector<Address>& peers, const InfoHash& /*info_hash*/) {
    for (const Address& peer : peers) {
        if (peer.ip.is_any() || peer.port == 0) continue;
        {
            std::lock_guard<std::mutex> lock(dialed_mutex_);
            if (!dialed_.insert(peer).second) continue;  // already dialed this address
        }
        LOG_DEBUG("dht-discovery", "Dialing discovered peer " << peer.to_string());
        network_->connect(peer);
    }
}

} // namespace librats
