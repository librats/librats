#include "subsystems/dht_discovery.h"
#include "nat/stun.h"
#include "sha1.h"
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
std::vector<Address> default_stun_servers() {
    return { Address("stun.l.google.com", 19302), Address("stun1.l.google.com", 19302) };
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
    : config_(std::move(config)), hash_(hash_for_key(config_.discovery_key)) {}

DhtDiscovery::~DhtDiscovery() { stop(); }

void DhtDiscovery::attach(PeerNetwork& network) { network_ = &network; }

void DhtDiscovery::start() {
    if (running_.exchange(true)) return;

    dht_ = std::make_unique<DhtClient>(config_.dht_port, config_.bind_address, /*data_directory=*/"");
    if (!dht_->start()) {
        LOG_ERROR("dht-discovery", "Failed to start DHT client");
        running_.store(false);
        dht_.reset();
        return;
    }

    const std::vector<Address> nodes =
        config_.bootstrap_nodes.empty() ? DhtClient::get_default_bootstrap_nodes() : config_.bootstrap_nodes;
    if (!nodes.empty()) dht_->bootstrap(nodes);

    thread_ = std::thread(&DhtDiscovery::loop, this);
    LOG_INFO("dht-discovery", "Started on UDP port " << dht_->get_port() << ", hash key '"
             << config_.discovery_key << "'");
}

void DhtDiscovery::stop() {
    if (!running_.exchange(false)) return;
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
    if (dht_) { dht_->stop(); dht_.reset(); }
}

bool DhtDiscovery::is_running() const { return running_.load() && dht_ && dht_->is_running(); }

uint16_t DhtDiscovery::dht_port() const { return dht_ ? static_cast<uint16_t>(dht_->get_port()) : 0; }

std::string DhtDiscovery::external_address() const { return dht_ ? dht_->get_external_address() : ""; }

// Discover our reflexive (public) address via STUN and feed it to the DHT so the
// node id is BEP-42-correct from the start instead of waiting for "ip" voting.
// Runs on the loop thread; stop() joins that thread before resetting dht_, so the
// dht_ access here can never touch a freed client.
void DhtDiscovery::probe_external_ip() {
    std::vector<Address> servers = config_.stun_servers.empty() ? default_stun_servers()
                                                                : config_.stun_servers;
    StunClient stun;
    const int timeout = static_cast<int>(config_.stun_timeout.count());
    for (const Address& s : servers) {
        if (!running_.load()) return;  // stopping; don't keep probing
        StunResult r = stun.binding_request(s.ip, s.port, timeout);
        if (r.success && r.mapped_address) {
            const std::string& ip = r.mapped_address->address;
            LOG_INFO("dht-discovery", "STUN reflexive address " << ip << " (via " << s.ip << ":" << s.port << ")");
            if (running_.load() && dht_) dht_->set_external_ip(ip);  // ignored if non-public / wrong family
            return;
        }
    }
    LOG_DEBUG("dht-discovery", "STUN external-IP discovery failed; relying on DHT ip voting");
}

void DhtDiscovery::loop() {
    if (config_.discover_external_ip) probe_external_ip();

    auto last_announce = std::chrono::steady_clock::now() - config_.announce_interval;
    while (running_.load()) {
        const auto now = std::chrono::steady_clock::now();
        if (now - last_announce >= config_.announce_interval) {
            dht_->announce_peer(hash_, network_->listen_port());
            last_announce = now;
        }
        dht_->find_peers(hash_, [this](const std::vector<Address>& peers, const InfoHash& h) { on_peers(peers, h); });

        std::unique_lock<std::mutex> lock(wait_mutex_);
        wake_.wait_for(lock, config_.search_interval, [this] { return !running_.load(); });
    }
}

void DhtDiscovery::on_peers(const std::vector<Address>& peers, const InfoHash& /*info_hash*/) {
    for (const Address& peer : peers) {
        if (peer.ip.empty() || peer.port == 0) continue;
        const std::string key = peer.ip + ":" + std::to_string(peer.port);
        {
            std::lock_guard<std::mutex> lock(dialed_mutex_);
            if (!dialed_.insert(key).second) continue;  // already dialed this address
        }
        LOG_DEBUG("dht-discovery", "Dialing discovered peer " << key);
        network_->connect(Address{peer.ip, peer.port});
    }
}

} // namespace librats
