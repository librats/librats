#include "subsystems/dht_discovery.h"
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

    const std::vector<Peer> nodes =
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

void DhtDiscovery::loop() {
    auto last_announce = std::chrono::steady_clock::now() - config_.announce_interval;
    while (running_.load()) {
        const auto now = std::chrono::steady_clock::now();
        if (now - last_announce >= config_.announce_interval) {
            dht_->announce_peer(hash_, network_->listen_port());
            last_announce = now;
        }
        dht_->find_peers(hash_, [this](const std::vector<Peer>& peers, const InfoHash& h) { on_peers(peers, h); });

        std::unique_lock<std::mutex> lock(wait_mutex_);
        wake_.wait_for(lock, config_.search_interval, [this] { return !running_.load(); });
    }
}

void DhtDiscovery::on_peers(const std::vector<Peer>& peers, const InfoHash& /*info_hash*/) {
    for (const Peer& peer : peers) {
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
