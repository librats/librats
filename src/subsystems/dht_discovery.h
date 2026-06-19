#pragma once

/**
 * @file dht_discovery.h
 * @brief Peer discovery via the Kademlia DHT — a thin adapter, not a rewrite.
 *
 * Wraps the existing, well-tested DhtClient (src/dht.h) as a Subsystem WITHOUT
 * modifying it. On start it brings up a DhtClient (its own UDP socket + threads),
 * then periodically announces our TCP listen port under a discovery hash and
 * searches that hash, dialing any peers it finds through the node. The discovery
 * hash namespaces peers of the same application (same key → same hash).
 *
 * Everything DHT-specific stays in DhtClient; this class only bridges its
 * callbacks to PeerNetwork::connect().
 */

#include "node/peer_network.h"
#include "dht/dht.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace librats {

class DhtDiscovery final : public Subsystem {
public:
    struct Config {
        uint16_t                  dht_port = 0;          ///< 0 = ephemeral
        std::string               bind_address = "";
        std::string               discovery_key = "librats";  ///< app namespace
        std::vector<Address>         bootstrap_nodes;       ///< empty → default internet nodes
        std::chrono::milliseconds search_interval{5000};
        std::chrono::milliseconds announce_interval{30000};
    };

    explicit DhtDiscovery(Config config);
    ~DhtDiscovery() override;

    void attach(PeerNetwork& network) override;
    void start() override;
    void stop() override;

    bool     is_running() const;
    uint16_t dht_port() const;
    InfoHash discovery_hash() const { return hash_; }

    /// Map an application key to a stable 20-byte discovery hash (SHA-1).
    static InfoHash hash_for_key(const std::string& key);

private:
    void loop();
    void on_peers(const std::vector<Address>& peers, const InfoHash& info_hash);

    Config                     config_;
    InfoHash                   hash_;
    PeerNetwork*               network_ = nullptr;
    std::unique_ptr<DhtClient> dht_;

    std::thread             thread_;
    std::atomic<bool>       running_{false};
    std::mutex              wait_mutex_;
    std::condition_variable wake_;

    std::mutex                      dialed_mutex_;
    std::unordered_set<std::string> dialed_;  ///< ip:port we've already dialed
};

} // namespace librats
