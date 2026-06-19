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

        /// Probe a STUN server once at startup to learn our public IP and seed the
        /// DHT node id per BEP 42. Without it we still converge via the slower
        /// in-DHT "ip" voting, but bootstrap under the wrong node id until then.
        bool                      discover_external_ip = true;
        std::vector<Address>      stun_servers;          ///< empty → built-in public defaults
        std::chrono::milliseconds stun_timeout{3000};
    };

    explicit DhtDiscovery(Config config);
    ~DhtDiscovery() override;

    void attach(PeerNetwork& network) override;
    void start() override;
    void stop() override;

    bool     is_running() const;
    uint16_t dht_port() const;
    InfoHash discovery_hash() const { return hash_; }

    /// Our external (public) IP currently used to derive the DHT node id, learned
    /// via STUN at startup or in-DHT "ip" voting. "" if not yet known / random.
    std::string external_address() const;

    /// Map an application key to a stable 20-byte discovery hash (SHA-1).
    static InfoHash hash_for_key(const std::string& key);

private:
    void loop();
    void probe_external_ip();  ///< STUN → dht_->set_external_ip (runs on the loop thread)
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
