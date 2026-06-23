#pragma once

/**
 * @file dht_discovery.h
 * @brief Peer discovery via the Kademlia DHT — a thin adapter, not a rewrite.
 *
 * Wraps the existing, well-tested DhtClient (src/dht.h) as a Subsystem WITHOUT
 * modifying it. On start it brings up DhtClients (their own UDP sockets + threads),
 * then periodically announces our TCP listen port under a discovery hash and
 * searches that hash, dialing any peers it finds through the node. The discovery
 * hash namespaces peers of the same application (same key → same hash).
 *
 * Dual-stack: IPv4 and IPv6 are separate Kademlia networks (BEP 32), so each runs
 * its own DhtClient. Both announce/search the same hash and feed discovered peers
 * to the same dial path, so a peer reachable over either family is found. Startup
 * is best-effort per family: if one family can't bind (e.g. a host with no usable
 * IPv6) the subsystem still runs on the other.
 *
 * Everything DHT-specific stays in DhtClient; this class only bridges its
 * callbacks to PeerNetwork::connect().
 */

#include "node/peer_network.h"
#include "subsystems/dht_service.h"
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

class DhtDiscovery final : public Subsystem, public DhtService {
public:
    struct Config {
        uint16_t                  dht_port = 0;          ///< 0 = ephemeral
        std::string               bind_address = "";
        std::string               data_dir = "";         ///< routing-table persistence dir (empty = cwd). Set to the node's data_dir to co-locate state.
        bool                      enable_ipv4 = true;    ///< run the IPv4 Kademlia network
        bool                      enable_ipv6 = true;    ///< run the IPv6 Kademlia network (BEP 32)
        std::string               discovery_key = "";  ///< DHT namespace. Empty → the node's `protocol` (resolved at attach), so peers of the same app/version discover each other and mismatched protocols (which can't handshake anyway) don't even meet. Set non-empty to override with a custom discovery network.
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

    void attach(NodeContext& ctx) override;
    void start() override;
    void stop() override;

    bool     is_running() const;

    /// DhtService: hand out the live Kademlia node so siblings (e.g. Bittorrent)
    /// can share this swarm. IPv4 preferred, IPv6 fallback; nullptr before start()
    /// / after stop(). Borrow it during start() and drop it in stop() (see DhtService).
    DhtClient* dht_client() override { return dht_ ? dht_.get() : dht6_.get(); }

    uint16_t dht_port() const;       ///< IPv4 DHT UDP port (0 if not running)
    uint16_t dht_port_v6() const;    ///< IPv6 DHT UDP port (0 if not running)
    InfoHash discovery_hash() const { return hash_; }

    /// Our external (public) IP currently used to derive the DHT node id, learned
    /// via STUN at startup or in-DHT "ip" voting. "" if not yet known / random.
    std::string external_address() const;

    /// Map an application key to a stable 20-byte discovery hash (SHA-1).
    static InfoHash hash_for_key(const std::string& key);

private:
    void loop();
    void probe_external_ip();  ///< STUN → set_external_ip on each client (runs on the loop thread)
    void on_peers(const std::vector<Address>& peers, const InfoHash& info_hash);

    /// Bring up one family's DhtClient (bind + bootstrap). Returns nullptr if it
    /// could not bind/start, so the caller can run on whatever family did come up.
    std::unique_ptr<DhtClient> make_client(AddressFamily family);

    /// Run `fn` on each live client (IPv4 then IPv6). Loop-thread side.
    template <typename Fn>
    void for_each_client(Fn fn) {
        if (dht_)  fn(*dht_);
        if (dht6_) fn(*dht6_);
    }

    Config                     config_;
    InfoHash                   hash_;
    PeerNetwork*               network_ = nullptr;
    std::unique_ptr<DhtClient> dht_;    ///< IPv4 Kademlia network
    std::unique_ptr<DhtClient> dht6_;   ///< IPv6 Kademlia network (BEP 32)

    std::thread             thread_;
    std::atomic<bool>       running_{false};
    std::atomic<bool>       recover_pending_{false};  ///< network changed: re-STUN + re-announce
    std::mutex              wait_mutex_;
    std::condition_variable wake_;

    std::mutex                      dialed_mutex_;
    std::unordered_set<std::string> dialed_;  ///< ip:port we've already dialed
};

} // namespace librats
