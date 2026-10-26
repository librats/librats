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
 * Two nodes behind NATs find each other here but cannot dial each other: each
 * NAT drops what comes in unless something went out to that peer first. Both
 * dial what they find, though, so each one's dial opens the way for the
 * other's — if they overlap. A peer found and not connected is therefore
 * dialed again, as a punch (DialProfile::punch(): dense probes over the shared
 * datagram socket), each time it is found again for a while after it was first
 * found (Redials) — or after it was last found connected, a link that went
 * since dialed for anew.
 *
 * The port announced is the one peers are to dial. Over IPv6, which has no NAT,
 * the listen port; over IPv4 the one the router forwards to it (PortMapped, from
 * PortMappingService), or else the one the NAT maps the shared datagram socket
 * to — asked of STUN from that socket (ReflexiveAddressService), as most
 * carrier-grade NATs pick another — or the listen port. STUN is asked again
 * every so often: that keeps the mapping alive while no peer does, and finds
 * it anew if it moved.
 *
 * Everything DHT-specific stays in DhtClient; this class only bridges its
 * callbacks to PeerNetwork::connect().
 */

#include "librats/util/rats_export.h"
#include "librats/node/peer_network.h"
#include "librats/subsystems/dht_service.h"
#include "librats/dht/dht.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace librats {

class DialService;
class ReflexiveAddressService;

class RATS_API DhtDiscovery final : public Subsystem, public DhtService {
public:
    struct Config {
        uint16_t                  dht_port = 0;          ///< 0 = ephemeral
        std::string               bind_address = "";
        std::string               data_dir = "";         ///< routing-table persistence dir (empty = cwd). Set to the node's data_dir to co-locate state.
        bool                      enable_ipv4 = true;    ///< run the IPv4 Kademlia network
        bool                      enable_ipv6 = true;    ///< run the IPv6 Kademlia network (BEP 32)
        std::string               discovery_key = "";  ///< DHT namespace. Empty → the node's `protocol` (resolved at attach), so peers of the same app/version discover each other and mismatched protocols (which can't handshake anyway) don't even meet. Set non-empty to override with a custom discovery network.
        std::vector<HostEndpoint>    bootstrap_nodes;       ///< empty → default internet nodes
        std::chrono::milliseconds search_interval{30000}; /// every 30 seconds
        /// Re-announce cadence. Kept at ~⅓ of the peer TTL (librats stores announced peers
        /// for 30 min, libtorrent ~45 min) so we stay findable with a comfortable margin
        /// even if an announce or two is lost — libtorrent's own default is 15 min. A fresh
        /// node still announces immediately at startup regardless of this value (see loop()).
        std::chrono::milliseconds announce_interval{600000};  // 10 min

        /// Ask STUN where we are: the public IP seeds the DHT node id per BEP 42
        /// (without it we still converge via the slower in-DHT "ip" voting, but
        /// bootstrap under the wrong node id until then), and the port the NAT
        /// maps the shared datagram socket to is the one announced over IPv4.
        bool                      discover_external_ip = true;
        std::vector<HostEndpoint> stun_servers;          ///< empty → built-in public defaults
        std::chrono::milliseconds stun_timeout{3000};
        /// STUN is asked again this often, on the search round it falls in —
        /// after a round with no answer, ten times as long. Shorter than a NAT
        /// keeps an idle mapping (30 s at the least), with search_interval.
        std::chrono::milliseconds stun_every{20000};

        /// A peer found and not connected is dialed again when found again, at
        /// most this often, for this long after it was first found (or last
        /// found connected: a link gone is dialed for anew). A NAT's
        /// mapping lives some 30 s at least, so two nodes that keep dialing
        /// each other more often than that get through on the second's dial.
        std::chrono::milliseconds redial_every{5000};
        std::chrono::milliseconds redial_for{120000};
    };

    /// Which addresses found to dial, and how: a policy of times alone.
    class RATS_API Redials {
    public:
        enum class Dial : uint8_t {
            None,   ///< dialed lately, or for long enough
            First,  ///< never dialed: the ordinary dial
            Again,  ///< not reached yet: a punch
        };
        using Clock = std::chrono::steady_clock;

        Redials(std::chrono::milliseconds every, std::chrono::milliseconds dial_for)
            : every_(every), for_(dial_for) {}

        /// `address` found at `now`, not connected.
        Dial found(const Address& address, Clock::time_point now);
        /// `address` found connected: once its link is gone, it is dialed as
        /// though found for the first time.
        void connected(const Address& address) { found_.erase(address); }
        /// Forget what has not been found for a while: the DHT stops handing
        /// out an address half an hour after its last announce.
        void forget_older_than(Clock::time_point before);
        size_t size() const { return found_.size(); }

    private:
        struct Dialed {
            Clock::time_point first;
            Clock::time_point last;
            Clock::time_point seen;
        };
        std::chrono::milliseconds every_;
        std::chrono::milliseconds for_;
        std::unordered_map<Address, Dialed> found_;
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
    /// STUN → set_external_ip on each client, and the shared socket's port.
    /// Whether a server answered. Runs on the loop thread.
    bool probe_external_ip();
    void on_peers(const std::vector<Address>& peers, const InfoHash& info_hash);
    /// The port peers are to dial us at over IPv4, or IPv6.
    uint16_t announced_port(bool v6 = false) const;

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
    DialService*               dial_ = nullptr;  ///< for punches; none: dials are ordinary
    ReflexiveAddressService*   reflexive_ = nullptr;  ///< STUN from the shared socket
    std::unique_ptr<DhtClient> dht_;    ///< IPv4 Kademlia network
    std::unique_ptr<DhtClient> dht6_;   ///< IPv6 Kademlia network (BEP 32)

    std::thread             thread_;
    std::atomic<bool>       running_{false};
    std::atomic<bool>       recover_pending_{false};  ///< network changed: re-STUN + re-announce
    std::atomic<bool>       announce_pending_{false}; ///< the port to announce changed
    std::atomic<uint16_t>   mapped_port_{0};          ///< the router's for ours; 0: none
    std::atomic<uint16_t>   reflexive_port_{0};       ///< where STUN saw the shared socket; 0: not
    bool                    mapping_checked_ = false; ///< a second STUN server asked (loop thread)
    std::optional<Address>  last_seen_;               ///< STUN's last answer (loop thread)
    std::mutex              wait_mutex_;
    std::condition_variable wake_;

    std::mutex dialed_mutex_;
    Redials    dialed_;  ///< under dialed_mutex_
};

} // namespace librats
