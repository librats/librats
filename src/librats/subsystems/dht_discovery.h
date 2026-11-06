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
 * datagram socket), every few seconds for a while after it was first found,
 * found again or not (Redials) — or after it was last found connected, a link
 * that went since dialed for anew — and after that each time it is found
 * again, once a round, for as long as the DHT hands it out: a peer that comes
 * online later at an address found before (the DHT keeps an announce half an
 * hour, and a NAT often keeps a port) is met as its own punches, every few
 * seconds, land while ours keep our NAT open to it.
 *
 * The port announced is the one peers are to dial. Over IPv6, which has no NAT,
 * the listen port; over IPv4 the one the router forwards to it (PortMapped, from
 * PortMappingService), or else the one the NAT maps the shared datagram socket
 * to — asked of STUN from that socket (ReflexiveAddressService), as most
 * carrier-grade NATs pick another — or the listen port. STUN is asked again
 * every so often: that keeps the mapping alive while no peer does, and finds
 * it anew if it moved.
 *
 * Several keys: one DHT, each key's hash announced and searched in its turn —
 * what a node meets several sets of peers under (an application's peers that
 * share a secret each: a hash only they work out). They change as the node
 * runs (set_keys()): a key new is announced, and so searched, at once; one gone
 * is no longer announced, and the DHT forgets it within half an hour. A key may
 * be announced alone (who asks for it finds the node; the node seeks nobody,
 * and dials none of what its announces' lookups hand back), or searched alone
 * (the node finds who is there, and is not found there).
 * A DHT that knows no node yet (bootstrapping) is asked nothing: its lookup
 * would end at once with none, and an announce so lost leave the node unfound
 * until the next — what is held back goes half a second on, then twice as
 * long each time up to a round (a family that never knows a node, IPv6 with
 * no route out, is not asked of twice a second for ever).
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
        std::string               data_dir = "";         ///< routing-table persistence dir (empty = nothing kept). Set to the node's data_dir to co-locate state.
        /// Another node's data_dir: the contacts of its saved tables seed
        /// these at start, its node ids never taken, nothing written there
        /// (DhtClient::set_seed_directory()). A node of a moment, with no
        /// data_dir, so starts from the warm set of one that lasts.
        std::string               seed_dir = "";
        bool                      enable_ipv4 = true;    ///< run the IPv4 Kademlia network
        bool                      enable_ipv6 = true;    ///< run the IPv6 Kademlia network (BEP 32)
        std::string               discovery_key = "";  ///< DHT namespace. Empty → the node's `protocol` (resolved at attach), so peers of the same app/version discover each other and mismatched protocols (which can't handshake anyway) don't even meet. Set non-empty to override with a custom discovery network.
        /// The keys to announce and search, in place of discovery_key when not
        /// empty (set_keys() changes them as the node runs).
        std::vector<std::string>  keys;
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

        /// A peer found and not connected is punched this often, found again
        /// or not, for this long after it was first found (or last found
        /// connected: a link gone is dialed for anew). A NAT lets in what
        /// comes from where it last sent to for some 30 s at least, so two
        /// nodes that keep punching each other more often than that get
        /// through on the second's punch.
        std::chrono::milliseconds redial_every{5000};
        std::chrono::milliseconds redial_for{120000};
        /// After redial_for: punched again each time the DHT hands it out
        /// again, at most this often, for as long as it does. A peer that
        /// comes online later at the address found (the DHT keeps an
        /// announce half an hour, and a NAT often keeps a port) is so met: its
        /// own punches, every redial_every, land while ours keep our NAT open
        /// to it. A little under search_interval: once a round.
        std::chrono::milliseconds redial_slow{25000};
    };

    /// Which addresses found to dial, and how: a policy of times alone.
    class RATS_API Redials {
    public:
        enum class Dial : uint8_t {
            None,   ///< dialed lately
            First,  ///< never dialed: the ordinary dial
            Again,  ///< not reached yet: a punch
        };
        using Clock = std::chrono::steady_clock;

        /// Punched every `every` for `dial_for` after first found (due());
        /// then, as found again, every `slow` at most (found()).
        Redials(std::chrono::milliseconds every, std::chrono::milliseconds dial_for,
                std::chrono::milliseconds slow)
            : every_(every), for_(dial_for), slow_(slow) {}

        /// `address` found at `now`, not connected.
        Dial found(const Address& address, Clock::time_point now);
        /// The addresses whose punch is due at `now` in their first stretch
        /// (`dial_for` after first found), found again or not — each marked
        /// punched.
        std::vector<Address> due(Clock::time_point now);
        /// When the next of those is due; none: none is in its first stretch.
        std::optional<Clock::time_point> next_due() const;
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
        std::chrono::milliseconds slow_;
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
    /// The first key's hash (the only one, unless keys were given).
    InfoHash discovery_hash() const;
    std::vector<InfoHash> discovery_hashes() const;

    /// What is done with a key: announced, so that the node is found under it;
    /// searched, so that it finds who is (and dials them); or both. A node
    /// that only announces a key never dials who it meets there, so one that
    /// finds it there gets through only if it can be dialed (a public address,
    /// a port the router forwards: PortMapped) — or meets it some other way.
    /// Behind NATs both must dial at once: Both, at both ends.
    enum class Use : uint8_t { Announce = 1, Search = 2, Both = 3 };
    struct Key {
        std::string key;
        Use use = Use::Both;
    };

    /// The keys announced and searched from now on, in place of those before
    /// (a key twice: what both say): one new is announced or searched at once,
    /// one gone no longer. None: the node finds and is found by none until some
    /// are set. Any thread; before start() too.
    void set_keys(const std::vector<Key>& keys);
    void set_keys(const std::vector<std::string>& keys);

    /// Our external (public) IP currently used to derive the DHT node id, learned
    /// via STUN at startup or in-DHT "ip" voting. "" if not yet known / random.
    std::string external_address() const;

    /// Whether `address` is this node's own, as a key it announces and searches
    /// hands it back: an IP of this host's (its interfaces, loopback) at the
    /// listen port, or where STUN sees it or the router's that forwards a port
    /// to it at a port the outside sees (the one announced, the router's, or
    /// STUN's — not the listen port: another device behind the same NAT may
    /// hold that one there). Such an address is never dialed (it would be
    /// handshaken with, and punched for two minutes). Another node on this
    /// host listens at another port.
    bool is_own(const Address& address) const;

    /// Map an application key to a stable 20-byte discovery hash (SHA-1).
    static InfoHash hash_for_key(const std::string& key);

private:
    void loop();
    /// STUN → set_external_ip on each client, and the shared socket's port.
    /// Whether a server answered. Runs on the loop thread.
    bool probe_external_ip();
    void on_peers(const std::vector<Address>& peers, const InfoHash& info_hash);
    /// Whether `hash` is a key's that is searched now: who its lookups hand
    /// back is dialed.
    bool searches(const InfoHash& hash) const;
    /// Where the peers connected are: the addresses they are dialed at, and
    /// where their packets come from — over UDP the endpoint a peer behind a
    /// NAT announces, which those addresses need not hold.
    std::vector<Address> connected_addresses() const;
    /// Punch what is due in its first stretch (Redials::due()). Loop thread.
    void punch_due(std::chrono::steady_clock::time_point now);
    /// The port peers are to dial us at over IPv4, or IPv6.
    uint16_t announced_port(bool v6 = false) const;

    /// Bring up one family's DhtClient (bind + bootstrap). Returns nullptr if it
    /// could not bind/start, so the caller can run on whatever family did come up.
    std::unique_ptr<DhtClient> make_client(AddressFamily family);

    /// Wake the loop for a flag just set: under wait_mutex_, so that the wake
    /// cannot fall between the loop's check of its flags and its sleep.
    void wake();

    /// This host's interfaces' addresses, read anew (start, a network changed).
    void refresh_own_ips();

    /// Run `fn` on each live client (IPv4 then IPv6). Loop-thread side.
    template <typename Fn>
    void for_each_client(Fn fn) {
        if (dht_)  fn(*dht_);
        if (dht6_) fn(*dht6_);
    }

    /// A key's hash, and when it was last announced over IPv4 and IPv6 (never:
    /// at once — a family whose DHT knows no node yet, at the next round).
    struct Announced {
        InfoHash hash{};
        Use use = Use::Both;
        std::optional<std::chrono::steady_clock::time_point> announced[2];
        bool searched = false;  ///< searched at all, with nodes to ask: one new at once
    };

    Config                     config_;
    mutable std::mutex         keys_mutex_;
    std::vector<Announced>     hashes_;            ///< under keys_mutex_
    bool                       keys_set_ = false;  ///< given, or set: not the protocol's (under keys_mutex_)
    PeerNetwork*               network_ = nullptr;
    DialService*               dial_ = nullptr;  ///< for punches; none: dials are ordinary
    ReflexiveAddressService*   reflexive_ = nullptr;  ///< STUN from the shared socket
    std::unique_ptr<DhtClient> dht_;    ///< IPv4 Kademlia network
    std::unique_ptr<DhtClient> dht6_;   ///< IPv6 Kademlia network (BEP 32)

    std::thread             thread_;
    std::atomic<bool>       running_{false};
    std::atomic<bool>       recover_pending_{false};  ///< network changed: re-STUN + re-announce
    std::atomic<bool>       announce_pending_{false}; ///< the port to announce changed
    std::atomic<bool>       keys_pending_{false};     ///< a key new, to announce
    std::atomic<bool>       punch_pending_{false};    ///< a peer found anew, its punches to time
    std::atomic<uint16_t>   mapped_port_{0};          ///< the router's for ours; 0: none
    std::atomic<uint16_t>   reflexive_port_{0};       ///< where STUN saw the shared socket; 0: not
    bool                    mapping_checked_ = false; ///< a second STUN server asked (loop thread)
    std::optional<Address>  last_seen_;               ///< STUN's last answer (loop thread)

    mutable std::mutex      own_mutex_;
    std::vector<IpAddress>  own_local_;   ///< this host's, loopback too (under own_mutex_)
    std::optional<IpAddress> own_seen_;   ///< where STUN sees us (under own_mutex_)
    std::optional<IpAddress> own_mapped_; ///< the router's that forwards a port (under own_mutex_)
    std::mutex              wait_mutex_;
    std::condition_variable wake_;

    std::mutex dialed_mutex_;
    Redials    dialed_;  ///< under dialed_mutex_
};

} // namespace librats
