#pragma once

/**
 * @file rendezvous.h
 * @brief A public node where peers that know one key meet: each is told of the
 *        others, at the endpoints their NATs map them to, all at the same moment.
 *
 * ── Why ─────────────────────────────────────────────────────────────────────
 * Two nodes behind NATs that know of each other only by a key (a call's link)
 * find each other in the DHT, but at endpoints they announced themselves, which
 * a NAT that maps the shared socket to another port for each destination never
 * keeps; and HolePunch and Relay need a peer both already hold, which two
 * strangers do not have. A node both reach — a public one, a `server` — is that
 * peer, and it sees each one's real endpoint: the address its UDP packets come
 * from, the NAT's mapping of its one shared socket.
 *
 * ── How ─────────────────────────────────────────────────────────────────────
 * A node that serves (`Config::serve`) says so to each peer as it connects
 * (Hello). A peer that has keys registers each with it (Register, a SHA-256 of
 * the key: the server learns no link) and is answered with the others
 * registered under it (Peers); those others are told of it in the same moment.
 * Each side then dials what it was told of over the shared socket, densely
 * (DialProfile::punch()), so the two dials cross as a punch's do — timed by the
 * server, half its round trip apart at most. One still not connected after
 * `punch_after` is behind a NAT no punch gets through, most likely (one that
 * maps the socket anew for each destination), and is handed to RelayService: a
 * circuit through the server (Relay's Serving puts it first), up in a round
 * trip, over which Relay has HolePunch try again, a direct link taking the
 * circuit's place unseen if one does. Without a Relay, HolePunchService.
 * A registration lasts while its connection does; registering again, every
 * `refresh`, is answered again, so a peer not reached is tried again.
 *
 * A peer that moves — another network, a VPN switched on, a NAT that gave it
 * another port — keeps its connection to the server, which follows it there
 * (udp_connection.h, "Migration"), but not those to its peers behind NATs of
 * their own: they let in only what comes from where they sent, and it now
 * comes from somewhere else. The server, seeing it move, tells the others
 * under its keys where it is now and it where they are (Moved), and both
 * sides dial as they would on Peers, connected or not: each dial opens its
 * NAT to the other, so the old connection follows the move, or a new one
 * comes up beside it and takes over (Node's standby). One whose link still
 * goes unanswered `punch_after_move` on is handed to Relay as above. A server
 * sees a peer move only when it hears from it, so a peer whose link to another
 * goes dead speaks to its servers at once (registering again): if it is the
 * one that moved, they see it.
 *
 * Servers are dialed from `Config::servers` (host:port, resolved here) and kept:
 * one lost is dialed again, 5 s after and doubling up to a minute. One of those
 * is known for a server as it connects, before its Hello — an application that
 * keeps servers apart from its peers (a call's members) asks is_server() in its
 * own connected handler, whichever runs first. A node learns of a server any other way as well — a
 * peer exchange naming it — by its Hello, and says so (on_server_found()).
 *
 * Servers that know each other — met however they met, a DHT's key of their
 * own as a rule — say Hello to each other too, and a server tells each peer
 * the others it is connected to (Servers): as it says Hello, and again as it
 * answers a registration when one has come since. A node keeps them as it
 * likes (on_servers()).
 *
 * Of many servers a node knows — `Config::candidates`, as many as it was told
 * of — it meets at a few, `Config::choose`, and every node under the same key
 * must pick the same ones although their lists differ in part: the ones that
 * rank first by a hash of the key and each server's IP (rendezvous hashing,
 * choose()). Two nodes whose lists differ in fewer than `choose` servers each
 * share the first of the servers both know, so they meet. A server is one by
 * its IP — of two at one address, the first listed — so many ports of one
 * host weigh no more than one. The chosen are resolved and picked on the
 * worker as it starts, then dialed and kept as Config::servers are.
 *
 * ── Wire format (MessageType::Rendezvous), big-endian ───────────────────────
 *   [u8 ver=1][u8 op]
 *     op=0 Hello    —                                          server → peer
 *     op=1 Register [32B key]                                  peer → server
 *     op=2 Peers    [u8 count] × { [32B id][u8 n] × { [u8 ip_len][ip][u16 port] } }
 *                                                              server → peer
 *     op=3 Moved    as Peers: dial them even if connected      server → peer
 *     op=4 Servers  [u8 count] × { [u8 ip_len][ip][u16 port] }  server → peer
 * The first endpoint of each in Peers is where the server sees its UDP packets
 * come from; the others are what it identified itself with (its listen port at
 * the address seen, and the ones it advertised: another on the same network
 * dials those). Servers names each server at the first of those alone.
 *
 * Trust: a server's word on where a peer is, is acted on with a few dense dials,
 * the exposure PeerExchange and HolePunch already accept, and only from a peer
 * that said Hello. A server bounds what it keeps: keys per peer, peers per key,
 * keys in all, and registrations per peer per second.
 *
 * Threading: handlers run on reactor threads; one worker thread dials servers,
 * registers again and hands unreached peers on. All state is behind one mutex,
 * never held across a call into the network.
 */

#include "librats/core/address.h"
#include "librats/core/host_endpoint.h"
#include "librats/node/peer_network.h"
#include "librats/peer/peer_id.h"
#include "librats/peer/peer_info.h"
#include "librats/util/rats_export.h"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace librats {

class DialService;
class ServiceRegistry;

class RATS_API Rendezvous final : public Subsystem {
public:
    struct Config {
        // ── Meeting through servers ─────────────────────────────────────────

        /// Servers to dial and keep ("host:port", a name or an address).
        std::vector<HostEndpoint> servers;
        /// Servers to choose from: `choose` of them per key (choose()) are
        /// dialed and kept as `servers` are. One whose name does not resolve
        /// is passed over.
        std::vector<HostEndpoint> candidates;
        size_t                    choose = 2;
        /// The keys this node is met under, registered with every server.
        std::vector<std::string> keys;
        /// How often each key is registered again: the others not reached are
        /// told of anew, and tried again.
        std::chrono::milliseconds refresh{30000};
        /// How long a peer told of may take to connect by the dials alone
        /// before it is handed to Relay (or, without one, HolePunch). Covers
        /// the punch profile's eight Initials and a handshake.
        std::chrono::milliseconds punch_after{3000};
        /// The same for a peer told of by Moved: a punch after a move goes
        /// through most often not at all — the moved side's packets to the old
        /// link left the other's NAT a mapping in the way — so a circuit comes
        /// sooner. A direct link that comes up later takes its place.
        std::chrono::milliseconds punch_after_move{1000};
        /// A server lost or not reached is dialed again after this, doubling up
        /// to `redial_max`.
        std::chrono::milliseconds redial{5000};
        std::chrono::milliseconds redial_max{60000};

        // ── Serving ─────────────────────────────────────────────────────────

        /// Be a server: keep who registered what, and introduce them.
        bool serve = false;
        size_t max_keys_per_peer = 4;
        /// Peers registered under one key; one past it is answered all the
        /// same, but kept nowhere, so nobody else is told of it.
        size_t max_peers_per_key = 64;
        size_t max_keys = 4096;
        /// Registrations one peer may make per window.
        size_t                    request_budget = 8;
        std::chrono::milliseconds request_window{1000};
    };

    /// What a key is registered as: a SHA-256 of it.
    using Key = std::array<uint8_t, 32>;
    static Key key_of(const std::string& key);

    /// The `count` of `candidates` that `key` meets at: those ranking first by
    /// a hash of the key and each one's IP, best first; of two at one IP, the
    /// first listed. The same wherever the same servers are known.
    static std::vector<Address> choose(const Key& key, const std::vector<Address>& candidates,
                                       size_t count);

    Rendezvous();
    explicit Rendezvous(Config config);
    ~Rendezvous() override;

    void attach(NodeContext& ctx) override;
    void start() override;
    void stop() override;

    /// The servers connected now: peers that said Hello, or connected at an
    /// address of Config::servers.
    std::vector<PeerId> servers() const;
    /// The servers chosen of Config::candidates, once the worker has picked
    /// them: every key's, best first.
    std::vector<Address> chosen() const;
    /// Whether `peer` is one of them. Known as it connects, in any connected
    /// handler, for a server of Config::servers.
    bool is_server(const PeerId& peer) const;
    /// A peer said Hello that was not known for a server as it connected. Runs
    /// on a reactor thread; register before start().
    void on_server_found(std::function<void(const PeerId&)> handler);
    /// A server told of the other servers it is connected to, where each is
    /// dialed. Runs on a reactor thread; register before start().
    void on_servers(std::function<void(const PeerId& server, const std::vector<Address>& servers)> handler);

    // — diagnostics and tests —
    /// Registrations this node keeps as a server, over every key.
    size_t registrations() const;
    /// Peers told of by servers and handed on, unreached, to a relay or a punch.
    uint64_t handed_on() const noexcept { return handed_on_.load(); }

private:
    struct ServerDial {
        HostEndpoint                          at;
        std::optional<Address>                resolved;  ///< what was dialed last
        std::chrono::steady_clock::time_point next{};
        std::chrono::milliseconds             backoff{};
    };
    struct Registered {
        std::unordered_set<PeerId, PeerId::Hash> peers;
    };
    /// Client: a peer told of, until it is reached or handed on.
    struct Unreached {
        std::chrono::steady_clock::time_point due;
        bool moved = false;  ///< told of by Moved: reached only once its link answers
    };
    struct Budget {
        std::chrono::steady_clock::time_point window_started{};
        size_t                                spent = 0;
    };

    // — reactor threads —
    void handle(const Peer& from, ByteView payload);
    void on_connected(const PeerId& peer);
    /// Client: whether `peer` connected at an address of Config::servers.
    bool at_server_address(const PeerId& peer) const;
    void on_disconnected(const PeerId& peer);
    /// Client: a server said Hello.
    void on_hello(const PeerId& server);
    /// Server: `peer` registered `key`.
    void on_register(const PeerId& peer, const Key& key);
    /// Client: a server told of the other servers.
    void on_servers_told(const PeerId& server, ByteView body);
    /// Client: a server told of peers; dial them — `moved`: connected or not.
    void on_peers(const PeerId& server, ByteView body, bool moved);
    /// Server: `peer` moved; tell those it meets, and it of them.
    void on_moved(const PeerId& peer);
    /// Client: a path sample of `peer`'s link; one gone dead — a peer's or a
    /// server's — has the servers spoken to.
    void on_path(const PeerId& peer, const PathStats& path);
    /// Server: whether `peer` may make another request now (Budget).
    bool spend(const PeerId& peer);

    // — outgoing —
    void register_keys(const PeerId& server);
    /// Server: tell `peer` of the other servers, if any came since it was last
    /// told.
    void tell_servers(const PeerId& peer);
    /// The Peers (or Moved) message naming `peers`, each with its endpoints
    /// from `known`.
    Bytes peers_message(uint8_t op, const std::vector<PeerId>& peers,
                        const std::unordered_map<PeerId, PeerInfo, PeerId::Hash>& known) const;

    // — worker —
    void loop();
    /// Resolve Config::candidates and add the chosen to the servers dialed.
    void choose_servers();
    void dial_servers(std::chrono::steady_clock::time_point now);
    void hand_on_unreached(std::chrono::steady_clock::time_point now);
    void refresh(std::chrono::steady_clock::time_point now);

    Config                config_;
    std::vector<Key>      keys_;  ///< config_.keys, hashed
    PeerNetwork*          network_  = nullptr;
    ServiceRegistry*      services_ = nullptr;
    DialService*          dial_     = nullptr;
    std::atomic<bool>     running_{false};
    std::atomic<uint64_t> handed_on_{0};

    mutable std::mutex      mutex_;
    std::condition_variable wake_;
    std::thread             worker_;
    // Client.
    std::vector<ServerDial>                              server_dials_;
    std::vector<Address>                                 chosen_;
    std::unordered_set<PeerId, PeerId::Hash>             servers_;     ///< said Hello
    std::unordered_set<PeerId, PeerId::Hash>             at_servers_;  ///< at a server address
    std::vector<std::function<void(const PeerId&)>>      found_handlers_;
    std::vector<std::function<void(const PeerId&, const std::vector<Address>&)>> servers_handlers_;
    std::unordered_map<PeerId, Unreached, PeerId::Hash>  unreached_;
    std::chrono::steady_clock::time_point                refresh_at_{};
    std::chrono::steady_clock::time_point                spoken_at_{};  ///< on a dead link
    // Server.
    std::map<Key, Registered>                                        registered_;
    std::unordered_map<PeerId, std::vector<Key>, PeerId::Hash>       keys_of_;
    std::unordered_map<PeerId, Budget, PeerId::Hash>                 budgets_;
    uint64_t                                                         servers_came_ = 0;  ///< Hellos heard
    std::unordered_map<PeerId, uint64_t, PeerId::Hash>               servers_told_;  ///< servers_came_ as told
};

} // namespace librats
