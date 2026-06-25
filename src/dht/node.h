#pragma once

/**
 * @file node.h
 * @brief The Kademlia engine: routing table + RPC + storage + lookups, wired together.
 *
 * Pure logic, no sockets and no threads — it sends through an injected Transport and
 * is driven from outside by on_datagram() (a packet arrived) and tick() (time passed).
 * That makes the whole DHT unit-testable with a mock transport. A thin UdpTransport +
 * DhtClient facade (Phase 5) supply the real socket and threading.
 *
 * One node serves a single address family (IPv4 or IPv6 — separate Kademlia networks
 * per BEP 32). It answers incoming queries (ping/find_node/get_peers/announce_peer)
 * and runs its own lookups (bootstrap, find_peers, announce_peer).
 */

#include "core/address.h"
#include "dht/dos_blocker.h"
#include "dht/find_peers.h"
#include "dht/id.h"
#include "dht/observer.h"
#include "dht/routing_table.h"
#include "dht/rpc_manager.h"
#include "dht/storage.h"
#include "dht/transport.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

namespace librats {
struct KrpcMessage;

namespace dht {

#ifdef RATS_SEARCH_FEATURES
// Invoked when another peer announces it has a torrent (spider mode collects these).
using SpiderAnnounceCallback = std::function<void(const InfoHash&, const Address&)>;
#endif

class Node {
public:
    Node(Transport& transport, const NodeId& self, bool ipv6);

    // -- driven by the transport layer -----------------------------------------
    void on_datagram(const std::vector<uint8_t>& data, const Address& from, TimePoint now);
    void tick(TimePoint now);  // periodic maintenance

    // -- our own lookups --------------------------------------------------------
    void bootstrap(const std::vector<Address>& nodes, TimePoint now);
    // Remember the (already resolved, numeric) seed set so an internal reseed — e.g. the
    // spider crawl when its frontier empties — can reuse it instead of unresolved hostnames.
    void set_bootstrap_nodes(std::vector<Address> nodes) { bootstrap_nodes_ = std::move(nodes); }
    void find_peers(const InfoHash& info_hash, FindPeers::PeersCallback on_peers,
                    FindPeers::DoneCallback on_done, TimePoint now);
    void announce_peer(const InfoHash& info_hash, uint16_t port, bool implied_port,
                       FindPeers::DoneCallback on_done, TimePoint now);
    void cancel_lookup(const InfoHash& info_hash);                       // drop active lookups for it
    bool lookup_active(const InfoHash& info_hash, bool announce) const;  // is one running?
    std::size_t lookup_count(bool announce) const;                       // how many running

#ifdef RATS_SEARCH_FEATURES
    // Spider mode — aggressive crawl that collects announce_peer requests from the
    // network. set/walk/clear must run on the loop thread (post them); the on/off and
    // ignore flags are atomics readable from anywhere.
    // Just flips the atomic (safe from any thread); spider_walk seeds the pool lazily.
    void set_spider_mode(bool enable) noexcept { spider_mode_.store(enable); }
    bool is_spider_mode() const noexcept { return spider_mode_.load(); }
    void set_spider_ignore(bool ignore) noexcept { spider_ignore_.store(ignore); }
    bool is_spider_ignoring() const noexcept { return spider_ignore_.load(); }
    void set_spider_announce_callback(SpiderAnnounceCallback cb) { spider_announce_ = std::move(cb); }
    void spider_walk(TimePoint now);
    void clear_spider_state();
    std::size_t spider_pool_size() const noexcept { return spider_pool_.size(); }
    std::size_t spider_visited_count() const noexcept { return spider_visited_.size(); }
#endif

    // -- accessors / config -----------------------------------------------------
    const NodeId& self() const noexcept { return self_; }
    bool is_ipv6() const noexcept { return ipv6_; }
    void set_external_ip(const std::string& ip);          // BEP 42: re-derive our id
    const std::string& external_address() const noexcept { return external_address_; }
    RoutingTable& routing_table() noexcept { return table_; }
    const RoutingTable& routing_table() const noexcept { return table_; }
    std::size_t active_lookups() const noexcept { return lookups_.size(); }

    static std::vector<Address> default_bootstrap_nodes();

private:
    // incoming query handlers (server side)
    void handle_query(const KrpcMessage& msg, const Address& from, TimePoint now);
    void handle_response(const KrpcMessage& msg, const Address& from, TimePoint now);

    void send_message(const KrpcMessage& msg, const Address& to);  // a response (echoes txn, stamps ip)
    void ping(const NodeId& id, const Address& ep, TimePoint now);  // liveness probe
    void maybe_update_external_ip(const std::string& reported_ip, const Address& from);
    FindPeers& start_lookup(std::unique_ptr<FindPeers> lookup, TimePoint now);
    void reap_finished();
    std::vector<std::string> want() const { return {ipv6_ ? "n6" : "n4"}; }

    Transport&   transport_;
    NodeId       self_;
    bool         ipv6_;
    RoutingTable table_;
    RpcManager   rpc_;
    PeerStore    peers_;
    TokenManager tokens_;
    DosBlocker   dos_;
    std::vector<std::unique_ptr<Traversal>> lookups_;
    std::vector<Address> bootstrap_nodes_;  // resolved seeds, reused by an internal reseed

    // BEP 42: learn our external address from the "ip" nodes echo back, but require a
    // consensus of distinct responders before trusting it (one node can't poison us).
    static constexpr int kExternalIpVoteThreshold = 5;
    std::string             external_address_;
    std::map<std::string, int> ip_votes_;
    std::set<std::string>      ip_voters_;

    // maintenance cadence
    static constexpr std::chrono::seconds kRefreshInterval{6};
    static constexpr std::chrono::minutes kSelfRefreshInterval{6};
    TimePoint last_refresh_{};
    TimePoint last_self_refresh_{};

#ifdef RATS_SEARCH_FEATURES
    // An id that looks close to `target` (first 10 bytes from target, last 10 from us),
    // so peers route more queries our way during a crawl.
    NodeId neighbor_id(const NodeId& target) const;
    void   add_spider_node(const NodeEntry& node);
    void   spider_absorb(const KrpcMessage& msg, const Address& from);  // reply → spider pool
    bool   spider_contacted(const std::string& ip) const;

    std::atomic<bool>      spider_mode_{false};
    std::atomic<bool>      spider_ignore_{false};
    SpiderAnnounceCallback spider_announce_;
    std::vector<NodeEntry>        spider_pool_;   // crawl frontier (kept apart from the routing table)
    std::unordered_set<NodeId, NodeIdHash> spider_visited_;
    std::unordered_set<std::string>        spider_contacted_ips_;
    TimePoint              last_spider_bootstrap_{};
    static constexpr std::size_t kMaxSpiderNodes = 2000;
    static constexpr std::size_t kMaxSpiderVisited = 10000;
    static constexpr std::size_t kMaxSpiderContactedIps = 10000;
#endif
};

} // namespace dht
} // namespace librats
