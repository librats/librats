#pragma once

/**
 * @file dht.h
 * @brief Public DHT client — a thin facade over the modular dht::Node engine.
 *
 * This is the long-standing `librats::DhtClient` API every consumer already uses. It
 * now wraps the rewritten engine (src/dht/node.h + friends): a single-threaded,
 * lock-free dht::Node driven by a DhtRunner over a UdpTransport. The facade owns that
 * trio and marshals public calls onto the runner's thread, so callers keep the same
 * simple, thread-safe surface they always had.
 *
 * The engine internals live in namespace librats::dht; this header only exposes the
 * stable public types so consumers (and their includes) are unchanged.
 */

#include "core/address.h"
#include "core/socket.h"   // AddressFamily
#include "dht/krpc.h"      // KrpcProtocol/KrpcMessage (wire format, used by tests)

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <vector>

namespace librats {

// Standard BitTorrent DHT port. The public NodeId/InfoHash id types come from
// dht/krpc.h (included above), so the facade re-exposes them without duplicating
// the engine-internal dht::NodeId.
constexpr int DHT_PORT = 6881;

/// Discovered peers for an info-hash are delivered through this callback.
using PeerDiscoveryCallback = std::function<void(const std::vector<Address>& peers, const InfoHash& info_hash)>;

#ifdef RATS_SEARCH_FEATURES
/// Spider mode: invoked when a peer announces it has a torrent.
using SpiderAnnounceCallback = std::function<void(const InfoHash& info_hash, const Address& peer)>;
#endif

/**
 * Kademlia DHT client (BEP 5/32/42). One instance serves one address family.
 */
class DhtClient {
public:
    DhtClient(int port = DHT_PORT, const std::string& bind_address = "",
              const std::string& data_directory = "",
              AddressFamily address_family = AddressFamily::IPv4);
    ~DhtClient();

    DhtClient(const DhtClient&) = delete;
    DhtClient& operator=(const DhtClient&) = delete;

    bool start();
    void stop();
    void shutdown_immediate();
    bool is_running() const;
    uint16_t get_port() const;

    bool bootstrap(const std::vector<Address>& bootstrap_nodes);
    bool find_peers(const InfoHash& info_hash, PeerDiscoveryCallback callback);
    bool announce_peer(const InfoHash& info_hash, uint16_t port = 0, PeerDiscoveryCallback callback = nullptr);
    void cancel_search(const InfoHash& info_hash);

    NodeId get_node_id() const;
    void set_external_ip(const std::string& ip);
    std::string get_external_address() const;
    static bool generate_node_id_from_ip(const std::string& ip, NodeId& out, std::mt19937& gen);
    static bool verify_node_id_for_ip(const NodeId& id, const std::string& ip);
    static std::vector<Address> get_default_bootstrap_nodes();

    size_t get_routing_table_size() const;
    bool is_search_active(const InfoHash& info_hash) const;
    bool is_announce_active(const InfoHash& info_hash) const;
    size_t get_active_searches_count() const;
    size_t get_active_announces_count() const;

    AddressFamily address_family() const;
    bool is_ipv6() const;

    std::string routing_table_file_path() const;
    bool save_routing_table();
    bool load_routing_table();
    void set_data_directory(const std::string& directory);

#ifdef RATS_SEARCH_FEATURES
    void set_spider_mode(bool enable);
    bool is_spider_mode() const;
    void set_spider_announce_callback(SpiderAnnounceCallback callback);
    void set_spider_ignore(bool ignore);
    bool is_spider_ignoring() const;
    void spider_walk();
    size_t get_spider_pool_size() const;
    size_t get_spider_visited_count() const;
    void clear_spider_state();
#endif

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Resolve any hostname bootstrap entries to numeric IPs of the given family, dropping
// wrong-family and unresolvable ones. The DHT engine matches a reply's source address
// verbatim against the address it queried (anti-spoofing), so a seed kept as a hostname
// would have every reply dropped — seeds must enter the engine as numeric IPs of the
// right family. Resolution can block, so callers run this off the DHT loop thread.
// Exposed for testing.
std::vector<Address> resolve_bootstrap_nodes(const std::vector<Address>& nodes, bool ipv6);

// Node id -> lowercase hex, for logging.
std::string node_id_to_hex(const NodeId& id);

} // namespace librats
