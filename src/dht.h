#pragma once

#include "socket.h"
#include "krpc.h"
#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <condition_variable>

// Hash specialization for Peer and NodeId (must be defined before use in unordered_map/set)
namespace std {
    template<>
    struct hash<librats::Peer> {
        std::size_t operator()(const librats::Peer& peer) const noexcept {
            std::hash<std::string> hasher;
            return hasher(peer.ip + ":" + std::to_string(peer.port));
        }
    };
    
    template<>
    struct hash<array<uint8_t, 20>> {
        std::size_t operator()(const array<uint8_t, 20>& id) const noexcept {
            std::size_t seed = 0;
            std::hash<uint8_t> hasher;
            for (const auto& byte : id) {
                seed ^= hasher(byte) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            }
            return seed;
        }
    };
}

namespace librats {

// Constants for Kademlia DHT
constexpr size_t NODE_ID_SIZE = 20;  // 160 bits = 20 bytes
constexpr size_t K_BUCKET_SIZE = 8;  // Maximum nodes per k-bucket
constexpr size_t ALPHA = 3;          // Concurrency parameter
constexpr int DHT_PORT = 6881;       // Standard BitTorrent DHT port

using NodeId = std::array<uint8_t, NODE_ID_SIZE>;
using InfoHash = std::array<uint8_t, NODE_ID_SIZE>;

/**
 * Search node state flags (bitfield)
 * Flags can be combined to track the full history of a node in a search.
 */
namespace SearchNodeFlags {
    constexpr uint8_t QUERIED       = 1 << 0;  // Query has been sent to this node
    constexpr uint8_t SHORT_TIMEOUT = 1 << 1;  // Node exceeded short timeout (slot freed, still waiting)
    constexpr uint8_t RESPONDED     = 1 << 2;  // Node successfully responded
    constexpr uint8_t TIMED_OUT     = 1 << 3;  // Node fully timed out (failed)
    constexpr uint8_t ABANDONED     = 1 << 4;  // Node was discarded during search truncation
}

/**
 * DHT Node information
 * Based on libtorrent's node_entry with fail_count and RTT tracking
 */
struct DhtNode {
    NodeId id;
    Peer peer;
    std::chrono::steady_clock::time_point last_seen;
    
    // Round-trip time in milliseconds (0xffff = unknown, lower is better)
    uint16_t rtt = 0xffff;
    
    // Number of consecutive failures (0xff = never pinged, 0 = confirmed good)
    uint8_t fail_count = 0xff;
    
    DhtNode() : last_seen(std::chrono::steady_clock::now()) {}
    DhtNode(const NodeId& id, const Peer& peer)
        : id(id), peer(peer), last_seen(std::chrono::steady_clock::now()) {}
    
    // Has this node ever responded to us?
    bool pinged() const { return fail_count != 0xff; }
    
    // Is this node confirmed good? (responded with no recent failures)
    bool confirmed() const { return fail_count == 0; }
    
    // Mark node as failed (timed out)
    void mark_failed() { 
        if (pinged() && fail_count < 0xfe) ++fail_count; 
    }
    
    // Mark node as successful (responded)
    void mark_success() { 
        fail_count = 0; 
        last_seen = std::chrono::steady_clock::now();
    }
    
    // Update RTT with exponential moving average
    void update_rtt(uint16_t new_rtt) {
        if (new_rtt == 0xffff) return;
        if (rtt == 0xffff) {
            rtt = new_rtt;
        } else {
            // Weighted average: 2/3 old + 1/3 new
            rtt = static_cast<uint16_t>(rtt * 2 / 3 + new_rtt / 3);
        }
    }
    
    // Compare nodes: "less" means "better" node
    // Priority: confirmed > not confirmed, then lower fail_count, then lower RTT
    bool is_worse_than(const DhtNode& other) const {
        // Nodes with failures are worse
        if (fail_count != other.fail_count) {
            return fail_count > other.fail_count;
        }
        // Higher RTT is worse
        return rtt > other.rtt;
    }
};



/**
 * Peer discovery callback
 */
using PeerDiscoveryCallback = std::function<void(const std::vector<Peer>& peers, const InfoHash& info_hash)>;

/**
 * Deferred callbacks structure for avoiding deadlock
 * Callbacks are collected while holding the mutex, then invoked after releasing it
 */
struct DeferredCallbacks {
    std::vector<PeerDiscoveryCallback> callbacks;
    std::vector<Peer> peers;
    InfoHash info_hash;
    bool should_invoke = false;
    
    void invoke() {
        if (should_invoke) {
            for (const auto& cb : callbacks) {
                if (cb) cb(peers, info_hash);
            }
        }
    }
};

/**
 * DHT Kademlia implementation
 */
class DhtClient {
public:
    /**
     * Constructor
     * @param port The UDP port to bind to (default: 6881)
     * @param bind_address The interface IP address to bind to (empty for all interfaces)
     */
    DhtClient(int port = DHT_PORT, const std::string& bind_address = "");
    
    /**
     * Destructor
     */
    ~DhtClient();
    
    /**
     * Start the DHT client
     * @return true if successful, false otherwise
     */
    bool start();
    
    /**
     * Stop the DHT client
     */
    void stop();
    
    /**
     * Trigger immediate shutdown of all background threads
     */
    void shutdown_immediate();
    
    /**
     * Bootstrap the DHT with known nodes
     * @param bootstrap_nodes Vector of bootstrap nodes
     * @return true if successful, false otherwise
     */
    bool bootstrap(const std::vector<Peer>& bootstrap_nodes);
    
    /**
     * Find peers for a specific info hash
     * @param info_hash The info hash to search for
     * @param callback Callback to receive discovered peers
     * @return true if search started successfully, false otherwise
     */
    bool find_peers(const InfoHash& info_hash, PeerDiscoveryCallback callback);
    
    /**
     * Announce that this node is a peer for a specific info hash
     * @param info_hash The info hash to announce
     * @param port The port to announce (0 for DHT port)
     * @return true if announcement started successfully, false otherwise
     */
    bool announce_peer(const InfoHash& info_hash, uint16_t port = 0);
    
    /**
     * Get our node ID
     * @return The node ID
     */
    const NodeId& get_node_id() const { return node_id_; }
    
    /**
     * Get number of nodes in routing table
     * @return Number of nodes
     */
    size_t get_routing_table_size() const;
    
    /**
     * Get number of pending ping verifications
     * @return Number of pending ping verifications
     */
    size_t get_pending_ping_verifications_count() const;
    
    /**
     * Check if DHT is running
     * @return true if running, false otherwise
     */
    bool is_running() const { return running_; }
    
    /**
     * Get default BitTorrent DHT bootstrap nodes
     * @return Vector of bootstrap nodes
     */
    static std::vector<Peer> get_default_bootstrap_nodes();

private:
    int port_;
    std::string bind_address_;
    NodeId node_id_;
    socket_t socket_;
    std::atomic<bool> running_;
    
    // ============================================================================
    // MUTEX LOCK ORDER - CRITICAL: Always acquire mutexes in this order to avoid deadlocks
    // ============================================================================
    // When acquiring multiple mutexes, ALWAYS follow this order:
    //
    // 1. pending_pings_mutex_           (Ping verification state, nodes_being_replaced_)
    // 2. pending_searches_mutex_        (Search state and transaction mappings)
    // 3. routing_table_mutex_           (core routing data)
    // 4. pending_announces_mutex_       (Announce state)
    // 5. announced_peers_mutex_         (Stored peer data)
    // 6. peer_tokens_mutex_             (Token validation data)
    // 7. shutdown_mutex_                (Lowest priority - can be locked independently)
    //
    // Routing table (k-buckets)
    std::vector<std::vector<DhtNode>> routing_table_;
    mutable std::mutex routing_table_mutex_;  // Lock order: 3
    
    // Tokens for peers (use Peer directly as key for efficiency)
    struct PeerToken {
        std::string token;
        std::chrono::steady_clock::time_point created_at;
        
        PeerToken() : created_at(std::chrono::steady_clock::now()) {}
        PeerToken(const std::string& t)
            : token(t), created_at(std::chrono::steady_clock::now()) {}
    };
    std::unordered_map<Peer, PeerToken> peer_tokens_;
    std::mutex peer_tokens_mutex_;  // Lock order: 6
    

    // Pending announce tracking (for BEP 5 compliance)
    struct PendingAnnounce {
        InfoHash info_hash;
        uint16_t port;
        std::chrono::steady_clock::time_point created_at;
        
        PendingAnnounce(const InfoHash& hash, uint16_t p)
            : info_hash(hash), port(p), created_at(std::chrono::steady_clock::now()) {}
    };
    std::unordered_map<std::string, PendingAnnounce> pending_announces_;
    std::mutex pending_announces_mutex_;  // Lock order: 4
    
    // Pending find_peers tracking (to map transaction IDs to info_hash)
    struct PendingSearch {
        InfoHash info_hash;
        std::chrono::steady_clock::time_point created_at;
        
        // Iterative search state - search_nodes is sorted by distance to info_hash (closest first)
        std::vector<DhtNode> search_nodes;
        std::vector<Peer> found_peers;          // found peers for this search
        // Single map tracking node states using SearchNodeFlags bitfield
        // A node is "known" if it exists in this map (any flags set or value 0)
        std::unordered_map<NodeId, uint8_t> node_states;
        
        int invoke_count;                           // number of outstanding requests
        int branch_factor;                          // adaptive concurrency limit (starts at ALPHA)
        bool is_finished;                           // whether the search is finished

        // Callbacks to invoke when peers are found (supports multiple concurrent searches for same info_hash)
        std::vector<PeerDiscoveryCallback> callbacks;
        
        PendingSearch(const InfoHash& hash)
            : info_hash(hash), created_at(std::chrono::steady_clock::now()), 
              invoke_count(0), branch_factor(ALPHA), is_finished(false) {}
    };
    std::unordered_map<std::string, PendingSearch> pending_searches_; // info_hash (hex) -> PendingSearch
    std::mutex pending_searches_mutex_;  // Lock order: 2
    
    // Transaction tracking with queried node info for proper responded_nodes tracking
    struct SearchTransaction {
        std::string info_hash_hex;
        NodeId queried_node_id;
        std::chrono::steady_clock::time_point sent_at;
        
        SearchTransaction() = default;
        SearchTransaction(const std::string& hash, const NodeId& id)
            : info_hash_hex(hash), queried_node_id(id), 
              sent_at(std::chrono::steady_clock::now()) {}
    };
    std::unordered_map<std::string, SearchTransaction> transaction_to_search_; // transaction_id -> SearchTransaction
    
    // Peer announcement storage (BEP 5 compliant)
    struct AnnouncedPeer {
        Peer peer;
        std::chrono::steady_clock::time_point announced_at;
        
        AnnouncedPeer(const Peer& p) 
            : peer(p), announced_at(std::chrono::steady_clock::now()) {}
    };
    // Map from info_hash (as hex string) to list of announced peers
    std::unordered_map<std::string, std::vector<AnnouncedPeer>> announced_peers_;
    std::mutex announced_peers_mutex_;  // Lock order: 5
    
    // Ping-before-replace eviction tracking (BEP 5 compliant)
    // When a bucket is full and a new node wants to join:
    // 1. We ping the WORST node in the bucket (highest RTT) to check if it's still alive
    // 2. If old node responds -> keep it, discard candidate
    // 3. If old node times out -> replace it with candidate
    struct PingVerification {
        DhtNode candidate_node;      // The new node waiting to be added
        DhtNode old_node;            // The existing node we're pinging to verify it's alive
        int bucket_index;            // Which bucket this affects
        std::chrono::steady_clock::time_point ping_sent_at;
        
        PingVerification(const DhtNode& candidate, const DhtNode& old, int bucket_idx)
            : candidate_node(candidate), old_node(old), bucket_index(bucket_idx), 
              ping_sent_at(std::chrono::steady_clock::now()) {}
    };
    std::unordered_map<std::string, PingVerification> pending_pings_;  // transaction_id -> PingVerification
    std::unordered_set<NodeId> nodes_being_replaced_;    // Track old nodes that have pending ping verifications
    mutable std::mutex pending_pings_mutex_;  // Lock order: 1 (protects pending_pings_, nodes_being_replaced_)
    
    // Network thread
    std::thread network_thread_;
    std::thread maintenance_thread_;
    
    // Conditional variables for immediate shutdown
    std::condition_variable shutdown_cv_;
    std::mutex shutdown_mutex_;  // Lock order: 7 (can be locked independently)
    
    // Helper functions
    void network_loop();
    void maintenance_loop();
    void handle_message(const std::vector<uint8_t>& data, const Peer& sender);
    

    
    // KRPC protocol handlers  
    void handle_krpc_message(const KrpcMessage& message, const Peer& sender);
    void handle_krpc_ping(const KrpcMessage& message, const Peer& sender);
    void handle_krpc_find_node(const KrpcMessage& message, const Peer& sender);
    void handle_krpc_get_peers(const KrpcMessage& message, const Peer& sender);
    void handle_krpc_announce_peer(const KrpcMessage& message, const Peer& sender);
    void handle_krpc_response(const KrpcMessage& message, const Peer& sender);
    void handle_krpc_error(const KrpcMessage& message, const Peer& sender);
    
    // KRPC protocol sending
    bool send_krpc_message(const KrpcMessage& message, const Peer& peer);
    void send_krpc_ping(const Peer& peer);
    void send_krpc_find_node(const Peer& peer, const NodeId& target);
    void send_krpc_get_peers(const Peer& peer, const InfoHash& info_hash);
    void send_krpc_announce_peer(const Peer& peer, const InfoHash& info_hash, uint16_t port, const std::string& token);
    
    void add_node(const DhtNode& node, bool confirmed = true);
    std::vector<DhtNode> find_closest_nodes(const NodeId& target, size_t count = K_BUCKET_SIZE);
    std::vector<DhtNode> find_closest_nodes_unlocked(const NodeId& target, size_t count = K_BUCKET_SIZE);
    int get_bucket_index(const NodeId& id);
    
    NodeId generate_node_id();
    NodeId xor_distance(const NodeId& a, const NodeId& b);
    bool is_closer(const NodeId& a, const NodeId& b, const NodeId& target);

    
    std::string generate_token(const Peer& peer);
    bool verify_token(const Peer& peer, const std::string& token);
    

    
    void cleanup_stale_nodes();
    void cleanup_stale_peer_tokens();
    void refresh_buckets();
    
    // Pending announce management
    void cleanup_stale_announces();
    void handle_get_peers_response_for_announce(const std::string& transaction_id, const Peer& responder, const std::string& token);
    
    // Pending search management
    void cleanup_stale_searches();
    void cleanup_timed_out_search_requests();
    void cleanup_search_node_states();
    void handle_get_peers_response_for_search(const std::string& transaction_id, const Peer& responder, const std::vector<Peer>& peers);
    void handle_get_peers_response_with_nodes(const std::string& transaction_id, const Peer& responder, const std::vector<KrpcNode>& nodes);
    void handle_get_peers_empty_response(const std::string& transaction_id, const Peer& responder);
    bool add_search_requests(PendingSearch& search, DeferredCallbacks& deferred);
    void add_node_to_search(PendingSearch& search, const DhtNode& node);
    
    // Peer announcement storage management
    void store_announced_peer(const InfoHash& info_hash, const Peer& peer);
    std::vector<Peer> get_announced_peers(const InfoHash& info_hash);
    void cleanup_stale_announced_peers();
    
    // Ping-before-replace eviction management
    void initiate_ping_verification(const DhtNode& candidate_node, const DhtNode& old_node, int bucket_index);
    void handle_ping_verification_response(const std::string& transaction_id, const NodeId& responder_id, const Peer& responder);
    void cleanup_stale_ping_verifications();
    bool perform_replacement(const DhtNode& candidate_node, const DhtNode& node_to_replace, int bucket_index);
    
    // Conversion utilities
    static KrpcNode dht_node_to_krpc_node(const DhtNode& node);
    static DhtNode krpc_node_to_dht_node(const KrpcNode& node);
    static std::vector<KrpcNode> dht_nodes_to_krpc_nodes(const std::vector<DhtNode>& nodes);
    static std::vector<DhtNode> krpc_nodes_to_dht_nodes(const std::vector<KrpcNode>& nodes);
};

/**
 * Utility functions
 */

/**
 * Convert string to NodeId
 * @param str The string to convert (must be 20 bytes)
 * @return NodeId
 */
NodeId string_to_node_id(const std::string& str);

/**
 * Convert NodeId to string
 * @param id The NodeId to convert
 * @return String representation
 */
std::string node_id_to_string(const NodeId& id);

/**
 * Convert hex string to NodeId
 * @param hex The hex string to convert (must be 40 characters)
 * @return NodeId
 */
NodeId hex_to_node_id(const std::string& hex);

/**
 * Convert NodeId to hex string
 * @param id The NodeId to convert
 * @return Hex string representation
 */
std::string node_id_to_hex(const NodeId& id);

} // namespace librats