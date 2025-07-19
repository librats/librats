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
#include <atomic>
#include <condition_variable>

// Hash specialization for Peer (must be defined before use in unordered_map)
namespace std {
    template<>
    struct hash<librats::Peer> {
        std::size_t operator()(const librats::Peer& peer) const noexcept {
            std::hash<std::string> hasher;
            return hasher(peer.ip + ":" + std::to_string(peer.port));
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
 * DHT Node information
 */
struct DhtNode {
    NodeId id;
    Peer peer;
    std::chrono::steady_clock::time_point last_seen;
    
    DhtNode() = default;
    DhtNode(const NodeId& id, const Peer& peer)
        : id(id), peer(peer), last_seen(std::chrono::steady_clock::now()) {}
};

/**
 * DHT Message types
 */
enum class DhtMessageType {
    PING = 0,
    FIND_NODE = 1,
    GET_PEERS = 2,
    ANNOUNCE_PEER = 3
};

/**
 * DHT Message structure
 */
struct DhtMessage {
    DhtMessageType type;
    std::string transaction_id;
    NodeId sender_id;
    NodeId target_id;
    std::vector<DhtNode> nodes;
    std::vector<Peer> peers;
    uint16_t announce_port;
    std::string token;
    bool is_response;
    
    DhtMessage() : type(DhtMessageType::PING), announce_port(0), is_response(false) {}
    DhtMessage(DhtMessageType type, const std::string& transaction_id, const NodeId& sender_id) 
        : type(type), transaction_id(transaction_id), sender_id(sender_id), announce_port(0), is_response(false) {}
};

/**
 * Peer discovery callback
 */
using PeerDiscoveryCallback = std::function<void(const std::vector<Peer>& peers, const InfoHash& info_hash)>;

/**
 * DHT Kademlia implementation
 */
class DhtClient {
public:
    /**
     * Constructor
     * @param port The UDP port to bind to (default: 6881)
     */
    DhtClient(int port = DHT_PORT);
    
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
     * @param iteration_max Maximum number of search iterations (default: 1)
     * @return true if search started successfully, false otherwise
     */
    bool find_peers(const InfoHash& info_hash, PeerDiscoveryCallback callback, int iteration_max = 1);
    
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
    NodeId node_id_;
    socket_t socket_;
    std::atomic<bool> running_;
    
    // Routing table (k-buckets)
    std::vector<std::vector<DhtNode>> routing_table_;
    mutable std::mutex routing_table_mutex_;
    
    // Active searches (use string keys instead of InfoHash to avoid hash conflicts)
    std::unordered_map<std::string, PeerDiscoveryCallback> active_searches_;
    std::mutex active_searches_mutex_;
    
    // Tokens for peers (use Peer directly as key for efficiency)
    std::unordered_map<Peer, std::string> peer_tokens_;
    std::mutex peer_tokens_mutex_;
    
    // Protocol detection - track which protocol each peer uses
    enum class PeerProtocol {
        Unknown,
        RatsDht,    // Our rats dht binary protocol
        BitTorrent  // Standard BitTorrent DHT (KRPC)
    };
    std::unordered_map<Peer, PeerProtocol> peer_protocols_;
    std::mutex peer_protocols_mutex_;
        
    // Transaction ID counters
    static std::atomic<uint32_t> rats_dht_transaction_counter_;
    
    // Pending announce tracking (for BEP 5 compliance)
    struct PendingAnnounce {
        InfoHash info_hash;
        uint16_t port;
        std::chrono::steady_clock::time_point created_at;
        
        PendingAnnounce(const InfoHash& hash, uint16_t p)
            : info_hash(hash), port(p), created_at(std::chrono::steady_clock::now()) {}
    };
    std::unordered_map<std::string, PendingAnnounce> pending_announces_;
    std::mutex pending_announces_mutex_;
    
    // Pending find_peers tracking (to map transaction IDs to info_hash)
    struct PendingSearch {
        InfoHash info_hash;
        std::chrono::steady_clock::time_point created_at;
        
        // Iterative search state
        std::unordered_set<std::string> queried_nodes;  // node_id as hex string
        int iteration_count;                            // current iteration number
        int iteration_max;                              // maximum iteration limit
        
        PendingSearch(const InfoHash& hash, int max_iterations = 1)
            : info_hash(hash), created_at(std::chrono::steady_clock::now()), 
              iteration_count(1), iteration_max(max_iterations) {}
    };
    std::unordered_map<std::string, PendingSearch> pending_searches_; // info_hash (hex) -> PendingSearch
    std::mutex pending_searches_mutex_;
    std::unordered_map<std::string, std::string> transaction_to_search_; // transaction_id -> info_hash (hex)
    
    // Peer announcement storage (BEP 5 compliant)
    struct AnnouncedPeer {
        Peer peer;
        std::chrono::steady_clock::time_point announced_at;
        
        AnnouncedPeer(const Peer& p) 
            : peer(p), announced_at(std::chrono::steady_clock::now()) {}
    };
    // Map from info_hash (as hex string) to list of announced peers
    std::unordered_map<std::string, std::vector<AnnouncedPeer>> announced_peers_;
    std::mutex announced_peers_mutex_;
    
    // Network thread
    std::thread network_thread_;
    std::thread maintenance_thread_;
    
    // Conditional variables for immediate shutdown
    std::condition_variable shutdown_cv_;
    std::mutex shutdown_mutex_;
    
    // Helper functions
    void network_loop();
    void maintenance_loop();
    void handle_message(const std::vector<uint8_t>& data, const Peer& sender);
    
    // Protocol detection
    PeerProtocol detect_protocol(const std::vector<uint8_t>& data);
    PeerProtocol get_peer_protocol(const Peer& peer);
    void set_peer_protocol(const Peer& peer, PeerProtocol protocol);
    bool is_known_bittorrent_bootstrap_node(const Peer& peer);
    
    // Rats DHT protocol handlers
    void handle_ping(const DhtMessage& message, const Peer& sender);
    void handle_find_node(const DhtMessage& message, const Peer& sender);
    void handle_get_peers(const DhtMessage& message, const Peer& sender);
    void handle_announce_peer(const DhtMessage& message, const Peer& sender);
    
    // KRPC protocol handlers  
    void handle_krpc_message(const KrpcMessage& message, const Peer& sender);
    void handle_krpc_ping(const KrpcMessage& message, const Peer& sender);
    void handle_krpc_find_node(const KrpcMessage& message, const Peer& sender);
    void handle_krpc_get_peers(const KrpcMessage& message, const Peer& sender);
    void handle_krpc_announce_peer(const KrpcMessage& message, const Peer& sender);
    void handle_krpc_response(const KrpcMessage& message, const Peer& sender);
    void handle_krpc_error(const KrpcMessage& message, const Peer& sender);
    
    // Sending functions (will auto-detect protocol)
    void send_ping(const Peer& peer);
    void send_find_node(const Peer& peer, const NodeId& target);
    void send_get_peers(const Peer& peer, const InfoHash& info_hash);
    void send_announce_peer(const Peer& peer, const InfoHash& info_hash, uint16_t port, const std::string& token);
    
    // Rats DHT protocol sending
    bool send_message(const DhtMessage& message, const Peer& peer);
    std::vector<uint8_t> encode_message(const DhtMessage& message);
    std::unique_ptr<DhtMessage> decode_message(const std::vector<uint8_t>& data);
    
    // KRPC protocol sending
    bool send_krpc_message(const KrpcMessage& message, const Peer& peer);
    void send_krpc_ping(const Peer& peer);
    void send_krpc_find_node(const Peer& peer, const NodeId& target);
    void send_krpc_get_peers(const Peer& peer, const InfoHash& info_hash);
    void send_krpc_announce_peer(const Peer& peer, const InfoHash& info_hash, uint16_t port, const std::string& token);
    
    void add_node(const DhtNode& node);
    std::vector<DhtNode> find_closest_nodes(const NodeId& target, size_t count = K_BUCKET_SIZE);
    std::vector<DhtNode> find_closest_nodes_unlocked(const NodeId& target, size_t count = K_BUCKET_SIZE);
    int get_bucket_index(const NodeId& id);
    
    NodeId generate_node_id();
    NodeId xor_distance(const NodeId& a, const NodeId& b);
    bool is_closer(const NodeId& a, const NodeId& b, const NodeId& target);
    
    std::string generate_token(const Peer& peer);
    bool verify_token(const Peer& peer, const std::string& token);
    
    // Transaction ID management
    std::string generate_rats_dht_transaction_id();
    
    void cleanup_stale_nodes();
    void refresh_buckets();
    
    // Pending announce management
    void cleanup_stale_announces();
    void handle_get_peers_response_for_announce(const std::string& transaction_id, const Peer& responder, const std::string& token);
    void handle_get_peers_response_for_announce_rats_dht(const std::string& transaction_id, const Peer& responder, const std::string& token);
    
    // Pending search management
    void cleanup_stale_searches();
    void handle_get_peers_response_for_search(const std::string& transaction_id, const Peer& responder, const std::vector<Peer>& peers);
    void handle_get_peers_response_for_search_rats_dht(const std::string& transaction_id, const Peer& responder, const std::vector<Peer>& peers);
    void handle_get_peers_response_with_nodes(const std::string& transaction_id, const Peer& responder, const std::vector<KrpcNode>& nodes);
    void handle_get_peers_response_with_nodes_rats_dht(const std::string& transaction_id, const Peer& responder, const std::vector<DhtNode>& nodes);
    bool continue_search_iteration(PendingSearch& search);
    
    // Peer announcement storage management
    void store_announced_peer(const InfoHash& info_hash, const Peer& peer);
    std::vector<Peer> get_announced_peers(const InfoHash& info_hash);
    void cleanup_stale_announced_peers();
    
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