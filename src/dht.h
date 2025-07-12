#pragma once

#include "udp_network.h"
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
    UdpPeer peer;
    std::chrono::steady_clock::time_point last_seen;
    
    DhtNode() = default;
    DhtNode(const NodeId& id, const UdpPeer& peer)
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
    NodeId sender_id;
    NodeId target_id;
    std::vector<DhtNode> nodes;
    std::vector<UdpPeer> peers;
    uint16_t announce_port;
    std::string token;
    
    DhtMessage(DhtMessageType type, const NodeId& sender_id) 
        : type(type), sender_id(sender_id), announce_port(0) {}
};

/**
 * Peer discovery callback
 */
using PeerDiscoveryCallback = std::function<void(const std::vector<UdpPeer>& peers, const InfoHash& info_hash)>;

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
     * Bootstrap the DHT with known nodes
     * @param bootstrap_nodes Vector of bootstrap nodes
     * @return true if successful, false otherwise
     */
    bool bootstrap(const std::vector<UdpPeer>& bootstrap_nodes);
    
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
     * Check if DHT is running
     * @return true if running, false otherwise
     */
    bool is_running() const { return running_; }
    
    /**
     * Get default BitTorrent DHT bootstrap nodes
     * @return Vector of bootstrap nodes
     */
    static std::vector<UdpPeer> get_default_bootstrap_nodes();

private:
    int port_;
    NodeId node_id_;
    udp_socket_t socket_;
    std::atomic<bool> running_;
    
    // Routing table (k-buckets)
    std::vector<std::vector<DhtNode>> routing_table_;
    mutable std::mutex routing_table_mutex_;
    
    // Active searches (use string keys instead of InfoHash to avoid hash conflicts)
    std::unordered_map<std::string, PeerDiscoveryCallback> active_searches_;
    std::mutex active_searches_mutex_;
    
    // Tokens for peers (use string key instead of UdpPeer for simplicity)
    std::unordered_map<std::string, std::string> peer_tokens_;
    std::mutex peer_tokens_mutex_;
    
    // Protocol detection - track which protocol each peer uses
    enum class PeerProtocol {
        Unknown,
        RatsDht,    // Our rats dht binary protocol
        BitTorrent  // Standard BitTorrent DHT (KRPC)
    };
    std::unordered_map<std::string, PeerProtocol> peer_protocols_;
    std::mutex peer_protocols_mutex_;
    
    // KRPC transaction tracking
    std::unordered_map<std::string, std::string> krpc_transactions_;
    std::mutex krpc_transactions_mutex_;
    
    // Network thread
    std::thread network_thread_;
    std::thread maintenance_thread_;
    
    // Helper functions
    void network_loop();
    void maintenance_loop();
    void handle_message(const std::vector<uint8_t>& data, const UdpPeer& sender);
    
    // Protocol detection
    PeerProtocol detect_protocol(const std::vector<uint8_t>& data);
    std::string get_peer_key(const UdpPeer& peer);
    PeerProtocol get_peer_protocol(const UdpPeer& peer);
    void set_peer_protocol(const UdpPeer& peer, PeerProtocol protocol);
    
    // Rats DHT protocol handlers
    void handle_ping(const DhtMessage& message, const UdpPeer& sender);
    void handle_find_node(const DhtMessage& message, const UdpPeer& sender);
    void handle_get_peers(const DhtMessage& message, const UdpPeer& sender);
    void handle_announce_peer(const DhtMessage& message, const UdpPeer& sender);
    
    // KRPC protocol handlers  
    void handle_krpc_message(const KrpcMessage& message, const UdpPeer& sender);
    void handle_krpc_ping(const KrpcMessage& message, const UdpPeer& sender);
    void handle_krpc_find_node(const KrpcMessage& message, const UdpPeer& sender);
    void handle_krpc_get_peers(const KrpcMessage& message, const UdpPeer& sender);
    void handle_krpc_announce_peer(const KrpcMessage& message, const UdpPeer& sender);
    void handle_krpc_response(const KrpcMessage& message, const UdpPeer& sender);
    void handle_krpc_error(const KrpcMessage& message, const UdpPeer& sender);
    
    // Sending functions (will auto-detect protocol)
    void send_ping(const UdpPeer& peer);
    void send_find_node(const UdpPeer& peer, const NodeId& target);
    void send_get_peers(const UdpPeer& peer, const InfoHash& info_hash);
    void send_announce_peer(const UdpPeer& peer, const InfoHash& info_hash, uint16_t port, const std::string& token);
    
    // Rats DHT protocol sending
    bool send_message(const DhtMessage& message, const UdpPeer& peer);
    std::vector<uint8_t> encode_message(const DhtMessage& message);
    std::unique_ptr<DhtMessage> decode_message(const std::vector<uint8_t>& data);
    
    // KRPC protocol sending
    bool send_krpc_message(const KrpcMessage& message, const UdpPeer& peer);
    void send_krpc_ping(const UdpPeer& peer);
    void send_krpc_find_node(const UdpPeer& peer, const NodeId& target);
    void send_krpc_get_peers(const UdpPeer& peer, const InfoHash& info_hash);
    void send_krpc_announce_peer(const UdpPeer& peer, const InfoHash& info_hash, uint16_t port, const std::string& token);
    
    void add_node(const DhtNode& node);
    std::vector<DhtNode> find_closest_nodes(const NodeId& target, size_t count = K_BUCKET_SIZE);
    int get_bucket_index(const NodeId& id);
    
    NodeId generate_node_id();
    NodeId xor_distance(const NodeId& a, const NodeId& b);
    bool is_closer(const NodeId& a, const NodeId& b, const NodeId& target);
    
    std::string generate_token(const UdpPeer& peer);
    bool verify_token(const UdpPeer& peer, const std::string& token);
    
    void cleanup_stale_nodes();
    void refresh_buckets();
    
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

// Hash specialization for UdpPeer only (InfoHash uses std::array's built-in hash)
namespace std {
    template<>
    struct hash<librats::UdpPeer> {
        std::size_t operator()(const librats::UdpPeer& peer) const {
            std::hash<std::string> hasher;
            return hasher(peer.ip + ":" + std::to_string(peer.port));
        }
    };
} 