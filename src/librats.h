#pragma once

#include "socket.h"
#include "dht.h"
#include "stun.h"
#include "mdns.h"
#include "ice.h"
#include "logger.h"
#include "encrypted_socket.h"
#include "json.hpp" // nlohmann::json
#include <string>
#include <functional>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <condition_variable>
#include <unordered_set> // Added for unordered_set

namespace librats {

// Forward declarations
class IceAgent;

/**
 * RatsPeer struct - comprehensive information about a connected rats peer
 */
struct RatsPeer {
    std::string peer_id;                    // Unique hash ID for the peer
    std::string ip;                         // IP address
    uint16_t port;                          // Port number  
    socket_t socket;                        // Socket handle
    std::string normalized_address;         // Normalized address for duplicate detection (ip:port)
    std::chrono::steady_clock::time_point connected_at; // Connection timestamp
    bool is_outgoing;                       // True if we initiated the connection, false if incoming
    
    // Handshake-related fields
    enum class HandshakeState {
        PENDING,        // Handshake not started
        SENT,          // Handshake sent, waiting for response
        COMPLETED,     // Handshake completed successfully
        FAILED         // Handshake failed
    };
    
    HandshakeState handshake_state;         // Current handshake state
    std::string version;                    // Protocol version of remote peer
    int peer_count;                         // Number of peers connected to remote peer
    std::chrono::steady_clock::time_point handshake_start_time; // When handshake started
    
    // Encryption-related fields
    bool encryption_enabled;                // Whether encryption is enabled for this peer
    bool noise_handshake_completed;         // Whether noise handshake is completed
    NoiseKey remote_static_key;             // Remote peer's static public key (after handshake)
    
    // NAT traversal fields
    bool ice_enabled;                       // Whether ICE is enabled for this peer
    std::string ice_ufrag;                  // ICE username fragment
    std::string ice_pwd;                    // ICE password
    std::vector<IceCandidate> ice_candidates; // ICE candidates for this peer
    IceConnectionState ice_state;           // Current ICE connection state
    NatType detected_nat_type;              // Detected NAT type for this peer
    std::string connection_method;          // How connection was established (direct, stun, turn, ice)
    
    // Connection quality metrics
    uint32_t rtt_ms;                        // Round-trip time in milliseconds
    uint32_t packet_loss_percent;           // Packet loss percentage
    std::string transport_protocol;         // UDP, TCP, etc.
    
    RatsPeer() : handshake_state(HandshakeState::PENDING), 
                 peer_count(0), encryption_enabled(false), noise_handshake_completed(false),
                 ice_enabled(false), ice_state(IceConnectionState::NEW),
                 detected_nat_type(NatType::UNKNOWN), rtt_ms(0), packet_loss_percent(0),
                 transport_protocol("UDP") {
        connected_at = std::chrono::steady_clock::now();
        handshake_start_time = connected_at;
    }
    
    RatsPeer(const std::string& id, const std::string& peer_ip, uint16_t peer_port, 
             socket_t sock, const std::string& norm_addr, bool outgoing)
        : peer_id(id), ip(peer_ip), port(peer_port), socket(sock), 
          normalized_address(norm_addr), is_outgoing(outgoing),
          handshake_state(HandshakeState::PENDING), peer_count(0),
          encryption_enabled(false), noise_handshake_completed(false),
          ice_enabled(false), ice_state(IceConnectionState::NEW),
          detected_nat_type(NatType::UNKNOWN), rtt_ms(0), packet_loss_percent(0),
          transport_protocol("UDP") {
        connected_at = std::chrono::steady_clock::now();
        handshake_start_time = connected_at;
    }
    
    // Helper methods
    bool is_handshake_completed() const { return handshake_state == HandshakeState::COMPLETED; }
    bool is_handshake_failed() const { return handshake_state == HandshakeState::FAILED; }
    bool is_ice_connected() const { 
        return ice_state == IceConnectionState::CONNECTED || 
               ice_state == IceConnectionState::COMPLETED; 
    }
    bool is_fully_connected() const {
        return is_handshake_completed() && (!ice_enabled || is_ice_connected());
    }
};

// NAT Traversal Configuration
struct NatTraversalConfig {
    bool enable_ice;                        // Enable ICE for NAT traversal
    bool enable_upnp;                       // Enable UPnP for port mapping
    bool enable_hole_punching;              // Enable UDP/TCP hole punching
    bool enable_turn_relay;                 // Enable TURN relay as last resort
    bool prefer_ipv6;                       // Prefer IPv6 connections when available
    
    // ICE configuration
    std::vector<std::string> stun_servers;
    std::vector<std::string> turn_servers;
    std::vector<std::string> turn_usernames;
    std::vector<std::string> turn_passwords;
    
    // Timeouts and limits
    int ice_gathering_timeout_ms;
    int ice_connectivity_timeout_ms;
    int hole_punch_attempts;
    int turn_allocation_timeout_ms;
    
    // Priority settings
    int host_candidate_priority;
    int server_reflexive_priority;
    int relay_candidate_priority;
    
    NatTraversalConfig() 
        : enable_ice(true), enable_upnp(false), enable_hole_punching(true),
          enable_turn_relay(true), prefer_ipv6(false),
          ice_gathering_timeout_ms(10000), ice_connectivity_timeout_ms(30000),
          hole_punch_attempts(5), turn_allocation_timeout_ms(10000),
          host_candidate_priority(65535), server_reflexive_priority(65534),
          relay_candidate_priority(65533) {
        
        // Default STUN servers
        stun_servers.push_back("stun.l.google.com:19302");
        stun_servers.push_back("stun1.l.google.com:19302");
        stun_servers.push_back("stun.stunprotocol.org:3478");
    }
};

// Connection establishment strategies
enum class ConnectionStrategy {
    DIRECT_ONLY,        // Try direct connection only
    STUN_ASSISTED,      // Use STUN for public IP discovery
    ICE_FULL,           // Full ICE with candidate gathering
    TURN_RELAY,         // Force TURN relay usage
    AUTO_ADAPTIVE       // Automatically choose best strategy
};

// Connection attempt result
struct ConnectionAttemptResult {
    bool success;
    std::string method;                     // "direct", "stun", "ice", "turn", "hole_punch"
    std::chrono::milliseconds duration;
    std::string error_message;
    NatType local_nat_type;
    NatType remote_nat_type;
    std::vector<IceCandidate> used_candidates;
};

// Enhanced connection callbacks
using AdvancedConnectionCallback = std::function<void(socket_t, const std::string&, const ConnectionAttemptResult&)>;
using NatTraversalProgressCallback = std::function<void(const std::string&, const std::string&)>; // peer_id, status
using IceCandidateDiscoveredCallback = std::function<void(const std::string&, const IceCandidate&)>; // peer_id, candidate

/**
 * Enhanced RatsClient with comprehensive NAT traversal capabilities
 */
class RatsClient {
public:
    // Callback function types
    using ConnectionCallback = std::function<void(socket_t, const std::string&)>;
    using DataCallback = std::function<void(socket_t, const std::string&, const std::string&)>;
    using DisconnectCallback = std::function<void(socket_t, const std::string&)>;
    using MessageCallback = std::function<void(const std::string&, const nlohmann::json&)>;
    using SendCallback = std::function<void(bool, const std::string&)>;

    /**
     * Constructor
     * @param listen_port Port to listen on for incoming connections
     * @param max_peers Maximum number of concurrent peers (default: 10)
     * @param nat_config NAT traversal configuration
     */
    RatsClient(int listen_port, int max_peers = 10, const NatTraversalConfig& nat_config = NatTraversalConfig());
    
    /**
     * Destructor
     */
    ~RatsClient();

    // Core lifecycle methods
    /**
     * Start the RatsClient and begin listening for connections
     * @return true if successful, false otherwise
     */
    bool start();

    /**
     * Stop the RatsClient and close all connections
     */
    void stop();

    /**
     * Trigger immediate shutdown of all background threads
     */
    void shutdown_immediate();

    /**
     * Check if the client is currently running
     * @return true if running, false otherwise
     */
    bool is_running() const;

    // Enhanced connection methods with NAT traversal
    /**
     * Connect to a peer with automatic NAT traversal
     * @param host Target host/IP address
     * @param port Target port
     * @param strategy Connection strategy to use
     * @return true if connection initiated successfully
     */
    bool connect_to_peer(const std::string& host, int port, 
                        ConnectionStrategy strategy = ConnectionStrategy::AUTO_ADAPTIVE);
    
    /**
     * Connect to a peer using ICE coordination
     * @param peer_id Target peer ID
     * @param ice_offer ICE offer from remote peer
     * @return true if ICE connection initiated successfully
     */
    bool connect_with_ice(const std::string& peer_id, const nlohmann::json& ice_offer);
    
    /**
     * Create ICE offer for a peer
     * @param peer_id Target peer ID
     * @return ICE offer JSON that can be sent to the peer
     */
    nlohmann::json create_ice_offer(const std::string& peer_id);
    
    /**
     * Handle ICE answer from a peer
     * @param peer_id Source peer ID
     * @param ice_answer ICE answer from the peer
     * @return true if successfully processed
     */
    bool handle_ice_answer(const std::string& peer_id, const nlohmann::json& ice_answer);

    // Data transmission methods
    /**
     * Send data to a specific peer
     * @param socket Target peer socket
     * @param data Data to send
     * @return true if sent successfully
     */
    bool send_to_peer(socket_t socket, const std::string& data);

    /**
     * Send JSON data to a specific peer
     * @param socket Target peer socket
     * @param json_data JSON data to send
     * @return true if sent successfully
     */
    bool send_json_to_peer(socket_t socket, const nlohmann::json& json_data);

    /**
     * Send data to a peer by peer hash ID
     * @param peer_hash_id Target peer hash ID
     * @param data Data to send
     * @return true if sent successfully
     */
    bool send_to_peer_by_hash(const std::string& peer_hash_id, const std::string& data);

    /**
     * Send JSON data to a peer by peer hash ID
     * @param peer_hash_id Target peer hash ID
     * @param json_data JSON data to send
     * @return true if sent successfully
     */
    bool send_json_to_peer_by_hash(const std::string& peer_hash_id, const nlohmann::json& json_data);

    /**
     * Broadcast data to all connected peers
     * @param data Data to broadcast
     * @return Number of peers the data was sent to
     */
    int broadcast_to_peers(const std::string& data);

    /**
     * Broadcast JSON data to all connected peers
     * @param json_data JSON data to broadcast
     * @return Number of peers the data was sent to
     */
    int broadcast_json_to_peers(const nlohmann::json& json_data);

    // Connection management
    /**
     * Disconnect from a specific peer
     * @param socket Peer socket to disconnect
     */
    void disconnect_peer(socket_t socket);

    /**
     * Disconnect from a peer by hash ID
     * @param peer_hash_id Peer hash ID to disconnect
     */
    void disconnect_peer_by_hash(const std::string& peer_hash_id);

    /**
     * Get the number of currently connected peers
     * @return Number of connected peers
     */
    int get_peer_count() const;

    // Peer information retrieval
    /**
     * Get hash ID for a peer by socket
     * @param socket Peer socket
     * @return Peer hash ID or empty string if not found
     */
    std::string get_peer_hash_id(socket_t socket) const;

    /**
     * Get socket for a peer by hash ID
     * @param peer_hash_id Peer hash ID
     * @return Peer socket or INVALID_SOCKET_VALUE if not found
     */
    socket_t get_peer_socket(const std::string& peer_hash_id) const;

    /**
     * Get our own peer ID
     * @return Our persistent peer ID
     */
    std::string get_our_peer_id() const;

    // Callback registration
    /**
     * Set connection callback (called when a new peer connects)
     * @param callback Function to call on new connections
     */
    void set_connection_callback(ConnectionCallback callback);
    
    /**
     * Set advanced connection callback with NAT traversal info
     * @param callback Function to call on new connections with detailed info
     */
    void set_advanced_connection_callback(AdvancedConnectionCallback callback);

    /**
     * Set data callback (called when data is received)
     * @param callback Function to call when data is received
     */
    void set_data_callback(DataCallback callback);

    /**
     * Set disconnect callback (called when a peer disconnects)
     * @param callback Function to call on disconnections
     */
    void set_disconnect_callback(DisconnectCallback callback);
    
    /**
     * Set NAT traversal progress callback
     * @param callback Function to call with NAT traversal progress updates
     */
    void set_nat_traversal_progress_callback(NatTraversalProgressCallback callback);
    
    /**
     * Set ICE candidate discovered callback
     * @param callback Function to call when ICE candidates are discovered
     */
    void set_ice_candidate_callback(IceCandidateDiscoveredCallback callback);

    // DHT functionality for peer discovery
    /**
     * Start DHT discovery on specified port
     * @param dht_port Port for DHT communication (default: 6881)
     * @return true if started successfully
     */
    bool start_dht_discovery(int dht_port = 6881);

    /**
     * Stop DHT discovery
     */
    void stop_dht_discovery();

    /**
     * Find peers by content hash using DHT
     * @param content_hash Hash to search for (40-character hex string)
     * @param callback Function to call with discovered peers
     * @param iteration_max Maximum DHT iterations (default: 1)
     * @return true if search initiated successfully
     */
    bool find_peers_by_hash(const std::string& content_hash, 
                           std::function<void(const std::vector<std::string>&)> callback,
                           int iteration_max = 1);

    /**
     * Announce our presence for a content hash
     * @param content_hash Hash to announce for (40-character hex string)
     * @param port Port to announce (default: our listen port)
     * @return true if announced successfully
     */
    bool announce_for_hash(const std::string& content_hash, uint16_t port = 0);

    /**
     * Check if DHT is currently running
     * @return true if DHT is running
     */
    bool is_dht_running() const;

    /**
     * Get the size of the DHT routing table
     * @return Number of nodes in routing table
     */
    size_t get_dht_routing_table_size() const;

    // mDNS functionality for local network discovery
    /**
     * Start mDNS service discovery and announcement
     * @param service_instance_name Service instance name (optional)
     * @param txt_records Additional TXT records for service announcement
     * @return true if started successfully
     */
    bool start_mdns_discovery(const std::string& service_instance_name = "", 
                             const std::map<std::string, std::string>& txt_records = {});

    /**
     * Stop mDNS discovery
     */
    void stop_mdns_discovery();

    /**
     * Check if mDNS is currently running
     * @return true if mDNS is running
     */
    bool is_mdns_running() const;

    /**
     * Set mDNS service discovery callback
     * @param callback Function to call when services are discovered
     */
    void set_mdns_callback(std::function<void(const std::string&, int, const std::string&)> callback);

    /**
     * Get recently discovered mDNS services
     * @return Vector of discovered services
     */
    std::vector<MdnsService> get_mdns_services() const;

    /**
     * Manually query for mDNS services
     * @return true if query sent successfully
     */
    bool query_mdns_services();

    // Enhanced STUN/NAT traversal functionality
    /**
     * Discover public IP address using STUN and add to ignore list
     * @param stun_server STUN server hostname (default: Google STUN)
     * @param stun_port STUN server port (default: 19302)
     * @return true if successful, false otherwise
     */
    bool discover_and_ignore_public_ip(const std::string& stun_server = "stun.l.google.com", int stun_port = 19302);
    
    /**
     * Detect NAT type using STUN servers
     * @return Detected NAT type
     */
    NatType detect_nat_type();
    
    /**
     * Get detailed NAT characteristics
     * @return Detailed NAT information
     */
    NatTypeInfo get_nat_characteristics();
    
    /**
     * Get the discovered public IP address
     * @return Public IP address string or empty if not discovered
     */
    std::string get_public_ip() const;
    
    /**
     * Add an IP address to the ignore list
     * @param ip_address IP address to ignore
     */
    void add_ignored_address(const std::string& ip_address);
    
    /**
     * Test connection to a peer with different strategies
     * @param host Target host
     * @param port Target port
     * @param strategies List of strategies to try
     * @return Connection attempt results
     */
    std::vector<ConnectionAttemptResult> test_connection_strategies(
        const std::string& host, int port,
        const std::vector<ConnectionStrategy>& strategies);
    
    /**
     * Perform coordinated hole punching with a peer
     * @param peer_ip Peer IP address
     * @param peer_port Peer port
     * @param coordination_data Coordination data from peer
     * @return true if successful
     */
    bool coordinate_hole_punching(const std::string& peer_ip, uint16_t peer_port,
                                 const nlohmann::json& coordination_data);

    // Peer information and statistics
    /**
     * Get all connected peers
     * @return Vector of RatsPeer objects
     */
    std::vector<RatsPeer> get_all_peers() const;
    
    /**
     * Get all peers that have completed handshake
     * @return Vector of RatsPeer objects with completed handshake
     */
    std::vector<RatsPeer> get_validated_peers() const;
    
    /**
     * Get peer information by peer ID
     * @param peer_id The peer ID to look up
     * @return Pointer to RatsPeer object, or nullptr if not found
     */
    const RatsPeer* get_peer_by_id(const std::string& peer_id) const;
    
    /**
     * Get peer information by socket
     * @param socket The socket handle to look up
     * @return Pointer to RatsPeer object, or nullptr if not found  
     */
    const RatsPeer* get_peer_by_socket(socket_t socket) const;
    
    /**
     * Get connection statistics
     * @return JSON object with detailed statistics
     */
    nlohmann::json get_connection_statistics() const;
    
    /**
     * Get NAT traversal statistics
     * @return JSON object with NAT traversal statistics
     */
    nlohmann::json get_nat_traversal_statistics() const;

    // Automatic peer discovery
    void start_automatic_peer_discovery();
    void stop_automatic_peer_discovery();
    bool is_automatic_discovery_running() const;
    static std::string get_rats_peer_discovery_hash();

    /**
     * Get maximum number of peers
     * @return Maximum peer count
     */
    int get_max_peers() const;

    /**
     * Set maximum number of peers
     * @param max_peers New maximum peer count
     */
    void set_max_peers(int max_peers);

    /**
     * Check if peer limit has been reached
     * @return true if at limit, false otherwise
     */
    bool is_peer_limit_reached() const;

    // Message exchange API
    /**
     * Register a persistent message handler
     * @param message_type Type of message to handle
     * @param callback Function to call when message is received
     */
    void on(const std::string& message_type, MessageCallback callback);

    /**
     * Register a one-time message handler
     * @param message_type Type of message to handle
     * @param callback Function to call when message is received (once only)
     */
    void once(const std::string& message_type, MessageCallback callback);

    /**
     * Remove all handlers for a message type
     * @param message_type Type of message to stop handling
     */
    void off(const std::string& message_type);

    /**
     * Send a message to all peers
     * @param message_type Type of message
     * @param data Message data
     * @param callback Optional callback for send result
     */
    void send(const std::string& message_type, const nlohmann::json& data, SendCallback callback = nullptr);

    /**
     * Send a message to a specific peer
     * @param peer_id Target peer ID
     * @param message_type Type of message
     * @param data Message data
     * @param callback Optional callback for send result
     */
    void send(const std::string& peer_id, const std::string& message_type, const nlohmann::json& data, SendCallback callback = nullptr);

    /**
     * Parse a JSON message
     * @param message Raw message string
     * @param out_json Parsed JSON output
     * @return true if parsed successfully
     */
    bool parse_json_message(const std::string& message, nlohmann::json& out_json);

    // Encryption functionality
    /**
     * Initialize encryption system
     * @param enable Whether to enable encryption
     * @return true if successful
     */
    bool initialize_encryption(bool enable);

    /**
     * Set encryption enabled/disabled
     * @param enabled Whether encryption should be enabled
     */
    void set_encryption_enabled(bool enabled);

    /**
     * Check if encryption is enabled
     * @return true if encryption is enabled
     */
    bool is_encryption_enabled() const;

    /**
     * Get the encryption key as hex string
     * @return Encryption key in hex format
     */
    std::string get_encryption_key() const;

    /**
     * Set encryption key from hex string
     * @param key_hex Encryption key in hex format
     * @return true if key was valid and set
     */
    bool set_encryption_key(const std::string& key_hex);

    /**
     * Generate a new encryption key
     * @return New encryption key in hex format
     */
    std::string generate_new_encryption_key();

    /**
     * Check if a peer connection is encrypted
     * @param peer_id Peer ID to check
     * @return true if peer connection is encrypted
     */
    bool is_peer_encrypted(const std::string& peer_id) const;

    // Configuration persistence
    /**
     * Load configuration from files
     * @return true if successful, false otherwise
     */
    bool load_configuration();

    /**
     * Save configuration to files
     * @return true if successful, false otherwise
     */
    bool save_configuration();

    /**
     * Load saved peers and attempt to reconnect
     * @return Number of connection attempts made
     */
    int load_and_reconnect_peers();

private:
    int listen_port_;
    int max_peers_;
    socket_t server_socket_;
    std::atomic<bool> running_;
    
    // NAT traversal configuration
    NatTraversalConfig nat_config_;
    
    // Configuration persistence
    std::string our_peer_id_;                               // Our persistent peer ID
    mutable std::mutex config_mutex_;                       // Protects configuration data
    static const std::string CONFIG_FILE_NAME;             // "config.json"
    static const std::string PEERS_FILE_NAME;              // "peers.rats"
    
    // Encryption state
    NoiseKey static_encryption_key_;                        // Our static encryption key
    bool encryption_enabled_;                               // Whether encryption is enabled
    mutable std::mutex encryption_mutex_;                   // Protects encryption state
    
    // ICE and NAT traversal
    std::unique_ptr<IceAgent> ice_agent_;                   // ICE agent for NAT traversal
    std::unique_ptr<AdvancedNatDetector> nat_detector_;     // Advanced NAT type detection
    NatType detected_nat_type_;                             // Our detected NAT type
    NatTypeInfo nat_characteristics_;                       // Detailed NAT information
    mutable std::mutex nat_mutex_;                          // Protects NAT-related data
    
    // ICE coordination tracking to prevent duplicate attempts
    std::unordered_set<std::string> ice_coordination_in_progress_;  // Set of peer_ids having ICE coordination
    mutable std::mutex ice_coordination_mutex_;                     // Protects ICE coordination state
    
    // Connection attempt tracking
    std::unordered_map<std::string, std::vector<ConnectionAttemptResult>> connection_attempts_;
    mutable std::mutex connection_attempts_mutex_;
    
    // Organized peer management using RatsPeer struct
    std::unordered_map<std::string, RatsPeer> peers_;          // keyed by peer_id
    std::unordered_map<socket_t, std::string> socket_to_peer_id_;  // for quick socket->peer_id lookup  
    std::unordered_map<std::string, std::string> address_to_peer_id_;  // for duplicate detection (normalized_address->peer_id)
    
    mutable std::mutex peers_mutex_;
    
    std::thread server_thread_;
    
    ConnectionCallback connection_callback_;
    AdvancedConnectionCallback advanced_connection_callback_;
    DataCallback data_callback_;
    DisconnectCallback disconnect_callback_;
    NatTraversalProgressCallback nat_progress_callback_;
    IceCandidateDiscoveredCallback ice_candidate_callback_;
    
    // DHT client for peer discovery
    std::unique_ptr<DhtClient> dht_client_;
    
    // STUN client for public IP discovery
    std::unique_ptr<StunClient> stun_client_;
    std::string public_ip_;
    mutable std::mutex public_ip_mutex_;
    
    // mDNS client for local network discovery
    std::unique_ptr<MdnsClient> mdns_client_;
    std::function<void(const std::string&, int, const std::string&)> mdns_callback_;
    
    // Message buffering system for handling partial TCP messages
    std::unordered_map<socket_t, std::string> message_buffers_;  // Buffer partial messages per socket
    mutable std::mutex message_buffers_mutex_;                   // Protects message buffers
    
    void server_loop();
    void handle_client(socket_t client_socket, const std::string& peer_hash_id);
    void remove_peer(socket_t socket);
    std::string generate_peer_hash_id(socket_t socket, const std::string& connection_info);
    void handle_dht_peer_discovery(const std::vector<Peer>& peers, const InfoHash& info_hash);
    void handle_mdns_service_discovery(const MdnsService& service, bool is_new);
    
    // Message buffering helpers for handling partial TCP messages
    std::vector<std::string> process_buffered_messages(socket_t socket, const std::string& new_data);
    void cleanup_message_buffer(socket_t socket);
    std::string prepare_message_for_sending(const std::string& message);
    
    // Enhanced connection establishment
    bool attempt_direct_connection(const std::string& host, int port, ConnectionAttemptResult& result);
    bool attempt_stun_assisted_connection(const std::string& host, int port, ConnectionAttemptResult& result);
    bool attempt_ice_connection(const std::string& host, int port, ConnectionAttemptResult& result);
    bool attempt_turn_relay_connection(const std::string& host, int port, ConnectionAttemptResult& result);
    bool attempt_hole_punch_connection(const std::string& host, int port, ConnectionAttemptResult& result);
    
    // ICE coordination helpers
    void handle_ice_candidate_discovered(const std::string& peer_id, const IceCandidate& candidate);
    void handle_ice_connection_state_change(const std::string& peer_id, IceConnectionState state);
    void initiate_ice_with_peer(const std::string& peer_id, const std::string& host, int port);
    
    // NAT traversal message handlers
    void handle_ice_offer_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload);
    void handle_ice_answer_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload);
    void handle_ice_candidate_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload);
    void handle_hole_punch_coordination_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload);
    void handle_nat_info_exchange_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload);
    void send_nat_info_to_peer(socket_t socket, const std::string& peer_id);
    
    // New peer management methods using RatsPeer
    void add_peer(const RatsPeer& peer);
    void remove_peer_by_id(const std::string& peer_id);
    bool is_already_connected_to_address(const std::string& normalized_address) const;
    std::string normalize_peer_address(const std::string& ip, int port) const;

    // Local interface address blocking (ignore list)
    std::vector<std::string> local_interface_addresses_;
    mutable std::mutex local_addresses_mutex_;
    void initialize_local_addresses();
    void refresh_local_addresses();
    bool is_blocked_address(const std::string& ip_address) const;
    bool should_ignore_peer(const std::string& ip, int port) const;
    static bool parse_address_string(const std::string& address_str, std::string& out_ip, int& out_port);
    
    // Helper functions that assume mutex is already locked
    int get_peer_count_unlocked() const;  // Helper that assumes peers_mutex_ is already locked

    // Handshake protocol
    static constexpr const char* RATS_PROTOCOL_VERSION = "1.0";
    static constexpr int HANDSHAKE_TIMEOUT_SECONDS = 10;

    struct HandshakeMessage {
        std::string protocol;
        std::string version;
        std::string peer_id;
        std::string message_type;
        int64_t timestamp;
    };

    std::string create_handshake_message(const std::string& message_type, const std::string& our_peer_id) const;
    bool parse_handshake_message(const std::string& message, HandshakeMessage& out_msg) const;
    bool validate_handshake_message(const HandshakeMessage& msg) const;
    bool is_handshake_message(const std::string& message) const;
    bool send_handshake(socket_t socket, const std::string& our_peer_id);
    bool send_handshake_unlocked(socket_t socket, const std::string& our_peer_id);
    bool handle_handshake_message(socket_t socket, const std::string& peer_hash_id, const std::string& message);
    void check_handshake_timeouts();
    void log_handshake_completion(const RatsPeer& peer);
    void log_handshake_completion_unlocked(const RatsPeer& peer);

    // Automatic discovery
    std::atomic<bool> auto_discovery_running_;
    std::thread auto_discovery_thread_;
    std::condition_variable shutdown_cv_;
    std::mutex shutdown_mutex_;
    void automatic_discovery_loop();
    void announce_rats_peer();
    void search_rats_peers(int iteration_max = 1);

    // Message handling system
    nlohmann::json create_rats_message(const std::string& type, const nlohmann::json& payload, const std::string& sender_peer_id);
    void handle_rats_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& message);

    // Specific message handlers
    void handle_peer_exchange_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload);
    void handle_peers_request_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload);
    void handle_peers_response_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload);

    // Message creation and broadcasting
    nlohmann::json create_peer_exchange_message(const RatsPeer& peer);
    void broadcast_peer_exchange_message(const RatsPeer& new_peer);
    nlohmann::json create_peers_request_message(const std::string& sender_peer_id);
    nlohmann::json create_peers_response_message(const std::vector<RatsPeer>& peers, const std::string& sender_peer_id);
    std::vector<RatsPeer> get_random_peers(int max_count, const std::string& exclude_peer_id = "") const;
    void send_peers_request(socket_t socket, const std::string& our_peer_id);

    int broadcast_rats_message(const nlohmann::json& message, const std::string& exclude_peer_id = "");
    int broadcast_rats_message_to_validated_peers(const nlohmann::json& message, const std::string& exclude_peer_id = "");
    int broadcast_custom_message(const std::string& type, const nlohmann::json& payload, 
                                const std::string& sender_peer_id = "", 
                                const std::string& exclude_peer_id = "");
    bool send_custom_message_to_peer(const std::string& peer_id, const std::string& type, 
                                    const nlohmann::json& payload, 
                                    const std::string& sender_peer_id = "");

    // Message exchange API implementation
    struct MessageHandler {
        MessageCallback callback;
        bool is_once;
        
        MessageHandler(MessageCallback cb, bool once) : callback(cb), is_once(once) {}
    };
    
    std::unordered_map<std::string, std::vector<MessageHandler>> message_handlers_;
    mutable std::mutex message_handlers_mutex_;
    
    void call_message_handlers(const std::string& message_type, const std::string& peer_id, const nlohmann::json& data);
    void remove_once_handlers(const std::string& message_type);

    // Configuration persistence helpers
    std::string generate_persistent_peer_id() const;
    nlohmann::json serialize_peer_for_persistence(const RatsPeer& peer) const;
    bool deserialize_peer_from_persistence(const nlohmann::json& json, std::string& ip, int& port, std::string& peer_id) const;
    std::string get_config_file_path() const;
    std::string get_peers_file_path() const;
    bool save_peers_to_file();
    
    // NAT traversal helpers
    void initialize_nat_traversal();
    void detect_and_cache_nat_type();
    void update_connection_statistics(const std::string& peer_id, const ConnectionAttemptResult& result);
    std::string select_best_connection_strategy(const std::string& host, int port);
    bool coordinate_connection_with_peer(const std::string& peer_id, const nlohmann::json& coordination_data);
};

// Utility functions
std::unique_ptr<RatsClient> create_rats_client(int listen_port);
void run_rats_client_demo(int listen_port, const std::string& peer_host = "", int peer_port = 0);

} // namespace librats 