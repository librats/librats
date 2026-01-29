#pragma once

#include "socket.h"
#include "dht.h"
#include "mdns.h"
#include "logger.h"
#include "threadmanager.h"
#include "gossipsub.h" // For ValidationResult enum and GossipSub types
#include "file_transfer.h" // File transfer functionality
#include "noise.h" // Noise Protocol encryption
#include "ice.h"   // ICE-lite NAT traversal
#ifdef RATS_STORAGE
#include "storage.h" // Distributed storage functionality
#endif
#ifdef RATS_SEARCH_FEATURES
#include "bittorrent.h" // BitTorrent functionality (optional, requires RATS_SEARCH_FEATURES)
#endif
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
#include <cstdint>
#include <cstring>
#include "rats_export.h"

namespace librats {

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
    std::chrono::steady_clock::time_point handshake_start_time; // When handshake started
    
    // Encryption-related fields
    bool encryption_enabled;                // Whether encryption is enabled for this peer
    bool noise_handshake_completed;         // Whether noise handshake is completed
    std::shared_ptr<rats::NoiseCipherState> send_cipher;   // Cipher for sending encrypted data
    std::shared_ptr<rats::NoiseCipherState> recv_cipher;   // Cipher for receiving encrypted data
    std::vector<uint8_t> remote_static_key;  // Remote peer's static public key (for identity verification)
    
    RatsPeer() : handshake_state(HandshakeState::PENDING), 
                 encryption_enabled(false),
                 noise_handshake_completed(false) {
        connected_at = std::chrono::steady_clock::now();
        handshake_start_time = connected_at;
    }
    
    RatsPeer(const std::string& id, const std::string& peer_ip, uint16_t peer_port, 
             socket_t sock, const std::string& norm_addr, bool outgoing)
        : peer_id(id), ip(peer_ip), port(peer_port), socket(sock), 
          normalized_address(norm_addr), is_outgoing(outgoing),
          handshake_state(HandshakeState::PENDING),
          encryption_enabled(false),
          noise_handshake_completed(false) {
        connected_at = std::chrono::steady_clock::now();
        handshake_start_time = connected_at;
    }
    
    // Check if peer has completed Noise handshake and is ready for encrypted communication
    bool is_noise_encrypted() const { 
        return noise_handshake_completed && send_cipher && recv_cipher; 
    }
    
    // Helper methods
    bool is_handshake_completed() const { return handshake_state == HandshakeState::COMPLETED; }
    bool is_handshake_failed() const { return handshake_state == HandshakeState::FAILED; }
};

/**
 * ReconnectConfig - Configuration for automatic peer reconnection
 */
struct ReconnectConfig {
    int max_attempts = 3;                                      // Maximum number of reconnection attempts
    std::vector<int> retry_intervals_seconds = {5, 30, 120};   // Intervals between attempts (5s, 30s, 2min)
    int stable_connection_threshold_seconds = 60;              // Connection duration to be considered "stable" (1 minute)
    int stable_first_retry_seconds = 2;                        // First retry interval for stable peers (faster)
    bool enabled = true;                                       // Whether auto-reconnection is enabled
};

/**
 * ReconnectInfo - Information about a peer pending reconnection
 */
struct ReconnectInfo {
    std::string peer_id;                                       // Peer ID for identification
    std::string ip;                                            // IP address to reconnect to
    uint16_t port;                                             // Port number
    int attempt_count;                                         // Current number of reconnection attempts
    std::chrono::steady_clock::time_point next_attempt_time;   // When to attempt next reconnection
    std::chrono::milliseconds connection_duration;             // How long the peer was connected before disconnect
    bool is_stable;                                            // Whether this was a "stable" connection
    
    ReconnectInfo() : port(0), attempt_count(0), connection_duration(0), is_stable(false) {
        next_attempt_time = std::chrono::steady_clock::now();
    }
    
    ReconnectInfo(const std::string& id, const std::string& peer_ip, uint16_t peer_port,
                  std::chrono::milliseconds duration, bool stable)
        : peer_id(id), ip(peer_ip), port(peer_port), attempt_count(0),
          connection_duration(duration), is_stable(stable) {
        next_attempt_time = std::chrono::steady_clock::now();
    }
};

/**
 * Message data types for librats message headers
 */
enum class MessageDataType : uint8_t {
    BINARY = 0x01,      // Raw binary data
    STRING = 0x02,      // UTF-8 string data  
    JSON = 0x03         // JSON formatted data
};

/**
 * Message header structure for librats messages
 * Fixed 8-byte header format:
 * [0-3]: Magic number "RATS" (4 bytes)
 * [4]: Message data type (1 byte)
 * [5-7]: Reserved for future use (3 bytes)
 */
struct MessageHeader {
    static constexpr uint32_t MAGIC_NUMBER = 0x52415453; // "RATS" in ASCII
    static constexpr size_t HEADER_SIZE = 8;
    
    uint32_t magic;         // Magic number for validation
    MessageDataType type;   // Message data type
    uint8_t reserved[3];    // Reserved bytes for future use
    
    MessageHeader(MessageDataType data_type) : magic(MAGIC_NUMBER), type(data_type) {
        reserved[0] = reserved[1] = reserved[2] = 0;
    }
    
    MessageHeader() : magic(MAGIC_NUMBER), type(MessageDataType::BINARY) {
        reserved[0] = reserved[1] = reserved[2] = 0;
    }
    
    // Serialize header to bytes
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data(HEADER_SIZE);
        uint32_t network_magic = htonl(magic);
        memcpy(data.data(), &network_magic, 4);
        data[4] = static_cast<uint8_t>(type);
        data[5] = reserved[0];
        data[6] = reserved[1]; 
        data[7] = reserved[2];
        return data;
    }
    
    // Deserialize header from bytes
    static bool deserialize(const std::vector<uint8_t>& data, MessageHeader& header) {
        if (data.size() < HEADER_SIZE) {
            return false;
        }
        
        uint32_t network_magic;
        memcpy(&network_magic, data.data(), 4);
        header.magic = ntohl(network_magic);
        
        if (header.magic != MAGIC_NUMBER) {
            return false;
        }
        
        header.type = static_cast<MessageDataType>(data[4]);
        header.reserved[0] = data[5];
        header.reserved[1] = data[6];
        header.reserved[2] = data[7];
        
        return true;
    }
    
    // Validate data type
    bool is_valid_type() const {
        return type == MessageDataType::BINARY || 
               type == MessageDataType::STRING || 
               type == MessageDataType::JSON;
    }
};

/**
 * RatsClient - Core peer-to-peer networking client
 */
class RATS_API RatsClient : public ThreadManager {
public:
    // =========================================================================
    // Type Definitions and Callbacks
    // =========================================================================
    using ConnectionCallback = std::function<void(socket_t, const std::string&)>;
    using BinaryDataCallback = std::function<void(socket_t, const std::string&, const std::vector<uint8_t>&)>;
    using StringDataCallback = std::function<void(socket_t, const std::string&, const std::string&)>;
    using JsonDataCallback = std::function<void(socket_t, const std::string&, const nlohmann::json&)>;
    using DisconnectCallback = std::function<void(socket_t, const std::string&)>;
    using MessageCallback = std::function<void(const std::string&, const nlohmann::json&)>;
    using SendCallback = std::function<void(bool, const std::string&)>;

    // =========================================================================
    // Constructor and Destructor
    // =========================================================================
    
    /**
     * Constructor
     * @param listen_port Port to listen on for incoming connections
     * @param max_peers Maximum number of concurrent peers (default: 10)
     * @param bind_address Interface IP address to bind to (empty for all interfaces)
     */
    RatsClient(int listen_port, int max_peers = 10, const std::string& bind_address = "");
    
    /**
     * Destructor
     */
    ~RatsClient();

    // =========================================================================
    // Core Lifecycle Management
    // =========================================================================
    
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
     * Shutdown all background threads
     */
    void shutdown_all_threads();

    /**
     * Check if the client is currently running
     * @return true if running, false otherwise
     */
    bool is_running() const;


    // =========================================================================
    // Utility Methods
    // =========================================================================

    int get_listen_port() const;
    
    /**
     * Get the bind address being used
     * @return Bind address (empty string if binding to all interfaces)
     */
    std::string get_bind_address() const;

    // =========================================================================
    // Connection Management
    // =========================================================================
    
    /**
     * Connect to a peer via direct TCP connection
     * @param host Target host/IP address
     * @param port Target port
     * @return true if connection initiated successfully
     */
    bool connect_to_peer(const std::string& host, int port);
    
    /**
     * Disconnect from a specific peer
     * @param socket Peer socket to disconnect
     */
    void disconnect_peer(socket_t socket);

    /**
     * Disconnect from a peer by peer_id (preferred)
     * @param peer_id Peer ID to disconnect
     */
    void disconnect_peer_by_id(const std::string& peer_id);

    // =========================================================================
    // Data Transmission Methods
    // =========================================================================
    
    // Send to specific peer by socket
    /**
     * Send binary data to a specific peer (primary method)
     * @param socket Target peer socket
     * @param data Binary data to send
     * @param message_type Type of message data (BINARY, STRING, JSON)
     * @return true if sent successfully
     */
    bool send_binary_to_peer(socket_t socket, const std::vector<uint8_t>& data, MessageDataType message_type = MessageDataType::BINARY);

    /**
     * Send string data to a specific peer
     * @param socket Target peer socket
     * @param data String data to send
     * @return true if sent successfully
     */
    bool send_string_to_peer(socket_t socket, const std::string& data);

    /**
     * Send JSON data to a specific peer
     * @param socket Target peer socket
     * @param data JSON data to send
     * @return true if sent successfully
     */
    bool send_json_to_peer(socket_t socket, const nlohmann::json& data);

    // Send to specific peer by ID
    /**
     * Send binary data to a peer by peer_id (preferred)
     * @param peer_id Target peer ID
     * @param data Binary data to send
     * @param message_type Type of message data (BINARY, STRING, JSON)
     * @return true if sent successfully
     */
    bool send_binary_to_peer_id(const std::string& peer_id, const std::vector<uint8_t>& data, MessageDataType message_type = MessageDataType::BINARY);

    /**
     * Send string data to a peer by peer_id (preferred)
     * @param peer_id Target peer ID
     * @param data String data to send
     * @return true if sent successfully
     */
    bool send_string_to_peer_id(const std::string& peer_id, const std::string& data);

    /**
     * Send JSON data to a peer by peer_id (preferred)
     * @param peer_id Target peer ID
     * @param data JSON data to send
     * @return true if sent successfully
     */
    bool send_json_to_peer_id(const std::string& peer_id, const nlohmann::json& data);

    // Broadcast to all peers
    /**
     * Broadcast binary data to all connected peers (primary method)
     * @param data Binary data to broadcast
     * @param message_type Type of message data (BINARY, STRING, JSON)
     * @return Number of peers the data was sent to
     */
    int broadcast_binary_to_peers(const std::vector<uint8_t>& data, MessageDataType message_type = MessageDataType::BINARY);

    /**
     * Broadcast string data to all connected peers
     * @param data String data to broadcast
     * @return Number of peers the data was sent to
     */
    int broadcast_string_to_peers(const std::string& data);

    /**
     * Broadcast JSON data to all connected peers
     * @param data JSON data to broadcast
     * @return Number of peers the data was sent to
     */
    int broadcast_json_to_peers(const nlohmann::json& data);

    // =========================================================================
    // Peer Information and Management
    // =========================================================================
    
    /**
     * Get the number of currently connected peers
     * @return Number of connected peers
     */
    int get_peer_count() const;


    /**
     * Get peer_id for a peer by socket (preferred)
     * @param socket Peer socket
     * @return Peer ID or empty string if not found
     */
    std::string get_peer_id(socket_t socket) const;

    /**
     * Get socket for a peer by peer_id (preferred)
     * @param peer_id Peer ID
     * @return Peer socket or INVALID_SOCKET_VALUE if not found
     */
    socket_t get_peer_socket_by_id(const std::string& peer_id) const;

    /**
     * Get our own peer ID
     * @return Our persistent peer ID
     */
    std::string get_our_peer_id() const;
    
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

    // =========================================================================
    // Automatic Reconnection
    // =========================================================================
    
    /**
     * Enable or disable automatic reconnection to disconnected peers
     * @param enabled Whether auto-reconnection should be enabled
     */
    void set_reconnect_enabled(bool enabled);
    
    /**
     * Check if automatic reconnection is enabled
     * @return true if auto-reconnection is enabled
     */
    bool is_reconnect_enabled() const;
    
    /**
     * Set reconnection configuration
     * @param config Reconnection configuration settings
     */
    void set_reconnect_config(const ReconnectConfig& config);
    
    /**
     * Get current reconnection configuration
     * @return Current reconnection configuration
     */
    const ReconnectConfig& get_reconnect_config() const;
    
    /**
     * Get the number of peers pending reconnection
     * @return Number of peers in reconnection queue
     */
    size_t get_reconnect_queue_size() const;
    
    /**
     * Clear all pending reconnection attempts
     */
    void clear_reconnect_queue();
    
    /**
     * Get information about peers pending reconnection
     * @return Vector of ReconnectInfo for all pending reconnections
     */
    std::vector<ReconnectInfo> get_reconnect_queue() const;

    // =========================================================================
    // Callback Registration
    // =========================================================================
    
    /**
     * Set connection callback (called when a new peer connects)
     * @param callback Function to call on new connections
     */
    void set_connection_callback(ConnectionCallback callback);

    /**
     * Set binary data callback (called when binary data is received)
     * @param callback Function to call when binary data is received
     */
    void set_binary_data_callback(BinaryDataCallback callback);

    /**
     * Set string data callback (called when string data is received)
     * @param callback Function to call when string data is received
     */
    void set_string_data_callback(StringDataCallback callback);

    /**
     * Set JSON data callback (called when JSON data is received)
     * @param callback Function to call when JSON data is received
     */
    void set_json_data_callback(JsonDataCallback callback);

    /**
     * Set disconnect callback (called when a peer disconnects)
     * @param callback Function to call on disconnections
     */
    void set_disconnect_callback(DisconnectCallback callback);

    // =========================================================================
    // Peer Discovery Methods
    // =========================================================================
    
    // DHT Discovery
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
     * @return true if search initiated successfully
     */
    bool find_peers_by_hash(const std::string& content_hash, 
                           std::function<void(const std::vector<std::string>&)> callback);

    /**
     * Announce our presence for a content hash with optional peer discovery callback
     * If callback is provided, peers discovered during DHT traversal will be returned through it
     * @param content_hash Hash to announce for (40-character hex string)
     * @param port Port to announce (default: our listen port)
     * @param callback Optional function to call with discovered peers during traversal
     * @return true if announced successfully
     */
    bool announce_for_hash(const std::string& content_hash, uint16_t port = 0,
                          std::function<void(const std::vector<std::string>&)> callback = nullptr);

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

    // mDNS Discovery
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

    // Automatic Discovery
    /**
     * Start automatic peer discovery
     */
    void start_automatic_peer_discovery();
    
    /**
     * Stop automatic peer discovery
     */
    void stop_automatic_peer_discovery();
    
    /**
     * Check if automatic discovery is running
     * @return true if automatic discovery is running
     */
    bool is_automatic_discovery_running() const;
    
    /**
     * Get the discovery hash for current protocol configuration
     * @return Discovery hash based on current protocol name and version
     */
    std::string get_discovery_hash() const;
    
    /**
     * Get the well-known RATS peer discovery hash
     * @return Standard RATS discovery hash
     */
    static std::string get_rats_peer_discovery_hash();

    /**
     * Add an IP address to the ignore list (for blocking connections to self)
     * @param ip_address IP address to ignore
     */
    void add_ignored_address(const std::string& ip_address);

    // =========================================================================
    // Protocol Configuration
    // =========================================================================
    
    /**
     * Set custom protocol name for handshakes and DHT discovery
     * @param protocol_name Custom protocol name (default: "rats")
     */
    void set_protocol_name(const std::string& protocol_name);

    /**
     * Set custom protocol version for handshakes
     * @param protocol_version Custom protocol version (default: "1.0")
     */
    void set_protocol_version(const std::string& protocol_version);

    /**
     * Get current protocol name
     * @return Current protocol name
     */
    std::string get_protocol_name() const;

    /**
     * Get current protocol version
     * @return Current protocol version
     */
    std::string get_protocol_version() const;

    // =========================================================================
    // Message Exchange API
    // =========================================================================
    
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

    // =========================================================================
    // Encryption Functionality
    // =========================================================================
    
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
     * Check if a peer connection is encrypted
     * @param peer_id Peer ID to check
     * @return true if peer connection is encrypted
     */
    bool is_peer_encrypted(const std::string& peer_id) const;
    
    /**
     * Set a custom static keypair for Noise Protocol
     * If not set, a new keypair is generated automatically
     * @param private_key 32-byte private key
     * @return true if the keypair was set successfully
     */
    bool set_noise_static_keypair(const uint8_t private_key[32]);
    
    /**
     * Get our Noise Protocol static public key
     * @return 32-byte public key
     */
    std::vector<uint8_t> get_noise_static_public_key() const;
    
    /**
     * Get the remote peer's Noise static public key
     * @param peer_id Peer ID to query
     * @return 32-byte public key, or empty vector if not available
     */
    std::vector<uint8_t> get_peer_noise_public_key(const std::string& peer_id) const;
    
    /**
     * Get the handshake hash for a peer connection (for channel binding)
     * @param peer_id Peer ID to query
     * @return 32-byte handshake hash, or empty vector if not available
     */
    std::vector<uint8_t> get_peer_handshake_hash(const std::string& peer_id) const;

    // =========================================================================
    // Configuration Persistence
    // =========================================================================
    
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
     * Set directory where data files will be stored
     * @param directory_path Path to directory (default: current folder)
     * @return true if directory is accessible, false otherwise
     */
    bool set_data_directory(const std::string& directory_path);

    /**
     * Get current data directory path
     * @return Current data directory path
     */
    std::string get_data_directory() const;

    /**
     * Load saved peers and attempt to reconnect
     * @return Number of connection attempts made
     */
    int load_and_reconnect_peers();

    /**
     * Load historical peers from a file
     * @return true if successful, false otherwise
     */
    bool load_historical_peers();

    /**
     * Save current peers to a historical file
     * @return true if successful, false otherwise
     */
    bool save_historical_peers();

    /**
     * Clear all historical peers
     */
    void clear_historical_peers();

    /**
     * Get all historical peers
     * @return Vector of RatsPeer objects
     */
    std::vector<RatsPeer> get_historical_peers() const;

    // =========================================================================
    // Statistics and Information
    // =========================================================================
    
    /**
     * Get connection statistics
     * @return JSON object with detailed statistics
     */
    nlohmann::json get_connection_statistics() const;

    // =========================================================================
    // GossipSub Functionality
    // =========================================================================
    
    /**
     * Get GossipSub instance for publish-subscribe messaging
     * @return Reference to GossipSub instance
     */
    GossipSub& get_gossipsub();
    
    /**
     * Check if GossipSub is available
     * @return true if GossipSub is initialized
     */
    bool is_gossipsub_available() const;
    
    // Topic Management
    /**
     * Subscribe to a GossipSub topic
     * @param topic Topic name to subscribe to
     * @return true if subscription successful
     */
    bool subscribe_to_topic(const std::string& topic);
    
    /**
     * Unsubscribe from a GossipSub topic
     * @param topic Topic name to unsubscribe from
     * @return true if unsubscription successful
     */
    bool unsubscribe_from_topic(const std::string& topic);
    
    /**
     * Check if subscribed to a GossipSub topic
     * @param topic Topic name to check
     * @return true if subscribed
     */
    bool is_subscribed_to_topic(const std::string& topic) const;
    
    /**
     * Get list of subscribed GossipSub topics
     * @return Vector of topic names
     */
    std::vector<std::string> get_subscribed_topics() const;
    
    // Publishing
    /**
     * Publish a message to a GossipSub topic
     * @param topic Topic to publish to
     * @param message Message content
     * @return true if published successfully
     */
    bool publish_to_topic(const std::string& topic, const std::string& message);
    
    /**
     * Publish a JSON message to a GossipSub topic
     * @param topic Topic to publish to
     * @param message JSON message content
     * @return true if published successfully
     */
    bool publish_json_to_topic(const std::string& topic, const nlohmann::json& message);
    
    // Event Handlers (Unified API)
    /**
     * Set a message handler for a GossipSub topic using unified event API pattern
     * @param topic Topic name
     * @param callback Function to call when messages are received (peer_id, topic, message_content)
     */
    void on_topic_message(const std::string& topic, std::function<void(const std::string&, const std::string&, const std::string&)> callback);
    
    /**
     * Set a JSON message handler for a GossipSub topic using unified event API pattern
     * @param topic Topic name  
     * @param callback Function to call when JSON messages are received (peer_id, topic, json_message)
     */
    void on_topic_json_message(const std::string& topic, std::function<void(const std::string&, const std::string&, const nlohmann::json&)> callback);
    
    /**
     * Set a peer joined handler for a GossipSub topic using unified event API pattern
     * @param topic Topic name
     * @param callback Function to call when peers join the topic
     */
    void on_topic_peer_joined(const std::string& topic, std::function<void(const std::string&, const std::string&)> callback);
    
    /**
     * Set a peer left handler for a GossipSub topic using unified event API pattern  
     * @param topic Topic name
     * @param callback Function to call when peers leave the topic
     */
    void on_topic_peer_left(const std::string& topic, std::function<void(const std::string&, const std::string&)> callback);
    
    /**
     * Set a message validator for a GossipSub topic
     * @param topic Topic name (empty for global validator)
     * @param validator Validation function returning ACCEPT, REJECT, or IGNORE_MSG
     */
    void set_topic_message_validator(const std::string& topic, std::function<ValidationResult(const std::string&, const std::string&, const std::string&)> validator);
    
    /**
     * Remove all event handlers for a GossipSub topic
     * @param topic Topic name
     */
    void off_topic(const std::string& topic);
    
    // Information
    /**
     * Get peers subscribed to a GossipSub topic
     * @param topic Topic name
     * @return Vector of peer IDs
     */
    std::vector<std::string> get_topic_peers(const std::string& topic) const;
    
    /**
     * Get mesh peers for a GossipSub topic
     * @param topic Topic name  
     * @return Vector of peer IDs in the mesh
     */
    std::vector<std::string> get_topic_mesh_peers(const std::string& topic) const;
    
    /**
     * Get GossipSub statistics
     * @return JSON object with comprehensive GossipSub statistics
     */
    nlohmann::json get_gossipsub_statistics() const;
    
    /**
     * Check if GossipSub is running
     * @return true if GossipSub service is active
     */
    bool is_gossipsub_running() const;

    // =========================================================================
    // Logging Control API
    // =========================================================================
    
    /**
     * Enable or disable file logging
     * When enabled, logs will be written to "rats.log" by default
     * @param enabled Whether to enable file logging
     */
    void set_logging_enabled(bool enabled);
    
    /**
     * Check if file logging is currently enabled
     * @return true if file logging is enabled
     */
    bool is_logging_enabled() const;
    
    /**
     * Set the log file path
     * @param file_path Path to the log file (default: "rats.log")
     */
    void set_log_file_path(const std::string& file_path);
    
    /**
     * Get the current log file path
     * @return Current log file path
     */
    std::string get_log_file_path() const;
    
    /**
     * Set the minimum log level
     * @param level Minimum log level (DEBUG=0, INFO=1, WARN=2, ERROR=3)
     */
    void set_log_level(LogLevel level);
    
    /**
     * Set the minimum log level using string
     * @param level_str Log level as string ("DEBUG", "INFO", "WARN", "ERROR")
     */
    void set_log_level(const std::string& level_str);
    
    /**
     * Get the current log level
     * @return Current minimum log level
     */
    LogLevel get_log_level() const;
    
    /**
     * Enable or disable colored log output
     * @param enabled Whether to enable colored output
     */
    void set_log_colors_enabled(bool enabled);
    
    /**
     * Check if colored log output is enabled
     * @return true if colors are enabled
     */
    bool is_log_colors_enabled() const;
    
    /**
     * Enable or disable timestamps in log output
     * @param enabled Whether to enable timestamps
     */
    void set_log_timestamps_enabled(bool enabled);
    
    /**
     * Check if timestamps are enabled in log output
     * @return true if timestamps are enabled
     */
    bool is_log_timestamps_enabled() const;
    
    /**
     * Set log file rotation size
     * @param max_size_bytes Maximum size in bytes before log rotation (default: 10MB)
     */
    void set_log_rotation_size(size_t max_size_bytes);
    
    /**
     * Set the number of log files to retain during rotation
     * @param count Number of old log files to keep (default: 5)
     */
    void set_log_retention_count(int count);
    
    /**
     * Clear/reset the current log file
     */
    void clear_log_file();

    // =========================================================================
    // File Transfer API
    // =========================================================================
    
    /**
     * Get the file transfer manager instance
     * @return Reference to the file transfer manager
     */
    FileTransferManager& get_file_transfer_manager();
    
    /**
     * Check if file transfer is available
     * @return true if file transfer manager is initialized
     */
    bool is_file_transfer_available() const;
    
    // Sending and Requesting
    /**
     * Send a file to a peer
     * @param peer_id Target peer ID
     * @param file_path Local file path to send
     * @param remote_filename Optional remote filename (default: use local name)
     * @return Transfer ID if successful, empty string if failed
     */
    std::string send_file(const std::string& peer_id, const std::string& file_path, 
                         const std::string& remote_filename = "");
    
    /**
     * Send an entire directory to a peer
     * @param peer_id Target peer ID
     * @param directory_path Local directory path to send
     * @param remote_directory_name Optional remote directory name
     * @param recursive Whether to include subdirectories (default: true)
     * @return Transfer ID if successful, empty string if failed
     */
    std::string send_directory(const std::string& peer_id, const std::string& directory_path,
                              const std::string& remote_directory_name = "", bool recursive = true);
    
    /**
     * Request a file from a remote peer
     * @param peer_id Target peer ID
     * @param remote_file_path Path to file on remote peer
     * @param local_path Local path where file should be saved
     * @return Transfer ID if successful, empty string if failed
     */
    std::string request_file(const std::string& peer_id, const std::string& remote_file_path,
                            const std::string& local_path);
    
    /**
     * Request a directory from a remote peer
     * @param peer_id Target peer ID
     * @param remote_directory_path Path to directory on remote peer
     * @param local_directory_path Local path where directory should be saved
     * @param recursive Whether to include subdirectories (default: true)
     * @return Transfer ID if successful, empty string if failed
     */
    std::string request_directory(const std::string& peer_id, const std::string& remote_directory_path,
                                 const std::string& local_directory_path, bool recursive = true);
    
    // Accept/Reject Operations
    /**
     * Accept an incoming file transfer
     * @param transfer_id Transfer identifier from request
     * @param local_path Local path where file should be saved
     * @return true if accepted successfully
     */
    bool accept_file_transfer(const std::string& transfer_id, const std::string& local_path);
    
    /**
     * Reject an incoming file transfer
     * @param transfer_id Transfer identifier from request
     * @param reason Optional reason for rejection
     * @return true if rejected successfully
     */
    bool reject_file_transfer(const std::string& transfer_id, const std::string& reason = "");
    
    /**
     * Accept an incoming directory transfer
     * @param transfer_id Transfer identifier from request
     * @param local_path Local path where directory should be saved
     * @return true if accepted successfully
     */
    bool accept_directory_transfer(const std::string& transfer_id, const std::string& local_path);
    
    /**
     * Reject an incoming directory transfer
     * @param transfer_id Transfer identifier from request
     * @param reason Optional reason for rejection
     * @return true if rejected successfully
     */
    bool reject_directory_transfer(const std::string& transfer_id, const std::string& reason = "");
    
    // Transfer Control
    /**
     * Pause an active file transfer
     * @param transfer_id Transfer to pause
     * @return true if paused successfully
     */
    bool pause_file_transfer(const std::string& transfer_id);
    
    /**
     * Resume a paused file transfer
     * @param transfer_id Transfer to resume
     * @return true if resumed successfully
     */
    bool resume_file_transfer(const std::string& transfer_id);
    
    /**
     * Cancel an active or paused file transfer
     * @param transfer_id Transfer to cancel
     * @return true if cancelled successfully
     */
    bool cancel_file_transfer(const std::string& transfer_id);
    
    // Information and Monitoring
    /**
     * Get file transfer progress information
     * @param transfer_id Transfer to query
     * @return Progress information or nullptr if not found
     */
    std::shared_ptr<FileTransferProgress> get_file_transfer_progress(const std::string& transfer_id) const;
    
    /**
     * Get all active file transfers
     * @return Vector of transfer progress objects
     */
    std::vector<std::shared_ptr<FileTransferProgress>> get_active_file_transfers() const;
    
    /**
     * Get file transfer statistics
     * @return JSON object with transfer statistics
     */
    nlohmann::json get_file_transfer_statistics() const;
    
    /**
     * Set file transfer configuration
     * @param config Transfer configuration settings
     */
    void set_file_transfer_config(const FileTransferConfig& config);
    
    /**
     * Get current file transfer configuration
     * @return Current configuration settings
     */
    const FileTransferConfig& get_file_transfer_config() const;
    
    // Event Handlers
    /**
     * Set file transfer progress callback
     * @param callback Function to call with progress updates
     */
    void on_file_transfer_progress(FileTransferProgressCallback callback);
    
    /**
     * Set file transfer completion callback
     * @param callback Function to call when transfers complete
     */
    void on_file_transfer_completed(FileTransferCompletedCallback callback);
    
    /**
     * Set incoming file transfer request callback
     * @param callback Function to call when receiving transfer requests
     */
    void on_file_transfer_request(FileTransferRequestCallback callback);
    
    /**
     * Set directory transfer progress callback
     * @param callback Function to call with directory transfer progress
     */
    void on_directory_transfer_progress(DirectoryTransferProgressCallback callback);
    
    /**
     * Set file request callback (called when receiving file requests)
     * @param callback Function to call when receiving file requests
     */
    void on_file_request(FileRequestCallback callback);
    
    /**
     * Set directory request callback (called when receiving directory requests)
     * @param callback Function to call when receiving directory requests
     */
    void on_directory_request(DirectoryRequestCallback callback);

    // =========================================================================
    // ICE (NAT Traversal) API
    // =========================================================================
    
    /**
     * Get the ICE manager instance
     * @return Reference to the ICE manager
     */
    IceManager& get_ice_manager();
    
    /**
     * Check if ICE is available
     * @return true if ICE manager is initialized
     */
    bool is_ice_available() const;
    
    // Server Configuration
    /**
     * Add a STUN server for NAT traversal
     * @param host STUN server hostname or IP
     * @param port STUN server port (default: 3478)
     */
    void add_stun_server(const std::string& host, uint16_t port = STUN_DEFAULT_PORT);
    
    /**
     * Add a TURN server for relay-based NAT traversal
     * @param host TURN server hostname or IP
     * @param port TURN server port (default: 3478)
     * @param username TURN username
     * @param password TURN password
     */
    void add_turn_server(const std::string& host, uint16_t port,
                         const std::string& username, const std::string& password);
    
    /**
     * Clear all ICE (STUN/TURN) servers
     */
    void clear_ice_servers();
    
    // Candidate Gathering
    /**
     * Start gathering ICE candidates
     * This discovers our public address and generates connection candidates
     * @return true if gathering started successfully
     */
    bool gather_ice_candidates();
    
    /**
     * Get our local ICE candidates
     * Call after gathering is complete
     * @return Vector of ICE candidates
     */
    std::vector<IceCandidate> get_ice_candidates() const;
    
    /**
     * Check if ICE candidate gathering is complete
     * @return true if gathering is complete
     */
    bool is_ice_gathering_complete() const;
    
    // Public Address Discovery
    /**
     * Get our public IP address (discovered via STUN)
     * @return Pair of (IP, port) or nullopt if not discovered
     */
    std::optional<std::pair<std::string, uint16_t>> get_public_address() const;
    
    /**
     * Perform a simple STUN binding request to discover public address
     * This is a convenience method that doesn't require full ICE setup
     * @param server STUN server hostname
     * @param port STUN server port (default: 3478)
     * @param timeout_ms Timeout in milliseconds (default: 5000)
     * @return Mapped address or nullopt on failure
     */
    std::optional<StunMappedAddress> discover_public_address(
        const std::string& server = "stun.l.google.com",
        uint16_t port = 19302,
        int timeout_ms = 5000);
    
    // Remote Candidates
    /**
     * Add a remote ICE candidate (received from peer via signaling)
     * @param candidate Remote candidate to add
     */
    void add_remote_ice_candidate(const IceCandidate& candidate);
    
    /**
     * Add remote ICE candidates from SDP attribute lines
     * @param sdp_lines Vector of SDP candidate lines
     */
    void add_remote_ice_candidates_from_sdp(const std::vector<std::string>& sdp_lines);
    
    /**
     * Signal end of remote candidates (trickle ICE complete)
     */
    void end_of_remote_ice_candidates();
    
    // Connectivity
    /**
     * Start ICE connectivity checks
     */
    void start_ice_checks();
    
    /**
     * Get current ICE connection state
     * @return ICE connection state
     */
    IceConnectionState get_ice_connection_state() const;
    
    /**
     * Get ICE gathering state
     * @return ICE gathering state
     */
    IceGatheringState get_ice_gathering_state() const;
    
    /**
     * Check if ICE is connected
     * @return true if ICE connection is established
     */
    bool is_ice_connected() const;
    
    /**
     * Get the selected ICE candidate pair
     * @return Selected candidate pair or nullopt
     */
    std::optional<IceCandidatePair> get_ice_selected_pair() const;
    
    // ICE Event Callbacks
    /**
     * Set callback for ICE candidates gathered
     * @param callback Function called with all candidates when gathering completes
     */
    void on_ice_candidates_gathered(IceCandidatesCallback callback);
    
    /**
     * Set callback for new ICE candidate (trickle ICE)
     * @param callback Function called when each new candidate is discovered
     */
    void on_ice_new_candidate(IceNewCandidateCallback callback);
    
    /**
     * Set callback for ICE gathering state changes
     * @param callback Function called when gathering state changes
     */
    void on_ice_gathering_state_changed(IceGatheringStateCallback callback);
    
    /**
     * Set callback for ICE connection state changes
     * @param callback Function called when connection state changes
     */
    void on_ice_connection_state_changed(IceConnectionStateCallback callback);
    
    /**
     * Set callback for ICE selected pair
     * @param callback Function called when a candidate pair is selected
     */
    void on_ice_selected_pair(IceSelectedPairCallback callback);
    
    // ICE Configuration
    /**
     * Set ICE configuration
     * @param config ICE configuration settings
     */
    void set_ice_config(const IceConfig& config);
    
    /**
     * Get current ICE configuration
     * @return Current ICE configuration
     */
    const IceConfig& get_ice_config() const;
    
    // ICE Lifecycle
    /**
     * Close ICE manager and release resources
     */
    void close_ice();
    
    /**
     * Restart ICE (re-gather candidates and restart checks)
     */
    void restart_ice();

#ifdef RATS_STORAGE
    // =========================================================================
    // Distributed Storage API (requires RATS_STORAGE)
    // =========================================================================
    
    /**
     * Get the storage manager instance
     * @return Reference to the storage manager
     */
    StorageManager& get_storage_manager();
    
    /**
     * Check if storage is available
     * @return true if storage manager is initialized
     */
    bool is_storage_available() const;
    
    // Put Operations
    /**
     * Store a string value
     * @param key Key to store under
     * @param value String value to store
     * @return true if stored successfully
     */
    bool storage_put(const std::string& key, const std::string& value);
    
    /**
     * Store a 64-bit integer value
     * @param key Key to store under
     * @param value Integer value to store
     * @return true if stored successfully
     */
    bool storage_put(const std::string& key, int64_t value);
    
    /**
     * Store a double-precision floating point value
     * @param key Key to store under
     * @param value Double value to store
     * @return true if stored successfully
     */
    bool storage_put(const std::string& key, double value);
    
    /**
     * Store binary data
     * @param key Key to store under
     * @param value Binary data to store
     * @return true if stored successfully
     */
    bool storage_put(const std::string& key, const std::vector<uint8_t>& value);
    
    /**
     * Store a JSON document
     * @param key Key to store under
     * @param value JSON value to store
     * @return true if stored successfully
     */
    bool storage_put_json(const std::string& key, const nlohmann::json& value);
    
    // Get Operations
    /**
     * Get a string value
     * @param key Key to retrieve
     * @return Optional containing value if found and type matches
     */
    std::optional<std::string> storage_get_string(const std::string& key) const;
    
    /**
     * Get a 64-bit integer value
     * @param key Key to retrieve
     * @return Optional containing value if found and type matches
     */
    std::optional<int64_t> storage_get_int(const std::string& key) const;
    
    /**
     * Get a double-precision floating point value
     * @param key Key to retrieve
     * @return Optional containing value if found and type matches
     */
    std::optional<double> storage_get_double(const std::string& key) const;
    
    /**
     * Get binary data
     * @param key Key to retrieve
     * @return Optional containing value if found and type matches
     */
    std::optional<std::vector<uint8_t>> storage_get_binary(const std::string& key) const;
    
    /**
     * Get a JSON document
     * @param key Key to retrieve
     * @return Optional containing value if found and type matches
     */
    std::optional<nlohmann::json> storage_get_json(const std::string& key) const;
    
    // Delete and Query Operations
    /**
     * Delete a key from storage
     * @param key Key to delete
     * @return true if key existed and was deleted
     */
    bool storage_delete(const std::string& key);
    
    /**
     * Check if a key exists in storage
     * @param key Key to check
     * @return true if key exists
     */
    bool storage_has(const std::string& key) const;
    
    /**
     * Get all keys in storage
     * @return Vector of all keys
     */
    std::vector<std::string> storage_keys() const;
    
    /**
     * Get keys matching a prefix
     * @param prefix Prefix to match
     * @return Vector of matching keys
     */
    std::vector<std::string> storage_keys_with_prefix(const std::string& prefix) const;
    
    /**
     * Get the number of entries in storage
     * @return Number of entries
     */
    size_t storage_size() const;
    
    // Synchronization
    /**
     * Request storage sync from connected peers
     * @return true if sync request was sent
     */
    bool storage_request_sync();
    
    /**
     * Check if storage is synchronized
     * @return true if initial sync is complete
     */
    bool is_storage_synced() const;
    
    // Statistics
    /**
     * Get storage statistics
     * @return JSON object with storage statistics
     */
    nlohmann::json get_storage_statistics() const;
    
    /**
     * Set storage configuration
     * @param config Storage configuration settings
     */
    void set_storage_config(const StorageConfig& config);
    
    /**
     * Get current storage configuration
     * @return Current configuration settings
     */
    const StorageConfig& get_storage_config() const;
    
    // Event Handlers
    /**
     * Set storage change callback
     * @param callback Function to call when storage changes
     */
    void on_storage_change(StorageChangeCallback callback);
    
    /**
     * Set storage sync complete callback
     * @param callback Function to call when sync completes
     */
    void on_storage_sync_complete(StorageSyncCompleteCallback callback);
#endif // RATS_STORAGE

#ifdef RATS_SEARCH_FEATURES
    // =========================================================================
    // BitTorrent API (requires RATS_SEARCH_FEATURES)
    // =========================================================================
    
    /**
     * Enable BitTorrent functionality
     * @param listen_port Port to listen for BitTorrent connections (default: 6881)
     * @return true if BitTorrent was successfully enabled
     */
    bool enable_bittorrent(int listen_port = 6881);
    
    /**
     * Disable BitTorrent functionality
     */
    void disable_bittorrent();
    
    /**
     * Check if BitTorrent is enabled
     * @return true if BitTorrent is active
     */
    bool is_bittorrent_enabled() const;
    
    /**
     * Add a torrent from a file
     * @param torrent_file Path to the .torrent file
     * @param download_path Directory where files will be downloaded
     * @return Shared pointer to TorrentDownload object, or nullptr on failure
     */
    std::shared_ptr<TorrentDownload> add_torrent(const std::string& torrent_file, 
                                                  const std::string& download_path);
    
    /**
     * Add a torrent from TorrentInfo
     * @param torrent_info TorrentInfo object with torrent metadata
     * @param download_path Directory where files will be downloaded
     * @return Shared pointer to TorrentDownload object, or nullptr on failure
     */
    std::shared_ptr<TorrentDownload> add_torrent(const TorrentInfo& torrent_info, 
                                                  const std::string& download_path);
    
    /**
     * Add a torrent by info hash (magnet link style - uses DHT to find peers)
     * @param info_hash Info hash of the torrent
     * @param download_path Directory where files will be downloaded
     * @return Shared pointer to TorrentDownload object, or nullptr on failure
     * @note Requires DHT to be running. Will discover peers via DHT.
     */
    std::shared_ptr<TorrentDownload> add_torrent_by_hash(const InfoHash& info_hash, 
                                                          const std::string& download_path);
    
    /**
     * Add a torrent by info hash hex string (magnet link style - uses DHT to find peers)
     * @param info_hash_hex Info hash as 40-character hex string
     * @param download_path Directory where files will be downloaded
     * @return Shared pointer to TorrentDownload object, or nullptr on failure
     * @note Requires DHT to be running. Will discover peers via DHT.
     */
    std::shared_ptr<TorrentDownload> add_torrent_by_hash(const std::string& info_hash_hex, 
                                                          const std::string& download_path);
    
    /**
     * Remove a torrent by info hash
     * @param info_hash Info hash of the torrent to remove
     * @return true if torrent was removed successfully
     */
    bool remove_torrent(const InfoHash& info_hash);
    
    /**
     * Get a torrent by info hash
     * @param info_hash Info hash of the torrent
     * @return Shared pointer to TorrentDownload object, or nullptr if not found
     */
    std::shared_ptr<TorrentDownload> get_torrent(const InfoHash& info_hash);
    
    /**
     * Get all active torrents
     * @return Vector of all active torrent downloads
     */
    std::vector<std::shared_ptr<TorrentDownload>> get_all_torrents();
    
    /**
     * Get the number of active torrents
     * @return Number of active torrents
     */
    size_t get_active_torrents_count() const;
    
    /**
     * Get BitTorrent statistics (downloaded and uploaded bytes)
     * @return Pair of (downloaded_bytes, uploaded_bytes)
     */
    std::pair<uint64_t, uint64_t> get_bittorrent_stats() const;
    
    /**
     * Get torrent metadata without downloading (requires DHT to be running)
     * @param info_hash Info hash of the torrent
     * @param callback Function called when metadata is retrieved (torrent_info, success, error_message)
     * @note This only retrieves metadata via BEP 9, it does not start downloading
     */
    void get_torrent_metadata(const InfoHash& info_hash, 
                             std::function<void(const TorrentInfo&, bool, const std::string&)> callback);
    
    /**
     * Get torrent metadata without downloading by hex string (requires DHT to be running)
     * @param info_hash_hex Info hash as 40-character hex string
     * @param callback Function called when metadata is retrieved (torrent_info, success, error_message)
     * @note This only retrieves metadata via BEP 9, it does not start downloading
     */
    void get_torrent_metadata(const std::string& info_hash_hex, 
                             std::function<void(const TorrentInfo&, bool, const std::string&)> callback);
    
    /**
     * Get torrent metadata directly from a specific peer (fast path - no DHT search needed)
     * This is more efficient when you already know a peer that has the torrent (e.g., from announce_peer)
     * @param info_hash Info hash of the torrent
     * @param peer_ip IP address of the peer
     * @param peer_port Port of the peer
     * @param callback Function called when metadata is retrieved (torrent_info, success, error_message)
     * @note This only retrieves metadata via BEP 9, it does not start downloading
     */
    void get_torrent_metadata_from_peer(const InfoHash& info_hash,
                                        const std::string& peer_ip,
                                        uint16_t peer_port,
                                        std::function<void(const TorrentInfo&, bool, const std::string&)> callback);
    
    /**
     * Get torrent metadata directly from a specific peer by hex string (fast path)
     * @param info_hash_hex Info hash as 40-character hex string
     * @param peer_ip IP address of the peer
     * @param peer_port Port of the peer
     * @param callback Function called when metadata is retrieved (torrent_info, success, error_message)
     * @note This only retrieves metadata via BEP 9, it does not start downloading
     */
    void get_torrent_metadata_from_peer(const std::string& info_hash_hex,
                                        const std::string& peer_ip,
                                        uint16_t peer_port,
                                        std::function<void(const TorrentInfo&, bool, const std::string&)> callback);
    
    // =========================================================================
    // Torrent Creation API (requires RATS_SEARCH_FEATURES)
    // =========================================================================
    
    /**
     * Torrent creation progress callback type
     * Called during piece hashing to report progress
     * @param current_piece Current piece being hashed (0-indexed)
     * @param total_pieces Total number of pieces
     */
    using TorrentCreationProgressCallback = std::function<void(uint32_t current_piece, uint32_t total_pieces)>;
    
    /**
     * Create a torrent from a file or directory and return TorrentInfo
     * This is a synchronous operation that reads all files to compute piece hashes.
     * @param path Path to file or directory to create torrent from
     * @param trackers Optional list of tracker URLs
     * @param comment Optional comment
     * @param progress_callback Optional callback for progress updates
     * @return TorrentInfo object, or nullopt on failure
     */
    std::optional<TorrentInfo> create_torrent_from_path(
        const std::string& path,
        const std::vector<std::string>& trackers = {},
        const std::string& comment = "",
        TorrentCreationProgressCallback progress_callback = nullptr);
    
    /**
     * Create a torrent from a file or directory and return raw torrent data
     * @param path Path to file or directory
     * @param trackers Optional list of tracker URLs
     * @param comment Optional comment
     * @param progress_callback Optional callback for progress updates
     * @return Bencoded torrent data, or empty vector on failure
     */
    std::vector<uint8_t> create_torrent_data(
        const std::string& path,
        const std::vector<std::string>& trackers = {},
        const std::string& comment = "",
        TorrentCreationProgressCallback progress_callback = nullptr);
    
    /**
     * Create a torrent and save it to a file
     * @param path Path to file or directory
     * @param output_file Path to save the .torrent file
     * @param trackers Optional list of tracker URLs
     * @param comment Optional comment
     * @param progress_callback Optional callback for progress updates
     * @return true if torrent was created and saved successfully
     */
    bool create_torrent_file(
        const std::string& path,
        const std::string& output_file,
        const std::vector<std::string>& trackers = {},
        const std::string& comment = "",
        TorrentCreationProgressCallback progress_callback = nullptr);
    
    /**
     * Create a torrent, add it to the BitTorrent client, and start seeding
     * This combines torrent creation with immediately starting to seed it.
     * @param path Path to file or directory
     * @param trackers Optional list of tracker URLs
     * @param comment Optional comment
     * @param progress_callback Optional callback for progress updates
     * @return Shared pointer to TorrentDownload for the seeding torrent, or nullptr on failure
     * @note Requires BitTorrent to be enabled (call enable_bittorrent() first)
     */
    std::shared_ptr<TorrentDownload> create_and_seed_torrent(
        const std::string& path,
        const std::vector<std::string>& trackers = {},
        const std::string& comment = "",
        TorrentCreationProgressCallback progress_callback = nullptr);
    
    // =========================================================================
    // Spider Mode API (requires RATS_SEARCH_FEATURES)
    // =========================================================================
    
    /**
     * Spider announce callback type
     * Called when a peer announces they have a torrent (announce_peer request received)
     * @param info_hash The info hash being announced (as hex string)
     * @param peer_address The peer that is announcing (ip:port format)
     */
    using SpiderAnnounceCallback = std::function<void(const std::string& info_hash, const std::string& peer_address)>;
    
    /**
     * Enable spider mode on DHT
     * In spider mode:
     * - Nodes are added to routing table without ping verification
     * - All announce_peer requests from other peers are collected via callback
     * @param enable true to enable spider mode, false to disable
     */
    void set_spider_mode(bool enable);
    
    /**
     * Check if spider mode is enabled
     * @return true if spider mode is enabled
     */
    bool is_spider_mode() const;
    
    /**
     * Set callback for announce_peer requests (spider mode)
     * Called when other peers announce they have a torrent
     * @param callback The callback to invoke
     */
    void set_spider_announce_callback(SpiderAnnounceCallback callback);
    
    /**
     * Set spider ignore mode - when true, incoming requests are not processed
     * Useful for rate limiting in spider mode
     * @param ignore true to ignore incoming requests, false to process them
     */
    void set_spider_ignore(bool ignore);
    
    /**
     * Check if spider ignore mode is enabled
     * @return true if ignoring incoming requests
     */
    bool is_spider_ignoring() const;
    
    /**
     * Trigger a single spider walk iteration
     * Sends find_node to a random node from the spider pool
     * Call this periodically at desired frequency to discover new nodes
     */
    void spider_walk();
    
    /**
     * Get the size of the spider node pool
     * @return Number of nodes in spider pool
     */
    size_t get_spider_pool_size() const;
    
    /**
     * Get the number of visited nodes in spider mode
     * @return Number of visited nodes
     */
    size_t get_spider_visited_count() const;
    
    /**
     * Clear spider state (pool and visited nodes)
     * Useful for resetting the spider walk
     */
    void clear_spider_state();
#endif // RATS_SEARCH_FEATURES

private:
    int listen_port_;
    std::string bind_address_;
    int max_peers_;
    socket_t server_socket_;
    std::atomic<bool> running_;
    
    // =========================================================================
    // MUTEX LOCKING ORDER - CRITICAL FOR DEADLOCK PREVENTION
    // =========================================================================
    // When acquiring multiple mutexes, ALWAYS follow this strict order:
    //
    // 1. config_mutex_              (Configuration and peer ID)
    // 2. protocol_config_mutex_      (Protocol name and version)
    // 3. encryption_mutex_           (Encryption settings and keys)
    // 4. local_addresses_mutex_      (Local interface addresses)
    // 5. peers_mutex_                (Peer management - most frequently locked)
    // 6. socket_send_mutexes_mutex_ (Socket send mutex management)
    // 7. message_handlers_mutex_    (Message handler registration)
    // 8. reconnect_mutex_           (Reconnection queue management)
    // =========================================================================
    
    // [1] Configuration persistence (protected by config_mutex_)
    mutable std::mutex config_mutex_;                       // [1] Protects configuration data
    std::string our_peer_id_;                               // Our persistent peer ID
    std::string data_directory_;                            // Directory where data files are stored
    static const std::string CONFIG_FILE_NAME;             // "config.json"
    static const std::string PEERS_FILE_NAME;              // "peers.rats"
    static const std::string PEERS_EVER_FILE_NAME;         // "peers_ever.rats"
    
    // [2] Custom protocol configuration (protected by protocol_config_mutex_)
    mutable std::mutex protocol_config_mutex_;              // [2] Protects protocol configuration
    std::string custom_protocol_name_;                      // Custom protocol name (default: "rats")
    std::string custom_protocol_version_;                   // Custom protocol version (default: "1.0")
    
    // [3] Encryption state (protected by encryption_mutex_)
    mutable std::mutex encryption_mutex_;                   // [3] Protects encryption state
    bool encryption_enabled_;                               // Whether encryption is enabled
    rats::NoiseKeyPair noise_static_keypair_;               // Our static Noise keypair
    bool noise_keypair_initialized_;                        // Whether keypair has been initialized
    
    // [4] Local interface address blocking (protected by local_addresses_mutex_)
    mutable std::mutex local_addresses_mutex_;              // [4] Protects local interface addresses
    std::vector<std::string> local_interface_addresses_;
    
    // [5] Organized peer management using RatsPeer struct (protected by peers_mutex_)
    mutable std::mutex peers_mutex_;                        // [5] Protects peer data (most frequently locked)
    std::unordered_map<std::string, RatsPeer> peers_;          // keyed by peer_id
    std::unordered_map<socket_t, std::string> socket_to_peer_id_;  // for quick socket->peer_id lookup  
    std::unordered_map<std::string, std::string> address_to_peer_id_;  // for duplicate detection (normalized_address->peer_id)
    
    // [6] Per-socket synchronization for thread-safe message sending (protected by socket_send_mutexes_mutex_)
    mutable std::mutex socket_send_mutexes_mutex_;          // [6] Protects socket send mutex map
    std::unordered_map<socket_t, std::shared_ptr<std::mutex>> socket_send_mutexes_;
    
    // Server and client management
    std::thread server_thread_;
    std::thread management_thread_;
    
    ConnectionCallback connection_callback_;
    BinaryDataCallback binary_data_callback_;
    StringDataCallback string_data_callback_;
    JsonDataCallback json_data_callback_;
    DisconnectCallback disconnect_callback_;
    
    // DHT client for peer discovery
    std::unique_ptr<DhtClient> dht_client_;
    
    // mDNS client for local network discovery
    std::unique_ptr<MdnsClient> mdns_client_;
    std::function<void(const std::string&, int, const std::string&)> mdns_callback_;
    
    // GossipSub for publish-subscribe messaging
    std::unique_ptr<GossipSub> gossipsub_;
    
    // File transfer manager
    std::unique_ptr<FileTransferManager> file_transfer_manager_;
    
    // ICE manager for NAT traversal
    std::unique_ptr<IceManager> ice_manager_;
    
#ifdef RATS_STORAGE
    // Distributed storage manager (optional, requires RATS_STORAGE)
    std::unique_ptr<StorageManager> storage_manager_;
#endif

#ifdef RATS_SEARCH_FEATURES
    // BitTorrent client (optional, requires RATS_SEARCH_FEATURES)
    std::unique_ptr<BitTorrentClient> bittorrent_client_;
#endif
    
    void initialize_modules();
    void destroy_modules();

    void server_loop();
    void management_loop();
    void handle_client(socket_t client_socket, const std::string& peer_hash_id);
    void remove_peer(socket_t socket);
    std::string generate_peer_hash_id(socket_t socket, const std::string& connection_info);
    void handle_dht_peer_discovery(const std::vector<Peer>& peers, const InfoHash& info_hash);
    void handle_mdns_service_discovery(const MdnsService& service, bool is_new);
    
    // Message header helpers
    std::vector<uint8_t> create_message_with_header(const std::vector<uint8_t>& payload, MessageDataType type);
    bool parse_message_with_header(const std::vector<uint8_t>& message, MessageHeader& header, std::vector<uint8_t>& payload) const;
    
    // Peer management methods using RatsPeer
    void add_peer(const RatsPeer& peer);
    void add_peer_unlocked(const RatsPeer& peer);  // Assumes peers_mutex_ is already locked
    void remove_peer_by_id(const std::string& peer_id);
    void remove_peer_by_id_unlocked(const std::string& peer_id);  // Assumes peers_mutex_ is already locked
    bool is_already_connected_to_address(const std::string& normalized_address) const;
    std::string normalize_peer_address(const std::string& ip, int port) const;
    
    // Data transmission helper - assumes peers_mutex_ is already locked or peer data is cached
    bool send_binary_to_peer_unlocked(socket_t socket, const std::vector<uint8_t>& data, 
                                       MessageDataType message_type, 
                                       rats::NoiseCipherState* send_cipher,
                                       const std::string& peer_id_for_logging);

    // Local interface address blocking helper functions
    void initialize_local_addresses();
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
        bool encryption_enabled;  // Whether peer supports/wants encryption
    };

    std::string create_handshake_message(const std::string& message_type, const std::string& our_peer_id) const;
    bool parse_handshake_message(const std::string& message, HandshakeMessage& out_msg) const;
    bool validate_handshake_message(const HandshakeMessage& msg) const;
    bool is_handshake_message(const std::string& message) const;
    bool send_handshake(socket_t socket, const std::string& our_peer_id);
    bool send_handshake_unlocked(socket_t socket, const std::string& our_peer_id);
    bool handle_handshake_message(socket_t socket, const std::string& peer_hash_id, const std::string& message);
    void check_handshake_timeouts();
    void log_handshake_completion_unlocked(const RatsPeer& peer);

    // Automatic discovery
    std::atomic<bool> auto_discovery_running_;
    std::thread auto_discovery_thread_;
    void automatic_discovery_loop();
    void announce_rats_peer();

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
    
    // [7] Message exchange API implementation (protected by message_handlers_mutex_)
    mutable std::mutex message_handlers_mutex_;             // [7] Protects message handlers
    struct MessageHandler {
        MessageCallback callback;
        bool is_once;
        
        MessageHandler(MessageCallback cb, bool once) : callback(cb), is_once(once) {}
    };
    std::unordered_map<std::string, std::vector<MessageHandler>> message_handlers_;
    
    void call_message_handlers(const std::string& message_type, const std::string& peer_id, const nlohmann::json& data);

    // [8] Automatic reconnection system (protected by reconnect_mutex_)
    mutable std::mutex reconnect_mutex_;                    // [8] Protects reconnection queue
    std::unordered_map<std::string, ReconnectInfo> reconnect_queue_;  // keyed by peer_id
    ReconnectConfig reconnect_config_;                      // Reconnection configuration
    std::unordered_set<std::string> manual_disconnect_peers_;  // Peers that were manually disconnected (don't reconnect)
    
    // Reconnection helper methods
    void schedule_reconnect(const RatsPeer& peer);
    void process_reconnect_queue();
    void remove_from_reconnect_queue(const std::string& peer_id);
    int get_retry_interval_seconds(int attempt, bool is_stable) const;

    // Per-socket synchronization helpers
    std::shared_ptr<std::mutex> get_socket_send_mutex(socket_t socket);
    void cleanup_socket_send_mutex(socket_t socket);

    // Configuration persistence helpers
    std::string generate_persistent_peer_id() const;
    nlohmann::json serialize_peer_for_persistence(const RatsPeer& peer) const;
    bool deserialize_peer_from_persistence(const nlohmann::json& json, std::string& ip, int& port, std::string& peer_id) const;
    std::string get_config_file_path() const;
    std::string get_peers_file_path() const;
    std::string get_peers_ever_file_path() const;
    bool save_peers_to_file();
    bool append_peer_to_historical_file(const RatsPeer& peer);
    int load_and_reconnect_historical_peers();
    
    // Noise Protocol encryption helpers
    void initialize_noise_keypair();
    bool perform_noise_handshake(socket_t socket, const std::string& peer_id, bool is_initiator);
    bool send_noise_message(socket_t socket, const uint8_t* data, size_t len);
    bool recv_noise_message(socket_t socket, std::vector<uint8_t>& out_data, int timeout_ms = 10000);
    bool encrypt_and_send(socket_t socket, const std::string& peer_id, const std::vector<uint8_t>& plaintext);
    bool receive_and_decrypt(socket_t socket, const std::string& peer_id, std::vector<uint8_t>& plaintext);
};

// Utility functions
std::unique_ptr<RatsClient> create_rats_client(int listen_port);

// Library version query (stable, binding-friendly)
RATS_API const char* rats_get_library_version_string();
RATS_API void rats_get_library_version(int* major, int* minor, int* patch, int* build);
RATS_API const char* rats_get_library_git_describe();
RATS_API uint32_t rats_get_library_abi(); // packed as (major<<16)|(minor<<8)|patch

} // namespace librats 