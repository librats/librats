#pragma once

#include "socket.h"
#include "dht.h"
#include "stun.h"
#include "logger.h"
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
    int peer_count;                         // Number of peers connected to remote peer
    std::chrono::steady_clock::time_point handshake_start_time; // When handshake started
    
    RatsPeer() : port(0), socket(INVALID_SOCKET_VALUE), is_outgoing(false), 
                 handshake_state(HandshakeState::PENDING), peer_count(0) {
        connected_at = std::chrono::steady_clock::now();
        handshake_start_time = connected_at;
    }
    
    RatsPeer(const std::string& peer_id, const std::string& ip, uint16_t port, 
             socket_t socket, const std::string& normalized_address, bool is_outgoing)
        : peer_id(peer_id), ip(ip), port(port), socket(socket), 
          normalized_address(normalized_address), is_outgoing(is_outgoing), 
          handshake_state(HandshakeState::PENDING), peer_count(0) {
        connected_at = std::chrono::steady_clock::now();
        handshake_start_time = connected_at;
    }
    
    /**
     * Get connection duration in seconds
     */
    double get_connection_duration() const {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - connected_at);
        return duration.count();
    }
    
    /**
     * Get handshake duration in seconds
     */
    double get_handshake_duration() const {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - handshake_start_time);
        return duration.count();
    }
    
    /**
     * Check if handshake is completed
     */
    bool is_handshake_completed() const {
        return handshake_state == HandshakeState::COMPLETED;
    }
    
    /**
     * Check if handshake has failed
     */
    bool is_handshake_failed() const {
        return handshake_state == HandshakeState::FAILED;
    }
    
    /**
     * Get peer address as string (ip:port)
     */
    std::string get_address() const {
        return ip + ":" + std::to_string(port);
    }
    
    bool operator==(const RatsPeer& other) const {
        return peer_id == other.peer_id;
    }
    
    bool operator!=(const RatsPeer& other) const {
        return !(*this == other);
    }
};

/**
 * Callback function type for handling incoming connections
 * @param client_socket The socket handle of the connected client
 * @param peer_hash_id Unique hash ID for the peer
 */
using ConnectionCallback = std::function<void(socket_t client_socket, const std::string& peer_hash_id)>;

/**
 * Callback function type for handling received data
 * @param socket The socket handle that received data
 * @param peer_hash_id Unique hash ID for the peer
 * @param data The received data
 */
using DataCallback = std::function<void(socket_t socket, const std::string& peer_hash_id, const std::string& data)>;

/**
 * Callback function type for handling disconnections
 * @param socket The socket handle that was disconnected
 * @param peer_hash_id Unique hash ID for the peer
 */
using DisconnectCallback = std::function<void(socket_t socket, const std::string& peer_hash_id)>;

/**
 * RatsClient class - provides simultaneous client and server functionality
 */
class RatsClient {
public:
    /**
     * Constructor
     * @param listen_port The port to listen on for incoming connections
     * @param max_peers Maximum number of peers to maintain (default: 10)
     */
    RatsClient(int listen_port, int max_peers = 10);
    
    /**
     * Destructor
     */
    ~RatsClient();
    
    /**
     * Start the rats client (begins listening for connections)
     * @return true if successful, false otherwise
     */
    bool start();
    
    /**
     * Stop the rats client
     */
    void stop();
    
    /**
     * Connect to another rats client
     * @param host The hostname or IP address to connect to
     * @param port The port number to connect to
     * @return true if successful, false otherwise
     */
    bool connect_to_peer(const std::string& host, int port);
    
    /**
     * Send data to a specific peer
     * @param socket The socket handle to send data to
     * @param data The data to send
     * @return true if successful, false otherwise
     */
    bool send_to_peer(socket_t socket, const std::string& data);
    
    /**
     * Send JSON data to a specific peer
     * @param socket The socket handle to send data to
     * @param json_data The JSON data to send
     * @return true if successful, false otherwise
     */
    bool send_json_to_peer(socket_t socket, const nlohmann::json& json_data);
    
    /**
     * Send data to a specific peer by hash ID
     * @param peer_hash_id The hash ID of the peer to send data to
     * @param data The data to send
     * @return true if successful, false otherwise
     */
    bool send_to_peer_by_hash(const std::string& peer_hash_id, const std::string& data);
    
    /**
     * Send JSON data to a specific peer by hash ID
     * @param peer_hash_id The hash ID of the peer to send data to
     * @param json_data The JSON data to send
     * @return true if successful, false otherwise
     */
    bool send_json_to_peer_by_hash(const std::string& peer_hash_id, const nlohmann::json& json_data);
    
    /**
     * Send data to all connected peers
     * @param data The data to send
     * @return Number of peers the data was sent to
     */
    int broadcast_to_peers(const std::string& data);
    
    /**
     * Send JSON data to all connected peers
     * @param json_data The JSON data to send
     * @return Number of peers the data was sent to
     */
    int broadcast_json_to_peers(const nlohmann::json& json_data);
    
    /**
     * Parse a JSON message from a string
     * @param message The message string to parse
     * @param out_json The parsed JSON object
     * @return true if successful, false otherwise
     */
    bool parse_json_message(const std::string& message, nlohmann::json& out_json);
    
    /**
     * Disconnect from a specific peer
     * @param socket The socket handle to disconnect
     */
    void disconnect_peer(socket_t socket);
    
    /**
     * Disconnect from a specific peer by hash ID
     * @param peer_hash_id The hash ID of the peer to disconnect
     */
    void disconnect_peer_by_hash(const std::string& peer_hash_id);
    
    /**
     * Get the number of connected peers
     * @return Number of connected peers
     */
    int get_peer_count() const;
    
    /**
     * Check if the rats client is running
     * @return true if running, false otherwise
     */
    bool is_running() const;
    
    /**
     * Get hash ID for a socket
     * @param socket The socket handle
     * @return Hash ID string or empty string if not found
     */
    std::string get_peer_hash_id(socket_t socket) const;
    
    /**
     * Get socket for a hash ID
     * @param peer_hash_id The hash ID
     * @return Socket handle or INVALID_SOCKET_VALUE if not found
     */
    socket_t get_peer_socket(const std::string& peer_hash_id) const;
    
    /**
     * Set callback for new incoming connections
     * @param callback The callback function
     */
    void set_connection_callback(ConnectionCallback callback);
    
    /**
     * Set callback for received data
     * @param callback The callback function
     */
    void set_data_callback(DataCallback callback);
    
    /**
     * Set callback for disconnections
     * @param callback The callback function
     */
    void set_disconnect_callback(DisconnectCallback callback);
    
    /**
     * Start DHT-based peer discovery
     * @param dht_port The port to use for DHT (default: 6881)
     * @return true if successful, false otherwise
     */
    bool start_dht_discovery(int dht_port = 6881);
    
    /**
     * Stop DHT-based peer discovery
     */
    void stop_dht_discovery();
    
    /**
     * Find peers using DHT for a specific content hash
     * @param content_hash The content hash to search for
     * @param callback Callback to receive discovered peers
     * @return true if search started successfully, false otherwise
     */
    bool find_peers_by_hash(const std::string& content_hash, std::function<void(const std::vector<std::string>&)> callback, int iteration_max = 1);
    
    /**
     * Announce this node as a peer for a specific content hash
     * @param content_hash The content hash to announce for
     * @param port The port to announce (0 for listen port)
     * @return true if announcement started successfully, false otherwise
     */
    bool announce_for_hash(const std::string& content_hash, uint16_t port = 0);
    
    /**
     * Check if DHT is running
     * @return true if DHT is running, false otherwise
     */
    bool is_dht_running() const;
    
    /**
     * Get DHT routing table size
     * @return Number of nodes in DHT routing table
     */
    size_t get_dht_routing_table_size() const;

    // STUN functionality for public IP discovery
    /**
     * Discover public IP address using STUN and add to ignore list
     * @param stun_server STUN server hostname (default: Google STUN)
     * @param stun_port STUN server port (default: 19302)
     * @return true if successful, false otherwise
     */
    bool discover_and_ignore_public_ip(const std::string& stun_server = "stun.l.google.com", int stun_port = 19302);
    
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
     * @param max_peers Maximum number of peers to maintain
     */
    void set_max_peers(int max_peers);
    
    /**
     * Check if peer limit is reached
     * @return true if at maximum capacity, false otherwise
     */
    bool is_peer_limit_reached() const;

    /**
     * Get our persistent peer ID
     * @return The persistent peer ID for this client
     */
    std::string get_our_peer_id() const;

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
    
    // Configuration persistence
    std::string our_peer_id_;                               // Our persistent peer ID
    mutable std::mutex config_mutex_;                       // Protects configuration data
    static const std::string CONFIG_FILE_NAME;             // "config.json"
    static const std::string PEERS_FILE_NAME;              // "peers.rats"
    
    // Organized peer management using RatsPeer struct
    std::unordered_map<std::string, RatsPeer> peers_;          // keyed by peer_id
    std::unordered_map<socket_t, std::string> socket_to_peer_id_;  // for quick socket->peer_id lookup  
    std::unordered_map<std::string, std::string> address_to_peer_id_;  // for duplicate detection (normalized_address->peer_id)
    
    mutable std::mutex peers_mutex_;
    
    std::thread server_thread_;
    
    ConnectionCallback connection_callback_;
    DataCallback data_callback_;
    DisconnectCallback disconnect_callback_;
    
    // DHT client for peer discovery
    std::unique_ptr<DhtClient> dht_client_;
    
    // STUN client for public IP discovery
    std::unique_ptr<StunClient> stun_client_;
    std::string public_ip_;
    mutable std::mutex public_ip_mutex_;
    
    void server_loop();
    void handle_client(socket_t client_socket, const std::string& peer_hash_id);
    void remove_peer(socket_t socket);
    std::string generate_peer_hash_id(socket_t socket, const std::string& connection_info);
    void handle_dht_peer_discovery(const std::vector<Peer>& peers, const InfoHash& info_hash);
    
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
        std::string protocol;           // "rats"
        std::string version;            // protocol version
        std::string peer_id;            // our peer ID
        std::string message_type;       // "handshake" (simplified from request/response)
        int64_t timestamp;              // message timestamp
        int peer_count;                 // Number of peers connected to this node
    };
    
    std::string create_handshake_message(const std::string& message_type, const std::string& our_peer_id) const;
    bool parse_handshake_message(const std::string& message, HandshakeMessage& out_msg) const;
    bool send_handshake(socket_t socket, const std::string& our_peer_id);
    bool send_handshake_unlocked(socket_t socket, const std::string& our_peer_id);  // Helper that assumes mutex is already locked
    bool handle_handshake_message(socket_t socket, const std::string& peer_hash_id, const std::string& message);
    bool is_handshake_message(const std::string& message) const;
    void check_handshake_timeouts();
    bool validate_handshake_message(const HandshakeMessage& msg) const;
    void log_handshake_completion(const RatsPeer& peer);
    void log_handshake_completion_unlocked(const RatsPeer& peer);  // Helper that assumes mutex is already locked

    // Message handling system
    struct RatsMessage {
        std::string type;               // Message type (e.g., "peer", "data", etc.)
        nlohmann::json payload;         // Message payload
        std::string sender_peer_id;     // ID of the sending peer
        int64_t timestamp;              // Message timestamp
    };
    
    // Message type handling
    void handle_rats_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& message);
    void handle_peer_exchange_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload);
    void broadcast_peer_exchange_message(const RatsPeer& new_peer);
    nlohmann::json create_rats_message(const std::string& type, const nlohmann::json& payload, const std::string& sender_peer_id = "");
    
    // General broadcasting functions
    int broadcast_rats_message(const nlohmann::json& message, const std::string& exclude_peer_id = "");
    int broadcast_rats_message_to_validated_peers(const nlohmann::json& message, const std::string& exclude_peer_id = "");
    
    // Specific message creation functions
    nlohmann::json create_peer_exchange_message(const RatsPeer& peer);
    
    // Utility functions for custom message types
    /**
     * Create and broadcast a custom rats message to all validated peers
     * @param type Message type (e.g., "status", "data", "announcement")
     * @param payload Message payload as JSON object
     * @param sender_peer_id Optional sender peer ID
     * @param exclude_peer_id Optional peer ID to exclude from broadcast
     * @return Number of peers the message was sent to
     */
    int broadcast_custom_message(const std::string& type, const nlohmann::json& payload, 
                                const std::string& sender_peer_id = "", 
                                const std::string& exclude_peer_id = "");
    
    /**
     * Send a custom rats message to a specific peer by peer ID
     * @param peer_id Target peer ID
     * @param type Message type
     * @param payload Message payload as JSON object
     * @param sender_peer_id Optional sender peer ID
     * @return true if successful, false otherwise
     */
    bool send_custom_message_to_peer(const std::string& peer_id, const std::string& type, 
                                    const nlohmann::json& payload, 
                                    const std::string& sender_peer_id = "");
    
    // Peers request/response system
    void handle_peers_request_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload);
    void handle_peers_response_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload);
    nlohmann::json create_peers_request_message(const std::string& sender_peer_id);
    nlohmann::json create_peers_response_message(const std::vector<RatsPeer>& peers, const std::string& sender_peer_id);
    std::vector<RatsPeer> get_random_peers(int max_count, const std::string& exclude_peer_id = "") const;
    void send_peers_request(socket_t socket, const std::string& our_peer_id);
    
    // Automatic peer discovery
    std::atomic<bool> auto_discovery_running_{false};
    std::thread auto_discovery_thread_;
    void automatic_discovery_loop();
    void announce_rats_peer();
    void search_rats_peers(int iteration_max = 1);
    
    // Configuration persistence helpers
    std::string generate_persistent_peer_id() const;
    nlohmann::json serialize_peer_for_persistence(const RatsPeer& peer) const;
    bool deserialize_peer_from_persistence(const nlohmann::json& json, std::string& ip, int& port, std::string& peer_id) const;
    std::string get_config_file_path() const;
    std::string get_peers_file_path() const;
    bool save_peers_to_file(); // Helper method that assumes config_mutex_ is already locked
};

/**
 * Simple helper functions for basic rats client operations
 */

/**
 * Create and start a basic rats client
 * @param listen_port The port to listen on
 * @return Pointer to RatsClient instance, or nullptr on failure
 */
std::unique_ptr<RatsClient> create_rats_client(int listen_port);

/**
 * Run a simple rats client demo
 * @param listen_port The port to listen on
 * @param peer_host Optional peer to connect to
 * @param peer_port Optional peer port to connect to
 */
void run_rats_client_demo(int listen_port, const std::string& peer_host = "", int peer_port = 0);

} // namespace librats 