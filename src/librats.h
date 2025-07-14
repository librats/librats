#pragma once

#include "socket.h"
#include "dht.h"
#include "stun.h"
#include "logger.h"
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
    
    RatsPeer() : port(0), socket(INVALID_SOCKET_VALUE), is_outgoing(false) {
        connected_at = std::chrono::steady_clock::now();
    }
    
    RatsPeer(const std::string& peer_id, const std::string& ip, uint16_t port, 
             socket_t socket, const std::string& normalized_address, bool is_outgoing)
        : peer_id(peer_id), ip(ip), port(port), socket(socket), 
          normalized_address(normalized_address), is_outgoing(is_outgoing) {
        connected_at = std::chrono::steady_clock::now();
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
     */
    RatsClient(int listen_port);
    
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
     * Send data to a specific peer by hash ID
     * @param peer_hash_id The hash ID of the peer to send data to
     * @param data The data to send
     * @return true if successful, false otherwise
     */
    bool send_to_peer_by_hash(const std::string& peer_hash_id, const std::string& data);
    
    /**
     * Send data to all connected peers
     * @param data The data to send
     * @return Number of peers the data was sent to
     */
    int broadcast_to_peers(const std::string& data);
    
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

private:
    int listen_port_;
    socket_t server_socket_;
    std::atomic<bool> running_;
    
    // Organized peer management using RatsPeer struct
    std::unordered_map<std::string, RatsPeer> peers_;          // keyed by peer_id
    std::unordered_map<socket_t, std::string> socket_to_peer_id_;  // for quick socket->peer_id lookup  
    std::unordered_map<std::string, std::string> address_to_peer_id_;  // for duplicate detection (normalized_address->peer_id)
    
    mutable std::mutex peers_mutex_;
    
    std::thread server_thread_;
    std::vector<std::thread> client_threads_;
    
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
    void add_peer_mapping(socket_t socket, const std::string& hash_id);
    void remove_peer_mapping(socket_t socket);
    void handle_dht_peer_discovery(const std::vector<Peer>& peers, const InfoHash& info_hash);
    
    // New peer management methods using RatsPeer
    void add_peer(const RatsPeer& peer);
    void remove_peer_by_id(const std::string& peer_id);
    bool is_already_connected_to_address(const std::string& normalized_address) const;
    
    // Peer address tracking methods (legacy - will be replaced)
    void add_peer_address_mapping(socket_t socket, const std::string& peer_address);
    void remove_peer_address_mapping(socket_t socket);
    bool is_already_connected_to_peer(const std::string& peer_address) const;
    std::string normalize_peer_address(const std::string& ip, int port) const;

    // Local interface address blocking (ignore list)
    std::vector<std::string> local_interface_addresses_;
    mutable std::mutex local_addresses_mutex_;
    void initialize_local_addresses();
    void refresh_local_addresses();
    bool is_blocked_address(const std::string& ip_address) const;
    bool should_ignore_peer(const std::string& ip, int port) const;

    // Automatic peer discovery
    std::atomic<bool> auto_discovery_running_{false};
    std::thread auto_discovery_thread_;
    void automatic_discovery_loop();
    void announce_rats_peer();
    void search_rats_peers(int iteration_max = 1);
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