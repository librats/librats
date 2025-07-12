#pragma once

#include "network.h"
#include "dht.h"
#include "logger.h"
#include <string>
#include <functional>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <memory>

namespace librats {

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
    bool find_peers_by_hash(const std::string& content_hash, std::function<void(const std::vector<std::string>&)> callback);
    
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

private:
    int listen_port_;
    socket_t server_socket_;
    std::atomic<bool> running_;
    
    std::vector<socket_t> peer_sockets_;
    std::unordered_map<socket_t, std::string> socket_to_hash_;
    std::unordered_map<std::string, socket_t> hash_to_socket_;
    mutable std::mutex peers_mutex_;
    
    std::thread server_thread_;
    std::vector<std::thread> client_threads_;
    
    ConnectionCallback connection_callback_;
    DataCallback data_callback_;
    DisconnectCallback disconnect_callback_;
    
    // DHT client for peer discovery
    std::unique_ptr<DhtClient> dht_client_;
    
    void server_loop();
    void handle_client(socket_t client_socket, const std::string& peer_hash_id);
    void remove_peer(socket_t socket);
    std::string generate_peer_hash_id(socket_t socket, const std::string& connection_info);
    void add_peer_mapping(socket_t socket, const std::string& hash_id);
    void remove_peer_mapping(socket_t socket);
    void handle_dht_peer_discovery(const std::vector<UdpPeer>& peers, const InfoHash& info_hash);
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