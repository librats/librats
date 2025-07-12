#pragma once

#include "network.h"
#include "logger.h"
#include <string>
#include <functional>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>

namespace librats {

/**
 * Callback function type for handling incoming connections
 * @param client_socket The socket handle of the connected client
 * @param client_info Information about the connected client (IP:port)
 */
using ConnectionCallback = std::function<void(socket_t client_socket, const std::string& client_info)>;

/**
 * Callback function type for handling received data
 * @param socket The socket handle that received data
 * @param data The received data
 */
using DataCallback = std::function<void(socket_t socket, const std::string& data)>;

/**
 * Callback function type for handling disconnections
 * @param socket The socket handle that was disconnected
 */
using DisconnectCallback = std::function<void(socket_t socket)>;

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

private:
    int listen_port_;
    socket_t server_socket_;
    std::atomic<bool> running_;
    
    std::vector<socket_t> peer_sockets_;
    mutable std::mutex peers_mutex_;
    
    std::thread server_thread_;
    std::vector<std::thread> client_threads_;
    
    ConnectionCallback connection_callback_;
    DataCallback data_callback_;
    DisconnectCallback disconnect_callback_;
    
    void server_loop();
    void handle_client(socket_t client_socket, const std::string& client_info);
    void remove_peer(socket_t socket);
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