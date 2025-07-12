#include "librats.h"
#include <iostream>
#include <algorithm>
#include <chrono>
#include <memory>

#define LOG_CLIENT_DEBUG(message) LOG_DEBUG("client", message)
#define LOG_CLIENT_INFO(message)  LOG_INFO("client", message)
#define LOG_CLIENT_WARN(message)  LOG_WARN("client", message)
#define LOG_CLIENT_ERROR(message) LOG_ERROR("client", message)

#define LOG_SERVER_DEBUG(message) LOG_DEBUG("server", message)
#define LOG_SERVER_INFO(message)  LOG_INFO("server", message)
#define LOG_SERVER_WARN(message)  LOG_WARN("server", message)
#define LOG_SERVER_ERROR(message) LOG_ERROR("server", message)

#define LOG_MAIN_DEBUG(message) LOG_DEBUG("main", message)
#define LOG_MAIN_INFO(message)  LOG_INFO("main", message)
#define LOG_MAIN_WARN(message)  LOG_WARN("main", message)
#define LOG_MAIN_ERROR(message) LOG_ERROR("main", message)

namespace librats {

RatsClient::RatsClient(int listen_port) 
    : listen_port_(listen_port), 
      server_socket_(INVALID_SOCKET_VALUE),
      running_(false) {
}

RatsClient::~RatsClient() {
    stop();
}

bool RatsClient::start() {
    if (running_.load()) {
        LOG_CLIENT_WARN("RatsClient is already running");
        return false;
    }

    LOG_CLIENT_INFO("Starting RatsClient on port " << listen_port_);
    init_networking();
    
    // Create server socket
    server_socket_ = create_tcp_server(listen_port_);
    if (!is_valid_socket(server_socket_)) {
        LOG_CLIENT_ERROR("Failed to create server socket on port " << listen_port_);
        return false;
    }
    
    running_.store(true);
    
    // Start server thread
    server_thread_ = std::thread(&RatsClient::server_loop, this);
    
    LOG_CLIENT_INFO("RatsClient started successfully on port " << listen_port_);
    return true;
}

void RatsClient::stop() {
    if (!running_.load()) {
        return;
    }
    
    LOG_CLIENT_INFO("Stopping RatsClient");
    running_.store(false);
    
    // Close server socket to break accept loop
    if (is_valid_socket(server_socket_)) {
        close_socket(server_socket_);
        server_socket_ = INVALID_SOCKET_VALUE;
    }
    
    // Close all peer connections
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        LOG_CLIENT_INFO("Closing " << peer_sockets_.size() << " peer connections");
        for (socket_t socket : peer_sockets_) {
            close_socket(socket);
        }
        peer_sockets_.clear();
    }
    
    // Wait for server thread to finish
    if (server_thread_.joinable()) {
        LOG_CLIENT_DEBUG("Waiting for server thread to finish");
        server_thread_.join();
    }
    
    // Wait for all client threads to finish
    LOG_CLIENT_DEBUG("Waiting for " << client_threads_.size() << " client threads to finish");
    for (auto& thread : client_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    client_threads_.clear();

    cleanup_networking();
    
    LOG_CLIENT_INFO("RatsClient stopped successfully");
}

bool RatsClient::connect_to_peer(const std::string& host, int port) {
    if (!running_.load()) {
        LOG_CLIENT_ERROR("RatsClient is not running");
        return false;
    }
    
    LOG_CLIENT_INFO("Connecting to peer " << host << ":" << port);
    socket_t peer_socket = create_tcp_client(host, port);
    if (!is_valid_socket(peer_socket)) {
        LOG_CLIENT_ERROR("Failed to connect to peer " << host << ":" << port);
        return false;
    }
    
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        peer_sockets_.push_back(peer_socket);
    }
    
    // Start a thread to handle this peer connection
    std::string peer_info = host + ":" + std::to_string(port);
    client_threads_.emplace_back(&RatsClient::handle_client, this, peer_socket, peer_info);
    
    LOG_CLIENT_INFO("Successfully connected to peer " << peer_info);
    
    // Notify connection callback
    if (connection_callback_) {
        connection_callback_(peer_socket, peer_info);
    }
    
    return true;
}

bool RatsClient::send_to_peer(socket_t socket, const std::string& data) {
    if (!running_.load()) {
        return false;
    }
    
    int sent = send_data(socket, data);
    return sent > 0;
}

int RatsClient::broadcast_to_peers(const std::string& data) {
    if (!running_.load()) {
        return 0;
    }
    
    int sent_count = 0;
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    for (socket_t socket : peer_sockets_) {
        if (send_to_peer(socket, data)) {
            sent_count++;
        }
    }
    
    return sent_count;
}

void RatsClient::disconnect_peer(socket_t socket) {
    remove_peer(socket);
    close_socket(socket);
}

int RatsClient::get_peer_count() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return static_cast<int>(peer_sockets_.size());
}

bool RatsClient::is_running() const {
    return running_.load();
}

void RatsClient::set_connection_callback(ConnectionCallback callback) {
    connection_callback_ = callback;
}

void RatsClient::set_data_callback(DataCallback callback) {
    data_callback_ = callback;
}

void RatsClient::set_disconnect_callback(DisconnectCallback callback) {
    disconnect_callback_ = callback;
}

void RatsClient::server_loop() {
    LOG_SERVER_INFO("Server loop started");
    
    while (running_.load()) {
        socket_t client_socket = accept_client(server_socket_);
        if (!is_valid_socket(client_socket)) {
            if (running_.load()) {
                LOG_SERVER_ERROR("Failed to accept client connection");
            }
            break;
        }
        
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            peer_sockets_.push_back(client_socket);
        }
        
        // Get client info (this is a simplified version)
        std::string client_info = "incoming_client_" + std::to_string(client_socket);
        
        // Start a thread to handle this client
        LOG_SERVER_DEBUG("Starting thread for client " << client_info);
        client_threads_.emplace_back(&RatsClient::handle_client, this, client_socket, client_info);
        
        // Notify connection callback
        if (connection_callback_) {
            connection_callback_(client_socket, client_info);
        }
    }
    
    LOG_SERVER_INFO("Server loop ended");
}

void RatsClient::handle_client(socket_t client_socket, const std::string& client_info) {
    LOG_CLIENT_INFO("Started handling client: " << client_info);
    
    while (running_.load()) {
        std::string data = receive_data(client_socket);
        if (data.empty()) {
            break; // Connection closed or error
        }
        
        LOG_CLIENT_DEBUG("Received data from " << client_info << ": " << data.substr(0, 50) << (data.length() > 50 ? "..." : ""));
        
        // Notify data callback
        if (data_callback_) {
            data_callback_(client_socket, data);
        }
    }
    
    // Clean up
    remove_peer(client_socket);
    close_socket(client_socket);
    
    // Notify disconnect callback
    if (disconnect_callback_) {
        disconnect_callback_(client_socket);
    }
    
    LOG_CLIENT_INFO("Client disconnected: " << client_info);
}

void RatsClient::remove_peer(socket_t socket) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = std::find(peer_sockets_.begin(), peer_sockets_.end(), socket);
    if (it != peer_sockets_.end()) {
        peer_sockets_.erase(it);
    }
}

// Helper functions
std::unique_ptr<RatsClient> create_rats_client(int listen_port) {
    auto client = std::make_unique<RatsClient>(listen_port);
    if (!client->start()) {
        return nullptr;
    }
    return client;
}

void run_rats_client_demo(int listen_port, const std::string& peer_host, int peer_port) {
    LOG_MAIN_INFO("Starting RatsClient demo on port " << listen_port);
    
    RatsClient client(listen_port);
    
    // Set up callbacks
    client.set_connection_callback([](socket_t socket, const std::string& info) {
        LOG_MAIN_INFO("New connection: " << info << " (socket: " << socket << ")");
    });
    
    client.set_data_callback([&client](socket_t socket, const std::string& data) {
        LOG_MAIN_INFO("Received from socket " << socket << ": " << data);
        
        // Echo back the data
        std::string response = "Echo: " + data;
        client.send_to_peer(socket, response);
    });
    
    client.set_disconnect_callback([](socket_t socket) {
        LOG_MAIN_INFO("Peer disconnected (socket: " << socket << ")");
    });
    
    // Start the client
    if (!client.start()) {
        LOG_MAIN_ERROR("Failed to start RatsClient");
        return;
    }
    
    // If peer information is provided, connect to peer
    if (!peer_host.empty() && peer_port > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (client.connect_to_peer(peer_host, peer_port)) {
            LOG_MAIN_INFO("Connected to peer " << peer_host << ":" << peer_port);
            
            // Send a test message
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            std::string test_msg = "Hello from RatsClient on port " + std::to_string(listen_port);
            int sent = client.broadcast_to_peers(test_msg);
            LOG_MAIN_INFO("Sent test message to " << sent << " peers");
        }
    }
    
    LOG_MAIN_INFO("RatsClient demo running. Press Enter to stop...");
    std::cin.ignore();
    std::cin.get();
    
    client.stop();
    LOG_MAIN_INFO("RatsClient demo finished");
}

} // namespace librats 