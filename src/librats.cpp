#include "librats.h"
#include <iostream>
#include <algorithm>
#include <chrono>
#include <memory>

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
        std::cerr << "RatsClient is already running" << std::endl;
        return false;
    }

    init_networking();
    
    // Create server socket
    server_socket_ = create_tcp_server(listen_port_);
    if (!is_valid_socket(server_socket_)) {
        std::cerr << "Failed to create server socket on port " << listen_port_ << std::endl;
        return false;
    }
    
    running_.store(true);
    
    // Start server thread
    server_thread_ = std::thread(&RatsClient::server_loop, this);
    
    std::cout << "RatsClient started on port " << listen_port_ << std::endl;
    return true;
}

void RatsClient::stop() {
    if (!running_.load()) {
        return;
    }
    
    running_.store(false);
    
    // Close server socket to break accept loop
    if (is_valid_socket(server_socket_)) {
        close_socket(server_socket_);
        server_socket_ = INVALID_SOCKET_VALUE;
    }
    
    // Close all peer connections
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (socket_t socket : peer_sockets_) {
            close_socket(socket);
        }
        peer_sockets_.clear();
    }
    
    // Wait for server thread to finish
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    
    // Wait for all client threads to finish
    for (auto& thread : client_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    client_threads_.clear();

    cleanup_networking();
    
    std::cout << "RatsClient stopped" << std::endl;
}

bool RatsClient::connect_to_peer(const std::string& host, int port) {
    if (!running_.load()) {
        std::cerr << "RatsClient is not running" << std::endl;
        return false;
    }
    
    socket_t peer_socket = create_tcp_client(host, port);
    if (!is_valid_socket(peer_socket)) {
        std::cerr << "Failed to connect to peer " << host << ":" << port << std::endl;
        return false;
    }
    
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        peer_sockets_.push_back(peer_socket);
    }
    
    // Start a thread to handle this peer connection
    std::string peer_info = host + ":" + std::to_string(port);
    client_threads_.emplace_back(&RatsClient::handle_client, this, peer_socket, peer_info);
    
    std::cout << "Connected to peer " << peer_info << std::endl;
    
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
    while (running_.load()) {
        socket_t client_socket = accept_client(server_socket_);
        if (!is_valid_socket(client_socket)) {
            if (running_.load()) {
                std::cerr << "Failed to accept client connection" << std::endl;
            }
            break;
        }
        
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            peer_sockets_.push_back(client_socket);
        }
        
        // Get client info (this is a simplified version)
        std::string client_info = "incoming_client";
        
        // Start a thread to handle this client
        client_threads_.emplace_back(&RatsClient::handle_client, this, client_socket, client_info);
        
        // Notify connection callback
        if (connection_callback_) {
            connection_callback_(client_socket, client_info);
        }
    }
}

void RatsClient::handle_client(socket_t client_socket, const std::string& client_info) {
    std::cout << "Handling client: " << client_info << std::endl;
    
    while (running_.load()) {
        std::string data = receive_data(client_socket);
        if (data.empty()) {
            break; // Connection closed or error
        }
        
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
    
    std::cout << "Client disconnected: " << client_info << std::endl;
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
    std::cout << "Starting RatsClient demo on port " << listen_port << std::endl;
    
    RatsClient client(listen_port);
    
    // Set up callbacks
    client.set_connection_callback([](socket_t socket, const std::string& info) {
        std::cout << "New connection: " << info << " (socket: " << socket << ")" << std::endl;
    });
    
    client.set_data_callback([&client](socket_t socket, const std::string& data) {
        std::cout << "Received from socket " << socket << ": " << data << std::endl;
        
        // Echo back the data
        std::string response = "Echo: " + data;
        client.send_to_peer(socket, response);
    });
    
    client.set_disconnect_callback([](socket_t socket) {
        std::cout << "Peer disconnected (socket: " << socket << ")" << std::endl;
    });
    
    // Start the client
    if (!client.start()) {
        std::cerr << "Failed to start RatsClient" << std::endl;
        return;
    }
    
    // If peer information is provided, connect to peer
    if (!peer_host.empty() && peer_port > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (client.connect_to_peer(peer_host, peer_port)) {
            std::cout << "Connected to peer " << peer_host << ":" << peer_port << std::endl;
            
            // Send a test message
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            std::string test_msg = "Hello from RatsClient on port " + std::to_string(listen_port);
            int sent = client.broadcast_to_peers(test_msg);
            std::cout << "Sent test message to " << sent << " peers" << std::endl;
        }
    }
    
    std::cout << "RatsClient demo running. Press Enter to stop..." << std::endl;
    std::cin.ignore();
    std::cin.get();
    
    client.stop();
    std::cout << "RatsClient demo finished" << std::endl;
}

} // namespace librats 