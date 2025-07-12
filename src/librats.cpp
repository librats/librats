#include "librats.h"
#include <iostream>
#include <algorithm>
#include <chrono>
#include <memory>
#include <random>
#include <sstream>
#include <iomanip>

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

std::string RatsClient::generate_peer_hash_id(socket_t socket, const std::string& connection_info) {
    // Generate unique hash ID using timestamp, socket, connection info, and random component
    auto now = std::chrono::high_resolution_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    
    // Create a random component
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    // Build hash string
    std::ostringstream hash_stream;
    hash_stream << std::hex << timestamp << "_" << socket << "_";
    
    // Add connection info hash
    std::hash<std::string> hasher;
    hash_stream << hasher(connection_info) << "_";
    
    // Add random component
    for (int i = 0; i < 8; ++i) {
        hash_stream << std::setfill('0') << std::setw(2) << dis(gen);
    }
    
    return hash_stream.str();
}

void RatsClient::add_peer_mapping(socket_t socket, const std::string& hash_id) {
    socket_to_hash_[socket] = hash_id;
    hash_to_socket_[hash_id] = socket;
}

void RatsClient::remove_peer_mapping(socket_t socket) {
    auto it = socket_to_hash_.find(socket);
    if (it != socket_to_hash_.end()) {
        hash_to_socket_.erase(it->second);
        socket_to_hash_.erase(it);
    }
}

std::string RatsClient::get_peer_hash_id(socket_t socket) const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = socket_to_hash_.find(socket);
    return (it != socket_to_hash_.end()) ? it->second : "";
}

socket_t RatsClient::get_peer_socket(const std::string& peer_hash_id) const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = hash_to_socket_.find(peer_hash_id);
    return (it != hash_to_socket_.end()) ? it->second : INVALID_SOCKET_VALUE;
}

bool RatsClient::start() {
    if (running_.load()) {
        LOG_CLIENT_WARN("RatsClient is already running");
        return false;
    }

    LOG_CLIENT_INFO("Starting RatsClient on port " << listen_port_);
    init_networking();
    
    // Create dual-stack server socket (supports both IPv4 and IPv6)
    server_socket_ = create_tcp_server_dual(listen_port_);
    if (!is_valid_socket(server_socket_)) {
        LOG_CLIENT_ERROR("Failed to create dual-stack server socket on port " << listen_port_);
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
    
    // Stop DHT discovery
    stop_dht_discovery();
    
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
        socket_to_hash_.clear();
        hash_to_socket_.clear();
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
    socket_t peer_socket = create_tcp_client_dual(host, port);
    if (!is_valid_socket(peer_socket)) {
        LOG_CLIENT_ERROR("Failed to connect to peer " << host << ":" << port);
        return false;
    }
    
    // Generate unique hash ID for this peer
    std::string connection_info = host + ":" + std::to_string(port);
    std::string peer_hash_id = generate_peer_hash_id(peer_socket, connection_info);
    
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        peer_sockets_.push_back(peer_socket);
        add_peer_mapping(peer_socket, peer_hash_id);
    }
    
    // Start a thread to handle this peer connection
    client_threads_.emplace_back(&RatsClient::handle_client, this, peer_socket, peer_hash_id);
    
    LOG_CLIENT_INFO("Successfully connected to peer " << connection_info << " (hash: " << peer_hash_id << ")");
    
    // Notify connection callback
    if (connection_callback_) {
        connection_callback_(peer_socket, peer_hash_id);
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

bool RatsClient::send_to_peer_by_hash(const std::string& peer_hash_id, const std::string& data) {
    socket_t socket = get_peer_socket(peer_hash_id);
    if (!is_valid_socket(socket)) {
        return false;
    }
    return send_to_peer(socket, data);
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

void RatsClient::disconnect_peer_by_hash(const std::string& peer_hash_id) {
    socket_t socket = get_peer_socket(peer_hash_id);
    if (is_valid_socket(socket)) {
        disconnect_peer(socket);
    }
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

bool RatsClient::start_dht_discovery(int dht_port) {
    if (dht_client_ && dht_client_->is_running()) {
        LOG_CLIENT_WARN("DHT discovery is already running");
        return true;
    }
    
    LOG_CLIENT_INFO("Starting DHT discovery on port " << dht_port);
    
    dht_client_ = std::make_unique<DhtClient>(dht_port);
    if (!dht_client_->start()) {
        LOG_CLIENT_ERROR("Failed to start DHT client");
        dht_client_.reset();
        return false;
    }
    
    // Bootstrap with default nodes
    auto bootstrap_nodes = DhtClient::get_default_bootstrap_nodes();
    if (!dht_client_->bootstrap(bootstrap_nodes)) {
        LOG_CLIENT_WARN("Failed to bootstrap DHT");
    }
    
    LOG_CLIENT_INFO("DHT discovery started successfully");
    return true;
}

void RatsClient::stop_dht_discovery() {
    if (!dht_client_) {
        return;
    }
    
    LOG_CLIENT_INFO("Stopping DHT discovery");
    dht_client_->stop();
    dht_client_.reset();
    LOG_CLIENT_INFO("DHT discovery stopped");
}

bool RatsClient::find_peers_by_hash(const std::string& content_hash, std::function<void(const std::vector<std::string>&)> callback) {
    if (!dht_client_ || !dht_client_->is_running()) {
        LOG_CLIENT_ERROR("DHT client not running");
        return false;
    }
    
    if (content_hash.length() != 40) {  // 160-bit hash as hex string
        LOG_CLIENT_ERROR("Invalid content hash length: " << content_hash.length() << " (expected 40)");
        return false;
    }
    
    LOG_CLIENT_INFO("Finding peers for content hash: " << content_hash);
    
    InfoHash info_hash = hex_to_node_id(content_hash);
    
    return dht_client_->find_peers(info_hash, [this, callback](const std::vector<UdpPeer>& peers, const InfoHash& info_hash) {
        handle_dht_peer_discovery(peers, info_hash);
        
        // Convert UdpPeer to string addresses for callback
        std::vector<std::string> peer_addresses;
        for (const auto& peer : peers) {
            peer_addresses.push_back(peer.ip + ":" + std::to_string(peer.port));
        }
        
        if (callback) {
            callback(peer_addresses);
        }
    });
}

bool RatsClient::announce_for_hash(const std::string& content_hash, uint16_t port) {
    if (!dht_client_ || !dht_client_->is_running()) {
        LOG_CLIENT_ERROR("DHT client not running");
        return false;
    }
    
    if (content_hash.length() != 40) {  // 160-bit hash as hex string
        LOG_CLIENT_ERROR("Invalid content hash length: " << content_hash.length() << " (expected 40)");
        return false;
    }
    
    if (port == 0) {
        port = listen_port_;
    }
    
    LOG_CLIENT_INFO("Announcing for content hash: " << content_hash << " on port " << port);
    
    InfoHash info_hash = hex_to_node_id(content_hash);
    return dht_client_->announce_peer(info_hash, port);
}

bool RatsClient::is_dht_running() const {
    return dht_client_ && dht_client_->is_running();
}

size_t RatsClient::get_dht_routing_table_size() const {
    if (!dht_client_) {
        return 0;
    }
    return dht_client_->get_routing_table_size();
}

void RatsClient::handle_dht_peer_discovery(const std::vector<UdpPeer>& peers, const InfoHash& info_hash) {
    LOG_CLIENT_INFO("DHT discovered " << peers.size() << " peers for info hash: " << node_id_to_hex(info_hash));
    
    // Auto-connect to discovered peers (optional behavior)
    for (const auto& peer : peers) {
        if (peer.port != listen_port_ || peer.ip != "127.0.0.1") {  // Don't connect to ourselves
            LOG_CLIENT_DEBUG("Attempting to connect to discovered peer: " << peer.ip << ":" << peer.port);
            
            // Try to connect to the peer
            connect_to_peer(peer.ip, peer.port);
        }
    }
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
        
        // Generate unique hash ID for this incoming client
        std::string connection_info = "incoming_connection";
        std::string peer_hash_id = generate_peer_hash_id(client_socket, connection_info);
        
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            peer_sockets_.push_back(client_socket);
            add_peer_mapping(client_socket, peer_hash_id);
        }
        
        // Start a thread to handle this client
        LOG_SERVER_DEBUG("Starting thread for client " << peer_hash_id);
        client_threads_.emplace_back(&RatsClient::handle_client, this, client_socket, peer_hash_id);
        
        // Notify connection callback
        if (connection_callback_) {
            connection_callback_(client_socket, peer_hash_id);
        }
    }
    
    LOG_SERVER_INFO("Server loop ended");
}

void RatsClient::handle_client(socket_t client_socket, const std::string& peer_hash_id) {
    LOG_CLIENT_INFO("Started handling client: " << peer_hash_id);
    
    while (running_.load()) {
        std::string data = receive_data(client_socket);
        if (data.empty()) {
            break; // Connection closed or error
        }
        
        LOG_CLIENT_DEBUG("Received data from " << peer_hash_id << ": " << data.substr(0, 50) << (data.length() > 50 ? "..." : ""));
        
        // Notify data callback
        if (data_callback_) {
            data_callback_(client_socket, peer_hash_id, data);
        }
    }
    
    // Clean up
    remove_peer(client_socket);
    close_socket(client_socket);
    
    // Notify disconnect callback
    if (disconnect_callback_) {
        disconnect_callback_(client_socket, peer_hash_id);
    }
    
    LOG_CLIENT_INFO("Client disconnected: " << peer_hash_id);
}

void RatsClient::remove_peer(socket_t socket) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = std::find(peer_sockets_.begin(), peer_sockets_.end(), socket);
    if (it != peer_sockets_.end()) {
        peer_sockets_.erase(it);
    }
    remove_peer_mapping(socket);
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
    client.set_connection_callback([](socket_t socket, const std::string& peer_hash_id) {
        LOG_MAIN_INFO("New connection: " << peer_hash_id << " (socket: " << socket << ")");
    });
    
    client.set_data_callback([&client](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
        LOG_MAIN_INFO("Received from peer " << peer_hash_id << ": " << data);
        
        // Echo back the data
        std::string response = "Echo: " + data;
        client.send_to_peer(socket, response);
    });
    
    client.set_disconnect_callback([](socket_t socket, const std::string& peer_hash_id) {
        LOG_MAIN_INFO("Peer disconnected: " << peer_hash_id << " (socket: " << socket << ")");
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