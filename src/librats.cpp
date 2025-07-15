#include "librats.h"
#include "sha1.h"
#include "os.h"
#include "network_utils.h"
#include "json.hpp" // nlohmann::json
#include <iostream>
#include <algorithm>
#include <chrono>
#include <memory>
#include <random>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <stdexcept>

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

RatsClient::RatsClient(int listen_port, int max_peers) 
    : listen_port_(listen_port), 
      max_peers_(max_peers),
      server_socket_(INVALID_SOCKET_VALUE),
      running_(false) {
    // Initialize STUN client
    stun_client_ = std::make_unique<StunClient>();
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

std::string RatsClient::normalize_peer_address(const std::string& ip, int port) const {
    // Normalize IPv6 addresses and create consistent format
    std::string normalized_ip = ip;
    
    // Remove brackets from IPv6 addresses if present
    if (!normalized_ip.empty() && normalized_ip.front() == '[' && normalized_ip.back() == ']') {
        normalized_ip = normalized_ip.substr(1, normalized_ip.length() - 2);
    }
    
    // Handle localhost variations
    if (normalized_ip == "localhost" || normalized_ip == "::1") {
        normalized_ip = "127.0.0.1";
    }
    
    // For IPv6 addresses, add brackets for consistency
    if (normalized_ip.find(':') != std::string::npos && normalized_ip.find('.') == std::string::npos) {
        // This is likely an IPv6 address (contains colons but no dots)
        return "[" + normalized_ip + "]:" + std::to_string(port);
    }
    
    return normalized_ip + ":" + std::to_string(port);
}

// New RatsPeer-based peer management methods
void RatsClient::add_peer(const RatsPeer& peer) {
    peers_[peer.peer_id] = peer;
    socket_to_peer_id_[peer.socket] = peer.peer_id;
    address_to_peer_id_[peer.normalized_address] = peer.peer_id;
}

void RatsClient::remove_peer_by_id(const std::string& peer_id) {
    auto it = peers_.find(peer_id);
    if (it != peers_.end()) {
        const RatsPeer& peer = it->second;
        socket_to_peer_id_.erase(peer.socket);
        address_to_peer_id_.erase(peer.normalized_address);
        peers_.erase(it);
    }
}

bool RatsClient::is_already_connected_to_address(const std::string& normalized_address) const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return address_to_peer_id_.find(normalized_address) != address_to_peer_id_.end();
}

std::vector<RatsPeer> RatsClient::get_all_peers() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    std::vector<RatsPeer> result;
    result.reserve(peers_.size());
    
    for (const auto& pair : peers_) {
        result.push_back(pair.second);
    }
    
    return result;
}

std::vector<RatsPeer> RatsClient::get_validated_peers() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    std::vector<RatsPeer> result;
    
    for (const auto& pair : peers_) {
        if (pair.second.is_handshake_completed()) {
            result.push_back(pair.second);
        }
    }
    
    return result;
}

const RatsPeer* RatsClient::get_peer_by_id(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = peers_.find(peer_id);
    return (it != peers_.end()) ? &it->second : nullptr;
}

const RatsPeer* RatsClient::get_peer_by_socket(socket_t socket) const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = socket_to_peer_id_.find(socket);
    if (it != socket_to_peer_id_.end()) {
        auto peer_it = peers_.find(it->second);
        return (peer_it != peers_.end()) ? &peer_it->second : nullptr;
    }
    return nullptr;
}

std::string RatsClient::get_peer_hash_id(socket_t socket) const {
    const RatsPeer* peer = get_peer_by_socket(socket);
    return peer ? peer->peer_id : "";
}

socket_t RatsClient::get_peer_socket(const std::string& peer_hash_id) const {
    const RatsPeer* peer = get_peer_by_id(peer_hash_id);
    return peer ? peer->socket : INVALID_SOCKET_VALUE;
}

bool RatsClient::start() {
    if (running_.load()) {
        LOG_CLIENT_WARN("RatsClient is already running");
        return false;
    }

    LOG_CLIENT_INFO("Starting RatsClient on port " << listen_port_);
    
    // Print system information for debugging and log analysis
    SystemInfo sys_info = get_system_info();
    LOG_CLIENT_INFO("=== System Information ===");
    LOG_CLIENT_INFO("OS: " << sys_info.os_name << " " << sys_info.os_version);
    LOG_CLIENT_INFO("Architecture: " << sys_info.architecture);
    LOG_CLIENT_INFO("Hostname: " << sys_info.hostname);
    LOG_CLIENT_INFO("CPU: " << sys_info.cpu_model);
    LOG_CLIENT_INFO("CPU Cores: " << sys_info.cpu_cores << " physical, " << sys_info.cpu_logical_cores << " logical");
    LOG_CLIENT_INFO("Memory: " << sys_info.total_memory_mb << " MB total, " << sys_info.available_memory_mb << " MB available");
    LOG_CLIENT_INFO("===========================");
    
    // Initialize socket library first (required for all socket operations)
    init_socket_library();
    
    // Initialize local interface addresses for connection blocking
    initialize_local_addresses();
    
    // Discover public IP address via STUN and add to ignore list
    if (!discover_and_ignore_public_ip()) {
        LOG_CLIENT_WARN("Failed to discover public IP via STUN - continuing without it");
    }
    
    // Create dual-stack server socket (supports both IPv4 and IPv6)
            server_socket_ = create_tcp_server(listen_port_);
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
    
    // Stop DHT discovery (this will also stop automatic discovery)
    stop_dht_discovery();
    
    // Close server socket to break accept loop
    if (is_valid_socket(server_socket_)) {
        close_socket(server_socket_);
        server_socket_ = INVALID_SOCKET_VALUE;
    }
    
    // Close all peer connections
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        LOG_CLIENT_INFO("Closing " << peers_.size() << " peer connections");
        for (const auto& pair : peers_) {
            const RatsPeer& peer = pair.second;
            close_socket(peer.socket);
        }
        peers_.clear();
        socket_to_peer_id_.clear();
        address_to_peer_id_.clear();
    }
    
    // Wait for server thread to finish
    if (server_thread_.joinable()) {
        LOG_CLIENT_DEBUG("Waiting for server thread to finish");
        server_thread_.join();
    }
    
    cleanup_socket_library();
    
    LOG_CLIENT_INFO("RatsClient stopped successfully");
}

bool RatsClient::connect_to_peer(const std::string& host, int port) {
    if (!running_.load()) {
        LOG_CLIENT_ERROR("RatsClient is not running");
        return false;
    }
    
    // Check if peer limit is reached
    if (is_peer_limit_reached()) {
        LOG_CLIENT_WARN("Peer limit reached (" << max_peers_ << "), not connecting to " << host << ":" << port);
        return false;
    }
    
    // Check if this peer should be ignored (local interface)
    if (should_ignore_peer(host, port)) {
        LOG_CLIENT_INFO("Ignoring connection to " << host << ":" << port << " - local interface address");
        return false;
    }
    
    // Check if we're already connected to this peer
    std::string peer_address = normalize_peer_address(host, port);
    if (is_already_connected_to_address(peer_address)) {
        LOG_CLIENT_INFO("Already connected to peer " << peer_address << ", skipping connection");
        return true; // Return true since we already have the connection
    }
    
    LOG_CLIENT_INFO("Connecting to peer " << host << ":" << port);
            socket_t peer_socket = create_tcp_client(host, port);
    if (!is_valid_socket(peer_socket)) {
        LOG_CLIENT_ERROR("Failed to connect to peer " << host << ":" << port);
        return false;
    }
    
    // Generate unique hash ID for this peer
    std::string connection_info = host + ":" + std::to_string(port);
    std::string peer_hash_id = generate_peer_hash_id(peer_socket, connection_info); // Temporary hash ID (real hash ID will be set after handshake)
    
    // Create RatsPeer object and add to peer management
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        RatsPeer new_peer(peer_hash_id, host, port, peer_socket, peer_address, true); // true = outgoing connection
        add_peer(new_peer);
    }
    
    // Start a thread to handle this peer connection
    std::thread(&RatsClient::handle_client, this, peer_socket, peer_hash_id).detach();
    
    LOG_CLIENT_INFO("Successfully connected to peer " << connection_info << " (hash: " << peer_hash_id << ")");
    
    // Initiate handshake for outgoing connections
    if (!send_handshake(peer_socket, peer_hash_id)) {
        LOG_CLIENT_ERROR("Failed to initiate handshake with peer " << peer_hash_id);
        disconnect_peer(peer_socket);
        return false;
    }
    
    // Note: Connection callback will be called after handshake completion
    return true;
}

bool RatsClient::send_to_peer(socket_t socket, const std::string& data) {
    if (!running_.load()) {
        return false;
    }
    
    int sent = send_tcp_data(socket, data);
    return sent > 0;
}

bool RatsClient::send_json_to_peer(socket_t socket, const nlohmann::json& json_data) {
    if (!running_.load()) {
        return false;
    }
    
    try {
        std::string data = json_data.dump();
        return send_to_peer(socket, data);
    } catch (const nlohmann::json::exception& e) {
        LOG_CLIENT_ERROR("Failed to serialize JSON message: " << e.what());
        return false;
    }
}

bool RatsClient::send_json_to_peer_by_hash(const std::string& peer_hash_id, const nlohmann::json& json_data) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = peers_.find(peer_hash_id);
    if (it == peers_.end() || !it->second.is_handshake_completed()) {
        return false;
    }
    
    return send_json_to_peer(it->second.socket, json_data);
}

int RatsClient::broadcast_json_to_peers(const nlohmann::json& json_data) {
    if (!running_.load()) {
        return 0;
    }
    
    int sent_count = 0;
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    for (const auto& pair : peers_) {
        const RatsPeer& peer = pair.second;
        // Only send to peers that have completed handshake
        if (peer.is_handshake_completed()) {
            if (send_json_to_peer(peer.socket, json_data)) {
                sent_count++;
            }
        }
    }
    
    return sent_count;
}

bool RatsClient::parse_json_message(const std::string& message, nlohmann::json& out_json) {
    try {
        out_json = nlohmann::json::parse(message);
        return true;
    } catch (const nlohmann::json::exception& e) {
        LOG_CLIENT_ERROR("Failed to parse JSON message: " << e.what());
        return false;
    }
}

bool RatsClient::send_to_peer_by_hash(const std::string& peer_hash_id, const std::string& data) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = peers_.find(peer_hash_id);
    if (it == peers_.end() || !it->second.is_handshake_completed()) {
        return false;
    }
    
    return send_to_peer(it->second.socket, data);
}

int RatsClient::broadcast_to_peers(const std::string& data) {
    if (!running_.load()) {
        return 0;
    }
    
    int sent_count = 0;
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    for (const auto& pair : peers_) {
        const RatsPeer& peer = pair.second;
        // Only send to peers that have completed handshake
        if (peer.is_handshake_completed()) {
            if (send_to_peer(peer.socket, data)) {
                sent_count++;
            }
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
    int count = 0;
    for (const auto& pair : peers_) {
        if (pair.second.is_handshake_completed()) {
            count++;
        }
    }
    return count;
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
    
    // Start automatic peer discovery
    start_automatic_peer_discovery();
    
    LOG_CLIENT_INFO("DHT discovery started successfully");
    return true;
}

void RatsClient::stop_dht_discovery() {
    if (!dht_client_) {
        return;
    }
    
    LOG_CLIENT_INFO("Stopping DHT discovery");
    
    // Stop automatic peer discovery
    stop_automatic_peer_discovery();
    
    dht_client_->stop();
    dht_client_.reset();
    LOG_CLIENT_INFO("DHT discovery stopped");
}

bool RatsClient::find_peers_by_hash(const std::string& content_hash, std::function<void(const std::vector<std::string>&)> callback, int iteration_max) {
    if (!dht_client_ || !dht_client_->is_running()) {
        LOG_CLIENT_ERROR("DHT client not running");
        return false;
    }
    
    if (content_hash.length() != 40) {  // 160-bit hash as hex string
        LOG_CLIENT_ERROR("Invalid content hash length: " << content_hash.length() << " (expected 40)");
        return false;
    }
    
    LOG_CLIENT_INFO("Finding peers for content hash: " << content_hash << " with iteration max: " << iteration_max);
    
    InfoHash info_hash = hex_to_node_id(content_hash);
    
    return dht_client_->find_peers(info_hash, [this, callback](const std::vector<Peer>& peers, const InfoHash& info_hash) {
        handle_dht_peer_discovery(peers, info_hash);
        
        // Convert Peer to string addresses for callback
        std::vector<std::string> peer_addresses;
        for (const auto& peer : peers) {
            peer_addresses.push_back(peer.ip + ":" + std::to_string(peer.port));
        }
        
        if (callback) {
            callback(peer_addresses);
        }
    }, iteration_max);
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

bool RatsClient::discover_and_ignore_public_ip(const std::string& stun_server, int stun_port) {
    if (!stun_client_) {
        LOG_CLIENT_ERROR("STUN client not initialized");
        return false;
    }
    
    LOG_CLIENT_INFO("Discovering public IP address using STUN server: " << stun_server << ":" << stun_port);
    
    StunAddress public_address;
    if (!stun_client_->get_public_address(stun_server, stun_port, public_address)) {
        LOG_CLIENT_ERROR("Failed to discover public IP address via STUN");
        return false;
    }
    
    // Store the discovered public IP
    {
        std::lock_guard<std::mutex> lock(public_ip_mutex_);
        public_ip_ = public_address.ip;
    }
    
    LOG_CLIENT_INFO("Discovered public IP address: " << public_address.ip << " (port: " << public_address.port << ")");
    
    // Add to ignore list
    add_ignored_address(public_address.ip);
    
    LOG_CLIENT_INFO("Added public IP " << public_address.ip << " to ignore list");
    return true;
}

std::string RatsClient::get_public_ip() const {
    std::lock_guard<std::mutex> lock(public_ip_mutex_);
    return public_ip_;
}

void RatsClient::add_ignored_address(const std::string& ip_address) {
    std::lock_guard<std::mutex> lock(local_addresses_mutex_);
    
    // Check if already in the list
    if (std::find(local_interface_addresses_.begin(), local_interface_addresses_.end(), ip_address) == local_interface_addresses_.end()) {
        local_interface_addresses_.push_back(ip_address);
        LOG_CLIENT_INFO("Added " << ip_address << " to ignore list");
    } else {
        LOG_CLIENT_DEBUG("IP address " << ip_address << " already in ignore list");
    }
}

void RatsClient::handle_dht_peer_discovery(const std::vector<Peer>& peers, const InfoHash& info_hash) {
    LOG_CLIENT_INFO("DHT discovered " << peers.size() << " peers for info hash: " << node_id_to_hex(info_hash));
    
    // Auto-connect to discovered peers (optional behavior)
    for (const auto& peer : peers) {
        // Check if this peer should be ignored (local interface)
        if (should_ignore_peer(peer.ip, peer.port)) {
            LOG_CLIENT_DEBUG("Ignoring discovered peer " << peer.ip << ":" << peer.port << " - local interface address");
            continue;
        }
        
        // Check if we're already connected to this peer
        std::string normalized_peer_address = normalize_peer_address(peer.ip, peer.port);
        bool already_connected = is_already_connected_to_address(normalized_peer_address);
        
        if (!already_connected) {
            LOG_CLIENT_DEBUG("Attempting to connect to discovered peer: " << peer.ip << ":" << peer.port);
            
            // Try to connect to the peer
            connect_to_peer(peer.ip, peer.port);
        } else {
            LOG_CLIENT_DEBUG("Already connected to discovered peer: " << normalized_peer_address);
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
        
        // Get peer address information
        std::string peer_address = get_peer_address(client_socket);
        if (peer_address.empty()) {
            LOG_SERVER_ERROR("Failed to get peer address for incoming connection");
            close_socket(client_socket);
            continue;
        }
        
        // Parse IP and port from peer_address
        std::string ip;
        int port = 0;
        if (!parse_address_string(peer_address, ip, port)) {
            LOG_SERVER_ERROR("Failed to parse peer address from incoming connection: " << peer_address);
            close_socket(client_socket);
            continue;
        }
        
        std::string normalized_peer_address = normalize_peer_address(ip, port);
        
        // Check if peer limit is reached
        if (is_peer_limit_reached()) {
            LOG_SERVER_INFO("Peer limit reached (" << max_peers_ << "), rejecting connection from " << normalized_peer_address);
            close_socket(client_socket);
            continue;
        }
        
        // Check if we're already connected to this peer
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            if (is_already_connected_to_address(normalized_peer_address)) {
                LOG_SERVER_INFO("Already connected to peer " << normalized_peer_address << ", rejecting duplicate connection");
                close_socket(client_socket);
                continue;
            }
        }
        
        // Generate unique hash ID for this incoming client
        std::string connection_info = "incoming_from_" + peer_address;
        std::string peer_hash_id = generate_peer_hash_id(client_socket, connection_info); // Temporary hash ID (real hash ID will be set after handshake)
        
        // Create RatsPeer object for incoming connection
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            RatsPeer new_peer(peer_hash_id, ip, port, client_socket, normalized_peer_address, false); // false = incoming connection
            add_peer(new_peer);
        }
        
        // Start a thread to handle this client
        LOG_SERVER_DEBUG("Starting thread for client " << peer_hash_id << " from " << peer_address);
        std::thread(&RatsClient::handle_client, this, client_socket, peer_hash_id).detach();
        
        // Note: Connection callback will be called after handshake completion in handle_client
    }
    
    LOG_SERVER_INFO("Server loop ended");
}

void RatsClient::handle_client(socket_t client_socket, const std::string& peer_hash_id) {
    LOG_CLIENT_INFO("Started handling client: " << peer_hash_id);
    
    bool handshake_completed = false;
    auto last_timeout_check = std::chrono::steady_clock::now();
    
    while (running_.load()) {
        std::string data = receive_tcp_data(client_socket);
        if (data.empty()) {
            // Check if this is a timeout or actual connection close
            if (!handshake_completed) {
                // Check for handshake timeout one more time before giving up
                auto now = std::chrono::steady_clock::now();
                if (now - last_timeout_check >= std::chrono::seconds(1)) {
                    check_handshake_timeouts();
                    last_timeout_check = now;
                    
                    // Check if handshake has failed due to timeout
                    std::lock_guard<std::mutex> lock(peers_mutex_);
                    auto it = socket_to_peer_id_.find(client_socket);
                    if (it != socket_to_peer_id_.end()) {
                        auto peer_it = peers_.find(it->second);
                        if (peer_it != peers_.end() && peer_it->second.is_handshake_failed()) {
                            LOG_CLIENT_ERROR("Handshake failed for peer " << peer_hash_id);
                            break;
                        }
                    }
                }
            }
            break; // Connection closed or error
        }
        
        LOG_CLIENT_DEBUG("Received data from " << peer_hash_id << ": " << data.substr(0, 50) << (data.length() > 50 ? "..." : ""));
        
        // Check if handshake is completed
        if (!handshake_completed) {
            // Check current handshake state and copy necessary data
            RatsPeer peer_copy;
            bool should_notify_connection = false;
            bool should_broadcast_exchange = false;
            bool should_exit = false;
            
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                auto it = socket_to_peer_id_.find(client_socket);
                if (it != socket_to_peer_id_.end()) {
                    auto peer_it = peers_.find(it->second);
                    if (peer_it != peers_.end()) {
                        const RatsPeer& peer = peer_it->second;
                        if (peer.is_handshake_completed()) {
                            handshake_completed = true;
                            should_notify_connection = true;
                            should_broadcast_exchange = true;
                            peer_copy = peer; // Copy peer data
                            
                            LOG_CLIENT_INFO("Handshake completed for peer " << peer_hash_id << " (peer_id: " << peer.peer_id << ")");
                        } else if (peer.is_handshake_failed()) {
                            LOG_CLIENT_ERROR("Handshake failed for peer " << peer_hash_id);
                            should_exit = true;
                        }
                    }
                }
            }
            
            // Call callbacks and methods outside of mutex to avoid deadlock
            if (should_notify_connection) {
                if (connection_callback_) {
                    connection_callback_(client_socket, peer_hash_id);
                }
                
                // Broadcast peer exchange message to other peers
                broadcast_peer_exchange_message(peer_copy);
            }
            
            if (should_exit) {
                break; // Exit loop to disconnect
            }
            
            // Check for handshake timeout
            auto now = std::chrono::steady_clock::now();
            if (now - last_timeout_check >= std::chrono::seconds(1)) {
                check_handshake_timeouts();
                last_timeout_check = now;
            }
        }
        
        // Handle handshake messages
        if (is_handshake_message(data)) {
            if (!handle_handshake_message(client_socket, peer_hash_id, data)) {
                LOG_CLIENT_ERROR("Failed to handle handshake message from " << peer_hash_id);
                break; // Exit loop to disconnect
            }
            continue; // Don't process handshake messages as regular data
        }
        
        // Only process regular data after handshake is completed
        if (handshake_completed) {
            // Try to parse as JSON rats message first
            nlohmann::json json_msg;
            if (parse_json_message(data, json_msg)) {
                // Check if it's a rats protocol message
                if (json_msg.contains("rats_protocol") && json_msg["rats_protocol"] == true) {
                    handle_rats_message(client_socket, peer_hash_id, json_msg);
                } else {
                    // Regular JSON data - call data callback
                    if (data_callback_) {
                        data_callback_(client_socket, peer_hash_id, data);
                    }
                }
            } else {
                // Regular text data - call data callback
                if (data_callback_) {
                    data_callback_(client_socket, peer_hash_id, data);
                }
            }
        } else {
            LOG_CLIENT_WARN("Received non-handshake data from " << peer_hash_id << " before handshake completion - ignoring");
        }
    }
    
    // Clean up
    remove_peer(client_socket);
    close_socket(client_socket);
    
    // Notify disconnect callback only if handshake was completed
    if (handshake_completed && disconnect_callback_) {
        disconnect_callback_(client_socket, peer_hash_id);
    }
    
    LOG_CLIENT_INFO("Client disconnected: " << peer_hash_id);
}

void RatsClient::remove_peer(socket_t socket) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = socket_to_peer_id_.find(socket);
    if (it != socket_to_peer_id_.end()) {
        remove_peer_by_id(it->second);
    }
}

// Local interface address blocking methods
void RatsClient::initialize_local_addresses() {
    LOG_CLIENT_INFO("Initializing local interface addresses for connection blocking");
    
    std::lock_guard<std::mutex> lock(local_addresses_mutex_);
    
    // Get all local interface addresses using network_utils
    local_interface_addresses_ = network_utils::get_local_interface_addresses();
    
    // Add common localhost addresses if not already present
    std::vector<std::string> localhost_addrs = {"127.0.0.1", "::1", "0.0.0.0", "::"};
    for (const auto& addr : localhost_addrs) {
        if (std::find(local_interface_addresses_.begin(), local_interface_addresses_.end(), addr) == local_interface_addresses_.end()) {
            local_interface_addresses_.push_back(addr);
        }
    }
    
    LOG_CLIENT_INFO("Found " << local_interface_addresses_.size() << " local addresses to block:");
    for (const auto& addr : local_interface_addresses_) {
        LOG_CLIENT_INFO("  - " << addr);
    }
}

void RatsClient::refresh_local_addresses() {
    LOG_CLIENT_DEBUG("Refreshing local interface addresses");
    
    std::lock_guard<std::mutex> lock(local_addresses_mutex_);
    
    // Clear old addresses and get fresh ones
    local_interface_addresses_.clear();
    local_interface_addresses_ = network_utils::get_local_interface_addresses();
    
    // Add common localhost addresses if not already present
    std::vector<std::string> localhost_addrs = {"127.0.0.1", "::1", "0.0.0.0", "::"};
    for (const auto& addr : localhost_addrs) {
        if (std::find(local_interface_addresses_.begin(), local_interface_addresses_.end(), addr) == local_interface_addresses_.end()) {
            local_interface_addresses_.push_back(addr);
        }
    }
    
    LOG_CLIENT_DEBUG("Refreshed " << local_interface_addresses_.size() << " local addresses");
}

bool RatsClient::is_blocked_address(const std::string& ip_address) const {
    std::lock_guard<std::mutex> lock(local_addresses_mutex_);
    
    // Check against our stored local addresses
    for (const auto& local_addr : local_interface_addresses_) {
        if (local_addr == ip_address) {
            return true;
        }
    }
    
    return false;
}

bool RatsClient::should_ignore_peer(const std::string& ip, int port) const {
    // Check if the IP is a local interface address
    if (is_blocked_address(ip)) {
        LOG_CLIENT_DEBUG("Ignoring peer " << ip << ":" << port << " - matches local interface address");
        return true;
    }
    
    // Check if it's the same port and a localhost-like address
    if (port == listen_port_) {
        if (ip == "127.0.0.1" || ip == "::1" || ip == "localhost" || ip == "0.0.0.0" || ip == "::") {
            LOG_CLIENT_DEBUG("Ignoring peer " << ip << ":" << port << " - localhost with same port");
            return true;
        }
    }
    
    return false;
}

// Helper functions
std::unique_ptr<RatsClient> create_rats_client(int listen_port) {
    auto client = std::make_unique<RatsClient>(listen_port, 10); // Default 10 max peers
    if (!client->start()) {
        return nullptr;
    }
    return client;
}

void run_rats_client_demo(int listen_port, const std::string& peer_host, int peer_port) {
    LOG_MAIN_INFO("Starting RatsClient demo on port " << listen_port);
    
    RatsClient client(listen_port, 10); // Default 10 max peers
    
    // Set up callbacks
    client.set_connection_callback([&client](socket_t socket, const std::string& peer_hash_id) {
        LOG_MAIN_INFO("New validated connection (handshake completed): " << peer_hash_id << " (socket: " << socket << ")");
        LOG_MAIN_INFO("Total connected peers: " << client.get_peer_count() << "/" << client.get_max_peers());
    });
    
    client.set_data_callback([&client](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
        LOG_MAIN_INFO("Received from peer " << peer_hash_id << ": " << data);
        
        // Try to parse as JSON first
        nlohmann::json json_data;
        if (client.parse_json_message(data, json_data)) {
            // Check if it's a rats protocol message (these are handled internally)
            if (json_data.contains("rats_protocol") && json_data["rats_protocol"] == true) {
                LOG_MAIN_INFO("Received rats protocol message of type: " << json_data.value("type", "unknown"));
                return; // Don't echo protocol messages
            }
            
            LOG_MAIN_INFO("Parsed JSON message with type: " << json_data.value("type", "unknown"));
            
            // Create a JSON response
            nlohmann::json response;
            response["type"] = "echo_response";
            response["original_message"] = json_data;
            response["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch()).count();
            
            client.send_json_to_peer(socket, response);
        } else {
            // Handle as plain text
            std::string response = "Echo: " + data;
            client.send_to_peer(socket, response);
        }
    });
    
    client.set_disconnect_callback([&client](socket_t socket, const std::string& peer_hash_id) {
        LOG_MAIN_INFO("Peer disconnected: " << peer_hash_id << " (socket: " << socket << ")");
        LOG_MAIN_INFO("Total connected peers: " << client.get_peer_count() << "/" << client.get_max_peers());
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
            
            // Send a JSON test message
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            nlohmann::json test_msg;
            test_msg["type"] = "greeting";
            test_msg["message"] = "Hello from RatsClient on port " + std::to_string(listen_port);
            test_msg["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch()).count();
            test_msg["sender_port"] = listen_port;
            
            int sent = client.broadcast_json_to_peers(test_msg);
            LOG_MAIN_INFO("Sent JSON test message to " << sent << " peers");
            LOG_MAIN_INFO("Peer exchange messages will be sent automatically when new peers connect");
        }
    }
    
    LOG_MAIN_INFO("RatsClient demo running. Press Enter to stop...");
    std::cin.ignore();
    std::cin.get();
    
    client.stop();
    LOG_MAIN_INFO("RatsClient demo finished");
}

void RatsClient::start_automatic_peer_discovery() {
    if (auto_discovery_running_.load()) {
        LOG_CLIENT_WARN("Automatic peer discovery is already running");
        return;
    }
    
    LOG_CLIENT_INFO("Starting automatic rats peer discovery");
    auto_discovery_running_.store(true);
    auto_discovery_thread_ = std::thread(&RatsClient::automatic_discovery_loop, this);
}

void RatsClient::stop_automatic_peer_discovery() {
    if (!auto_discovery_running_.load()) {
        return;
    }
    
    LOG_CLIENT_INFO("Stopping automatic peer discovery");
    auto_discovery_running_.store(false);
    
    if (auto_discovery_thread_.joinable()) {
        auto_discovery_thread_.join();
    }
    
    LOG_CLIENT_INFO("Automatic peer discovery stopped");
}

bool RatsClient::is_automatic_discovery_running() const {
    return auto_discovery_running_.load();
}

std::string RatsClient::get_rats_peer_discovery_hash() {
    // Well-known hash for rats peer discovery
    // Compute SHA1 hash of "rats_peer_discovery_v1"
    return SHA1::hash("rats_peer_discovery_v1");
}

void RatsClient::automatic_discovery_loop() {
    LOG_CLIENT_INFO("Automatic peer discovery loop started");
    
    // Initial delay to let DHT bootstrap
    std::this_thread::sleep_for(std::chrono::seconds(5));

    // Search immediately
    search_rats_peers(5);
    
    std::this_thread::sleep_for(std::chrono::seconds(10));
    
    // Announce immediately
    announce_rats_peer();

    auto last_announce = std::chrono::steady_clock::now();
    auto last_search = std::chrono::steady_clock::now();
    
    while (auto_discovery_running_.load()) {
        auto now = std::chrono::steady_clock::now();
        
        if (get_peer_count() == 0) {
            // No peers: aggressive search and announce
            if (now - last_search >= std::chrono::seconds(2)) {
                search_rats_peers();
                last_search = now;
            }
            if (now - last_announce >= std::chrono::seconds(10)) {
                announce_rats_peer();
                last_announce = now;
            }
        } else {
            // Peers connected: less aggressive, similar to original logic
            if (now - last_search >= std::chrono::minutes(5)) {
                search_rats_peers();
                last_search = now;
            }
            if (now - last_announce >= std::chrono::minutes(10)) {
                announce_rats_peer();
                last_announce = now;
            }
        }
        
        // Sleep for a short duration to avoid busy-waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    LOG_CLIENT_INFO("Automatic peer discovery loop stopped");
}

void RatsClient::announce_rats_peer() {
    if (!dht_client_ || !dht_client_->is_running()) {
        LOG_CLIENT_WARN("DHT client not running, cannot announce rats peer");
        return;
    }
    
    std::string discovery_hash = get_rats_peer_discovery_hash();
    LOG_CLIENT_INFO("Announcing rats peer for discovery hash: " << discovery_hash << " on port " << listen_port_);
    
    if (announce_for_hash(discovery_hash, listen_port_)) {
        LOG_CLIENT_DEBUG("Successfully announced rats peer for discovery");
    } else {
        LOG_CLIENT_WARN("Failed to announce rats peer for discovery");
    }
}

void RatsClient::search_rats_peers(int iteration_max) {
    if (!dht_client_ || !dht_client_->is_running()) {
        LOG_CLIENT_WARN("DHT client not running, cannot search for rats peers");
        return;
    }
    
    std::string discovery_hash = get_rats_peer_discovery_hash();
    LOG_CLIENT_INFO("Searching for rats peers using discovery hash: " << discovery_hash << " with iteration max: " << iteration_max);
    
    find_peers_by_hash(discovery_hash, [this](const std::vector<std::string>& peers) {
        LOG_CLIENT_INFO("Found " << peers.size() << " rats peers through DHT discovery");
        
        // Attempt to connect to discovered peers
        for (const auto& peer_address : peers) {
            LOG_CLIENT_INFO("Discovered rats peer: " << peer_address);
            
            // Parse IP and port
            size_t colon_pos = peer_address.find_last_of(':');
            if (colon_pos != std::string::npos) {
                std::string ip = peer_address.substr(0, colon_pos);
                int port = std::stoi(peer_address.substr(colon_pos + 1));
                
                // Check if this peer should be ignored (local interface)
                if (should_ignore_peer(ip, port)) {
                    LOG_CLIENT_DEBUG("Ignoring discovered rats peer " << ip << ":" << port << " - local interface address");
                    continue;
                }
                
                // Check if we're already connected to this peer
                std::string normalized_peer_address = normalize_peer_address(ip, port);
                bool already_connected = false;
                {
                    std::lock_guard<std::mutex> lock(peers_mutex_);
                    already_connected = is_already_connected_to_address(normalized_peer_address);
                }
                
                if (!already_connected) {
                    LOG_CLIENT_INFO("Attempting to connect to discovered rats peer: " << ip << ":" << port);
                    
                    // Try to connect (non-blocking)
                    std::thread([this, ip, port]() {
                        if (connect_to_peer(ip, port)) {
                            LOG_CLIENT_INFO("Successfully connected to discovered rats peer: " << ip << ":" << port);
                        } else {
                            LOG_CLIENT_DEBUG("Failed to connect to discovered rats peer: " << ip << ":" << port);
                        }
                    }).detach();
                } else {
                    LOG_CLIENT_DEBUG("Already connected to discovered rats peer: " << normalized_peer_address);
                }
            }
        }
    }, iteration_max);
}

// Handshake protocol implementation
std::string RatsClient::create_handshake_message(const std::string& message_type, const std::string& our_peer_id) const {
    auto now = std::chrono::high_resolution_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    // Use nlohmann::json for proper JSON serialization
    nlohmann::json handshake_msg;
    handshake_msg["protocol"] = "rats";
    handshake_msg["version"] = RATS_PROTOCOL_VERSION;
    handshake_msg["peer_id"] = our_peer_id;
    handshake_msg["message_type"] = message_type;
    handshake_msg["timestamp"] = timestamp;
    
    return handshake_msg.dump();
}

bool RatsClient::parse_handshake_message(const std::string& message, HandshakeMessage& out_msg) const {
    try {
        // Use nlohmann::json for proper JSON parsing
        nlohmann::json json_msg = nlohmann::json::parse(message);
        
        // Clear the output structure
        out_msg = HandshakeMessage{};
        
        // Extract fields using nlohmann::json
        out_msg.protocol = json_msg.value("protocol", "");
        out_msg.version = json_msg.value("version", "");
        out_msg.peer_id = json_msg.value("peer_id", "");
        out_msg.message_type = json_msg.value("message_type", "");
        out_msg.timestamp = json_msg.value("timestamp", 0L);
        
        return true;
        
    } catch (const nlohmann::json::exception& e) {
        LOG_CLIENT_ERROR("Failed to parse handshake message: " << e.what());
        return false;
    } catch (const std::exception& e) {
        LOG_CLIENT_ERROR("Failed to parse handshake message: " << e.what());
        return false;
    }
}

bool RatsClient::validate_handshake_message(const HandshakeMessage& msg) const {
    // Validate protocol
    if (msg.protocol != "rats") {
        LOG_CLIENT_WARN("Invalid handshake protocol: " << msg.protocol);
        return false;
    }
    
    // Validate version (for now, only accept exact version match)
    if (msg.version != RATS_PROTOCOL_VERSION) {
        LOG_CLIENT_WARN("Unsupported protocol version: " << msg.version << " (expected: " << RATS_PROTOCOL_VERSION << ")");
        return false;
    }
    
    // Validate message type
    if (msg.message_type != "handshake") {
        LOG_CLIENT_WARN("Invalid handshake message type: " << msg.message_type);
        return false;
    }
    
    // Validate peer_id (must not be empty)
    if (msg.peer_id.empty()) {
        LOG_CLIENT_WARN("Empty peer_id in handshake message");
        return false;
    }
    
    // Validate timestamp (should be recent, within 60 seconds)
    auto now = std::chrono::high_resolution_clock::now();
    auto current_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    int64_t time_diff = std::abs(current_timestamp - msg.timestamp);
    if (time_diff > 60000) { // 60 seconds in milliseconds
        LOG_CLIENT_WARN("Handshake timestamp too old: " << time_diff << "ms");
        return false;
    }
    
    return true;
}

bool RatsClient::is_handshake_message(const std::string& message) const {
    try {
        nlohmann::json json_msg = nlohmann::json::parse(message);
        return json_msg.value("protocol", "") == "rats" && 
               json_msg.value("message_type", "") == "handshake";
    } catch (const std::exception&) {
        return false;
    }
}

bool RatsClient::send_handshake(socket_t socket, const std::string& our_peer_id) {
    std::string handshake_msg = create_handshake_message("handshake", our_peer_id);
    LOG_CLIENT_DEBUG("Sending handshake to socket " << socket << ": " << handshake_msg);
    
    if (!send_to_peer(socket, handshake_msg)) {
        LOG_CLIENT_ERROR("Failed to send handshake to socket " << socket);
        return false;
    }
    
    // Update peer state
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = socket_to_peer_id_.find(socket);
    if (it != socket_to_peer_id_.end()) {
        auto peer_it = peers_.find(it->second);
        if (peer_it != peers_.end()) {
            peer_it->second.handshake_state = RatsPeer::HandshakeState::SENT;
            peer_it->second.handshake_start_time = std::chrono::steady_clock::now();
        }
    }
    
    return true;
}

bool RatsClient::handle_handshake_message(socket_t socket, const std::string& peer_hash_id, const std::string& message) {
    HandshakeMessage handshake_msg;
    if (!parse_handshake_message(message, handshake_msg)) {
        LOG_CLIENT_ERROR("Failed to parse handshake message from " << peer_hash_id);
        return false;
    }
    
    if (!validate_handshake_message(handshake_msg)) {
        LOG_CLIENT_ERROR("Invalid handshake message from " << peer_hash_id);
        return false;
    }
    
    LOG_CLIENT_INFO("Received valid handshake from " << peer_hash_id 
                    << " (peer_id: " << handshake_msg.peer_id << ")");
    
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = socket_to_peer_id_.find(socket);
    if (it == socket_to_peer_id_.end()) {
        LOG_CLIENT_ERROR("Socket " << socket << " not found in peer mapping");
        return false;
    }
    
    auto peer_it = peers_.find(it->second);
    if (peer_it == peers_.end()) {
        LOG_CLIENT_ERROR("Peer " << peer_hash_id << " not found in peers");
        return false;
    }
    
    RatsPeer& peer = peer_it->second;
    
    // Store old peer ID for mapping updates
    std::string old_peer_id = peer.peer_id;
    
    // Store remote peer information
    peer.peer_id = handshake_msg.peer_id;  // Update to real peer ID from handshake
    peer.version = handshake_msg.version;
    
    // Update peer mappings with new peer_id if it changed
    if (old_peer_id != peer.peer_id) {
        // Update socket mapping
        socket_to_peer_id_[peer.socket] = peer.peer_id;
        
        // Create a copy of the peer with updated ID and re-insert
        RatsPeer updated_peer = peer;
        peers_.erase(peer_it);  // Remove using iterator
        peers_[updated_peer.peer_id] = updated_peer;  // Insert with new ID
        // address_to_peer_id_ stays the same since address doesn't change
    }
    
    // Simplified handshake logic - just one message type
    if (peer.handshake_state == RatsPeer::HandshakeState::PENDING) {
        // This is an incoming handshake - send our handshake back
        if (send_handshake(socket, peer.peer_id)) {
            peer.handshake_state = RatsPeer::HandshakeState::COMPLETED;
            LOG_CLIENT_INFO("Handshake completed with " << peer_hash_id << " (remote peer_id: " << handshake_msg.peer_id << ")");
            return true;
        } else {
            peer.handshake_state = RatsPeer::HandshakeState::FAILED;
            LOG_CLIENT_ERROR("Failed to send handshake response to " << peer_hash_id);
            return false;
        }
    } else if (peer.handshake_state == RatsPeer::HandshakeState::SENT) {
        // This is a response to our handshake
        peer.handshake_state = RatsPeer::HandshakeState::COMPLETED;
        LOG_CLIENT_INFO("Handshake completed with " << peer_hash_id << " (peer_id: " << handshake_msg.peer_id << ")");
        return true;
    } else {
        LOG_CLIENT_WARN("Received handshake from " << peer_hash_id << " but handshake state is " << static_cast<int>(peer.handshake_state));
        return false;
    }
}

void RatsClient::check_handshake_timeouts() {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto now = std::chrono::steady_clock::now();
    
    std::vector<std::string> peers_to_remove;
    
    for (auto& pair : peers_) {
        RatsPeer& peer = pair.second;
        
        if (peer.handshake_state != RatsPeer::HandshakeState::COMPLETED && 
            peer.handshake_state != RatsPeer::HandshakeState::FAILED) {
            
            auto handshake_duration = std::chrono::duration_cast<std::chrono::seconds>(now - peer.handshake_start_time);
            
            if (handshake_duration.count() > HANDSHAKE_TIMEOUT_SECONDS) {
                LOG_CLIENT_WARN("Handshake timeout for peer " << peer.peer_id << " after " << handshake_duration.count() << " seconds");
                peer.handshake_state = RatsPeer::HandshakeState::FAILED;
                peers_to_remove.push_back(peer.peer_id);
            }
        }
    }
    
    // Remove timed out peers
    for (const auto& peer_id : peers_to_remove) {
        auto peer_it = peers_.find(peer_id);
        if (peer_it != peers_.end()) {
            socket_t socket = peer_it->second.socket;
            LOG_CLIENT_INFO("Disconnecting peer " << peer_id << " due to handshake timeout");
            
            // Clean up peer data
            remove_peer_by_id(peer_id);
            close_socket(socket);
        }
    }
}

bool RatsClient::parse_address_string(const std::string& address_str, std::string& out_ip, int& out_port) {
    if (address_str.empty()) {
        return false;
    }

    size_t colon_pos;
    if (address_str.front() == '[') {
        // IPv6 format: [ip]:port
        size_t bracket_end = address_str.find(']');
        if (bracket_end == std::string::npos || bracket_end < 2) { // Must be at least [a]
            return false;
        }
        out_ip = address_str.substr(1, bracket_end - 1);
        colon_pos = address_str.find(':', bracket_end);
    } else {
        // IPv4 or IPv6 without brackets
        colon_pos = address_str.find_last_of(':');
        if (colon_pos == std::string::npos || colon_pos == 0) {
            return false;
        }
        out_ip = address_str.substr(0, colon_pos);
    }

    if (colon_pos == std::string::npos || colon_pos + 1 >= address_str.length()) {
        return false;
    }

    try {
        out_port = std::stoi(address_str.substr(colon_pos + 1));
    } catch (const std::exception&) {
        return false;
    }

    return !out_ip.empty() && out_port > 0 && out_port <= 65535;
}

// Peer limit management methods
int RatsClient::get_max_peers() const {
    return max_peers_;
}

void RatsClient::set_max_peers(int max_peers) {
    max_peers_ = max_peers;
    LOG_CLIENT_INFO("Maximum peers set to " << max_peers_);
}

bool RatsClient::is_peer_limit_reached() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return static_cast<int>(peers_.size()) >= max_peers_;
}

// Message handling system
nlohmann::json RatsClient::create_rats_message(const std::string& type, const nlohmann::json& payload, const std::string& sender_peer_id) {
    nlohmann::json message;
    message["rats_protocol"] = true;
    message["type"] = type;
    message["payload"] = payload;
    message["sender_peer_id"] = sender_peer_id;
    message["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    
    return message;
}

void RatsClient::handle_rats_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& message) {
    try {
        std::string message_type = message.value("type", "");
        nlohmann::json payload = message.value("payload", nlohmann::json::object());
        std::string sender_peer_id = message.value("sender_peer_id", "");
        
        LOG_CLIENT_DEBUG("Received rats message type '" << message_type << "' from " << peer_hash_id);
        
        // Handle different message types
        if (message_type == "peer") {
            handle_peer_exchange_message(socket, peer_hash_id, payload);
        } 
        // Add more message types here as needed:
        // else if (message_type == "status") {
        //     handle_status_message(socket, peer_hash_id, payload);
        // }
        // else if (message_type == "data") {
        //     handle_data_message(socket, peer_hash_id, payload);
        // }
        // else if (message_type == "announcement") {
        //     handle_announcement_message(socket, peer_hash_id, payload);
        // }
        else {
            LOG_CLIENT_WARN("Unknown rats message type: " << message_type << " from " << peer_hash_id);
        }
        
    } catch (const nlohmann::json::exception& e) {
        LOG_CLIENT_ERROR("Failed to handle rats message: " << e.what());
    }
}

void RatsClient::handle_peer_exchange_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload) {
    try {
        std::string peer_ip = payload.value("ip", "");
        int peer_port = payload.value("port", 0);
        std::string peer_id = payload.value("peer_id", "");
        
        if (peer_ip.empty() || peer_port <= 0 || peer_id.empty()) {
            LOG_CLIENT_WARN("Invalid peer exchange message from " << peer_hash_id);
            return;
        }
        
        LOG_CLIENT_INFO("Received peer exchange: " << peer_ip << ":" << peer_port << " (peer_id: " << peer_id << ")");
        
        // Check if we should ignore this peer (local interface)
        if (should_ignore_peer(peer_ip, peer_port)) {
            LOG_CLIENT_DEBUG("Ignoring exchanged peer " << peer_ip << ":" << peer_port << " - local interface address");
            return;
        }
        
        // Check if we're already connected to this peer
        std::string normalized_peer_address = normalize_peer_address(peer_ip, peer_port);
        if (is_already_connected_to_address(normalized_peer_address)) {
            LOG_CLIENT_DEBUG("Already connected to exchanged peer " << normalized_peer_address);
            return;
        }
        
        // Check if peer limit is reached
        if (is_peer_limit_reached()) {
            LOG_CLIENT_DEBUG("Peer limit reached, not connecting to exchanged peer " << peer_ip << ":" << peer_port);
            return;
        }
        
        // Try to connect to the exchanged peer (non-blocking)
        std::thread([this, peer_ip, peer_port, peer_id]() {
            if (connect_to_peer(peer_ip, peer_port)) {
                LOG_CLIENT_INFO("Successfully connected to exchanged peer: " << peer_ip << ":" << peer_port);
            } else {
                LOG_CLIENT_DEBUG("Failed to connect to exchanged peer: " << peer_ip << ":" << peer_port);
            }
        }).detach();
        
    } catch (const nlohmann::json::exception& e) {
        LOG_CLIENT_ERROR("Failed to handle peer exchange message: " << e.what());
    }
}

// General broadcasting functions
int RatsClient::broadcast_rats_message(const nlohmann::json& message, const std::string& exclude_peer_id) {
    int sent_count = 0;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& pair : peers_) {
            const RatsPeer& peer = pair.second;
            // Don't send to excluded peer
            if (!exclude_peer_id.empty() && peer.peer_id == exclude_peer_id) {
                continue;
            }
            
            if (send_json_to_peer(peer.socket, message)) {
                sent_count++;
            }
        }
    }
    return sent_count;
}

int RatsClient::broadcast_rats_message_to_validated_peers(const nlohmann::json& message, const std::string& exclude_peer_id) {
    int sent_count = 0;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (const auto& pair : peers_) {
            const RatsPeer& peer = pair.second;
            // Don't send to excluded peer and only send to peers with completed handshake
            if ((!exclude_peer_id.empty() && peer.peer_id == exclude_peer_id) || 
                !peer.is_handshake_completed()) {
                continue;
            }
            
            if (send_json_to_peer(peer.socket, message)) {
                sent_count++;
            }
        }
    }
    return sent_count;
}

// Specific message creation functions
nlohmann::json RatsClient::create_peer_exchange_message(const RatsPeer& peer) {
    // Create peer exchange payload
    nlohmann::json payload;
    payload["ip"] = peer.ip;
    payload["port"] = peer.port;
    payload["peer_id"] = peer.peer_id;
    payload["connection_type"] = peer.is_outgoing ? "outgoing" : "incoming";
    
    // Create rats message
    return create_rats_message("peer", payload, peer.peer_id);
}

void RatsClient::broadcast_peer_exchange_message(const RatsPeer& new_peer) {
    // Don't broadcast exchange messages for ourselves
    if (new_peer.peer_id.empty()) {
        return;
    }
    
    // Create peer exchange message
    nlohmann::json message = create_peer_exchange_message(new_peer);
    
    // Broadcast to all validated peers except the new peer
    int sent_count = broadcast_rats_message_to_validated_peers(message, new_peer.peer_id);
    
    LOG_CLIENT_INFO("Broadcasted peer exchange message for " << new_peer.ip << ":" << new_peer.port 
                    << " to " << sent_count << " peers");
}

// Utility functions for custom message types
int RatsClient::broadcast_custom_message(const std::string& type, const nlohmann::json& payload, 
                                        const std::string& sender_peer_id, 
                                        const std::string& exclude_peer_id) {
    // Create rats message
    nlohmann::json message = create_rats_message(type, payload, sender_peer_id);
    
    // Broadcast to all validated peers
    int sent_count = broadcast_rats_message_to_validated_peers(message, exclude_peer_id);
    
    LOG_CLIENT_DEBUG("Broadcasted custom message type '" << type << "' to " << sent_count << " peers");
    return sent_count;
}

/*
 * EXAMPLE: How to add new message types using the broadcasting system
 * 
 * 1. Create a message creation function:
 *    nlohmann::json create_status_message(const std::string& status, const std::string& details) {
 *        nlohmann::json payload;
 *        payload["status"] = status;
 *        payload["details"] = details;
 *        payload["node_info"] = get_node_info(); // example additional data
 *        return payload;
 *    }
 * 
 * 2. Create a handler function:
 *    void handle_status_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload) {
 *        std::string status = payload.value("status", "");
 *        std::string details = payload.value("details", "");
 *        LOG_CLIENT_INFO("Peer " << peer_hash_id << " status: " << status << " - " << details);
 *        // Handle the status update...
 *    }
 * 
 * 3. Add the handler to handle_rats_message() function:
 *    else if (message_type == "status") {
 *        handle_status_message(socket, peer_hash_id, payload);
 *    }
 * 
 * 4. Use the broadcasting system to send messages:
 *    // Broadcast to all peers:
 *    nlohmann::json status_payload = create_status_message("online", "Node is healthy");
 *    broadcast_custom_message("status", status_payload);
 * 
 *    // Send to specific peer:
 *    send_custom_message_to_peer("target_peer_id", "status", status_payload);
 * 
 * 5. Message format will automatically be:
 *    {
 *      "rats_protocol": true,
 *      "type": "status",
 *      "payload": { "status": "online", "details": "Node is healthy", ... },
 *      "sender_peer_id": "your_peer_id",
 *      "timestamp": 1234567890123
 *    }
 */

bool RatsClient::send_custom_message_to_peer(const std::string& peer_id, const std::string& type, 
                                            const nlohmann::json& payload, 
                                            const std::string& sender_peer_id) {
    // Create rats message
    nlohmann::json message = create_rats_message(type, payload, sender_peer_id);
    
    // Send to specific peer
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = peers_.find(peer_id);
    if (it == peers_.end() || !it->second.is_handshake_completed()) {
        LOG_CLIENT_WARN("Cannot send custom message to peer " << peer_id << " - peer not found or handshake not completed");
        return false;
    }
    
    bool success = send_json_to_peer(it->second.socket, message);
    if (success) {
        LOG_CLIENT_DEBUG("Sent custom message type '" << type << "' to peer " << peer_id);
    } else {
        LOG_CLIENT_ERROR("Failed to send custom message type '" << type << "' to peer " << peer_id);
    }
    
    return success;
}

} // namespace librats 