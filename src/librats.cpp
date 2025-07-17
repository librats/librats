#include "librats.h"
#include "sha1.h"
#include "os.h"
#include "network_utils.h"
#include "fs.h"
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

// Configuration file constants
const std::string RatsClient::CONFIG_FILE_NAME = "config.json";
const std::string RatsClient::PEERS_FILE_NAME = "peers.rats";

RatsClient::RatsClient(int listen_port, int max_peers) 
    : listen_port_(listen_port), 
      max_peers_(max_peers),
      server_socket_(INVALID_SOCKET_VALUE),
      running_(false) {
    // Initialize STUN client
    stun_client_ = std::make_unique<StunClient>();
    
    // Load configuration (this will generate peer ID if needed)
    load_configuration();
}

RatsClient::~RatsClient() {
    stop();
    
    // Save configuration before destruction
    save_configuration();
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

std::string RatsClient::get_our_peer_id() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return our_peer_id_;
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
    
    // Attempt to reconnect to saved peers
    std::thread([this]() {
        // Give the server some time to fully initialize
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        int reconnect_attempts = load_and_reconnect_peers();
        if (reconnect_attempts > 0) {
            LOG_CLIENT_INFO("Attempted to reconnect to " << reconnect_attempts << " saved peers");
        }
    }).detach();
    
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

int RatsClient::get_peer_count_unlocked() const {
    // Assumes peers_mutex_ is already locked
    int count = 0;
    for (const auto& pair : peers_) {
        if (pair.second.is_handshake_completed()) {
            count++;
        }
    }
    return count;
}

int RatsClient::get_peer_count() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return get_peer_count_unlocked();
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
        if (is_already_connected_to_address(normalized_peer_address)) {
            LOG_SERVER_INFO("Already connected to peer " << normalized_peer_address << ", rejecting duplicate connection");
            close_socket(client_socket);
            continue;
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
        
        // Check for handshake timeout and failure
        if (!handshake_completed) {
            bool should_exit = false;
            
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                auto it = socket_to_peer_id_.find(client_socket);
                if (it != socket_to_peer_id_.end()) {
                    auto peer_it = peers_.find(it->second);
                    if (peer_it != peers_.end()) {
                        const RatsPeer& peer = peer_it->second;
                        if (peer.is_handshake_failed()) {
                            LOG_CLIENT_ERROR("Handshake failed for peer " << peer_hash_id);
                            should_exit = true;
                        }
                    }
                }
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
            
            // Check if handshake just completed and trigger notifications
            if (!handshake_completed) {
                RatsPeer peer_copy;
                bool should_notify_connection = false;
                bool should_broadcast_exchange = false;
                
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
                    
                    // Send peers request to the newly connected peer to discover more peers
                    if (peer_copy.is_outgoing) {
                        send_peers_request(client_socket, peer_copy.peer_id);
                    }
                    
                    // Save configuration after a new peer connects to keep peer list current
                    std::thread([this]() {
                        save_configuration();
                    }).detach();
                }
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
    
    // Save configuration after a validated peer disconnects to update the saved peer list
    if (handshake_completed) {
        // Save configuration in a separate thread to avoid blocking
        std::thread([this]() {
            save_configuration();
        }).detach();
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
    // Always block connections to ourselves (same port)
    if (port == listen_port_) {
        if (ip == "127.0.0.1" || ip == "::1" || ip == "localhost" || ip == "0.0.0.0" || ip == "::") {
            LOG_CLIENT_DEBUG("Ignoring peer " << ip << ":" << port << " - localhost with same port");
            return true;
        }
    }
    
    // For localhost addresses on different ports, allow the connection (for testing)
    if (ip == "127.0.0.1" || ip == "::1" || ip == "localhost") {
        LOG_CLIENT_DEBUG("Allowing localhost peer " << ip << ":" << port << " on different port");
        return false;
    }
    
    // Check if the IP is a non-localhost local interface address
    if (is_blocked_address(ip)) {
        LOG_CLIENT_DEBUG("Ignoring peer " << ip << ":" << port << " - matches local interface address");
        return true;
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
    
    // Set up connection callback
    client.set_connection_callback([&client](socket_t socket, const std::string& peer_hash_id) {
        LOG_MAIN_INFO("New validated connection (handshake completed): " << peer_hash_id << " (socket: " << socket << ")");
        LOG_MAIN_INFO("Total connected peers: " << client.get_peer_count() << "/" << client.get_max_peers());
    });
    
    // Set up message exchange API handlers
    client.on("greeting", [](const std::string& peer_id, const nlohmann::json& data) {
        LOG_MAIN_INFO("Received greeting from " << peer_id << ": " << data.value("message", ""));
    });
    
    client.on("status", [](const std::string& peer_id, const nlohmann::json& data) {
        LOG_MAIN_INFO("Peer " << peer_id << " status: " << data.value("status", "unknown"));
    });
    
    client.once("test_once", [](const std::string& peer_id, const nlohmann::json& data) {
        LOG_MAIN_INFO("One-time handler triggered by " << peer_id << ": " << data.dump());
    });
    
    // Set up legacy data callback for non-protocol messages
    client.set_data_callback([&client](socket_t socket, const std::string& peer_hash_id, const std::string& data) {
        LOG_MAIN_INFO("Received legacy data from peer " << peer_hash_id << ": " << data);
        
        // Try to parse as JSON first
        nlohmann::json json_data;
        if (client.parse_json_message(data, json_data)) {
            // Check if it's a rats protocol message (these are handled by message exchange API)
            if (json_data.contains("rats_protocol") && json_data["rats_protocol"] == true) {
                LOG_MAIN_INFO("Received rats protocol message (handled by API)");
                return; // Don't echo protocol messages
            }
            
            LOG_MAIN_INFO("Parsed legacy JSON message: " << json_data.dump());
            
            // Create a JSON response using new API
            nlohmann::json response_data;
            response_data["original_message"] = json_data;
            response_data["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch()).count();
            
            client.send("echo_response", response_data);
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
            
            // Send test messages using the new message exchange API
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            // Send a greeting message
            nlohmann::json greeting_data;
            greeting_data["message"] = "Hello from RatsClient on port " + std::to_string(listen_port);
            greeting_data["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch()).count();
            greeting_data["sender_port"] = listen_port;
            
            client.send("greeting", greeting_data, [](bool success, const std::string& error) {
                if (success) {
                    LOG_MAIN_INFO("Greeting message sent successfully");
                } else {
                    LOG_MAIN_ERROR("Failed to send greeting: " << error);
                }
            });
            
            // Send a status message
            nlohmann::json status_data;
            status_data["status"] = "online";
            status_data["details"] = "Demo client running";
            status_data["peer_count"] = client.get_peer_count();
            
            client.send("status", status_data);
            
            // Send a test_once message to demonstrate once handlers
            nlohmann::json once_data;
            once_data["message"] = "This should only be handled once";
            once_data["attempt"] = 1;
            
            client.send("test_once", once_data);
            
            LOG_MAIN_INFO("Sent test messages using new message exchange API");
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
                bool already_connected = is_already_connected_to_address(normalized_peer_address);
                
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
        out_msg.timestamp = json_msg["timestamp"].get<int64_t>();
        
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

// Add this private helper function before send_handshake
bool RatsClient::send_handshake_unlocked(socket_t socket, const std::string& our_peer_id) {
    std::string handshake_msg = create_handshake_message("handshake", our_peer_id);
    LOG_CLIENT_DEBUG("Sending handshake to socket " << socket << ": " << handshake_msg);
    
    if (!send_to_peer(socket, handshake_msg)) {
        LOG_CLIENT_ERROR("Failed to send handshake to socket " << socket);
        return false;
    }
    
    // Update peer state (assumes peers_mutex_ is already locked)
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

bool RatsClient::send_handshake(socket_t socket, const std::string& our_peer_id) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return send_handshake_unlocked(socket, our_peer_id);
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

    if (handshake_msg.peer_id == get_our_peer_id()) {
        LOG_CLIENT_INFO("Received handshake from ourselves, ignoring");
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
    
    // Store old peer ID for mapping updates
    std::string old_peer_id = peer_it->second.peer_id;
    
    // Update peer mappings with new peer_id if it changed
    if (old_peer_id != handshake_msg.peer_id) {
        // Create a copy of the peer object before erasing it.
        RatsPeer peer_copy = peer_it->second;
        
        // Erase the old entry from the main peers map.
        peers_.erase(peer_it);
        
        // Update the peer_id within the copied object.
        peer_copy.peer_id = handshake_msg.peer_id;
        
        // Insert the updated peer object back into the maps with the new peer_id.
        peers_[peer_copy.peer_id] = peer_copy;
        socket_to_peer_id_[socket] = peer_copy.peer_id;
        address_to_peer_id_[peer_copy.normalized_address] = peer_copy.peer_id;

        // Find the iterator for the newly inserted peer.
        peer_it = peers_.find(peer_copy.peer_id);
    }

    RatsPeer& peer = peer_it->second;

    // Store remote peer information
    peer.version = handshake_msg.version;
    
    // Simplified handshake logic - just one message type
    if (peer.handshake_state == RatsPeer::HandshakeState::PENDING) {
        // This is an incoming handshake - send our handshake back
        if (send_handshake_unlocked(socket, peer.peer_id)) {
            peer.handshake_state = RatsPeer::HandshakeState::COMPLETED;
            log_handshake_completion_unlocked(peer);
            return true;
        } else {
            peer.handshake_state = RatsPeer::HandshakeState::FAILED;
            LOG_CLIENT_ERROR("Failed to send handshake response to " << peer_hash_id);
            return false;
        }
    } else if (peer.handshake_state == RatsPeer::HandshakeState::SENT) {
        // This is a response to our handshake
        peer.handshake_state = RatsPeer::HandshakeState::COMPLETED;
        log_handshake_completion_unlocked(peer);
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

void RatsClient::log_handshake_completion_unlocked(const RatsPeer& peer) {
    // Calculate connection duration
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - peer.connected_at);
    
    // Get current peer count (assumes peers_mutex_ is already locked)
    int current_peer_count = get_peer_count_unlocked();
    
    // Create visually appealing log output
    std::string connection_type = peer.is_outgoing ? "OUTGOING" : "INCOMING";
    std::string separator = "════════════════════════════════════════════════════════════════════";
    
    LOG_CLIENT_INFO("");
    LOG_CLIENT_INFO(separator);
    LOG_CLIENT_INFO("✓ HANDSHAKE COMPLETED - NEW PEER CONNECTED");
    LOG_CLIENT_INFO(separator);
    LOG_CLIENT_INFO("│ Peer ID       : " << peer.peer_id);
    LOG_CLIENT_INFO("│ Address       : " << peer.ip << ":" << peer.port);
    LOG_CLIENT_INFO("│ Connection    : " << connection_type);
    LOG_CLIENT_INFO("│ Protocol Ver. : " << peer.version);
    LOG_CLIENT_INFO("│ Socket        : " << peer.socket);
    LOG_CLIENT_INFO("│ Duration      : " << duration.count() << "ms");
    LOG_CLIENT_INFO("│ Network Peers : " << current_peer_count << "/" << max_peers_);
    
    LOG_CLIENT_INFO(separator);
    LOG_CLIENT_INFO("");
}

void RatsClient::log_handshake_completion(const RatsPeer& peer) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    log_handshake_completion_unlocked(peer);
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
        
        // Call registered message handlers for all message types (including custom ones)
        call_message_handlers(message_type, sender_peer_id.empty() ? peer_hash_id : sender_peer_id, payload);
        
        // Handle built-in message types for internal functionality
        if (message_type == "peer") {
            handle_peer_exchange_message(socket, peer_hash_id, payload);
        } 
        else if (message_type == "peers_request") {
            handle_peers_request_message(socket, peer_hash_id, payload);
        }
        else if (message_type == "peers_response") {
            handle_peers_response_message(socket, peer_hash_id, payload);
        }
        // Custom message types are now handled by registered handlers above
        // No need for else clause - all message types are valid if they have registered handlers
        
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

// Peers request/response system implementation
nlohmann::json RatsClient::create_peers_request_message(const std::string& sender_peer_id) {
    nlohmann::json payload;
    payload["max_peers"] = 5;  // Request up to 5 peers
    payload["requester_info"] = {
        {"listen_port", listen_port_},
        {"peer_count", get_peer_count()}
    };
    
    return create_rats_message("peers_request", payload, sender_peer_id);
}

nlohmann::json RatsClient::create_peers_response_message(const std::vector<RatsPeer>& peers, const std::string& sender_peer_id) {
    nlohmann::json payload;
    nlohmann::json peers_array = nlohmann::json::array();
    
    for (const auto& peer : peers) {
        nlohmann::json peer_info;
        peer_info["ip"] = peer.ip;
        peer_info["port"] = peer.port;
        peer_info["peer_id"] = peer.peer_id;
        peer_info["connection_type"] = peer.is_outgoing ? "outgoing" : "incoming";
        peers_array.push_back(peer_info);
    }
    
    payload["peers"] = peers_array;
    payload["total_peers"] = get_peer_count();
    
    return create_rats_message("peers_response", payload, sender_peer_id);
}

std::vector<RatsPeer> RatsClient::get_random_peers(int max_count, const std::string& exclude_peer_id) const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    std::vector<RatsPeer> all_validated_peers;
    
    // Get all validated peers excluding the specified peer
    for (const auto& pair : peers_) {
        const RatsPeer& peer = pair.second;
        if (peer.is_handshake_completed() && peer.peer_id != exclude_peer_id) {
            all_validated_peers.push_back(peer);
        }
    }
    
    // If we have fewer peers than requested, return all
    if (all_validated_peers.size() <= static_cast<size_t>(max_count)) {
        return all_validated_peers;
    }
    
    // Randomly select peers
    std::vector<RatsPeer> selected_peers;
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Use random sampling to select peers
    std::sample(all_validated_peers.begin(), all_validated_peers.end(),
                std::back_inserter(selected_peers), max_count, gen);
    
    return selected_peers;
}

void RatsClient::handle_peers_request_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload) {
    try {
        int max_peers = payload.value("max_peers", 5);
        
        LOG_CLIENT_INFO("Received peers request from " << peer_hash_id << " for up to " << max_peers << " peers");
        
        // Get random peers excluding the requester
        std::vector<RatsPeer> random_peers = get_random_peers(max_peers, peer_hash_id);
        
        LOG_CLIENT_DEBUG("Sending " << random_peers.size() << " peers to " << peer_hash_id);
        
        // Create and send peers response
        nlohmann::json response_message = create_peers_response_message(random_peers, peer_hash_id);
        
        if (!send_json_to_peer(socket, response_message)) {
            LOG_CLIENT_ERROR("Failed to send peers response to " << peer_hash_id);
        } else {
            LOG_CLIENT_DEBUG("Sent peers response with " << random_peers.size() << " peers to " << peer_hash_id);
        }
        
    } catch (const nlohmann::json::exception& e) {
        LOG_CLIENT_ERROR("Failed to handle peers request message: " << e.what());
    }
}

void RatsClient::handle_peers_response_message(socket_t socket, const std::string& peer_hash_id, const nlohmann::json& payload) {
    try {
        nlohmann::json peers_array = payload.value("peers", nlohmann::json::array());
        int total_peers = payload.value("total_peers", 0);
        
        LOG_CLIENT_INFO("Received peers response from " << peer_hash_id << " with " << peers_array.size() 
                        << " peers (total: " << total_peers << ")");
        
        // Process each peer in the response
        for (const auto& peer_info : peers_array) {
            std::string peer_ip = peer_info.value("ip", "");
            int peer_port = peer_info.value("port", 0);
            std::string peer_id = peer_info.value("peer_id", "");
            
            if (peer_ip.empty() || peer_port <= 0 || peer_id.empty()) {
                LOG_CLIENT_WARN("Invalid peer info in peers response from " << peer_hash_id);
                continue;
            }
            
            LOG_CLIENT_DEBUG("Processing peer from response: " << peer_ip << ":" << peer_port << " (peer_id: " << peer_id << ")");
            
            // Check if we should ignore this peer (local interface)
            if (should_ignore_peer(peer_ip, peer_port)) {
                LOG_CLIENT_DEBUG("Ignoring peer from response " << peer_ip << ":" << peer_port << " - local interface address");
                continue;
            }
            
            // Check if we're already connected to this peer
            std::string normalized_peer_address = normalize_peer_address(peer_ip, peer_port);
            if (is_already_connected_to_address(normalized_peer_address)) {
                LOG_CLIENT_DEBUG("Already connected to peer from response " << normalized_peer_address);
                continue;
            }
            
            // Check if peer limit is reached
            if (is_peer_limit_reached()) {
                LOG_CLIENT_DEBUG("Peer limit reached, not connecting to peer from response " << peer_ip << ":" << peer_port);
                continue;
            }
            
            // Try to connect to the peer (non-blocking)
            LOG_CLIENT_INFO("Attempting to connect to peer from response: " << peer_ip << ":" << peer_port);
            std::thread([this, peer_ip, peer_port, peer_id]() {
                if (connect_to_peer(peer_ip, peer_port)) {
                    LOG_CLIENT_INFO("Successfully connected to peer from response: " << peer_ip << ":" << peer_port);
                } else {
                    LOG_CLIENT_DEBUG("Failed to connect to peer from response: " << peer_ip << ":" << peer_port);
                }
            }).detach();
        }
        
    } catch (const nlohmann::json::exception& e) {
        LOG_CLIENT_ERROR("Failed to handle peers response message: " << e.what());
    }
}

void RatsClient::send_peers_request(socket_t socket, const std::string& our_peer_id) {
    nlohmann::json request_message = create_peers_request_message(our_peer_id);
    
    if (send_json_to_peer(socket, request_message)) {
        LOG_CLIENT_INFO("Sent peers request to socket " << socket);
    } else {
        LOG_CLIENT_ERROR("Failed to send peers request to socket " << socket);
    }
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

// Configuration persistence implementation
std::string RatsClient::generate_persistent_peer_id() const {
    // Generate a unique peer ID using SHA1 hash of timestamp, random data, and hostname
    auto now = std::chrono::high_resolution_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    
    // Get system information for uniqueness
    SystemInfo sys_info = get_system_info();
    
    // Create random component
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    // Build unique string
    std::ostringstream unique_stream;
    unique_stream << timestamp << "_" << sys_info.hostname << "_" << listen_port_ << "_";
    
    // Add random component
    for (int i = 0; i < 16; ++i) {
        unique_stream << std::setfill('0') << std::setw(2) << std::hex << dis(gen);
    }
    
    // Generate SHA1 hash of the unique string
    std::string unique_string = unique_stream.str();
    std::string peer_id = SHA1::hash(unique_string);
    
    LOG_CLIENT_INFO("Generated new persistent peer ID: " << peer_id);
    return peer_id;
}

nlohmann::json RatsClient::serialize_peer_for_persistence(const RatsPeer& peer) const {
    nlohmann::json peer_json;
    peer_json["ip"] = peer.ip;
    peer_json["port"] = peer.port;
    peer_json["peer_id"] = peer.peer_id;
    peer_json["normalized_address"] = peer.normalized_address;
    peer_json["is_outgoing"] = peer.is_outgoing;
    peer_json["version"] = peer.version;
    
    // Add timestamp for cleanup of old peers
    auto now = std::chrono::high_resolution_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    peer_json["last_seen"] = timestamp;
    
    return peer_json;
}

bool RatsClient::deserialize_peer_from_persistence(const nlohmann::json& json, std::string& ip, int& port, std::string& peer_id) const {
    try {
        ip = json.value("ip", "");
        port = json.value("port", 0);
        peer_id = json.value("peer_id", "");
        
        // Validate required fields
        if (ip.empty() || port <= 0 || port > 65535 || peer_id.empty()) {
            return false;
        }
        
        // Check if peer data is not too old (optional - remove peers older than 7 days)
        if (json.contains("last_seen")) {
            auto now = std::chrono::high_resolution_clock::now();
            auto current_timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
            int64_t last_seen = json.value("last_seen", current_timestamp);
            
            const int64_t MAX_PEER_AGE_SECONDS = 7 * 24 * 60 * 60; // 7 days
            if (current_timestamp - last_seen > MAX_PEER_AGE_SECONDS) {
                LOG_CLIENT_DEBUG("Skipping old peer " << ip << ":" << port << " (last seen " << (current_timestamp - last_seen) << " seconds ago)");
                return false;
            }
        }
        
        return true;
        
    } catch (const nlohmann::json::exception& e) {
        LOG_CLIENT_ERROR("Failed to deserialize peer: " << e.what());
        return false;
    }
}

std::string RatsClient::get_config_file_path() const {
    return CONFIG_FILE_NAME;
}

std::string RatsClient::get_peers_file_path() const {
    return PEERS_FILE_NAME;
}

bool RatsClient::load_configuration() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    LOG_CLIENT_INFO("Loading configuration from " << get_config_file_path());
    
    // Check if config file exists
    if (!file_exists(get_config_file_path())) {
        LOG_CLIENT_INFO("No existing configuration found, generating new peer ID");
        our_peer_id_ = generate_persistent_peer_id();
        
        // Save the new configuration immediately
        {
            nlohmann::json config;
            config["peer_id"] = our_peer_id_;
            config["version"] = RATS_PROTOCOL_VERSION;
            config["listen_port"] = listen_port_;
            config["max_peers"] = max_peers_;
            
            auto now = std::chrono::high_resolution_clock::now();
            auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
            config["created_at"] = timestamp;
            config["last_updated"] = timestamp;
            
            std::string config_data = config.dump(4); // Pretty print with 4 spaces
            if (create_file(get_config_file_path(), config_data)) {
                LOG_CLIENT_INFO("Created new configuration file with peer ID: " << our_peer_id_);
            } else {
                LOG_CLIENT_ERROR("Failed to create configuration file");
                return false;
            }
        }
        
        return true;
    }
    
    // Load existing configuration
    try {
        std::string config_data = read_file_text_cpp(get_config_file_path());
        if (config_data.empty()) {
            LOG_CLIENT_ERROR("Configuration file is empty");
            return false;
        }
        
        nlohmann::json config = nlohmann::json::parse(config_data);
        
        // Load peer ID
        our_peer_id_ = config.value("peer_id", "");
        if (our_peer_id_.empty()) {
            LOG_CLIENT_WARN("No peer ID in configuration, generating new one");
            our_peer_id_ = generate_persistent_peer_id();
            return save_configuration(); // Save the new peer ID
        }
        
        LOG_CLIENT_INFO("Loaded configuration with peer ID: " << our_peer_id_);
        
        // Update last_updated timestamp
        auto now = std::chrono::high_resolution_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        config["last_updated"] = timestamp;
        
        // Save updated config
        std::string updated_config_data = config.dump(4);
        create_file(get_config_file_path(), updated_config_data);
        
        return true;
        
    } catch (const nlohmann::json::exception& e) {
        LOG_CLIENT_ERROR("Failed to parse configuration file: " << e.what());
        return false;
    } catch (const std::exception& e) {
        LOG_CLIENT_ERROR("Failed to load configuration: " << e.what());
        return false;
    }
}

bool RatsClient::save_configuration() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    if (our_peer_id_.empty()) {
        LOG_CLIENT_WARN("No peer ID to save");
        return false;
    }
    
    LOG_CLIENT_DEBUG("Saving configuration to " << get_config_file_path());
    
    try {
        // Create configuration JSON
        nlohmann::json config;
        config["peer_id"] = our_peer_id_;
        config["version"] = RATS_PROTOCOL_VERSION;
        config["listen_port"] = listen_port_;
        config["max_peers"] = max_peers_;
        
        auto now = std::chrono::high_resolution_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        config["last_updated"] = timestamp;
        
        // If config file exists, preserve created_at timestamp
        if (file_exists(get_config_file_path())) {
            try {
                std::string existing_config_data = read_file_text_cpp(get_config_file_path());
                nlohmann::json existing_config = nlohmann::json::parse(existing_config_data);
                if (existing_config.contains("created_at")) {
                    config["created_at"] = existing_config["created_at"];
                }
            } catch (const std::exception&) {
                // If we can't read existing config, just use current timestamp
                config["created_at"] = timestamp;
            }
        } else {
            config["created_at"] = timestamp;
        }
        
        // Save configuration
        std::string config_data = config.dump(4);
        if (create_file(get_config_file_path(), config_data)) {
            LOG_CLIENT_DEBUG("Configuration saved successfully");
        } else {
            LOG_CLIENT_ERROR("Failed to save configuration file");
            return false;
        }
        
        // Save peers
        return save_peers_to_file();
        
    } catch (const nlohmann::json::exception& e) {
        LOG_CLIENT_ERROR("Failed to create configuration JSON: " << e.what());
        return false;
    } catch (const std::exception& e) {
        LOG_CLIENT_ERROR("Failed to save configuration: " << e.what());
        return false;
    }
}

bool RatsClient::save_peers_to_file() {
    // This method assumes config_mutex_ is already locked by save_configuration()
    
    LOG_CLIENT_DEBUG("Saving peers to " << get_peers_file_path());
    
    try {
        nlohmann::json peers_json = nlohmann::json::array();
        
        // Get validated peers for saving
        {
            std::lock_guard<std::mutex> peers_lock(peers_mutex_);
            for (const auto& pair : peers_) {
                const RatsPeer& peer = pair.second;
                // Only save peers that have completed handshake and have valid peer IDs
                if (peer.is_handshake_completed() && !peer.peer_id.empty()) {
                    // Don't save ourselves
                    if (peer.peer_id != our_peer_id_) {
                        peers_json.push_back(serialize_peer_for_persistence(peer));
                    }
                }
            }
        }
        
        LOG_CLIENT_INFO("Saving " << peers_json.size() << " peers to persistence file");
        
        // Save peers file
        std::string peers_data = peers_json.dump(4);
        if (create_file(get_peers_file_path(), peers_data)) {
            LOG_CLIENT_DEBUG("Peers saved successfully");
            return true;
        } else {
            LOG_CLIENT_ERROR("Failed to save peers file");
            return false;
        }
        
    } catch (const nlohmann::json::exception& e) {
        LOG_CLIENT_ERROR("Failed to serialize peers: " << e.what());
        return false;
    } catch (const std::exception& e) {
        LOG_CLIENT_ERROR("Failed to save peers: " << e.what());
        return false;
    }
}

int RatsClient::load_and_reconnect_peers() {
    if (!running_.load()) {
        LOG_CLIENT_DEBUG("Client not running, skipping peer reconnection");
        return 0;
    }
    
    LOG_CLIENT_INFO("Loading saved peers from " << get_peers_file_path());
    
    // Check if peers file exists
    if (!file_exists(get_peers_file_path())) {
        LOG_CLIENT_INFO("No saved peers file found");
        return 0;
    }
    
    try {
        std::string peers_data = read_file_text_cpp(get_peers_file_path());
        if (peers_data.empty()) {
            LOG_CLIENT_INFO("Peers file is empty");
            return 0;
        }
        
        nlohmann::json peers_json = nlohmann::json::parse(peers_data);
        
        if (!peers_json.is_array()) {
            LOG_CLIENT_ERROR("Invalid peers file format - expected array");
            return 0;
        }
        
        int reconnect_attempts = 0;
        
        for (const auto& peer_json : peers_json) {
            std::string ip;
            int port;
            std::string peer_id;
            
            if (!deserialize_peer_from_persistence(peer_json, ip, port, peer_id)) {
                continue; // Skip invalid or old peers
            }
            
            // Don't connect to ourselves
            if (peer_id == get_our_peer_id()) {
                LOG_CLIENT_DEBUG("Skipping connection to ourselves: " << peer_id);
                continue;
            }
            
            // Check if we should ignore this peer (local interface)
            if (should_ignore_peer(ip, port)) {
                LOG_CLIENT_DEBUG("Ignoring saved peer " << ip << ":" << port << " - local interface address");
                continue;
            }
            
            // Check if we're already connected to this peer
            std::string normalized_peer_address = normalize_peer_address(ip, port);
            if (is_already_connected_to_address(normalized_peer_address)) {
                LOG_CLIENT_DEBUG("Already connected to saved peer " << normalized_peer_address);
                continue;
            }
            
            // Check if peer limit is reached
            if (is_peer_limit_reached()) {
                LOG_CLIENT_DEBUG("Peer limit reached, stopping reconnection attempts");
                break;
            }
            
            LOG_CLIENT_INFO("Attempting to reconnect to saved peer: " << ip << ":" << port << " (peer_id: " << peer_id << ")");
            
            // Attempt to connect (non-blocking)
            std::thread([this, ip, port, peer_id]() {
                if (connect_to_peer(ip, port)) {
                    LOG_CLIENT_INFO("Successfully reconnected to saved peer: " << ip << ":" << port);
                } else {
                    LOG_CLIENT_DEBUG("Failed to reconnect to saved peer: " << ip << ":" << port);
                }
            }).detach();
            
            reconnect_attempts++;
            
            // Small delay between connection attempts to avoid overwhelming the network
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        LOG_CLIENT_INFO("Processed " << peers_json.size() << " saved peers, attempted " << reconnect_attempts << " reconnections");
        return reconnect_attempts;
        
    } catch (const nlohmann::json::exception& e) {
        LOG_CLIENT_ERROR("Failed to parse saved peers file: " << e.what());
        return 0;
    } catch (const std::exception& e) {
        LOG_CLIENT_ERROR("Failed to load saved peers: " << e.what());
        return 0;
    }
}

// Message exchange API implementation
void RatsClient::on(const std::string& message_type, MessageCallback callback) {
    std::lock_guard<std::mutex> lock(message_handlers_mutex_);
    message_handlers_[message_type].emplace_back(callback, false); // false = not once
    LOG_CLIENT_INFO("Registered persistent handler for message type: " << message_type << " (total handlers: " << message_handlers_[message_type].size() << ")");
}

void RatsClient::once(const std::string& message_type, MessageCallback callback) {
    std::lock_guard<std::mutex> lock(message_handlers_mutex_);
    message_handlers_[message_type].emplace_back(callback, true); // true = once
    LOG_CLIENT_DEBUG("Registered one-time handler for message type: " << message_type);
}

void RatsClient::off(const std::string& message_type) {
    std::lock_guard<std::mutex> lock(message_handlers_mutex_);
    auto it = message_handlers_.find(message_type);
    if (it != message_handlers_.end()) {
        size_t removed_count = it->second.size();
        message_handlers_.erase(it);
        LOG_CLIENT_DEBUG("Removed " << removed_count << " handlers for message type: " << message_type);
    }
}

void RatsClient::send(const std::string& message_type, const nlohmann::json& data, SendCallback callback) {
    if (!running_.load()) {
        LOG_CLIENT_ERROR("Cannot send message '" << message_type << "' - client is not running");
        if (callback) {
            callback(false, "Client is not running");
        }
        return;
    }
    
    LOG_CLIENT_INFO("Sending broadcast message type '" << message_type << "' with data: " << data.dump());
    
    // Create rats message
    nlohmann::json message = create_rats_message(message_type, data, get_our_peer_id());
    
    // Broadcast to all validated peers
    int sent_count = broadcast_rats_message_to_validated_peers(message);
    
    LOG_CLIENT_INFO("Broadcasted message type '" << message_type << "' to " << sent_count << " peers");
    
    if (callback) {
        if (sent_count > 0) {
            callback(true, "");
        } else {
            LOG_CLIENT_WARN("No peers to send message to");
            callback(false, "No peers to send message to");
        }
    }
}

void RatsClient::send(const std::string& peer_id, const std::string& message_type, const nlohmann::json& data, SendCallback callback) {
    if (!running_.load()) {
        LOG_CLIENT_ERROR("Cannot send message '" << message_type << "' to peer " << peer_id << " - client is not running");
        if (callback) {
            callback(false, "Client is not running");
        }
        return;
    }
    
    LOG_CLIENT_INFO("Sending targeted message type '" << message_type << "' to peer " << peer_id << " with data: " << data.dump());
    
    // Create rats message
    nlohmann::json message = create_rats_message(message_type, data, get_our_peer_id());
    
    // Send to specific peer
    socket_t target_socket = INVALID_SOCKET_VALUE;
    bool peer_found = false;
    bool handshake_completed = false;
    
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        auto it = peers_.find(peer_id);
        if (it != peers_.end()) {
            peer_found = true;
            handshake_completed = it->second.is_handshake_completed();
            if (handshake_completed) {
                target_socket = it->second.socket;
            }
        }
    }
    
    if (!peer_found) {
        LOG_CLIENT_ERROR("Cannot send message '" << message_type << "' - peer not found: " << peer_id);
        if (callback) {
            callback(false, "Peer not found: " + peer_id);
        }
        return;
    }
    
    if (!handshake_completed) {
        LOG_CLIENT_ERROR("Cannot send message '" << message_type << "' - peer handshake not completed: " << peer_id);
        if (callback) {
            callback(false, "Peer handshake not completed: " + peer_id);
        }
        return;
    }
    
    bool success = send_json_to_peer(target_socket, message);
    
    LOG_CLIENT_INFO("Sent message type '" << message_type << "' to peer " << peer_id << " - " << (success ? "success" : "failed"));
    
    if (callback) {
        if (success) {
            callback(true, "");
        } else {
            callback(false, "Failed to send message to peer: " + peer_id);
        }
    }
}

// Message exchange system helpers
void RatsClient::call_message_handlers(const std::string& message_type, const std::string& peer_id, const nlohmann::json& data) {
    std::vector<MessageHandler> handlers_to_call;
    std::vector<MessageHandler> remaining_handlers;
    
    LOG_CLIENT_INFO("Calling message handlers for type '" << message_type << "' from peer " << peer_id << " with data: " << data.dump());
    
    // Get handlers to call and identify once handlers
    {
        std::lock_guard<std::mutex> lock(message_handlers_mutex_);
        auto it = message_handlers_.find(message_type);
        if (it != message_handlers_.end()) {
            handlers_to_call = it->second; // Copy handlers
            
            // Keep only non-once handlers for the remaining list
            for (const auto& handler : it->second) {
                if (!handler.is_once) {
                    remaining_handlers.push_back(handler);
                }
            }
            
            // Update the handlers list (removes once handlers)
            it->second = remaining_handlers;
        } else {
            LOG_CLIENT_WARN("No handlers registered for message type '" << message_type << "'");
        }
    }
    
    LOG_CLIENT_INFO("Found " << handlers_to_call.size() << " handlers for message type '" << message_type << "'");
    
    // Call handlers outside of mutex to avoid deadlock
    for (const auto& handler : handlers_to_call) {
        try {
            LOG_CLIENT_INFO("Calling handler for message type '" << message_type << "'");
            handler.callback(peer_id, data);
            LOG_CLIENT_INFO("Handler for message type '" << message_type << "' completed successfully");
        } catch (const std::exception& e) {
            LOG_CLIENT_ERROR("Exception in message handler for type '" << message_type << "': " << e.what());
        } catch (...) {
            LOG_CLIENT_ERROR("Unknown exception in message handler for type '" << message_type << "'");
        }
    }
    
    if (!handlers_to_call.empty()) {
        LOG_CLIENT_INFO("Called " << handlers_to_call.size() << " handlers for message type '" << message_type << "'");
    }
}

void RatsClient::remove_once_handlers(const std::string& message_type) {
    std::lock_guard<std::mutex> lock(message_handlers_mutex_);
    auto it = message_handlers_.find(message_type);
    if (it != message_handlers_.end()) {
        auto& handlers = it->second;
        auto new_end = std::remove_if(handlers.begin(), handlers.end(), 
                                     [](const MessageHandler& handler) { return handler.is_once; });
        handlers.erase(new_end, handlers.end());
        
        // Remove the entire entry if no handlers remain
        if (handlers.empty()) {
            message_handlers_.erase(it);
        }
    }
}

} // namespace librats