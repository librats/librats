#include "dht.h"
#include "logger.h"
#include <random>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cmath>

// DHT module logging macros
#define LOG_DHT_DEBUG(message) LOG_DEBUG("dht", message)
#define LOG_DHT_INFO(message)  LOG_INFO("dht", message)
#define LOG_DHT_WARN(message)  LOG_WARN("dht", message)
#define LOG_DHT_ERROR(message) LOG_ERROR("dht", message)

namespace librats {

// Hash function for UdpPeer
struct UdpPeerHash {
    std::size_t operator()(const UdpPeer& peer) const {
        std::hash<std::string> hasher;
        return hasher(peer.ip + ":" + std::to_string(peer.port));
    }
};

// Hash function for InfoHash
struct InfoHashHash {
    std::size_t operator()(const InfoHash& hash) const {
        std::size_t result = 0;
        for (size_t i = 0; i < NODE_ID_SIZE; ++i) {
            result ^= std::hash<uint8_t>{}(hash[i]) + 0x9e3779b9 + (result << 6) + (result >> 2);
        }
        return result;
    }
};

} // namespace librats

// Specialize std::hash for UdpPeer and InfoHash
namespace std {
template<>
struct hash<librats::UdpPeer> {
    std::size_t operator()(const librats::UdpPeer& peer) const {
        return librats::UdpPeerHash{}(peer);
    }
};

template<>
struct hash<librats::InfoHash> {
    std::size_t operator()(const librats::InfoHash& hash) const {
        return librats::InfoHashHash{}(hash);
    }
};
} // namespace std

namespace librats {

DhtClient::DhtClient(int port) 
    : port_(port), socket_(INVALID_SOCKET_VALUE), running_(false) {
    node_id_ = generate_node_id();
    routing_table_.resize(NODE_ID_SIZE * 8);  // 160 buckets for 160-bit node IDs
    
    LOG_DHT_INFO("DHT client created with node ID: " << node_id_to_hex(node_id_));
}

DhtClient::~DhtClient() {
    stop();
}

bool DhtClient::start() {
    if (running_) {
        return true;
    }
    
    LOG_DHT_INFO("Starting DHT client on port " << port_);
    
    socket_ = create_udp_socket(port_);
    if (!is_valid_udp_socket(socket_)) {
        LOG_DHT_ERROR("Failed to create UDP socket");
        return false;
    }
    
    if (!set_udp_socket_nonblocking(socket_)) {
        LOG_DHT_WARN("Failed to set socket to non-blocking mode");
    }
    
    running_ = true;
    
    // Start network and maintenance threads
    network_thread_ = std::thread(&DhtClient::network_loop, this);
    maintenance_thread_ = std::thread(&DhtClient::maintenance_loop, this);
    
    LOG_DHT_INFO("DHT client started successfully");
    return true;
}

void DhtClient::stop() {
    if (!running_) {
        return;
    }
    
    LOG_DHT_INFO("Stopping DHT client");
    running_ = false;
    
    // Wait for threads to finish
    if (network_thread_.joinable()) {
        network_thread_.join();
    }
    if (maintenance_thread_.joinable()) {
        maintenance_thread_.join();
    }
    
    // Close socket
    if (is_valid_udp_socket(socket_)) {
        close_udp_socket(socket_);
        socket_ = INVALID_SOCKET_VALUE;
    }
    
    LOG_DHT_INFO("DHT client stopped");
}

bool DhtClient::bootstrap(const std::vector<UdpPeer>& bootstrap_nodes) {
    if (!running_) {
        LOG_DHT_ERROR("DHT client not running");
        return false;
    }
    
    LOG_DHT_INFO("Bootstrapping DHT with " << bootstrap_nodes.size() << " nodes");
    
    // Send ping to bootstrap nodes
    for (const auto& peer : bootstrap_nodes) {
        send_ping(peer);
    }
    
    // Start node discovery by finding our own node
    for (const auto& peer : bootstrap_nodes) {
        send_find_node(peer, node_id_);
    }
    
    return true;
}

bool DhtClient::find_peers(const InfoHash& info_hash, PeerDiscoveryCallback callback) {
    if (!running_) {
        LOG_DHT_ERROR("DHT client not running");
        return false;
    }
    
    LOG_DHT_INFO("Finding peers for info hash: " << node_id_to_hex(info_hash));
    
    {
        std::lock_guard<std::mutex> lock(active_searches_mutex_);
        active_searches_[info_hash] = callback;
    }
    
    // Start search by querying closest nodes
    auto closest_nodes = find_closest_nodes(info_hash, ALPHA);
    for (const auto& node : closest_nodes) {
        send_get_peers(node.peer, info_hash);
    }
    
    return true;
}

bool DhtClient::announce_peer(const InfoHash& info_hash, uint16_t port) {
    if (!running_) {
        LOG_DHT_ERROR("DHT client not running");
        return false;
    }
    
    if (port == 0) {
        port = port_;
    }
    
    LOG_DHT_INFO("Announcing peer for info hash: " << node_id_to_hex(info_hash) << " on port " << port);
    
    // First find nodes close to the info hash
    auto closest_nodes = find_closest_nodes(info_hash, ALPHA);
    for (const auto& node : closest_nodes) {
        send_get_peers(node.peer, info_hash);
    }
    
    return true;
}

size_t DhtClient::get_routing_table_size() const {
    std::lock_guard<std::mutex> lock(routing_table_mutex_);
    size_t total = 0;
    for (const auto& bucket : routing_table_) {
        total += bucket.size();
    }
    return total;
}

std::vector<UdpPeer> DhtClient::get_default_bootstrap_nodes() {
    return {
        {"router.bittorrent.com", 6881},
        {"dht.transmissionbt.com", 6881},
        {"router.utorrent.com", 6881},
        {"dht.aelitis.com", 6881}
    };
}

void DhtClient::network_loop() {
    LOG_DHT_DEBUG("Network loop started");
    
    while (running_) {
        UdpPeer sender;
        auto data = receive_udp_data(socket_, 1500, sender);  // MTU size
        
        if (!data.empty()) {
            handle_message(data, sender);
        }
        
        // Small delay to prevent busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    LOG_DHT_DEBUG("Network loop stopped");
}

void DhtClient::maintenance_loop() {
    LOG_DHT_DEBUG("Maintenance loop started");
    
    while (running_) {
        // Cleanup stale nodes every 5 minutes
        cleanup_stale_nodes();
        
        // Refresh buckets every 15 minutes
        refresh_buckets();
        
        // Sleep for 1 minute between maintenance cycles
        for (int i = 0; i < 60 && running_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    LOG_DHT_DEBUG("Maintenance loop stopped");
}

void DhtClient::handle_message(const std::vector<uint8_t>& data, const UdpPeer& sender) {
    auto message = decode_message(data);
    if (!message) {
        LOG_DHT_WARN("Failed to decode message from " << sender.ip << ":" << sender.port);
        return;
    }
    
    LOG_DHT_DEBUG("Received message type " << static_cast<int>(message->type) << " from " << sender.ip << ":" << sender.port);
    
    // Add sender to routing table
    DhtNode sender_node(message->sender_id, sender);
    add_node(sender_node);
    
    switch (message->type) {
        case DhtMessageType::PING:
            handle_ping(*message, sender);
            break;
        case DhtMessageType::FIND_NODE:
            handle_find_node(*message, sender);
            break;
        case DhtMessageType::GET_PEERS:
            handle_get_peers(*message, sender);
            break;
        case DhtMessageType::ANNOUNCE_PEER:
            handle_announce_peer(*message, sender);
            break;
    }
}

void DhtClient::handle_ping(const DhtMessage& message, const UdpPeer& sender) {
    // Respond with pong
    DhtMessage response(DhtMessageType::PING, node_id_);
    send_message(response, sender);
}

void DhtClient::handle_find_node(const DhtMessage& message, const UdpPeer& sender) {
    auto closest_nodes = find_closest_nodes(message.target_id, K_BUCKET_SIZE);
    
    DhtMessage response(DhtMessageType::FIND_NODE, node_id_);
    response.nodes = closest_nodes;
    
    send_message(response, sender);
}

void DhtClient::handle_get_peers(const DhtMessage& message, const UdpPeer& sender) {
    // Generate token for this peer
    std::string token = generate_token(sender);
    
    DhtMessage response(DhtMessageType::GET_PEERS, node_id_);
    response.token = token;
    
    // For now, we don't store actual peers, so just return closest nodes
    response.nodes = find_closest_nodes(message.target_id, K_BUCKET_SIZE);
    
    send_message(response, sender);
}

void DhtClient::handle_announce_peer(const DhtMessage& message, const UdpPeer& sender) {
    // Verify token
    if (!verify_token(sender, message.token)) {
        LOG_DHT_WARN("Invalid token from " << sender.ip << ":" << sender.port);
        return;
    }
    
    // Store the peer announcement (simplified - in real implementation would store in peer table)
    LOG_DHT_INFO("Peer announced: " << sender.ip << ":" << message.announce_port 
                 << " for info hash: " << node_id_to_hex(message.target_id));
    
    // Respond with success
    DhtMessage response(DhtMessageType::ANNOUNCE_PEER, node_id_);
    send_message(response, sender);
}

void DhtClient::send_ping(const UdpPeer& peer) {
    DhtMessage message(DhtMessageType::PING, node_id_);
    send_message(message, peer);
}

void DhtClient::send_find_node(const UdpPeer& peer, const NodeId& target) {
    DhtMessage message(DhtMessageType::FIND_NODE, node_id_);
    message.target_id = target;
    send_message(message, peer);
}

void DhtClient::send_get_peers(const UdpPeer& peer, const InfoHash& info_hash) {
    DhtMessage message(DhtMessageType::GET_PEERS, node_id_);
    message.target_id = info_hash;
    send_message(message, peer);
}

void DhtClient::send_announce_peer(const UdpPeer& peer, const InfoHash& info_hash, uint16_t port, const std::string& token) {
    DhtMessage message(DhtMessageType::ANNOUNCE_PEER, node_id_);
    message.target_id = info_hash;
    message.announce_port = port;
    message.token = token;
    send_message(message, peer);
}

bool DhtClient::send_message(const DhtMessage& message, const UdpPeer& peer) {
    auto data = encode_message(message);
    if (data.empty()) {
        LOG_DHT_ERROR("Failed to encode message");
        return false;
    }
    
    int result = send_udp_data(socket_, data, peer);
    return result > 0;
}

std::vector<uint8_t> DhtClient::encode_message(const DhtMessage& message) {
    std::vector<uint8_t> data;
    
    // Simple binary encoding
    data.push_back(static_cast<uint8_t>(message.type));
    data.insert(data.end(), message.sender_id.begin(), message.sender_id.end());
    data.insert(data.end(), message.target_id.begin(), message.target_id.end());
    
    // Encode nodes
    data.push_back(static_cast<uint8_t>(message.nodes.size()));
    for (const auto& node : message.nodes) {
        data.insert(data.end(), node.id.begin(), node.id.end());
        
        // Encode IP address (4 bytes for IPv4)
        in_addr addr;
        inet_pton(AF_INET, node.peer.ip.c_str(), &addr);
        uint32_t ip = ntohl(addr.s_addr);
        data.push_back((ip >> 24) & 0xFF);
        data.push_back((ip >> 16) & 0xFF);
        data.push_back((ip >> 8) & 0xFF);
        data.push_back(ip & 0xFF);
        
        // Encode port (2 bytes)
        data.push_back((node.peer.port >> 8) & 0xFF);
        data.push_back(node.peer.port & 0xFF);
    }
    
    // Encode peers
    data.push_back(static_cast<uint8_t>(message.peers.size()));
    for (const auto& peer : message.peers) {
        // Encode IP address (4 bytes for IPv4)
        in_addr addr;
        inet_pton(AF_INET, peer.ip.c_str(), &addr);
        uint32_t ip = ntohl(addr.s_addr);
        data.push_back((ip >> 24) & 0xFF);
        data.push_back((ip >> 16) & 0xFF);
        data.push_back((ip >> 8) & 0xFF);
        data.push_back(ip & 0xFF);
        
        // Encode port (2 bytes)
        data.push_back((peer.port >> 8) & 0xFF);
        data.push_back(peer.port & 0xFF);
    }
    
    // Encode announce port
    data.push_back((message.announce_port >> 8) & 0xFF);
    data.push_back(message.announce_port & 0xFF);
    
    // Encode token
    data.push_back(static_cast<uint8_t>(message.token.size()));
    data.insert(data.end(), message.token.begin(), message.token.end());
    
    return data;
}

std::unique_ptr<DhtMessage> DhtClient::decode_message(const std::vector<uint8_t>& data) {
    if (data.size() < 1 + NODE_ID_SIZE * 2 + 4) {  // Minimum size
        return nullptr;
    }
    
    size_t offset = 0;
    
    // Decode message type
    auto type = static_cast<DhtMessageType>(data[offset++]);
    
    // Decode sender ID
    NodeId sender_id;
    std::copy(data.begin() + offset, data.begin() + offset + NODE_ID_SIZE, sender_id.begin());
    offset += NODE_ID_SIZE;
    
    auto message = std::make_unique<DhtMessage>(type, sender_id);
    
    // Decode target ID
    std::copy(data.begin() + offset, data.begin() + offset + NODE_ID_SIZE, message->target_id.begin());
    offset += NODE_ID_SIZE;
    
    if (offset >= data.size()) return message;
    
    // Decode nodes
    uint8_t node_count = data[offset++];
    for (int i = 0; i < node_count && offset + NODE_ID_SIZE + 6 <= data.size(); ++i) {
        NodeId node_id;
        std::copy(data.begin() + offset, data.begin() + offset + NODE_ID_SIZE, node_id.begin());
        offset += NODE_ID_SIZE;
        
        // Decode IP address
        uint32_t ip = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        
        // Decode port
        uint16_t port = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        
        // Convert IP to string
        struct in_addr addr;
        addr.s_addr = htonl(ip);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        
        message->nodes.emplace_back(node_id, UdpPeer(ip_str, port));
    }
    
    if (offset >= data.size()) return message;
    
    // Decode peers
    uint8_t peer_count = data[offset++];
    for (int i = 0; i < peer_count && offset + 6 <= data.size(); ++i) {
        // Decode IP address
        uint32_t ip = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        
        // Decode port
        uint16_t port = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        
        // Convert IP to string
        struct in_addr addr;
        addr.s_addr = htonl(ip);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        
        message->peers.emplace_back(ip_str, port);
    }
    
    if (offset + 2 < data.size()) {
        // Decode announce port
        message->announce_port = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        
        if (offset < data.size()) {
            // Decode token
            uint8_t token_size = data[offset++];
            if (offset + token_size <= data.size()) {
                message->token = std::string(data.begin() + offset, data.begin() + offset + token_size);
            }
        }
    }
    
    return message;
}

void DhtClient::add_node(const DhtNode& node) {
    std::lock_guard<std::mutex> lock(routing_table_mutex_);
    
    int bucket_index = get_bucket_index(node.id);
    auto& bucket = routing_table_[bucket_index];
    
    // Check if node already exists
    auto it = std::find_if(bucket.begin(), bucket.end(),
                          [&node](const DhtNode& existing) {
                              return existing.id == node.id;
                          });
    
    if (it != bucket.end()) {
        // Update existing node
        it->peer = node.peer;
        it->last_seen = std::chrono::steady_clock::now();
        return;
    }
    
    // Add new node
    if (bucket.size() < K_BUCKET_SIZE) {
        bucket.push_back(node);
        LOG_DHT_DEBUG("Added node to bucket " << bucket_index << " (size: " << bucket.size() << ")");
    } else {
        // Bucket is full, replace least recently seen node
        auto oldest_it = std::min_element(bucket.begin(), bucket.end(),
                                         [](const DhtNode& a, const DhtNode& b) {
                                             return a.last_seen < b.last_seen;
                                         });
        *oldest_it = node;
        LOG_DHT_DEBUG("Replaced oldest node in bucket " << bucket_index);
    }
}

std::vector<DhtNode> DhtClient::find_closest_nodes(const NodeId& target, size_t count) {
    std::lock_guard<std::mutex> lock(routing_table_mutex_);
    
    std::vector<DhtNode> all_nodes;
    for (const auto& bucket : routing_table_) {
        all_nodes.insert(all_nodes.end(), bucket.begin(), bucket.end());
    }
    
    // Sort by distance to target
    std::sort(all_nodes.begin(), all_nodes.end(),
              [&target, this](const DhtNode& a, const DhtNode& b) {
                  return is_closer(a.id, b.id, target);
              });
    
    // Return up to 'count' closest nodes
    if (all_nodes.size() > count) {
        all_nodes.resize(count);
    }
    
    return all_nodes;
}

int DhtClient::get_bucket_index(const NodeId& id) {
    NodeId distance = xor_distance(node_id_, id);
    
    // Find the position of the most significant bit
    for (int i = 0; i < NODE_ID_SIZE; ++i) {
        if (distance[i] != 0) {
            for (int j = 7; j >= 0; --j) {
                if (distance[i] & (1 << j)) {
                    return i * 8 + (7 - j);
                }
            }
        }
    }
    
    return NODE_ID_SIZE * 8 - 1;  // All bits are 0, maximum distance
}

NodeId DhtClient::generate_node_id() {
    NodeId id;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < NODE_ID_SIZE; ++i) {
        id[i] = dis(gen);
    }
    
    return id;
}

NodeId DhtClient::xor_distance(const NodeId& a, const NodeId& b) {
    NodeId result;
    for (size_t i = 0; i < NODE_ID_SIZE; ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

bool DhtClient::is_closer(const NodeId& a, const NodeId& b, const NodeId& target) {
    NodeId dist_a = xor_distance(a, target);
    NodeId dist_b = xor_distance(b, target);
    
    return std::lexicographical_compare(dist_a.begin(), dist_a.end(),
                                       dist_b.begin(), dist_b.end());
}

std::string DhtClient::generate_token(const UdpPeer& peer) {
    // Simple token generation (in real implementation, use proper cryptographic hash)
    std::string data = peer.ip + ":" + std::to_string(peer.port);
    std::hash<std::string> hasher;
    size_t hash = hasher(data);
    
    // Convert hash to hex string
    std::ostringstream oss;
    oss << std::hex << hash;
    return oss.str();
}

bool DhtClient::verify_token(const UdpPeer& peer, const std::string& token) {
    return token == generate_token(peer);
}

void DhtClient::cleanup_stale_nodes() {
    std::lock_guard<std::mutex> lock(routing_table_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto stale_threshold = std::chrono::minutes(15);
    
    for (auto& bucket : routing_table_) {
        bucket.erase(std::remove_if(bucket.begin(), bucket.end(),
                                   [now, stale_threshold](const DhtNode& node) {
                                       return now - node.last_seen > stale_threshold;
                                   }), bucket.end());
    }
}

void DhtClient::refresh_buckets() {
    // Find random nodes in each bucket to refresh
    std::lock_guard<std::mutex> lock(routing_table_mutex_);
    
    for (size_t i = 0; i < routing_table_.size(); ++i) {
        if (routing_table_[i].empty()) {
            // Generate a random node ID in this bucket's range
            NodeId random_id = generate_node_id();
            
            // Set the appropriate bits to place it in bucket i
            int byte_index = i / 8;
            int bit_index = i % 8;
            
            if (byte_index < NODE_ID_SIZE) {
                // Clear the target bit and higher bits
                for (int j = byte_index; j < NODE_ID_SIZE; ++j) {
                    random_id[j] = node_id_[j];
                }
                
                // Set the target bit
                random_id[byte_index] |= (1 << (7 - bit_index));
                
                // Find nodes to query
                auto closest_nodes = find_closest_nodes(random_id, ALPHA);
                for (const auto& node : closest_nodes) {
                    send_find_node(node.peer, random_id);
                }
            }
        }
    }
}

// Utility functions implementation
NodeId string_to_node_id(const std::string& str) {
    NodeId id;
    size_t copy_size = std::min(str.size(), NODE_ID_SIZE);
    std::copy(str.begin(), str.begin() + copy_size, id.begin());
    return id;
}

std::string node_id_to_string(const NodeId& id) {
    return std::string(id.begin(), id.end());
}

NodeId hex_to_node_id(const std::string& hex) {
    NodeId id;
    if (hex.size() != NODE_ID_SIZE * 2) {
        return id;  // Return zero-filled ID on error
    }
    
    for (size_t i = 0; i < NODE_ID_SIZE; ++i) {
        std::string byte_str = hex.substr(i * 2, 2);
        id[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
    
    return id;
}

std::string node_id_to_hex(const NodeId& id) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : id) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

} // namespace librats 