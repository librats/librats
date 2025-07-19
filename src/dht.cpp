#include "dht.h"
#include "network_utils.h"
#include "logger.h"
#include "socket.h"
#include <random>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cmath>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

// DHT module logging macros
#define LOG_DHT_DEBUG(message) LOG_DEBUG("dht", message)
#define LOG_DHT_INFO(message)  LOG_INFO("dht", message)
#define LOG_DHT_WARN(message)  LOG_WARN("dht", message)
#define LOG_DHT_ERROR(message) LOG_ERROR("dht", message)

namespace librats {

// Static variable initialization
std::atomic<uint32_t> DhtClient::rats_dht_transaction_counter_ = 0;

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
    
    // Initialize socket library (safe to call multiple times)
    if (!init_socket_library()) {
        LOG_DHT_ERROR("Failed to initialize socket library");
        return false;
    }
    
    socket_ = create_udp_socket(port_);
    if (!is_valid_socket(socket_)) {
        LOG_DHT_ERROR("Failed to create dual-stack UDP socket");
        return false;
    }
    
    if (!set_socket_nonblocking(socket_)) {
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
    
    // Trigger immediate shutdown of all background threads
    shutdown_immediate();
    
    // Wait for threads to finish
    if (network_thread_.joinable()) {
        network_thread_.join();
    }
    if (maintenance_thread_.joinable()) {
        maintenance_thread_.join();
    }
    
    // Close socket
    if (is_valid_socket(socket_)) {
        close_socket(socket_);
        socket_ = INVALID_SOCKET_VALUE;
    }
    
    LOG_DHT_INFO("DHT client stopped");
}

void DhtClient::shutdown_immediate() {
    LOG_DHT_INFO("Triggering immediate shutdown of DHT background threads");
    
    running_.store(false);
    
    // Notify all waiting threads to wake up immediately
    shutdown_cv_.notify_all();
}

bool DhtClient::bootstrap(const std::vector<Peer>& bootstrap_nodes) {
    if (!running_) {
        LOG_DHT_ERROR("DHT client not running");
        return false;
    }
    
    LOG_DHT_INFO("Bootstrapping DHT with " << bootstrap_nodes.size() << " nodes");
    LOG_DHT_DEBUG("Bootstrap nodes:");
    for (const auto& peer : bootstrap_nodes) {
        LOG_DHT_DEBUG("  - " << peer.ip << ":" << peer.port);
    }
    
    // Pre-set protocol for known BitTorrent bootstrap nodes
    for (const auto& peer : bootstrap_nodes) {
        if (is_known_bittorrent_bootstrap_node(peer)) {
            LOG_DHT_DEBUG("Setting BitTorrent protocol for known bootstrap node: " << peer.ip << ":" << peer.port);
            set_peer_protocol(peer, PeerProtocol::BitTorrent);
        }
    }
    
    // Send ping to bootstrap nodes
    LOG_DHT_DEBUG("Sending PING to all bootstrap nodes");
    for (const auto& peer : bootstrap_nodes) {
        send_ping(peer);
    }
    
    // Start node discovery by finding our own node
    LOG_DHT_DEBUG("Starting node discovery by finding our own node ID: " << node_id_to_hex(node_id_));
    for (const auto& peer : bootstrap_nodes) {
        send_find_node(peer, node_id_);
    }
    
    LOG_DHT_DEBUG("Bootstrap process initiated");
    return true;
}

bool DhtClient::find_peers(const InfoHash& info_hash, PeerDiscoveryCallback callback, int iteration_max) {
    if (!running_) {
        LOG_DHT_ERROR("DHT client not running");
        return false;
    }
    
    LOG_DHT_INFO("Finding peers for info hash: " << node_id_to_hex(info_hash));
    
    {
        std::lock_guard<std::mutex> lock(active_searches_mutex_);
        std::string hash_key = node_id_to_hex(info_hash);
        active_searches_[hash_key] = callback;
    }
    
    // Start search by querying closest nodes
    auto closest_nodes = find_closest_nodes(info_hash, ALPHA);
    std::string hash_key = node_id_to_hex(info_hash);
    
    {
        std::lock_guard<std::mutex> lock(pending_searches_mutex_);
        // Create or get existing PendingSearch for this info_hash
        auto search_it = pending_searches_.find(hash_key);
        if (search_it == pending_searches_.end()) {
            pending_searches_.emplace(hash_key, PendingSearch(info_hash, iteration_max));
        }
    }
    
    for (const auto& node : closest_nodes) {
        PeerProtocol protocol = get_peer_protocol(node.peer);
        
        if (protocol == PeerProtocol::BitTorrent) {
            // Generate transaction ID and track this as a pending search for KRPC
            std::string transaction_id = KrpcProtocol::generate_transaction_id();
            
            {
                std::lock_guard<std::mutex> lock(pending_searches_mutex_);
                transaction_to_search_[transaction_id] = hash_key;
                auto search_it = pending_searches_.find(hash_key);
                if (search_it != pending_searches_.end()) {
                    search_it->second.queried_nodes.insert(node_id_to_hex(node.id));
                }
            }
            
            auto message = KrpcProtocol::create_get_peers_query(transaction_id, node_id_, info_hash);
            send_krpc_message(message, node.peer);
        } else {
            // For rats DHT protocol, also use proper transaction tracking
            std::string transaction_id = generate_rats_dht_transaction_id();
            
            {
                std::lock_guard<std::mutex> lock(pending_searches_mutex_);
                transaction_to_search_[transaction_id] = hash_key;
                auto search_it = pending_searches_.find(hash_key);
                if (search_it != pending_searches_.end()) {
                    search_it->second.queried_nodes.insert(node_id_to_hex(node.id));
                }
            }
            
            // Send get_peers with transaction ID for rats dht protocol
            DhtMessage message(DhtMessageType::GET_PEERS, transaction_id, node_id_);
            message.target_id = info_hash;
            send_message(message, node.peer);
        }
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
    
    // First find nodes close to the info hash and send get_peers to them
    // This is the proper BEP 5 flow: get_peers -> collect tokens -> announce_peer
    auto closest_nodes = find_closest_nodes(info_hash, ALPHA);
    for (const auto& node : closest_nodes) {
        PeerProtocol protocol = get_peer_protocol(node.peer);
        
        if (protocol == PeerProtocol::BitTorrent) {
            // Generate transaction ID and track this as a pending announce for KRPC
            std::string transaction_id = KrpcProtocol::generate_transaction_id();
            
            {
                std::lock_guard<std::mutex> lock(pending_announces_mutex_);
                pending_announces_.emplace(transaction_id, PendingAnnounce(info_hash, port));
            }
            
            auto message = KrpcProtocol::create_get_peers_query(transaction_id, node_id_, info_hash);
            send_krpc_message(message, node.peer);
        } else {
            // For rats DHT protocol, also use proper transaction tracking
            std::string transaction_id = generate_rats_dht_transaction_id();
            
            {
                std::lock_guard<std::mutex> lock(pending_announces_mutex_);
                pending_announces_.emplace(transaction_id, PendingAnnounce(info_hash, port));
            }
            
            // Send get_peers with transaction ID for rats dht protocol
            DhtMessage message(DhtMessageType::GET_PEERS, transaction_id, node_id_);
            message.target_id = info_hash;
            send_message(message, node.peer);
        }
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

std::vector<Peer> DhtClient::get_default_bootstrap_nodes() {
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
        Peer sender;
        auto data = receive_udp_data(socket_, 1500, sender);  // MTU size
        
        if (!data.empty()) {
            LOG_DHT_DEBUG("Received " << data.size() << " bytes from " << sender.ip << ":" << sender.port);
            handle_message(data, sender);
        }
        
        // Use conditional variable for responsive shutdown
        {
            std::unique_lock<std::mutex> lock(shutdown_mutex_);
            if (shutdown_cv_.wait_for(lock, std::chrono::milliseconds(10), [this] { return !running_.load(); })) {
                break;
            }
        }
    }
    
    LOG_DHT_DEBUG("Network loop stopped");
}

void DhtClient::maintenance_loop() {
    LOG_DHT_DEBUG("Maintenance loop started");
    
    auto last_bucket_refresh = std::chrono::steady_clock::now();
    
    while (running_) {
        auto now = std::chrono::steady_clock::now();

        // Cleanup stale nodes every 5 minutes
        cleanup_stale_nodes();
        
        // Cleanup stale pending announces
        cleanup_stale_announces();
        
        // Cleanup stale pending searches
        cleanup_stale_searches();
        

        
        // Cleanup stale announced peers
        cleanup_stale_announced_peers();
        
        // Refresh buckets every 30 minutes
        if (now - last_bucket_refresh >= std::chrono::minutes(30)) {
            refresh_buckets();
            last_bucket_refresh = now;
        }
        
        // Use conditional variable for responsive shutdown
        {
            std::unique_lock<std::mutex> lock(shutdown_mutex_);
            if (shutdown_cv_.wait_for(lock, std::chrono::minutes(1), [this] { return !running_.load(); })) {
                break;
            }
        }
    }
    
    LOG_DHT_DEBUG("Maintenance loop stopped");
}

void DhtClient::handle_message(const std::vector<uint8_t>& data, const Peer& sender) {
    LOG_DHT_DEBUG("Processing message of " << data.size() << " bytes from " << sender.ip << ":" << sender.port);
    
    // First, try to detect the protocol
    PeerProtocol protocol = get_peer_protocol(sender);
    if (protocol == PeerProtocol::Unknown) {
        protocol = detect_protocol(data);
        if (protocol != PeerProtocol::Unknown) {
            LOG_DHT_DEBUG("Detected protocol " << (protocol == PeerProtocol::BitTorrent ? "BitTorrent" : "RatsDht") << " for peer " << sender.ip << ":" << sender.port);
            set_peer_protocol(sender, protocol);
        }
    }
    
    if (protocol == PeerProtocol::BitTorrent) {
        LOG_DHT_DEBUG("Detected BitTorrent DHT (KRPC) protocol from " << sender.ip << ":" << sender.port);

        // Handle KRPC message
        auto krpc_message = KrpcProtocol::decode_message(data);
        if (!krpc_message) {
            LOG_DHT_WARN("Failed to decode KRPC message from " << sender.ip << ":" << sender.port);
            return;
        }
        
        handle_krpc_message(*krpc_message, sender);
    } else {
        // Try rats dht protocol first
        auto rats_dht_message = decode_message(data);
        if (rats_dht_message) {
            LOG_DHT_DEBUG("Decoded rats dht protocol message from " << sender.ip << ":" << sender.port);

            LOG_DHT_DEBUG("Received message type " << static_cast<int>(rats_dht_message->type) << " from " << node_id_to_hex(rats_dht_message->sender_id) << " at " << sender.ip << ":" << sender.port);
            
            // Add sender to routing table
            DhtNode sender_node(rats_dht_message->sender_id, sender);
            LOG_DHT_DEBUG("Adding/updating node " << node_id_to_hex(rats_dht_message->sender_id) << " in routing table");
            add_node(sender_node);
            
            switch (rats_dht_message->type) {
                case DhtMessageType::PING:
                    handle_ping(*rats_dht_message, sender);
                    break;
                case DhtMessageType::FIND_NODE:
                    handle_find_node(*rats_dht_message, sender);
                    break;
                case DhtMessageType::GET_PEERS:
                    handle_get_peers(*rats_dht_message, sender);
                    break;
                case DhtMessageType::ANNOUNCE_PEER:
                    handle_announce_peer(*rats_dht_message, sender);
                    break;
                default:
                    LOG_DHT_WARN("Unknown message type " << static_cast<int>(rats_dht_message->type) << " from " << sender.ip << ":" << sender.port);
                    break;
            }
        } else {
            LOG_DHT_WARN("Failed to decode message from " << sender.ip << ":" << sender.port << " with any protocol");
        }
    }
}

void DhtClient::handle_ping(const DhtMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling PING from " << node_id_to_hex(message.sender_id) << " at " << sender.ip << ":" << sender.port << " (transaction: " << message.transaction_id << ")");
    // Respond with pong using the same transaction ID
    DhtMessage response(DhtMessageType::PING, message.transaction_id, node_id_);
    LOG_DHT_DEBUG("Responding to PING with PONG to " << sender.ip << ":" << sender.port << " (transaction: " << message.transaction_id << ")");
    send_message(response, sender);
}

void DhtClient::handle_find_node(const DhtMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling FIND_NODE from " << node_id_to_hex(message.sender_id) << " at " << sender.ip << ":" << sender.port << " for target " << node_id_to_hex(message.target_id) << " (transaction: " << message.transaction_id << ")");
    
    auto closest_nodes = find_closest_nodes(message.target_id, K_BUCKET_SIZE);
    LOG_DHT_DEBUG("Found " << closest_nodes.size() << " closest nodes for target " << node_id_to_hex(message.target_id));
    
    DhtMessage response(DhtMessageType::FIND_NODE, message.transaction_id, node_id_);
    response.nodes = closest_nodes;
    
    LOG_DHT_DEBUG("Responding to FIND_NODE with " << response.nodes.size() << " nodes to " << sender.ip << ":" << sender.port << " (transaction: " << message.transaction_id << ")");
    send_message(response, sender);
}

void DhtClient::handle_get_peers(const DhtMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling GET_PEERS from " << node_id_to_hex(message.sender_id) << " at " << sender.ip << ":" << sender.port << " for info_hash " << node_id_to_hex(message.target_id) << " (transaction: " << message.transaction_id << ")");
    
    // Check if this is a response to our own get_peers request
    if (!message.peers.empty() || !message.nodes.empty()) {
        // Check if we have a pending search for this transaction
        {
            std::lock_guard<std::mutex> lock(pending_searches_mutex_);
            auto it = pending_searches_.find(message.transaction_id);
            if (it != pending_searches_.end()) {
                // This is a response to our get_peers request for search
                if (!message.peers.empty()) {
                    handle_get_peers_response_for_search_rats_dht(message.transaction_id, sender, message.peers);
                } else {
                    handle_get_peers_response_with_nodes_rats_dht(message.transaction_id, sender, message.nodes);
                }
                return;
            }
        }
        
        // Check if we have a pending announce for this transaction
        if (!message.token.empty()) {
            std::lock_guard<std::mutex> lock(pending_announces_mutex_);
            auto it = pending_announces_.find(message.transaction_id);
            if (it != pending_announces_.end()) {
                // This is a response to our get_peers request for announce
                handle_get_peers_response_for_announce_rats_dht(message.transaction_id, sender, message.token);
                return;
            }
        }
    }
    
    // Handle as a regular get_peers request
    DhtMessage response(DhtMessageType::GET_PEERS, message.transaction_id, node_id_);
    
    // First check if we have announced peers for this info_hash
    auto announced_peers = get_announced_peers(message.target_id);
    
    if (!announced_peers.empty()) {
        // Return the peers we have stored
        response.peers = announced_peers;
        LOG_DHT_DEBUG("Responding to GET_PEERS with " << response.peers.size() << " announced peers for info_hash " << node_id_to_hex(message.target_id));
    } else {
        // Return closest nodes
        auto closest_nodes = find_closest_nodes(message.target_id, K_BUCKET_SIZE);
        response.nodes = closest_nodes;
        LOG_DHT_DEBUG("Responding to GET_PEERS with " << response.nodes.size() << " closest nodes for info_hash " << node_id_to_hex(message.target_id));
    }
    
    // Generate a token for this peer
    std::string token = generate_token(sender);
    response.token = token;
    
    LOG_DHT_DEBUG("Sending GET_PEERS response with token '" << token << "' to " << sender.ip << ":" << sender.port << " (transaction: " << message.transaction_id << ")");
    send_message(response, sender);
}

void DhtClient::handle_announce_peer(const DhtMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling ANNOUNCE_PEER from " << node_id_to_hex(message.sender_id) << " at " << sender.ip << ":" << sender.port << " for info_hash " << node_id_to_hex(message.target_id) << " on port " << message.announce_port << " (transaction: " << message.transaction_id << ")");
    
    // Verify token
    if (!verify_token(sender, message.token)) {
        LOG_DHT_WARN("Invalid token '" << message.token << "' from " << sender.ip << ":" << sender.port << " for ANNOUNCE_PEER (transaction: " << message.transaction_id << ")");
        return;
    }
    
    LOG_DHT_DEBUG("Token verified, accepting announcement from " << sender.ip << ":" << sender.port);
    
    // Store the peer announcement
    Peer announcing_peer(sender.ip, message.announce_port);
    store_announced_peer(message.target_id, announcing_peer);
    
    DhtMessage response(DhtMessageType::ANNOUNCE_PEER, message.transaction_id, node_id_);
    LOG_DHT_DEBUG("Responding to ANNOUNCE_PEER with acknowledgment to " << sender.ip << ":" << sender.port << " (transaction: " << message.transaction_id << ")");
    send_message(response, sender);
}



bool DhtClient::send_message(const DhtMessage& message, const Peer& peer) {
    LOG_DHT_DEBUG("Encoding message type " << static_cast<int>(message.type) << " for " << peer.ip << ":" << peer.port);
    auto data = encode_message(message);
    if (data.empty()) {
        LOG_DHT_ERROR("Failed to encode message");
        return false;
    }
    
    LOG_DHT_DEBUG("Sending " << data.size() << " bytes to " << peer.ip << ":" << peer.port);
    int result = send_udp_data(socket_, data, peer);
    
    if (result > 0) {
        LOG_DHT_DEBUG("Successfully sent message type " << static_cast<int>(message.type) << " to " << peer.ip << ":" << peer.port);
    } else {
        LOG_DHT_ERROR("Failed to send message type " << static_cast<int>(message.type) << " to " << peer.ip << ":" << peer.port);
    }
    
    return result > 0;
}

std::vector<uint8_t> DhtClient::encode_message(const DhtMessage& message) {
    LOG_DHT_DEBUG("Encoding message: type=" << static_cast<int>(message.type) << 
                  ", transaction_id=" << message.transaction_id <<
                  ", sender=" << node_id_to_hex(message.sender_id) << 
                  ", target=" << node_id_to_hex(message.target_id) << 
                  ", nodes=" << message.nodes.size() << 
                  ", peers=" << message.peers.size() << 
                  ", announce_port=" << message.announce_port << 
                  ", token_size=" << message.token.size());
    
    std::vector<uint8_t> data;
    
    // Simple binary encoding
    data.push_back(static_cast<uint8_t>(message.type));
    
    // Encode transaction ID
    data.push_back(static_cast<uint8_t>(message.transaction_id.size()));
    data.insert(data.end(), message.transaction_id.begin(), message.transaction_id.end());
    
    data.insert(data.end(), message.sender_id.begin(), message.sender_id.end());
    data.insert(data.end(), message.target_id.begin(), message.target_id.end());
    
    // Encode nodes
    data.push_back(static_cast<uint8_t>(message.nodes.size()));
    for (const auto& node : message.nodes) {
        LOG_DHT_DEBUG("Encoding node: " << node_id_to_hex(node.id) << " at " << node.peer.ip << ":" << node.peer.port);
        data.insert(data.end(), node.id.begin(), node.id.end());
        
        // Encode IP address (support both IPv4 and IPv6)
        if (network_utils::is_valid_ipv4(node.peer.ip)) {
            // IPv4 address
            data.push_back(0x04);  // IPv4 flag
            in_addr addr;
            inet_pton(AF_INET, node.peer.ip.c_str(), &addr);
            uint32_t ip = ntohl(addr.s_addr);
            data.push_back((ip >> 24) & 0xFF);
            data.push_back((ip >> 16) & 0xFF);
            data.push_back((ip >> 8) & 0xFF);
            data.push_back(ip & 0xFF);
        } else if (network_utils::is_valid_ipv6(node.peer.ip)) {
            // IPv6 address
            data.push_back(0x06);  // IPv6 flag
            in6_addr addr;
            inet_pton(AF_INET6, node.peer.ip.c_str(), &addr);
            for (int i = 0; i < 16; ++i) {
                data.push_back(addr.s6_addr[i]);
            }
        } else {
            // Invalid IP address, treat as IPv4 with 0.0.0.0
            data.push_back(0x04);  // IPv4 flag
            data.push_back(0x00);
            data.push_back(0x00);
            data.push_back(0x00);
            data.push_back(0x00);
        }
        
        // Encode port (2 bytes)
        data.push_back((node.peer.port >> 8) & 0xFF);
        data.push_back(node.peer.port & 0xFF);
    }
    
    // Encode peers
    data.push_back(static_cast<uint8_t>(message.peers.size()));
    for (const auto& peer : message.peers) {
        LOG_DHT_DEBUG("Encoding peer: " << peer.ip << ":" << peer.port);
        // Encode IP address (support both IPv4 and IPv6)
        if (network_utils::is_valid_ipv4(peer.ip)) {
            // IPv4 address
            data.push_back(0x04);  // IPv4 flag
            in_addr addr;
            inet_pton(AF_INET, peer.ip.c_str(), &addr);
            uint32_t ip = ntohl(addr.s_addr);
            data.push_back((ip >> 24) & 0xFF);
            data.push_back((ip >> 16) & 0xFF);
            data.push_back((ip >> 8) & 0xFF);
            data.push_back(ip & 0xFF);
        } else if (network_utils::is_valid_ipv6(peer.ip)) {
            // IPv6 address
            data.push_back(0x06);  // IPv6 flag
            in6_addr addr;
            inet_pton(AF_INET6, peer.ip.c_str(), &addr);
            for (int i = 0; i < 16; ++i) {
                data.push_back(addr.s6_addr[i]);
            }
        } else {
            // Invalid IP address, treat as IPv4 with 0.0.0.0
            data.push_back(0x04);  // IPv4 flag
            data.push_back(0x00);
            data.push_back(0x00);
            data.push_back(0x00);
            data.push_back(0x00);
        }
        
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
    
    LOG_DHT_DEBUG("Encoded message to " << data.size() << " bytes");
    return data;
}

std::unique_ptr<DhtMessage> DhtClient::decode_message(const std::vector<uint8_t>& data) {
    LOG_DHT_DEBUG("Decoding message of " << data.size() << " bytes");
    
    if (data.size() < 1 + 1 + NODE_ID_SIZE * 2 + 4) {  // Minimum size with transaction ID
        LOG_DHT_ERROR("Message too small: " << data.size() << " bytes (minimum " << (1 + 1 + NODE_ID_SIZE * 2 + 4) << ")");
        return nullptr;
    }
    
    size_t offset = 0;
    
    // Decode message type
    auto type = static_cast<DhtMessageType>(data[offset++]);
    LOG_DHT_DEBUG("Decoded message type: " << static_cast<int>(type));
    
    // Decode transaction ID
    uint8_t transaction_id_size = data[offset++];
    if (offset + transaction_id_size > data.size()) {
        LOG_DHT_ERROR("Invalid transaction ID size: " << static_cast<int>(transaction_id_size));
        return nullptr;
    }
    std::string transaction_id(data.begin() + offset, data.begin() + offset + transaction_id_size);
    offset += transaction_id_size;
    LOG_DHT_DEBUG("Decoded transaction ID: " << transaction_id);
    
    // Decode sender ID
    NodeId sender_id;
    if (offset + NODE_ID_SIZE > data.size()) {
        LOG_DHT_ERROR("Insufficient data for sender ID");
        return nullptr;
    }
    std::copy(data.begin() + offset, data.begin() + offset + NODE_ID_SIZE, sender_id.begin());
    offset += NODE_ID_SIZE;
    LOG_DHT_DEBUG("Decoded sender ID: " << node_id_to_hex(sender_id));
    
    auto message = std::make_unique<DhtMessage>(type, transaction_id, sender_id);
    
    // Decode target ID
    std::copy(data.begin() + offset, data.begin() + offset + NODE_ID_SIZE, message->target_id.begin());
    offset += NODE_ID_SIZE;
    LOG_DHT_DEBUG("Decoded target ID: " << node_id_to_hex(message->target_id));
    
    if (offset >= data.size()) {
        LOG_DHT_DEBUG("Message decoded successfully (minimal)");
        return message;
    }
    
    // Decode nodes
    uint8_t node_count = data[offset++];
    LOG_DHT_DEBUG("Decoding " << static_cast<int>(node_count) << " nodes");
    for (int i = 0; i < node_count && offset + NODE_ID_SIZE + 1 < data.size(); ++i) {
        NodeId node_id;
        std::copy(data.begin() + offset, data.begin() + offset + NODE_ID_SIZE, node_id.begin());
        offset += NODE_ID_SIZE;
        
        // Check if we have enough data for IP version flag
        if (offset >= data.size()) break;
        
        // Decode IP address (support both IPv4 and IPv6)
        uint8_t ip_version = data[offset++];
        std::string ip_str;
        
        if (ip_version == 0x04) {
            // IPv4 address
            if (offset + 4 > data.size()) break;
            uint32_t ip = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
            offset += 4;
            
            struct in_addr addr;
            addr.s_addr = htonl(ip);
            char ip_str_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str_buf, INET_ADDRSTRLEN);
            ip_str = ip_str_buf;
        } else if (ip_version == 0x06) {
            // IPv6 address
            if (offset + 16 > data.size()) break;
            struct in6_addr addr;
            for (int j = 0; j < 16; ++j) {
                addr.s6_addr[j] = data[offset + j];
            }
            offset += 16;
            
            char ip_str_buf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr, ip_str_buf, INET6_ADDRSTRLEN);
            ip_str = ip_str_buf;
        } else {
            // Unknown IP version, skip this node
            LOG_DHT_WARN("Unknown IP version " << static_cast<int>(ip_version) << " in node data");
            break;
        }
        
        // Decode port
        if (offset + 2 > data.size()) break;
        uint16_t port = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        
        LOG_DHT_DEBUG("Decoded node: " << node_id_to_hex(node_id) << " at " << ip_str << ":" << port);
        message->nodes.emplace_back(node_id, Peer(ip_str, port));
    }
    
    if (offset >= data.size()) {
        LOG_DHT_DEBUG("Message decoded successfully (with nodes)");
        return message;
    }
    
    // Decode peers
    uint8_t peer_count = data[offset++];
    LOG_DHT_DEBUG("Decoding " << static_cast<int>(peer_count) << " peers");
    for (int i = 0; i < peer_count && offset + 1 < data.size(); ++i) {
        // Check if we have enough data for IP version flag
        if (offset >= data.size()) break;
        
        // Decode IP address (support both IPv4 and IPv6)
        uint8_t ip_version = data[offset++];
        std::string ip_str;
        
        if (ip_version == 0x04) {
            // IPv4 address
            if (offset + 4 > data.size()) break;
            uint32_t ip = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
            offset += 4;
            
            struct in_addr addr;
            addr.s_addr = htonl(ip);
            char ip_str_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str_buf, INET_ADDRSTRLEN);
            ip_str = ip_str_buf;
        } else if (ip_version == 0x06) {
            // IPv6 address
            if (offset + 16 > data.size()) break;
            struct in6_addr addr;
            for (int j = 0; j < 16; ++j) {
                addr.s6_addr[j] = data[offset + j];
            }
            offset += 16;
            
            char ip_str_buf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr, ip_str_buf, INET6_ADDRSTRLEN);
            ip_str = ip_str_buf;
        } else {
            // Unknown IP version, skip this peer
            LOG_DHT_WARN("Unknown IP version " << static_cast<int>(ip_version) << " in peer data");
            break;
        }
        
        // Decode port
        if (offset + 2 > data.size()) break;
        uint16_t port = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        
        LOG_DHT_DEBUG("Decoded peer: " << ip_str << ":" << port);
        message->peers.emplace_back(ip_str, port);
    }
    
    if (offset + 2 < data.size()) {
        // Decode announce port
        message->announce_port = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        LOG_DHT_DEBUG("Decoded announce port: " << message->announce_port);
        
        if (offset < data.size()) {
            // Decode token
            uint8_t token_size = data[offset++];
            if (offset + token_size <= data.size()) {
                message->token = std::string(data.begin() + offset, data.begin() + offset + token_size);
                LOG_DHT_DEBUG("Decoded token: " << message->token << " (size: " << static_cast<int>(token_size) << ")");
            }
        }
    }
    
    LOG_DHT_DEBUG("Message decoded successfully (complete): type=" << static_cast<int>(type) << 
                  ", nodes=" << message->nodes.size() << 
                  ", peers=" << message->peers.size());
    
    return message;
}

void DhtClient::add_node(const DhtNode& node) {
    std::lock_guard<std::mutex> lock(routing_table_mutex_);
    
    int bucket_index = get_bucket_index(node.id);
    auto& bucket = routing_table_[bucket_index];
    
    LOG_DHT_DEBUG("Adding node " << node_id_to_hex(node.id) << " at " << node.peer.ip << ":" << node.peer.port << " to bucket " << bucket_index);
    
    // Check if node already exists
    auto it = std::find_if(bucket.begin(), bucket.end(),
                          [&node](const DhtNode& existing) {
                              return existing.id == node.id;
                          });
    
    if (it != bucket.end()) {
        // Update existing node
        LOG_DHT_DEBUG("Node " << node_id_to_hex(node.id) << " already exists in bucket " << bucket_index << ", updating");
        it->peer = node.peer;
        it->last_seen = std::chrono::steady_clock::now();
        return;
    }
    
    // Add new node
    if (bucket.size() < K_BUCKET_SIZE) {
        bucket.push_back(node);
        LOG_DHT_DEBUG("Added new node " << node_id_to_hex(node.id) << " to bucket " << bucket_index << " (size: " << bucket.size() << "/" << K_BUCKET_SIZE << ")");
    } else {
        // Bucket is full, replace least recently seen node
        auto oldest_it = std::min_element(bucket.begin(), bucket.end(),
                                         [](const DhtNode& a, const DhtNode& b) {
                                             return a.last_seen < b.last_seen;
                                         });
        LOG_DHT_DEBUG("Bucket " << bucket_index << " is full, replacing oldest node " << node_id_to_hex(oldest_it->id) << " with " << node_id_to_hex(node.id));
        *oldest_it = node;
    }
}

std::vector<DhtNode> DhtClient::find_closest_nodes(const NodeId& target, size_t count) {
    std::lock_guard<std::mutex> lock(routing_table_mutex_);
    
    auto result = find_closest_nodes_unlocked(target, count);
    
    return result;
}

std::vector<DhtNode> DhtClient::find_closest_nodes_unlocked(const NodeId& target, size_t count) {
    LOG_DHT_DEBUG("Finding closest nodes to target " << node_id_to_hex(target) << " (max " << count << " nodes)");
    
    std::vector<DhtNode> all_nodes;
    size_t total_nodes = 0;
    for (const auto& bucket : routing_table_) {
        all_nodes.insert(all_nodes.end(), bucket.begin(), bucket.end());
        total_nodes += bucket.size();
    }
    
    LOG_DHT_DEBUG("Routing table contains " << total_nodes << " nodes across " << routing_table_.size() << " buckets");
    
    // Sort by distance to target
    std::sort(all_nodes.begin(), all_nodes.end(),
              [&target, this](const DhtNode& a, const DhtNode& b) {
                  return is_closer(a.id, b.id, target);
              });
    
    // Return up to 'count' closest nodes
    if (all_nodes.size() > count) {
        all_nodes.resize(count);
    }
    
    LOG_DHT_DEBUG("Found " << all_nodes.size() << " closest nodes to target " << node_id_to_hex(target));
    for (size_t i = 0; i < all_nodes.size(); ++i) {
        LOG_DHT_DEBUG("  [" << i << "] " << node_id_to_hex(all_nodes[i].id) << " at " << all_nodes[i].peer.ip << ":" << all_nodes[i].peer.port);
    }
    // Print the xor distance for each node
    // for (size_t i = 0; i < all_nodes.size(); ++i) {
    //     NodeId dist = xor_distance(all_nodes[i].id, target);
    //     // Convert the NodeId (20 bytes) to a single uint64_t for a simple distance metric (using the first 8 bytes)
    //     uint64_t dist_metric = 0;
    //     for (int j = 0; j < 8 && j < dist.size(); ++j) {
    //         dist_metric = (dist_metric << 8) | dist[j];
    //     }
    //     LOG_DHT_DEBUG("  [" << i << "] " << node_id_to_hex(all_nodes[i].id) 
    //         << " at " << all_nodes[i].peer.ip << ":" << all_nodes[i].peer.port
    //         << " xor_distance=" << dist_metric);
    // }
    
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

// Protocol detection and management
DhtClient::PeerProtocol DhtClient::detect_protocol(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return PeerProtocol::Unknown;
    }
    
    // Check for KRPC (bencode) format
    // KRPC messages start with 'd' (dictionary) and contain specific keys
    if (data[0] == 'd') {
        try {
            auto decoded = bencode::decode(data);
            if (decoded.is_dict() && decoded.has_key("y") && decoded.has_key("t")) {
                // This looks like a valid KRPC message
                return PeerProtocol::BitTorrent;
            }
        } catch (const std::exception&) {
            // Not valid bencode, fall through to custom protocol
        }
    }
    
    // Check for our rats dht protocol format
    // Our rats dht messages have specific structure: type (1 byte) + transaction_id_size (1 byte) + transaction_id + sender_id (20 bytes) + target_id (20 bytes) + ...
    if (data.size() >= 43 && data[0] <= 3) { // Message type 0-3, minimum size for transaction ID
        // Additional check: ensure transaction ID size is reasonable
        if (data.size() > 1 && data[1] <= 32) { // Transaction ID should be <= 32 bytes
            return PeerProtocol::RatsDht;
        }
    }
    
    return PeerProtocol::Unknown;
}

DhtClient::PeerProtocol DhtClient::get_peer_protocol(const Peer& peer) {
    std::lock_guard<std::mutex> lock(peer_protocols_mutex_);
    auto it = peer_protocols_.find(peer);
    if (it != peer_protocols_.end()) {
        return it->second;
    }
    return PeerProtocol::BitTorrent;  // Default to BitTorrent protocol
}

void DhtClient::set_peer_protocol(const Peer& peer, PeerProtocol protocol) {
    std::lock_guard<std::mutex> lock(peer_protocols_mutex_);
    peer_protocols_[peer] = protocol;
}

bool DhtClient::is_known_bittorrent_bootstrap_node(const Peer& peer) {
    // Check if this is a known BitTorrent DHT bootstrap node
    // These nodes are expected to use KRPC protocol only
    static const std::vector<std::string> known_bittorrent_hosts = {
        "router.bittorrent.com",
        "dht.transmissionbt.com", 
        "router.utorrent.com",
        "dht.aelitis.com",
        "dht.libtorrent.org",
        "bootstrap.ring.cx"
    };
    
    // Check if the peer is on a known BitTorrent DHT port
    if (peer.port != 6881) {
        return false;
    }
    
    // Check if the hostname/IP matches known BitTorrent bootstrap nodes
    for (const auto& host : known_bittorrent_hosts) {
        if (peer.ip == host) {
            return true;
        }
    }
    
    return false;
}

// KRPC message handling
void DhtClient::handle_krpc_message(const KrpcMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling KRPC message type " << static_cast<int>(message.type) << " from " << sender.ip << ":" << sender.port);
    
    switch (message.type) {
        case KrpcMessageType::Query:
            switch (message.query_type) {
                case KrpcQueryType::Ping:
                    handle_krpc_ping(message, sender);
                    break;
                case KrpcQueryType::FindNode:
                    handle_krpc_find_node(message, sender);
                    break;
                case KrpcQueryType::GetPeers:
                    handle_krpc_get_peers(message, sender);
                    break;
                case KrpcQueryType::AnnouncePeer:
                    handle_krpc_announce_peer(message, sender);
                    break;
            }
            break;
        case KrpcMessageType::Response:
            handle_krpc_response(message, sender);
            break;
        case KrpcMessageType::Error:
            handle_krpc_error(message, sender);
            break;
    }
}

void DhtClient::handle_krpc_ping(const KrpcMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling KRPC PING from " << node_id_to_hex(message.sender_id) << " at " << sender.ip << ":" << sender.port);
    
    // Add sender to routing table
    KrpcNode krpc_node(message.sender_id, sender.ip, sender.port);
    DhtNode sender_node = krpc_node_to_dht_node(krpc_node);
    add_node(sender_node);
    
    // Respond with ping response
    auto response = KrpcProtocol::create_ping_response(message.transaction_id, node_id_);
    send_krpc_message(response, sender);
}

void DhtClient::handle_krpc_find_node(const KrpcMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling KRPC FIND_NODE from " << node_id_to_hex(message.sender_id) << " at " << sender.ip << ":" << sender.port);
    
    // Add sender to routing table
    KrpcNode krpc_node(message.sender_id, sender.ip, sender.port);
    DhtNode sender_node = krpc_node_to_dht_node(krpc_node);
    add_node(sender_node);
    
    // Find closest nodes
    auto closest_nodes = find_closest_nodes(message.target_id, K_BUCKET_SIZE);
    auto krpc_nodes = dht_nodes_to_krpc_nodes(closest_nodes);
    
    // Respond with closest nodes
    auto response = KrpcProtocol::create_find_node_response(message.transaction_id, node_id_, krpc_nodes);
    send_krpc_message(response, sender);
}

void DhtClient::handle_krpc_get_peers(const KrpcMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling KRPC GET_PEERS from " << node_id_to_hex(message.sender_id) << " at " << sender.ip << ":" << sender.port << " for info_hash " << node_id_to_hex(message.info_hash));
    
    // Add sender to routing table
    KrpcNode krpc_node(message.sender_id, sender.ip, sender.port);
    DhtNode sender_node = krpc_node_to_dht_node(krpc_node);
    add_node(sender_node);
    
    // Generate a token for this peer
    std::string token = generate_token(sender);
    
    // First check if we have announced peers for this info_hash
    auto announced_peers = get_announced_peers(message.info_hash);
    
    KrpcMessage response;
    if (!announced_peers.empty()) {
        // Return the peers we have stored
        response = KrpcProtocol::create_get_peers_response(message.transaction_id, node_id_, announced_peers, token);
        LOG_DHT_DEBUG("Responding to KRPC GET_PEERS with " << announced_peers.size() << " announced peers for info_hash " << node_id_to_hex(message.info_hash));
    } else {
        // Return closest nodes
        auto closest_nodes = find_closest_nodes(message.info_hash, K_BUCKET_SIZE);
        auto krpc_nodes = dht_nodes_to_krpc_nodes(closest_nodes);
        response = KrpcProtocol::create_get_peers_response_with_nodes(message.transaction_id, node_id_, krpc_nodes, token);
        LOG_DHT_DEBUG("Responding to KRPC GET_PEERS with " << krpc_nodes.size() << " closest nodes for info_hash " << node_id_to_hex(message.info_hash));
    }
    
    send_krpc_message(response, sender);
}

void DhtClient::handle_krpc_announce_peer(const KrpcMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling KRPC ANNOUNCE_PEER from " << node_id_to_hex(message.sender_id) << " at " << sender.ip << ":" << sender.port);
    
    // Verify token
    if (!verify_token(sender, message.token)) {
        LOG_DHT_WARN("Invalid token from " << sender.ip << ":" << sender.port << " for KRPC ANNOUNCE_PEER");
        auto error = KrpcProtocol::create_error(message.transaction_id, KrpcErrorCode::ProtocolError, "Invalid token");
        send_krpc_message(error, sender);
        return;
    }
    
    // Add sender to routing table
    KrpcNode krpc_node(message.sender_id, sender.ip, sender.port);
    DhtNode sender_node = krpc_node_to_dht_node(krpc_node);
    add_node(sender_node);
    
    // Store the peer announcement
    Peer announcing_peer(sender.ip, message.port);
    store_announced_peer(message.info_hash, announcing_peer);
    
    // Respond with acknowledgment
    auto response = KrpcProtocol::create_announce_peer_response(message.transaction_id, node_id_);
    send_krpc_message(response, sender);
}

void DhtClient::handle_krpc_response(const KrpcMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling KRPC response from " << sender.ip << ":" << sender.port);
    
    // Add responder to routing table
    KrpcNode krpc_node(message.response_id, sender.ip, sender.port);
    DhtNode sender_node = krpc_node_to_dht_node(krpc_node);
    add_node(sender_node);
    
    // Add any nodes from the response
    for (const auto& node : message.nodes) {
        DhtNode dht_node = krpc_node_to_dht_node(node);
        add_node(dht_node);
    }
    
    // Check if this is a response to a pending search (get_peers with peers)
    if (!message.peers.empty()) {
        handle_get_peers_response_for_search(message.transaction_id, sender, message.peers);
    }
    // Check if this is a response to a pending search (get_peers with nodes)
    else if (!message.nodes.empty()) {
        handle_get_peers_response_with_nodes(message.transaction_id, sender, message.nodes);
    }
    
    // Check if this is a response to a pending announce (get_peers with token)
    if (!message.token.empty()) {
        handle_get_peers_response_for_announce(message.transaction_id, sender, message.token);
    }
}

void DhtClient::handle_krpc_error(const KrpcMessage& message, const Peer& sender) {
    LOG_DHT_WARN("Received KRPC error from " << sender.ip << ":" << sender.port 
                 << " - Code: " << static_cast<int>(message.error_code) 
                 << " Message: " << message.error_message);
}

// KRPC sending functions
bool DhtClient::send_krpc_message(const KrpcMessage& message, const Peer& peer) {
    auto data = KrpcProtocol::encode_message(message);
    if (data.empty()) {
        LOG_DHT_ERROR("Failed to encode KRPC message");
        return false;
    }
    
    LOG_DHT_DEBUG("Sending KRPC message (" << data.size() << " bytes) to " << peer.ip << ":" << peer.port);
    int result = send_udp_data(socket_, data, peer);
    
    if (result > 0) {
        LOG_DHT_DEBUG("Successfully sent KRPC message to " << peer.ip << ":" << peer.port);
    } else {
        LOG_DHT_ERROR("Failed to send KRPC message to " << peer.ip << ":" << peer.port);
    }
    
    return result > 0;
}

void DhtClient::send_krpc_ping(const Peer& peer) {
    std::string transaction_id = KrpcProtocol::generate_transaction_id();
    auto message = KrpcProtocol::create_ping_query(transaction_id, node_id_);
    send_krpc_message(message, peer);
}

void DhtClient::send_krpc_find_node(const Peer& peer, const NodeId& target) {
    std::string transaction_id = KrpcProtocol::generate_transaction_id();
    auto message = KrpcProtocol::create_find_node_query(transaction_id, node_id_, target);
    send_krpc_message(message, peer);
}

void DhtClient::send_krpc_get_peers(const Peer& peer, const InfoHash& info_hash) {
    std::string transaction_id = KrpcProtocol::generate_transaction_id();
    auto message = KrpcProtocol::create_get_peers_query(transaction_id, node_id_, info_hash);
    send_krpc_message(message, peer);
}

void DhtClient::send_krpc_announce_peer(const Peer& peer, const InfoHash& info_hash, uint16_t port, const std::string& token) {
    std::string transaction_id = KrpcProtocol::generate_transaction_id();
    auto message = KrpcProtocol::create_announce_peer_query(transaction_id, node_id_, info_hash, port, token);
    send_krpc_message(message, peer);
}

// Update sending functions to use protocol detection
void DhtClient::send_ping(const Peer& peer) {
    PeerProtocol protocol = get_peer_protocol(peer);
    
    if (protocol == PeerProtocol::BitTorrent) {
        LOG_DHT_DEBUG("Sending KRPC PING to " << peer.ip << ":" << peer.port);
        send_krpc_ping(peer);
    } else {
        std::string transaction_id = generate_rats_dht_transaction_id();
        LOG_DHT_DEBUG("Sending rats dht PING to " << peer.ip << ":" << peer.port << " (transaction: " << transaction_id << ")");
        DhtMessage message(DhtMessageType::PING, transaction_id, node_id_);
        send_message(message, peer);
    }
}

void DhtClient::send_find_node(const Peer& peer, const NodeId& target) {
    PeerProtocol protocol = get_peer_protocol(peer);
    
    if (protocol == PeerProtocol::BitTorrent) {
        LOG_DHT_DEBUG("Sending KRPC FIND_NODE to " << peer.ip << ":" << peer.port);
        send_krpc_find_node(peer, target);
    } else {
        std::string transaction_id = generate_rats_dht_transaction_id();
        LOG_DHT_DEBUG("Sending rats dht FIND_NODE to " << peer.ip << ":" << peer.port << " (transaction: " << transaction_id << ")");
        DhtMessage message(DhtMessageType::FIND_NODE, transaction_id, node_id_);
        message.target_id = target;
        send_message(message, peer);
    }
}

void DhtClient::send_get_peers(const Peer& peer, const InfoHash& info_hash) {
    PeerProtocol protocol = get_peer_protocol(peer);
    
    if (protocol == PeerProtocol::BitTorrent) {
        LOG_DHT_DEBUG("Sending KRPC GET_PEERS to " << peer.ip << ":" << peer.port);
        send_krpc_get_peers(peer, info_hash);
    } else {
        std::string transaction_id = generate_rats_dht_transaction_id();
        LOG_DHT_DEBUG("Sending rats dht GET_PEERS to " << peer.ip << ":" << peer.port << " (transaction: " << transaction_id << ")");
        DhtMessage message(DhtMessageType::GET_PEERS, transaction_id, node_id_);
        message.target_id = info_hash;
        send_message(message, peer);
    }
}

void DhtClient::send_announce_peer(const Peer& peer, const InfoHash& info_hash, uint16_t port, const std::string& token) {
    PeerProtocol protocol = get_peer_protocol(peer);
    
    if (protocol == PeerProtocol::BitTorrent) {
        LOG_DHT_DEBUG("Sending KRPC ANNOUNCE_PEER to " << peer.ip << ":" << peer.port);
        send_krpc_announce_peer(peer, info_hash, port, token);
    } else {
        std::string transaction_id = generate_rats_dht_transaction_id();
        LOG_DHT_DEBUG("Sending rats dht ANNOUNCE_PEER to " << peer.ip << ":" << peer.port << " (transaction: " << transaction_id << ")");
        DhtMessage message(DhtMessageType::ANNOUNCE_PEER, transaction_id, node_id_);
        message.target_id = info_hash;
        message.announce_port = port;
        message.token = token;
        send_message(message, peer);
    }
}

// Conversion utilities
KrpcNode DhtClient::dht_node_to_krpc_node(const DhtNode& node) {
    return KrpcNode(node.id, node.peer.ip, node.peer.port);
}

DhtNode DhtClient::krpc_node_to_dht_node(const KrpcNode& node) {
    Peer peer(node.ip, node.port);
    return DhtNode(node.id, peer);
}

std::vector<KrpcNode> DhtClient::dht_nodes_to_krpc_nodes(const std::vector<DhtNode>& nodes) {
    std::vector<KrpcNode> krpc_nodes;
    krpc_nodes.reserve(nodes.size());
    for (const auto& node : nodes) {
        krpc_nodes.push_back(dht_node_to_krpc_node(node));
    }
    return krpc_nodes;
}

std::vector<DhtNode> DhtClient::krpc_nodes_to_dht_nodes(const std::vector<KrpcNode>& nodes) {
    std::vector<DhtNode> dht_nodes;
    dht_nodes.reserve(nodes.size());
    for (const auto& node : nodes) {
        dht_nodes.push_back(krpc_node_to_dht_node(node));
    }
    return dht_nodes;
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

std::string DhtClient::generate_token(const Peer& peer) {
    // Simple token generation (in real implementation, use proper cryptographic hash)
    std::string data = peer.ip + ":" + std::to_string(peer.port);
    std::hash<std::string> hasher;
    size_t hash = hasher(data);
    
    // Convert hash to hex string
    std::ostringstream oss;
    oss << std::hex << hash;
    
    // Store token for this peer
    {
        std::lock_guard<std::mutex> lock(peer_tokens_mutex_);
        peer_tokens_[peer] = oss.str();
    }
    
    return oss.str();
}

std::string DhtClient::generate_rats_dht_transaction_id() {
    return "r" + std::to_string(++rats_dht_transaction_counter_);
}



bool DhtClient::verify_token(const Peer& peer, const std::string& token) {
    std::lock_guard<std::mutex> lock(peer_tokens_mutex_);
    auto it = peer_tokens_.find(peer);
    if (it != peer_tokens_.end()) {
        return it->second == token;
    }
    return false;
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
                auto closest_nodes = find_closest_nodes_unlocked(random_id, ALPHA);
                for (const auto& node : closest_nodes) {
                    send_find_node(node.peer, random_id);
                }
            }
        }
    }
}

void DhtClient::cleanup_stale_announces() {
    std::lock_guard<std::mutex> lock(pending_announces_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto stale_threshold = std::chrono::minutes(5);  // Remove announces older than 5 minutes
    
    auto it = pending_announces_.begin();
    while (it != pending_announces_.end()) {
        if (now - it->second.created_at > stale_threshold) {
            LOG_DHT_DEBUG("Removing stale pending announce for transaction " << it->first);
            it = pending_announces_.erase(it);
        } else {
            ++it;
        }
    }
}

void DhtClient::cleanup_stale_searches() {
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto stale_threshold = std::chrono::minutes(5);  // Remove searches older than 5 minutes
    
    // Clean up stale searches (by info_hash)
    auto search_it = pending_searches_.begin();
    while (search_it != pending_searches_.end()) {
        if (now - search_it->second.created_at > stale_threshold) {
            LOG_DHT_DEBUG("Removing stale pending search for info_hash " << search_it->first);
            search_it = pending_searches_.erase(search_it);
        } else {
            ++search_it;
        }
    }
    
    // Clean up stale transaction mappings (remove ones that point to non-existent searches)
    auto trans_it = transaction_to_search_.begin();
    while (trans_it != transaction_to_search_.end()) {
        if (pending_searches_.find(trans_it->second) == pending_searches_.end()) {
            LOG_DHT_DEBUG("Removing stale transaction mapping " << trans_it->first << " -> " << trans_it->second);
            trans_it = transaction_to_search_.erase(trans_it);
        } else {
            ++trans_it;
        }
    }
}

void DhtClient::handle_get_peers_response_for_announce(const std::string& transaction_id, const Peer& responder, const std::string& token) {
    std::lock_guard<std::mutex> lock(pending_announces_mutex_);
    
    auto it = pending_announces_.find(transaction_id);
    if (it != pending_announces_.end()) {
        const auto& pending_announce = it->second;
        LOG_DHT_DEBUG("Found pending announce for transaction " << transaction_id 
                      << " - sending announce_peer for info_hash " << node_id_to_hex(pending_announce.info_hash) 
                      << " to " << responder.ip << ":" << responder.port);
        
        // Send announce_peer with the received token using unified function
        send_announce_peer(responder, pending_announce.info_hash, pending_announce.port, token);
        
        // Remove the pending announce since we've handled it
        pending_announces_.erase(it);
    }
}

void DhtClient::handle_get_peers_response_for_announce_rats_dht(const std::string& transaction_id, const Peer& responder, const std::string& token) {
    std::lock_guard<std::mutex> lock(pending_announces_mutex_);
    
    auto it = pending_announces_.find(transaction_id);
    if (it != pending_announces_.end()) {
        const auto& pending_announce = it->second;
        LOG_DHT_DEBUG("Found pending announce for rats DHT transaction " << transaction_id 
                      << " - sending announce_peer for info_hash " << node_id_to_hex(pending_announce.info_hash) 
                      << " to " << responder.ip << ":" << responder.port);
        
        // Send announce_peer with the received token using unified function
        send_announce_peer(responder, pending_announce.info_hash, pending_announce.port, token);
        
        // Remove the pending announce since we've handled it
        pending_announces_.erase(it);
    }
}

void DhtClient::handle_get_peers_response_for_search(const std::string& transaction_id, const Peer& responder, const std::vector<Peer>& peers) {
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    
    auto trans_it = transaction_to_search_.find(transaction_id);
    if (trans_it != transaction_to_search_.end()) {
        std::string hash_key = trans_it->second;
        auto search_it = pending_searches_.find(hash_key);
        if (search_it != pending_searches_.end()) {
            auto& pending_search = search_it->second;
            LOG_DHT_DEBUG("Found pending search for KRPC transaction " << transaction_id 
                          << " - received " << peers.size() << " peers for info_hash " << hash_key 
                          << " from " << responder.ip << ":" << responder.port);
            
            if (!peers.empty()) {
                // We found actual peers - call callback and clean up search
                {
                    std::lock_guard<std::mutex> search_lock(active_searches_mutex_);
                    auto active_it = active_searches_.find(hash_key);
                    if (active_it != active_searches_.end() && active_it->second) {
                        active_it->second(peers, pending_search.info_hash);
                    }
                    // Remove from active searches since we found peers
                    active_searches_.erase(hash_key);
                }
                // Remove the completed search
                pending_searches_.erase(search_it);
            }
        }
        
        // Remove the transaction mapping since we've handled it
        transaction_to_search_.erase(trans_it);
    }
}

void DhtClient::handle_get_peers_response_for_search_rats_dht(const std::string& transaction_id, const Peer& responder, const std::vector<Peer>& peers) {
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    
    auto trans_it = transaction_to_search_.find(transaction_id);
    if (trans_it != transaction_to_search_.end()) {
        std::string hash_key = trans_it->second;
        auto search_it = pending_searches_.find(hash_key);
        if (search_it != pending_searches_.end()) {
            auto& pending_search = search_it->second;
            LOG_DHT_DEBUG("Found pending search for rats DHT transaction " << transaction_id 
                          << " - received " << peers.size() << " peers for info_hash " << hash_key 
                          << " from " << responder.ip << ":" << responder.port);
            
            if (!peers.empty()) {
                // We found actual peers - call callback and clean up search
                {
                    std::lock_guard<std::mutex> search_lock(active_searches_mutex_);
                    auto active_it = active_searches_.find(hash_key);
                    if (active_it != active_searches_.end() && active_it->second) {
                        active_it->second(peers, pending_search.info_hash);
                    }
                    // Remove from active searches since we found peers
                    active_searches_.erase(hash_key);
                }
                // Remove the completed search
                pending_searches_.erase(search_it);
            }
        }
        
        // Remove the transaction mapping since we've handled it
        transaction_to_search_.erase(trans_it);
    }
}

void DhtClient::handle_get_peers_response_with_nodes(const std::string& transaction_id, const Peer& responder, const std::vector<KrpcNode>& nodes) {
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    
    auto trans_it = transaction_to_search_.find(transaction_id);
    if (trans_it != transaction_to_search_.end()) {
        std::string hash_key = trans_it->second;
        auto search_it = pending_searches_.find(hash_key);
        if (search_it != pending_searches_.end()) {
            auto& pending_search = search_it->second;
            LOG_DHT_DEBUG("Found pending search for KRPC transaction " << transaction_id 
                          << " - received " << nodes.size() << " nodes for info_hash " << hash_key 
                          << " from " << responder.ip << ":" << responder.port);

            // Continue search iteration
            bool should_remove_search = continue_search_iteration(pending_search);
            if (should_remove_search) {
                LOG_DHT_DEBUG("Removing completed search for info_hash " << hash_key);
                pending_searches_.erase(search_it);
                
                // Also clean up the active search callback
                {
                    std::lock_guard<std::mutex> search_lock(active_searches_mutex_);
                    active_searches_.erase(hash_key);
                }
            }
        }
        
        // Remove the transaction mapping since we've handled it
        transaction_to_search_.erase(trans_it);
    }
}

void DhtClient::handle_get_peers_response_with_nodes_rats_dht(const std::string& transaction_id, const Peer& responder, const std::vector<DhtNode>& nodes) {
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    
    auto trans_it = transaction_to_search_.find(transaction_id);
    if (trans_it != transaction_to_search_.end()) {
        std::string hash_key = trans_it->second;
        auto search_it = pending_searches_.find(hash_key);
        if (search_it != pending_searches_.end()) {
            auto& pending_search = search_it->second;
            LOG_DHT_DEBUG("Found pending search for rats DHT transaction " << transaction_id 
                          << " - received " << nodes.size() << " nodes for info_hash " << hash_key 
                          << " from " << responder.ip << ":" << responder.port);

            // Continue search iteration
            bool should_remove_search = continue_search_iteration(pending_search);
            if (should_remove_search) {
                LOG_DHT_DEBUG("Removing completed search for info_hash " << hash_key);
                pending_searches_.erase(search_it);
                
                // Also clean up the active search callback
                {
                    std::lock_guard<std::mutex> search_lock(active_searches_mutex_);
                    active_searches_.erase(hash_key);
                }
            }
        }
        
        // Remove the transaction mapping since we've handled it
        transaction_to_search_.erase(trans_it);
    }
}

bool DhtClient::continue_search_iteration(PendingSearch& search) {
    std::string hash_key = node_id_to_hex(search.info_hash);
    
    LOG_DHT_DEBUG("Continuing search iteration for info_hash " << hash_key 
                  << " with " << search.queried_nodes.size() << " queried nodes, iteration " 
                  << search.iteration_count << "/" << search.iteration_max);
    
    // Stop if we've reached max iterations (simple limit)
    if (search.iteration_count >= search.iteration_max) {
        LOG_DHT_DEBUG("Stopping search for " << hash_key << " - reached max iterations (" << search.iteration_count << "/" << search.iteration_max << ")");
        return true;  // Return true to indicate the search should be removed
    }
    
    // Get closest nodes from routing table (already sorted by distance to target)
    std::vector<DhtNode> closest_nodes = find_closest_nodes(search.info_hash, ALPHA);
    
    // Query up to ALPHA closest unqueried nodes
    int nodes_queried = 0;
    int candidates_found = 0;
    for (const auto& node : closest_nodes) {
        if (nodes_queried >= ALPHA) {
            LOG_DHT_DEBUG("Reached ALPHA limit (" << ALPHA << ") for querying nodes in iteration " << (search.iteration_count + 1) << "/" << search.iteration_max);
            break;
        }
        
        std::string node_hex = node_id_to_hex(node.id);
        candidates_found++;
        
        if (search.queried_nodes.find(node_hex) == search.queried_nodes.end()) {
            PeerProtocol protocol = get_peer_protocol(node.peer);
            
            LOG_DHT_DEBUG("Querying node " << node_hex << " at " << node.peer.ip << ":" << node.peer.port 
                          << " (protocol: " << (protocol == PeerProtocol::BitTorrent ? "BitTorrent" : "RatsDht") 
                          << ", iteration: " << (search.iteration_count + 1) << ")");
            
            // Mark node as queried in the shared search object
            search.queried_nodes.insert(node_hex);
            
            if (protocol == PeerProtocol::BitTorrent) {
                std::string transaction_id = KrpcProtocol::generate_transaction_id();
                transaction_to_search_[transaction_id] = hash_key;
                
                auto message = KrpcProtocol::create_get_peers_query(transaction_id, node_id_, search.info_hash);
                send_krpc_message(message, node.peer);
            } else {
                std::string transaction_id = generate_rats_dht_transaction_id();
                transaction_to_search_[transaction_id] = hash_key;
                
                DhtMessage message(DhtMessageType::GET_PEERS, transaction_id, node_id_);
                message.target_id = search.info_hash;
                send_message(message, node.peer);
            }
            
            nodes_queried++;
        } else {
            LOG_DHT_DEBUG("Skipping already queried node " << node_hex << " at " << node.peer.ip << ":" << node.peer.port);
        }
    }
    
    // Update iteration count
    search.iteration_count++;
    
    LOG_DHT_DEBUG("Search iteration summary for " << hash_key << ":");
    LOG_DHT_DEBUG("  - Candidates evaluated: " << candidates_found);
    LOG_DHT_DEBUG("  - Nodes queried: " << nodes_queried);
    LOG_DHT_DEBUG("  - Already queried nodes skipped: " << (candidates_found - nodes_queried));
    LOG_DHT_DEBUG("  - Current iteration: " << search.iteration_count << "/" << search.iteration_max);
    
    // If we are not making progress, or if we've hit the limit, stop the search.
    if (nodes_queried == 0) {
        LOG_DHT_DEBUG("Stopping search for " << hash_key << " - no new nodes to query");
        return true; // Signal to remove the search
    }
    
    return false;
}

// Peer announcement storage management
void DhtClient::store_announced_peer(const InfoHash& info_hash, const Peer& peer) {
    std::lock_guard<std::mutex> lock(announced_peers_mutex_);
    
    std::string hash_key = node_id_to_hex(info_hash);
    auto& peers = announced_peers_[hash_key];
    
    // Check if peer already exists
    auto it = std::find_if(peers.begin(), peers.end(),
                          [&peer](const AnnouncedPeer& announced) {
                              return announced.peer.ip == peer.ip && announced.peer.port == peer.port;
                          });
    
    if (it != peers.end()) {
        // Update existing peer's timestamp
        it->announced_at = std::chrono::steady_clock::now();
        LOG_DHT_DEBUG("Updated existing announced peer " << peer.ip << ":" << peer.port 
                      << " for info_hash " << hash_key);
    } else {
        // Add new peer
        peers.emplace_back(peer);
        LOG_DHT_DEBUG("Stored new announced peer " << peer.ip << ":" << peer.port 
                      << " for info_hash " << hash_key << " (total: " << peers.size() << ")");
    }
}

std::vector<Peer> DhtClient::get_announced_peers(const InfoHash& info_hash) {
    std::lock_guard<std::mutex> lock(announced_peers_mutex_);
    
    std::string hash_key = node_id_to_hex(info_hash);
    auto it = announced_peers_.find(hash_key);
    
    std::vector<Peer> peers;
    if (it != announced_peers_.end()) {
        peers.reserve(it->second.size());
        for (const auto& announced : it->second) {
            peers.push_back(announced.peer);
        }
        LOG_DHT_DEBUG("Retrieved " << peers.size() << " announced peers for info_hash " << hash_key);
    } else {
        LOG_DHT_DEBUG("No announced peers found for info_hash " << hash_key);
    }
    
    return peers;
}

void DhtClient::cleanup_stale_announced_peers() {
    std::lock_guard<std::mutex> lock(announced_peers_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto stale_threshold = std::chrono::minutes(30);  // BEP 5 standard: 30 minutes
    
    size_t total_before = 0;
    size_t total_after = 0;
    
    for (auto it = announced_peers_.begin(); it != announced_peers_.end(); ) {
        auto& peers = it->second;
        total_before += peers.size();
        
        // Remove stale peers
        peers.erase(std::remove_if(peers.begin(), peers.end(),
                                   [now, stale_threshold](const AnnouncedPeer& announced) {
                                       return now - announced.announced_at > stale_threshold;
                                   }), peers.end());
        
        total_after += peers.size();
        
        // Remove empty info_hash entries
        if (peers.empty()) {
            LOG_DHT_DEBUG("Removing empty announced peers entry for info_hash " << it->first);
            it = announced_peers_.erase(it);
        } else {
            ++it;
        }
    }
    
    if (total_before > total_after) {
        LOG_DHT_DEBUG("Cleaned up " << (total_before - total_after) << " stale announced peers "
                      << "(from " << total_before << " to " << total_after << ")");
    }
}

// Utility functions implementation
NodeId string_to_node_id(const std::string& str) {
    NodeId id;
    size_t copy_size = (std::min)(str.size(), NODE_ID_SIZE);
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