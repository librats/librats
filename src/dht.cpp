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


DhtClient::DhtClient(int port, const std::string& bind_address) 
    : port_(port), bind_address_(bind_address), socket_(INVALID_SOCKET_VALUE), running_(false) {
    node_id_ = generate_node_id();
    routing_table_.resize(NODE_ID_SIZE * 8);  // 160 buckets for 160-bit node IDs
    
    LOG_DHT_INFO("DHT client created with node ID: " << node_id_to_hex(node_id_) <<
                 (bind_address_.empty() ? "" : " bind address: " + bind_address_));
}

DhtClient::~DhtClient() {
    stop();
}

bool DhtClient::start() {
    if (running_) {
        return true;
    }
    
    LOG_DHT_INFO("Starting DHT client on port " << port_ <<
                 (bind_address_.empty() ? "" : " bound to " + bind_address_));
    
    // Initialize socket library (safe to call multiple times)
    if (!init_socket_library()) {
        LOG_DHT_ERROR("Failed to initialize socket library");
        return false;
    }
    
    socket_ = create_udp_socket(port_, bind_address_);
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
    

    
    // Send ping to bootstrap nodes
    LOG_DHT_DEBUG("Sending PING to all bootstrap nodes");
    for (const auto& peer : bootstrap_nodes) {
        send_krpc_ping(peer);
    }
    
    // Start node discovery by finding our own node
    LOG_DHT_DEBUG("Starting node discovery by finding our own node ID: " << node_id_to_hex(node_id_));
    for (const auto& peer : bootstrap_nodes) {
        send_krpc_find_node(peer, node_id_);
    }
    
    LOG_DHT_DEBUG("Bootstrap process initiated");
    return true;
}

bool DhtClient::find_peers(const InfoHash& info_hash, PeerDiscoveryCallback callback) {
    if (!running_) {
        LOG_DHT_ERROR("DHT client not running");
        return false;
    }
    
    std::string hash_key = node_id_to_hex(info_hash);
    LOG_DHT_INFO("Finding peers for info hash: " << hash_key);
    
    // Get initial nodes from routing table
    auto closest_nodes = find_closest_nodes(info_hash, K_BUCKET_SIZE);
    
    if (closest_nodes.empty()) {
        LOG_DHT_WARN("No nodes in routing table to query for info_hash " << hash_key);
        return false;
    }
    
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    
    // Check if a search is already ongoing for this info_hash
    auto search_it = pending_searches_.find(hash_key);
    if (search_it != pending_searches_.end()) {
        // Search already in progress - just add the callback to the list
        LOG_DHT_INFO("Search already in progress for info hash " << hash_key << " - adding callback to existing search");
        search_it->second.callbacks.push_back(callback);
        return true;
    }
    
    // Create new search
    PendingSearch new_search(info_hash);
    new_search.callbacks.push_back(callback);
    
    // Initialize search_nodes with closest nodes from routing table (already sorted)
    new_search.search_nodes = std::move(closest_nodes);
    
    auto insert_result = pending_searches_.emplace(hash_key, std::move(new_search));
    PendingSearch& search_ref = insert_result.first->second;
    
    LOG_DHT_DEBUG("Initialized search with " << search_ref.search_nodes.size() << " nodes from routing table");
    
    // Start sending requests
    add_search_requests(search_ref);
    
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
            // Generate transaction ID and track this as a pending announce for KRPC
            std::string transaction_id = KrpcProtocol::generate_transaction_id();
            
            {
                std::lock_guard<std::mutex> lock(pending_announces_mutex_);
                pending_announces_.emplace(transaction_id, PendingAnnounce(info_hash, port));
            }
            
            auto message = KrpcProtocol::create_get_peers_query(transaction_id, node_id_, info_hash);
            send_krpc_message(message, node.peer);
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

size_t DhtClient::get_pending_ping_verifications_count() const {
    std::lock_guard<std::mutex> lock(pending_pings_mutex_);
    return pending_pings_.size();
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
    auto last_ping_verification_cleanup = std::chrono::steady_clock::now();
    auto last_general_cleanup = std::chrono::steady_clock::now();
    auto last_stats_print = std::chrono::steady_clock::now();
    auto last_search_timeout_check = std::chrono::steady_clock::now();
    
    while (running_) {
        auto now = std::chrono::steady_clock::now();

        // Check for timed out search requests every 2 seconds (frequent check)
        if (now - last_search_timeout_check >= std::chrono::seconds(2)) {
            cleanup_timed_out_search_requests();
            last_search_timeout_check = now;
        }
        
        // General cleanup operations every 1 minute (like previously)
        if (now - last_general_cleanup >= std::chrono::minutes(1)) {
            // Cleanup stale nodes every 1 minute
            cleanup_stale_nodes();
            
            // Cleanup stale peer tokens
            cleanup_stale_peer_tokens();
            
            // Cleanup stale pending announces
            cleanup_stale_announces();
            
            // Cleanup stale pending searches
            cleanup_stale_searches();
            
            // Cleanup stale announced peers
            cleanup_stale_announced_peers();
            
            last_general_cleanup = now;
        }
        
        // Refresh buckets every 30 minutes
        if (now - last_bucket_refresh >= std::chrono::minutes(30)) {
            refresh_buckets();
            last_bucket_refresh = now;
        }
        
        // Frequent maintenance: ping verifications time out at ~30s, so check often
        if (now - last_ping_verification_cleanup >= std::chrono::seconds(30)) {
            cleanup_stale_ping_verifications();
            last_ping_verification_cleanup = now;
        }
        
        // Print DHT statistics every 10 seconds
        if (now - last_stats_print >= std::chrono::seconds(10)) {
            // Count filled buckets
            size_t filled_buckets = 0;
            size_t total_nodes = 0;
            size_t max_bucket_size = 0;
            {
                std::lock_guard<std::mutex> lock(routing_table_mutex_);
                for (const auto& bucket : routing_table_) {
                    if (!bucket.empty()) {
                        filled_buckets++;
                        total_nodes += bucket.size();
                        max_bucket_size = (std::max)(max_bucket_size, bucket.size());
                    }
                }
            }
            
            size_t pending_searches = 0;
            size_t pending_announces_count = 0;
            size_t announced_peers_total = 0;
            size_t announced_peers_infohashes = 0;
            
            {
                std::lock_guard<std::mutex> search_lock(pending_searches_mutex_);
                pending_searches = pending_searches_.size();
            }
            
            {
                std::lock_guard<std::mutex> announce_lock(pending_announces_mutex_);
                pending_announces_count = pending_announces_.size();
            }
            
            {
                std::lock_guard<std::mutex> peers_lock(announced_peers_mutex_);
                announced_peers_infohashes = announced_peers_.size();
                for (const auto& entry : announced_peers_) {
                    announced_peers_total += entry.second.size();
                }
            }
            
            size_t pending_pings = 0;
            size_t nodes_being_replaced = 0;
            {
                std::lock_guard<std::mutex> ping_lock(pending_pings_mutex_);
                pending_pings = pending_pings_.size();
                nodes_being_replaced = nodes_being_replaced_.size();
            }
            
            size_t peer_tokens_count = 0;
            {
                std::lock_guard<std::mutex> tokens_lock(peer_tokens_mutex_);
                peer_tokens_count = peer_tokens_.size();
            }
            
            LOG_DHT_INFO("=== DHT Global Statistics ===");
            LOG_DHT_INFO("  Routing Table:");
            LOG_DHT_INFO("    - Total nodes: " << total_nodes);
            LOG_DHT_INFO("    - Filled buckets: " << filled_buckets << "/" << routing_table_.size());
            LOG_DHT_INFO("    - Max bucket size: " << max_bucket_size << "/" << K_BUCKET_SIZE);
            LOG_DHT_INFO("  Active Operations:");
            LOG_DHT_INFO("    - Pending searches: " << pending_searches);
            LOG_DHT_INFO("    - Pending announces: " << pending_announces_count);
            LOG_DHT_INFO("    - Pending ping verifications: " << pending_pings);
            LOG_DHT_INFO("    - Nodes being replaced: " << nodes_being_replaced);
            LOG_DHT_INFO("  Stored Data:");
            LOG_DHT_INFO("    - Announced peers (total): " << announced_peers_total);
            LOG_DHT_INFO("    - Announced peers (infohashes): " << announced_peers_infohashes);
            LOG_DHT_INFO("    - Peer tokens: " << peer_tokens_count);
            
            last_stats_print = now;
        }
        
        // Execute maintenance loop every 1 second
        {
            std::unique_lock<std::mutex> lock(shutdown_mutex_);
            if (shutdown_cv_.wait_for(lock, std::chrono::seconds(1), [this] { return !running_.load(); })) {
                break;
            }
        }
    }
    
    LOG_DHT_DEBUG("Maintenance loop stopped");
}

void DhtClient::handle_message(const std::vector<uint8_t>& data, const Peer& sender) {
    LOG_DHT_DEBUG("Processing message of " << data.size() << " bytes from " << sender.ip << ":" << sender.port);
    
    auto krpc_message = KrpcProtocol::decode_message(data);
    if (!krpc_message) {
        LOG_DHT_WARN("Failed to decode KRPC message from " << sender.ip << ":" << sender.port);
        return;
    }
    
    handle_krpc_message(*krpc_message, sender);
}

void DhtClient::add_node(const DhtNode& node, bool verify) {
    bool should_initiate_ping = false;
    DhtNode worst_node_copy;
    int bucket_index_copy = 0;
    
    {
        std::lock_guard<std::mutex> pings_lock(pending_pings_mutex_);
        std::lock_guard<std::mutex> lock(routing_table_mutex_);
        
        int bucket_index = get_bucket_index(node.id);
        auto& bucket = routing_table_[bucket_index];
        
        LOG_DHT_DEBUG("Adding node " << node_id_to_hex(node.id) << " at " << node.peer.ip << ":" << node.peer.port << " to bucket " << bucket_index << " (verify: " << verify << ")");
        
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
        } else {
            // Add new node
            if (bucket.size() < K_BUCKET_SIZE) {
                bucket.push_back(node);
                LOG_DHT_DEBUG("Added new node " << node_id_to_hex(node.id) << " to bucket " << bucket_index << " (size: " << bucket.size() << "/" << K_BUCKET_SIZE << ")");
            } else {
                // Bucket is full
                if (!verify) {
                    // Direct replacement without ping verification
                    auto worst_it = std::min_element(bucket.begin(), bucket.end(),
                                                     [](const DhtNode& a, const DhtNode& b) {
                                                         return a.last_seen < b.last_seen;
                                                     });
                    
                    LOG_DHT_DEBUG("Bucket " << bucket_index << " is full, directly replacing oldest node " 
                                  << node_id_to_hex(worst_it->id) << " with " << node_id_to_hex(node.id) 
                                  << " (verify=false)");
                    
                    *worst_it = node;
                } else {
                    // Bucket is full, use ping-before-replace eviction (BEP 5)
                    
                    // Find the worst node that's not already being pinged for replacement
                    auto worst_it = bucket.end();
                    for (auto it = bucket.begin(); it != bucket.end(); ++it) {
                        if (nodes_being_replaced_.find(it->id) == nodes_being_replaced_.end()) {
                            if (worst_it == bucket.end() || it->last_seen < worst_it->last_seen) {
                                worst_it = it;
                            }
                        }
                    }
                    
                    if (worst_it == bucket.end()) {
                        LOG_DHT_DEBUG("Bucket " << bucket_index << " is full, but all nodes already have pending ping verifications - skipping new node " << node_id_to_hex(node.id));
                        return;
                    }
                    
                    LOG_DHT_DEBUG("Bucket " << bucket_index << " is full, initiating ping-before-replace for node " 
                                  << node_id_to_hex(worst_it->id) << " (last_seen age: " 
                                  << std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - worst_it->last_seen).count() 
                                  << "s) to potentially replace with " << node_id_to_hex(node.id));
                    
                    // Copy data for ping verification to be done outside the lock
                    should_initiate_ping = true;
                    worst_node_copy = *worst_it;
                    bucket_index_copy = bucket_index;
                }
            }
        }
    } // Release routing_table_mutex_ here
    
    // Initiate ping verification outside the routing_table_mutex_ to avoid deadlock
    if (should_initiate_ping) {
        initiate_ping_verification(node, worst_node_copy, bucket_index_copy);
    }
}

std::vector<DhtNode> DhtClient::find_closest_nodes(const NodeId& target, size_t count) {
    std::lock_guard<std::mutex> lock(routing_table_mutex_);
    
    auto result = find_closest_nodes_unlocked(target, count);
    
    return result;
}

std::vector<DhtNode> DhtClient::find_closest_nodes_unlocked(const NodeId& target, size_t count) {
    LOG_DHT_DEBUG("Finding closest nodes to target " << node_id_to_hex(target) << " (max " << count << " nodes)");
    
    // Find closest bucket to target
    int target_bucket = get_bucket_index(target);
    
    // Candidate nodes to be closest to target
    std::vector<DhtNode> candidates;
    // Reserve extra space: 3x count + buffer for 2 full buckets to avoid reallocation
    candidates.reserve(count * 3 + K_BUCKET_SIZE * 2);
    
    // Add nodes from ideal bucket
    if (target_bucket < routing_table_.size()) {
        const auto& bucket = routing_table_[target_bucket];
        candidates.insert(candidates.end(), bucket.begin(), bucket.end());
        LOG_DHT_DEBUG("Collected " << bucket.size() << " nodes from target bucket " << target_bucket);
    }
    
    // Add nodes from buckets above and below the ideal bucket
    // Collect more candidates than needed to ensure we get the actual closest ones after sorting
    size_t desired_candidates = count * 3;  // Collect 3x more candidates for better selection
    int low = target_bucket - 1;
    int high = target_bucket + 1;
    const int max_bucket_index = static_cast<int>(routing_table_.size()) - 1;
    int buckets_checked = 1;  // Already checked target_bucket
    
    while (candidates.size() < desired_candidates && (low >= 0 || high <= max_bucket_index)) {
        // Search left (closer buckets)
        if (low >= 0) {
            const auto& bucket = routing_table_[low];
            if (!bucket.empty()) {
                candidates.insert(candidates.end(), bucket.begin(), bucket.end());
                LOG_DHT_DEBUG("Collected " << bucket.size() << " nodes from bucket " << low);
            }
            low--;
            buckets_checked++;
        }
        
        // Search right (farther buckets)
        if (high <= max_bucket_index) {
            const auto& bucket = routing_table_[high];
            if (!bucket.empty()) {
                candidates.insert(candidates.end(), bucket.begin(), bucket.end());
                LOG_DHT_DEBUG("Collected " << bucket.size() << " nodes from bucket " << high);
            }
            high++;
            buckets_checked++;
        }
    }
    
    LOG_DHT_DEBUG("Bucket-aware collection: checked " << buckets_checked << " buckets, collected " 
                  << candidates.size() << " candidate nodes around target bucket " << target_bucket);
    
    if (candidates.empty()) {
        LOG_DHT_DEBUG("No candidates found in routing table");
        return candidates;
    }
    
    // Use partial_sort to efficiently get only the 'count' closest nodes - O(n log k) vs O(n log n)
    size_t sort_count = (std::min)(count, candidates.size());
    std::partial_sort(
        candidates.begin(), 
        candidates.begin() + sort_count, 
        candidates.end(),
        [&target, this](const DhtNode& a, const DhtNode& b) {
            return is_closer(a.id, b.id, target);
        }
    );
    
    // Return up to 'count' closest nodes
    if (candidates.size() > count) {
        candidates.resize(count);
    }
    
    LOG_DHT_DEBUG("Found " << candidates.size() << " closest nodes to target " << node_id_to_hex(target));
    for (size_t i = 0; i < candidates.size(); ++i) {
        LOG_DHT_DEBUG("  [" << i << "] " << node_id_to_hex(candidates[i].id) << " at " << candidates[i].peer.ip << ":" << candidates[i].peer.port);
    }

    // Debug alternative: Compare with full routing table algorithm
    /*
    candidates.clear();
    for (const auto& bucket : routing_table_) {
        candidates.insert(candidates.end(), bucket.begin(), bucket.end());
    }
    sort_count = (std::min)(count, candidates.size());
    std::partial_sort(
        candidates.begin(),
        candidates.begin() + sort_count,
        candidates.end(),
        [&target, this](const DhtNode& a, const DhtNode& b) {
            return is_closer(a.id, b.id, target);
        }
    );
    // Return up to 'count' closest nodes
    if (candidates.size() > count) {
        candidates.resize(count);
    }
    LOG_DHT_DEBUG("Found " << candidates.size() << " closest nodes to target " << node_id_to_hex(target));
    for (size_t i = 0; i < candidates.size(); ++i) {
        LOG_DHT_DEBUG("  +[" << i << "] " << node_id_to_hex(candidates[i].id) << " at " << candidates[i].peer.ip << ":" << candidates[i].peer.port);
    }
    */
    // End of debug alternative
    
    return candidates;
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
    
    // Add sender to routing table (no verification needed - they contacted us)
    KrpcNode krpc_node(message.sender_id, sender.ip, sender.port);
    DhtNode sender_node = krpc_node_to_dht_node(krpc_node);
    add_node(sender_node, false);
    
    // Respond with ping response
    auto response = KrpcProtocol::create_ping_response(message.transaction_id, node_id_);
    send_krpc_message(response, sender);
}

void DhtClient::handle_krpc_find_node(const KrpcMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling KRPC FIND_NODE from " << node_id_to_hex(message.sender_id) << " at " << sender.ip << ":" << sender.port);
    
    // Add sender to routing table (no verification needed - they contacted us)
    KrpcNode krpc_node(message.sender_id, sender.ip, sender.port);
    DhtNode sender_node = krpc_node_to_dht_node(krpc_node);
    add_node(sender_node, false);
    
    // Find closest nodes
    auto closest_nodes = find_closest_nodes(message.target_id, K_BUCKET_SIZE);
    auto krpc_nodes = dht_nodes_to_krpc_nodes(closest_nodes);
    
    // Respond with closest nodes
    auto response = KrpcProtocol::create_find_node_response(message.transaction_id, node_id_, krpc_nodes);
    send_krpc_message(response, sender);
}

void DhtClient::handle_krpc_get_peers(const KrpcMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling KRPC GET_PEERS from " << node_id_to_hex(message.sender_id) << " at " << sender.ip << ":" << sender.port << " for info_hash " << node_id_to_hex(message.info_hash));
    
    // Add sender to routing table (no verification needed - they contacted us)
    KrpcNode krpc_node(message.sender_id, sender.ip, sender.port);
    DhtNode sender_node = krpc_node_to_dht_node(krpc_node);
    add_node(sender_node, false);
    
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
    
    // Add sender to routing table (no verification needed - they contacted us)
    KrpcNode krpc_node(message.sender_id, sender.ip, sender.port);
    DhtNode sender_node = krpc_node_to_dht_node(krpc_node);
    add_node(sender_node, false);
    
    // Store the peer announcement
    Peer announcing_peer(sender.ip, message.port);
    store_announced_peer(message.info_hash, announcing_peer);
    
    // Respond with acknowledgment
    auto response = KrpcProtocol::create_announce_peer_response(message.transaction_id, node_id_);
    send_krpc_message(response, sender);
}

void DhtClient::handle_krpc_response(const KrpcMessage& message, const Peer& sender) {
    LOG_DHT_DEBUG("Handling KRPC response from " << sender.ip << ":" << sender.port);
    
    // Check if this is a ping verification response before normal processing
    handle_ping_verification_response(message.transaction_id, message.response_id, sender);
    
    // Add responder to routing table (no verification needed - they responded to us)
    KrpcNode krpc_node(message.response_id, sender.ip, sender.port);
    DhtNode sender_node = krpc_node_to_dht_node(krpc_node);
    add_node(sender_node, false);
    
    // Add any nodes from the response (these need verification - we haven't contacted them)
    for (const auto& node : message.nodes) {
        DhtNode dht_node = krpc_node_to_dht_node(node);
        add_node(dht_node, true);
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
    
    // Clean up finished searches AFTER all response data has been processed
    // This ensures peers and nodes are fully handled before removing the search
    {
        std::lock_guard<std::mutex> lock(pending_searches_mutex_);
        auto trans_it = transaction_to_search_.find(message.transaction_id);
        if (trans_it != transaction_to_search_.end()) {
            const std::string& hash_key = trans_it->second.info_hash_hex;
            auto search_it = pending_searches_.find(hash_key);
            if (search_it != pending_searches_.end() && search_it->second.is_finished) {
                LOG_DHT_DEBUG("Cleaning up finished search for info_hash " << hash_key 
                              << " after processing transaction " << message.transaction_id);
                pending_searches_.erase(search_it);
            }
            // Always remove the transaction mapping after processing
            transaction_to_search_.erase(trans_it);
        }
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
    std::string token = oss.str();
    
    // Store token for this peer with timestamp
    {
        std::lock_guard<std::mutex> lock(peer_tokens_mutex_);
        peer_tokens_[peer] = PeerToken(token);
    }
    
    return token;
}

bool DhtClient::verify_token(const Peer& peer, const std::string& token) {
    std::lock_guard<std::mutex> lock(peer_tokens_mutex_);
    auto it = peer_tokens_.find(peer);
    if (it != peer_tokens_.end()) {
        return it->second.token == token;
    }
    return false;
}

void DhtClient::cleanup_stale_nodes() {
    std::lock_guard<std::mutex> routing_lock(routing_table_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto stale_threshold = std::chrono::minutes(15);
    
    size_t total_removed = 0;
    
    for (auto& bucket : routing_table_) {
        auto old_size = bucket.size();
        
        bucket.erase(std::remove_if(bucket.begin(), bucket.end(),
                                   [now, stale_threshold](const DhtNode& node) {
                                       bool should_remove = (now - node.last_seen > stale_threshold);
                                       
                                       if (should_remove) {
                                           LOG_DHT_DEBUG("Removing stale node " << node_id_to_hex(node.id) 
                                                       << " at " << node.peer.ip << ":" << node.peer.port);
                                       }
                                       
                                       return should_remove;
                                   }), bucket.end());
        
        total_removed += (old_size - bucket.size());
    }
    
    if (total_removed > 0) {
        LOG_DHT_DEBUG("Cleaned up " << total_removed << " stale/failed nodes from routing table");
    }
}

void DhtClient::cleanup_stale_peer_tokens() {
    std::lock_guard<std::mutex> lock(peer_tokens_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto stale_threshold = std::chrono::minutes(10);  // Tokens valid for 10 minutes (BEP 5 recommends tokens expire)
    
    size_t total_before = peer_tokens_.size();
    
    auto it = peer_tokens_.begin();
    while (it != peer_tokens_.end()) {
        if (now - it->second.created_at > stale_threshold) {
            LOG_DHT_DEBUG("Removing stale token for peer " << it->first.ip << ":" << it->first.port);
            it = peer_tokens_.erase(it);
        } else {
            ++it;
        }
    }
    
    size_t total_after = peer_tokens_.size();
    
    if (total_before > total_after) {
        LOG_DHT_DEBUG("Cleaned up " << (total_before - total_after) << " stale peer tokens "
                      << "(from " << total_before << " to " << total_after << ")");
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
            int byte_index = static_cast<int>(i / 8);
            int bit_index = static_cast<int>(i % 8);
            
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
                    send_krpc_find_node(node.peer, random_id);
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
        if (pending_searches_.find(trans_it->second.info_hash_hex) == pending_searches_.end()) {
            LOG_DHT_DEBUG("Removing stale transaction mapping " << trans_it->first << " -> " << trans_it->second.info_hash_hex);
            trans_it = transaction_to_search_.erase(trans_it);
        } else {
            ++trans_it;
        }
    }
}

void DhtClient::cleanup_timed_out_search_requests() {
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);

    if (pending_searches_.empty()) {
        return;
    }
    
    auto now = std::chrono::steady_clock::now();
    // - Short timeout (3s): Free up the slot by increasing branch_factor, but keep waiting for late response
    // - Full timeout (15s): Mark node as failed and remove the transaction
    auto short_timeout_threshold = std::chrono::seconds(2);
    auto full_timeout_threshold = std::chrono::seconds(15);
    
    // Collect transactions that need short timeout or full timeout
    std::vector<std::string> short_timeout_transactions;
    std::vector<std::string> full_timeout_transactions;
    
    for (const auto& [transaction_id, trans_info] : transaction_to_search_) {
        auto elapsed = now - trans_info.sent_at;
        
        if (elapsed > full_timeout_threshold) {
            full_timeout_transactions.push_back(transaction_id);
        } else if (elapsed > short_timeout_threshold) {
            // Check if this node already has short timeout
            auto search_it = pending_searches_.find(trans_info.info_hash_hex);
            if (search_it != pending_searches_.end()) {
                auto& search = search_it->second;
                // Only process if not already marked with short timeout
                auto state_it = search.node_states.find(trans_info.queried_node_id);
                if (state_it == search.node_states.end() || !(state_it->second & SearchNodeFlags::SHORT_TIMEOUT)) {
                    short_timeout_transactions.push_back(transaction_id);
                }
            }
        }
    }
    
    // Group by search to batch process and call add_search_requests once per search
    std::unordered_set<std::string> affected_searches;
    
    // Process short timeouts first - these nodes are slow but we still wait for a response
    for (const auto& transaction_id : short_timeout_transactions) {
        auto trans_it = transaction_to_search_.find(transaction_id);
        if (trans_it == transaction_to_search_.end()) {
            continue;
        }
        
        const auto& trans_info = trans_it->second;
        auto search_it = pending_searches_.find(trans_info.info_hash_hex);
        
        if (search_it != pending_searches_.end()) {
            auto& search = search_it->second;
            
            if (!search.is_finished) {
                // Mark node with short timeout (add flag, preserving existing flags)
                search.node_states[trans_info.queried_node_id] |= SearchNodeFlags::SHORT_TIMEOUT;
                
                // Increase branch factor to allow another request (opening up a slot)
                search.branch_factor++;
                
                LOG_DHT_DEBUG("Short timeout for node " << node_id_to_hex(trans_info.queried_node_id) 
                              << " in search " << trans_info.info_hash_hex 
                              << " - increased branch_factor to " << search.branch_factor
                              << " (still waiting for late response)");
                
                affected_searches.insert(trans_info.info_hash_hex);
            }
        }
        // Note: We DON'T remove the transaction - we're still waiting for a possible late response
    }
    
    // Process full timeouts - these nodes have completely failed
    for (const auto& transaction_id : full_timeout_transactions) {
        auto trans_it = transaction_to_search_.find(transaction_id);
        if (trans_it == transaction_to_search_.end()) {
            continue;
        }
        
        const auto& trans_info = trans_it->second;
        auto search_it = pending_searches_.find(trans_info.info_hash_hex);
        
        if (search_it != pending_searches_.end()) {
            auto& search = search_it->second;
            
            if (!search.is_finished) {
                // Get current flags for this node
                uint8_t& flags = search.node_states[trans_info.queried_node_id];
                bool had_short_timeout = flags & SearchNodeFlags::SHORT_TIMEOUT;
                
                // Always decrement invoke_count on full timeout (node was still in-flight)
                if (search.invoke_count > 0) {
                    search.invoke_count--;
                }
                
                if (had_short_timeout) {
                    // Restore branch factor since node fully timed out
                    if (search.branch_factor > static_cast<int>(ALPHA)) {
                        search.branch_factor--;
                    }
                    
                    LOG_DHT_DEBUG("Full timeout for node " << node_id_to_hex(trans_info.queried_node_id) 
                                  << " in search " << trans_info.info_hash_hex 
                                  << " (had short timeout) - restored branch_factor to " << search.branch_factor
                                  << ", invoke_count now: " << search.invoke_count);
                } else {
                    LOG_DHT_DEBUG("Full timeout for node " << node_id_to_hex(trans_info.queried_node_id) 
                                  << " in search " << trans_info.info_hash_hex 
                                  << " - invoke_count now: " << search.invoke_count);
                }
                
                // Mark the node as timed out (add flag, preserving history)
                flags |= SearchNodeFlags::TIMED_OUT;
                
                affected_searches.insert(trans_info.info_hash_hex);
            }
        }
        
        // Remove the fully timed out transaction
        transaction_to_search_.erase(trans_it);
    }
    
    if (!short_timeout_transactions.empty() || !full_timeout_transactions.empty()) {
        LOG_DHT_DEBUG("Timeout handling: " << short_timeout_transactions.size() << " short timeouts, "
                      << full_timeout_transactions.size() << " full timeouts");
    }
    
    // Continue searches that had timeout events
    for (const auto& hash_key : affected_searches) {
        auto search_it = pending_searches_.find(hash_key);
        if (search_it != pending_searches_.end() && !search_it->second.is_finished) {
            LOG_DHT_DEBUG("Continuing search " << hash_key << " after timeout handling");
            add_search_requests(search_it->second);
        }
    }
    
    // Clean up finished searches
    for (const auto& hash_key : affected_searches) {
        auto search_it = pending_searches_.find(hash_key);
        if (search_it != pending_searches_.end() && search_it->second.is_finished) {
            LOG_DHT_DEBUG("Removing finished search " << hash_key << " after timeout handling");
            pending_searches_.erase(search_it);
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
        
        // Send announce_peer with the received token
        send_krpc_announce_peer(responder, pending_announce.info_hash, pending_announce.port, token);
        
        // Remove the pending announce since we've handled it
        pending_announces_.erase(it);
    }
}


void DhtClient::handle_get_peers_response_for_search(const std::string& transaction_id, const Peer& responder, const std::vector<Peer>& peers) {
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    
    auto trans_it = transaction_to_search_.find(transaction_id);
    if (trans_it != transaction_to_search_.end()) {
        const auto& trans_info = trans_it->second;
        auto search_it = pending_searches_.find(trans_info.info_hash_hex);
        if (search_it != pending_searches_.end()) {
            auto& pending_search = search_it->second;

            // Get flags for this node and mark as responded
            uint8_t& flags = pending_search.node_states[trans_info.queried_node_id];
            
            // Decrement invoke count since we received a response
            if (pending_search.invoke_count > 0) {
                pending_search.invoke_count--;
            }
            
            // If this node had short timeout, restore the branch factor (late response arrived)
            if (flags & SearchNodeFlags::SHORT_TIMEOUT) {
                if (pending_search.branch_factor > static_cast<int>(ALPHA)) {
                    pending_search.branch_factor--;
                }
                LOG_DHT_DEBUG("Late response from node " << node_id_to_hex(trans_info.queried_node_id)
                              << " (had short timeout) - restored branch_factor to " << pending_search.branch_factor);
            }
            
            // Mark as responded (add flag, preserving history including SHORT_TIMEOUT)
            flags |= SearchNodeFlags::RESPONDED;
            
            LOG_DHT_DEBUG("Found pending search for KRPC transaction " << transaction_id 
                          << " - received " << peers.size() << " peers for info_hash " << trans_info.info_hash_hex 
                          << " from " << responder.ip << ":" << responder.port
                          << " (invoke_count now: " << pending_search.invoke_count << ")");

            // Accumulate peers (with deduplication) - continue search like reference implementation
            if (!peers.empty()) {
                for (const auto& peer : peers) {
                    // Check if peer already exists in found_peers
                    auto it = std::find_if(pending_search.found_peers.begin(), 
                                           pending_search.found_peers.end(),
                                           [&peer](const Peer& p) { 
                                               return p.ip == peer.ip && p.port == peer.port; 
                                           });
                    if (it == pending_search.found_peers.end()) {
                        pending_search.found_peers.push_back(peer);
                        LOG_DHT_DEBUG("  [new] found peer for hash(" << trans_info.info_hash_hex << ") = " << peer.ip << ":" << peer.port);
                    }
                }
                LOG_DHT_DEBUG("Accumulated " << pending_search.found_peers.size() << " total peers for info_hash " << trans_info.info_hash_hex);
            }
            
            // Continue search - let add_search_requests determine when to finish
            add_search_requests(pending_search);
        }
        
        // DON'T remove the transaction mapping here - it will be removed at the end of handle_krpc_response
        // This ensures all response data is fully processed before cleanup
    }
}


void DhtClient::handle_get_peers_response_with_nodes(const std::string& transaction_id, const Peer& responder, const std::vector<KrpcNode>& nodes) {
    // This function is called when get_peers returns nodes instead of peers
    // Add the new nodes to search_nodes and continue the search
    
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    
    auto trans_it = transaction_to_search_.find(transaction_id);
    if (trans_it != transaction_to_search_.end()) {
        const auto& trans_info = trans_it->second;
        auto search_it = pending_searches_.find(trans_info.info_hash_hex);
        if (search_it != pending_searches_.end()) {
            auto& pending_search = search_it->second;

            // Get flags for this node and mark as responded
            uint8_t& flags = pending_search.node_states[trans_info.queried_node_id];
            
            // Decrement invoke count since we received a response
            if (pending_search.invoke_count > 0) {
                pending_search.invoke_count--;
            }
            
            // If this node had short timeout, restore the branch factor (late response arrived)
            if (flags & SearchNodeFlags::SHORT_TIMEOUT) {
                if (pending_search.branch_factor > static_cast<int>(ALPHA)) {
                    pending_search.branch_factor--;
                }
                LOG_DHT_DEBUG("Late response from node " << node_id_to_hex(trans_info.queried_node_id)
                              << " (had short timeout) - restored branch_factor to " << pending_search.branch_factor);
            }
            
            // Mark as responded (add flag, preserving history including SHORT_TIMEOUT)
            flags |= SearchNodeFlags::RESPONDED;
            
            LOG_DHT_DEBUG("Processing get_peers response with " << nodes.size() 
                          << " nodes for info_hash " << trans_info.info_hash_hex << " from " << responder.ip << ":" << responder.port
                          << " (invoke_count now: " << pending_search.invoke_count << ")");
            
            // Add new nodes to search_nodes (sorted by distance)
            size_t nodes_added = 0;
            for (const auto& node : nodes) {
                DhtNode dht_node = krpc_node_to_dht_node(node);
                size_t old_size = pending_search.search_nodes.size();
                add_node_to_search(pending_search, dht_node);
                if (pending_search.search_nodes.size() > old_size) {
                    nodes_added++;
                }
            }
            
            LOG_DHT_DEBUG("Added " << nodes_added << " new nodes to search_nodes (total: " << pending_search.search_nodes.size() << ")");
            
            // Continue search with new nodes
            add_search_requests(pending_search);
        }
        
        // DON'T remove the transaction mapping here - it will be removed at the end of handle_krpc_response
        // This ensures all response data is fully processed before cleanup
    }
}


void DhtClient::add_node_to_search(PendingSearch& search, const DhtNode& node) {
    // Check if node already exists in search (node is "known" if it's in node_states map)
    if (search.node_states.find(node.id) != search.node_states.end()) {
        LOG_DHT_DEBUG("Node " << node_id_to_hex(node.id) << " already known for search - skipping");
        return;
    }
    
    // Find insertion point to maintain sorted order (closest first)
    auto insert_pos = std::lower_bound(search.search_nodes.begin(), search.search_nodes.end(), node,
                                       [&search, this](const DhtNode& a, const DhtNode& b) {
                                           return is_closer(a.id, b.id, search.info_hash);
                                       });
    
    search.search_nodes.insert(insert_pos, node);
    // Mark node as known (add to map with no flags set - will get QUERIED flag when query is sent)
    search.node_states[node.id] = 0;
    
    // Limit search_nodes size to avoid unbounded growth
    constexpr size_t MAX_SEARCH_NODES = 100;
    if (search.search_nodes.size() > MAX_SEARCH_NODES) {
        // Before truncating, clean up counters for in-flight queries being discarded
        for (size_t i = MAX_SEARCH_NODES; i < search.search_nodes.size(); ++i) {
            const auto& discarded_node = search.search_nodes[i];
            auto state_it = search.node_states.find(discarded_node.id);
            if (state_it != search.node_states.end()) {
                uint8_t flags = state_it->second;
                // If queried but not responded/failed, it's in-flight
                if ((flags & SearchNodeFlags::QUERIED) && 
                    !(flags & (SearchNodeFlags::RESPONDED | SearchNodeFlags::TIMED_OUT))) {
                    // Decrement invoke_count since this request is being abandoned
                    if (search.invoke_count > 0) {
                        search.invoke_count--;
                        LOG_DHT_DEBUG("Decrementing invoke_count for abandoned node " 
                                      << node_id_to_hex(discarded_node.id) 
                                      << " (now: " << search.invoke_count << ")");
                    }
                    // If it had short timeout, also restore branch factor
                    if (flags & SearchNodeFlags::SHORT_TIMEOUT) {
                        if (search.branch_factor > static_cast<int>(ALPHA)) {
                            search.branch_factor--;
                            LOG_DHT_DEBUG("Decrementing branch_factor for abandoned node with short_timeout " 
                                          << node_id_to_hex(discarded_node.id) 
                                          << " (now: " << search.branch_factor << ")");
                        }
                    }
                }
                // Remove from node_states to avoid orphaned state
                search.node_states.erase(state_it);
            }
        }
        search.search_nodes.resize(MAX_SEARCH_NODES);
    }
}

bool DhtClient::add_search_requests(PendingSearch& search) {
    // Returns true if search is done (completed or should be finished)
    
    if (search.is_finished) {
        return true;
    }
    
    std::string hash_key = node_id_to_hex(search.info_hash);
    
    LOG_DHT_DEBUG("Adding search requests for info_hash " << hash_key 
                  << " - search_nodes: " << search.search_nodes.size()
                  << ", known: " << search.node_states.size()
                  << ", invoke_count: " << search.invoke_count
                  << ", branch_factor: " << search.branch_factor);
    
    const int k = static_cast<int>(K_BUCKET_SIZE);  // Target number of results
    int results_found = 0;       // Nodes that have responded
    int queries_in_flight = 0;   // Requests currently in flight
    int timed_out_count = 0;     // Nodes that timed out
    int queries_sent = 0;        // Queries sent this round
    
    // Iterate through search_nodes (sorted by distance, closest first)
    // Important: We must continue iterating to count results even when we can't send more requests
    for (auto& node : search.search_nodes) {
        // Stop if we have enough completed results
        if (results_found >= k) {
            break;
        }

        // Get flags for this node (0 if not in map, meaning just "known")
        auto state_it = search.node_states.find(node.id);
        uint8_t flags = (state_it != search.node_states.end()) ? state_it->second : 0;
        
        // Check if this node has already responded (counts toward results)
        if (flags & SearchNodeFlags::RESPONDED) {
            results_found++;
            continue;
        }
        
        // Skip nodes that have timed out (don't count as results or in-flight)
        if (flags & SearchNodeFlags::TIMED_OUT) {
            timed_out_count++;
            continue;
        }
        
        // Check if this node was already queried (in-flight)
        if (flags & SearchNodeFlags::QUERIED) {
            queries_in_flight++;
            continue;
        }
        
        // Check if we have capacity to send more requests
        // Important: use 'continue' not 'break' to keep counting results
        // Use adaptive branch_factor (increases on short timeout, restores on response/full timeout)
        if (search.invoke_count >= search.branch_factor) {
            continue;
        }
        
        // Send query to this node
        std::string transaction_id = KrpcProtocol::generate_transaction_id();
        transaction_to_search_[transaction_id] = SearchTransaction(hash_key, node.id);
        search.node_states[node.id] |= SearchNodeFlags::QUERIED;
        search.invoke_count++;
        
        LOG_DHT_DEBUG("Querying node " << node_id_to_hex(node.id) << " at " << node.peer.ip << ":" << node.peer.port);
        
        auto message = KrpcProtocol::create_get_peers_query(transaction_id, node_id_, search.info_hash);
        send_krpc_message(message, node.peer);
        
        queries_sent++;
    }
    
    LOG_DHT_DEBUG("Search requests summary for " << hash_key << ":"
        << " * search_nodes=" << search.search_nodes.size()
        << " * queries_sent=" << queries_sent
        << " * invoke_count=" << search.invoke_count
        << " * branch_factor=" << search.branch_factor
        << " * results_found=" << results_found
        << " * queries_in_flight=" << queries_in_flight
        << " * timed_out=" << timed_out_count);
    
    if ((results_found >= k && queries_in_flight == 0) || search.invoke_count == 0) {
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - search.created_at
        ).count();
        
        // Count final stats for completion log
        int queried_total = 0, responded_total = 0, timed_out_total = 0, short_timeout_total = 0;
        for (const auto& [id, f] : search.node_states) {
            if (f & SearchNodeFlags::QUERIED) queried_total++;
            if (f & SearchNodeFlags::RESPONDED) responded_total++;
            if (f & SearchNodeFlags::TIMED_OUT) timed_out_total++;
            if (f & SearchNodeFlags::SHORT_TIMEOUT) short_timeout_total++;
        }
        
        LOG_DHT_INFO("=== Search Completed for info_hash " << hash_key << " ===");
        LOG_DHT_INFO("  Duration: " << duration_ms << "ms");
        LOG_DHT_INFO("  Total nodes queried: " << queried_total);
        LOG_DHT_INFO("  Total nodes responded: " << responded_total);
        LOG_DHT_INFO("  Total nodes timed out: " << timed_out_total);
        LOG_DHT_INFO("  Nodes with short timeout: " << short_timeout_total);
        LOG_DHT_INFO("  Final branch_factor: " << search.branch_factor << " (initial: " << ALPHA << ")");
        LOG_DHT_INFO("  Total peers found: " << search.found_peers.size());
        LOG_DHT_INFO("  Callbacks to invoke: " << search.callbacks.size());
        
        // Invoke all callbacks with accumulated peers
        for (const auto& callback : search.callbacks) {
            if (callback) {
                callback(search.found_peers, search.info_hash);
            }
        }
        
        search.is_finished = true;
        return true;
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

// Ping-before-replace eviction implementation
void DhtClient::initiate_ping_verification(const DhtNode& candidate_node, const DhtNode& old_node, int bucket_index) {
    std::string ping_transaction_id = KrpcProtocol::generate_transaction_id();
    
    LOG_DHT_DEBUG("Initiating ping verification for candidate node " << node_id_to_hex(candidate_node.id) 
                  << " at " << candidate_node.peer.ip << ":" << candidate_node.peer.port 
                  << " to potentially replace old node " << node_id_to_hex(old_node.id) 
                  << " (transaction: " << ping_transaction_id << ")");
    
    // Store ping verification state and mark old node as being replaced
    {
        std::lock_guard<std::mutex> ping_lock(pending_pings_mutex_);

        if (candidates_being_pinged_.find(candidate_node.id) != candidates_being_pinged_.end()) {
            LOG_DHT_DEBUG("Already pinging candidate node " << node_id_to_hex(candidate_node.id) 
                          << " - skipping duplicate ping verification");
            return;
        }

        pending_pings_.emplace(ping_transaction_id, PingVerification(candidate_node, old_node, bucket_index));
        nodes_being_replaced_.insert(old_node.id);
        candidates_being_pinged_.insert(candidate_node.id);
    }
    
    // Send ping to the CANDIDATE node to verify it's alive
    auto message = KrpcProtocol::create_ping_query(ping_transaction_id, node_id_);
    send_krpc_message(message, candidate_node.peer);
}

void DhtClient::handle_ping_verification_response(const std::string& transaction_id, const NodeId& responder_id, const Peer& responder) {
    std::lock_guard<std::mutex> ping_lock(pending_pings_mutex_);
    
    auto it = pending_pings_.find(transaction_id);
    if (it != pending_pings_.end()) {
        const auto& verification = it->second;
        
        // Check if the responder node ID matches the candidate node we pinged
        if (responder_id == verification.candidate_node.id) {
            LOG_DHT_DEBUG("Ping verification successful for candidate node " << node_id_to_hex(verification.candidate_node.id) 
                          << " - proceeding with replacement of old node " << node_id_to_hex(verification.old_node.id));
            
            // The candidate node responded and is alive - perform the replacement
            DhtNode updated_candidate = verification.candidate_node;
            updated_candidate.last_seen = std::chrono::steady_clock::now();
            perform_replacement(updated_candidate, verification.old_node, verification.bucket_index);
        } else {
            LOG_DHT_WARN("Ping verification response from unexpected node " << node_id_to_hex(responder_id) 
                         << " at " << responder.ip << ":" << responder.port 
                         << " (expected candidate node " << node_id_to_hex(verification.candidate_node.id) << ")");
        }
        
        // Remove tracking entries
        nodes_being_replaced_.erase(verification.old_node.id);
        candidates_being_pinged_.erase(verification.candidate_node.id);
        pending_pings_.erase(it);
    }
}

void DhtClient::cleanup_stale_ping_verifications() {
    std::lock_guard<std::mutex> ping_lock(pending_pings_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto timeout_threshold = std::chrono::seconds(30);  // 30 second timeout for ping responses
    
    auto it = pending_pings_.begin();
    while (it != pending_pings_.end()) {
        if (now - it->second.ping_sent_at > timeout_threshold) {
            LOG_DHT_DEBUG("Ping verification timed out for candidate node " << node_id_to_hex(it->second.candidate_node.id) 
                          << " - candidate is unresponsive, keeping old node " << node_id_to_hex(it->second.old_node.id));
            
            // Remove tracking entries since the ping verification failed
            nodes_being_replaced_.erase(it->second.old_node.id);
            candidates_being_pinged_.erase(it->second.candidate_node.id);
            
            it = pending_pings_.erase(it);
        } else {
            ++it;
        }
    }
}

bool DhtClient::perform_replacement(const DhtNode& candidate_node, const DhtNode& node_to_replace, int bucket_index) {
    std::lock_guard<std::mutex> lock(routing_table_mutex_);
    
    auto& bucket = routing_table_[bucket_index];
    auto it = std::find_if(bucket.begin(), bucket.end(),
                          [&node_to_replace](const DhtNode& node) {
                              return node.id == node_to_replace.id;
                          });
    
    if (it != bucket.end()) {
        LOG_DHT_DEBUG("Replacing old node " << node_id_to_hex(node_to_replace.id) 
                      << " with " << node_id_to_hex(candidate_node.id) << " in bucket " << bucket_index);
        *it = candidate_node;
        return true;
    } else {
        LOG_DHT_WARN("Could not find node " << node_id_to_hex(node_to_replace.id) 
                     << " to replace in bucket " << bucket_index);
    }

    return false;
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