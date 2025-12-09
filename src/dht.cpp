#include "dht.h"
#include "network_utils.h"
#include "logger.h"
#include "socket.h"
#include "json.hpp"
#include <random>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cmath>
#include <fstream>

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


DhtClient::DhtClient(int port, const std::string& bind_address, const std::string& data_directory) 
    : port_(port), bind_address_(bind_address), data_directory_(data_directory), 
      socket_(INVALID_SOCKET_VALUE), running_(false) {
    node_id_ = generate_node_id();
    routing_table_.resize(NODE_ID_SIZE * 8);  // 160 buckets for 160-bit node IDs
    
    if (data_directory_.empty()) {
        data_directory_ = ".";
    }
    
    LOG_DHT_INFO("DHT client created with node ID: " << node_id_to_hex(node_id_) <<
                 (bind_address_.empty() ? "" : " bind address: " + bind_address_) <<
                 " data directory: " << data_directory_);
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
    
    // Load saved routing table before starting threads
    if (load_routing_table()) {
        LOG_DHT_INFO("Loaded routing table from disk (" << get_routing_table_size() << " nodes)");
    }
    
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
    
    // Save routing table before closing
    if (save_routing_table()) {
        LOG_DHT_INFO("Saved routing table to disk (" << get_routing_table_size() << " nodes)");
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
    
    DeferredCallbacks deferred;
    
    {
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
        add_search_requests(search_ref, deferred);
    }
    
    // Invoke callbacks outside the lock to avoid deadlock
    deferred.invoke();
    
    return true;
}

bool DhtClient::announce_peer(const InfoHash& info_hash, uint16_t port, PeerDiscoveryCallback callback) {
    if (!running_) {
        LOG_DHT_ERROR("DHT client not running");
        return false;
    }
    
    if (port == 0) {
        port = port_;
    }
    
    std::string hash_key = node_id_to_hex(info_hash);
    LOG_DHT_INFO("Announcing peer for info hash: " << hash_key << " on port " << port);
    
    // BEP 5 compliant announce: 
    // 1. Perform iterative Kademlia lookup (like find_peers)
    // 2. Collect tokens from responding nodes
    // 3. Send announce_peer to k closest nodes with their tokens
    
    // Get initial nodes from routing table
    auto closest_nodes = find_closest_nodes(info_hash, K_BUCKET_SIZE);
    
    if (closest_nodes.empty()) {
        LOG_DHT_WARN("No nodes in routing table to announce to for info_hash " << hash_key);
        return false;
    }
    
    DeferredCallbacks deferred;
    
    {
        std::lock_guard<std::mutex> lock(pending_searches_mutex_);
        
        // Check if a search/announce is already ongoing for this info_hash
        auto search_it = pending_searches_.find(hash_key);
        if (search_it != pending_searches_.end()) {
            if (search_it->second.is_announce) {
                LOG_DHT_INFO("Announce already in progress for info hash " << hash_key);
                return true;
            }
            // Regular find_peers in progress - let it complete, then user can announce again
            LOG_DHT_WARN("find_peers already in progress for info hash " << hash_key << " - announce will wait");
            return false;
        }
        
        // Create new search with announce flag
        PendingSearch new_search(info_hash);
        new_search.is_announce = true;
        new_search.announce_port = port;
        
        // Add callback if provided - peers discovered during traversal will be returned through it
        if (callback) {
            new_search.callbacks.push_back(callback);
        }
        
        // Initialize search_nodes with closest nodes from routing table (already sorted)
        new_search.search_nodes = std::move(closest_nodes);
        
        auto insert_result = pending_searches_.emplace(hash_key, std::move(new_search));
        PendingSearch& search_ref = insert_result.first->second;
        
        LOG_DHT_DEBUG("Initialized announce search with " << search_ref.search_nodes.size() << " nodes from routing table");
        
        // Start sending requests
        add_search_requests(search_ref, deferred);
    }
    
    // Invoke callbacks outside the lock to avoid deadlock
    deferred.invoke();
    
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

bool DhtClient::is_search_active(const InfoHash& info_hash) const {
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    std::string hash_key = node_id_to_hex(info_hash);
    auto it = pending_searches_.find(hash_key);
    return it != pending_searches_.end() && !it->second.is_finished;
}

bool DhtClient::is_announce_active(const InfoHash& info_hash) const {
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    std::string hash_key = node_id_to_hex(info_hash);
    auto it = pending_searches_.find(hash_key);
    return it != pending_searches_.end() && !it->second.is_finished && it->second.is_announce;
}

size_t DhtClient::get_active_searches_count() const {
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    size_t count = 0;
    for (const auto& [hash, search] : pending_searches_) {
        if (!search.is_finished) {
            count++;
        }
    }
    return count;
}

size_t DhtClient::get_active_announces_count() const {
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    size_t count = 0;
    for (const auto& [hash, search] : pending_searches_) {
        if (!search.is_finished && search.is_announce) {
            count++;
        }
    }
    return count;
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
    auto last_search_node_cleanup = std::chrono::steady_clock::now();
    auto last_routing_table_save = std::chrono::steady_clock::now();
    
    while (running_) {
        auto now = std::chrono::steady_clock::now();

        // Check for timed out search requests every 2 seconds (frequent check)
        if (now - last_search_timeout_check >= std::chrono::seconds(2)) {
            cleanup_timed_out_search_requests();
            last_search_timeout_check = now;
        }
        
        // Clean up finalized node_states entries in active searches every 10 seconds
        if (now - last_search_node_cleanup >= std::chrono::seconds(10)) {
            cleanup_search_node_states();
            last_search_node_cleanup = now;
        }
        
        // General cleanup operations every 1 minute (like previously)
        if (now - last_general_cleanup >= std::chrono::minutes(1)) {
            // Cleanup stale nodes every 1 minute
            cleanup_stale_nodes();
            
            // Cleanup stale peer tokens
            cleanup_stale_peer_tokens();
            
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
            print_statistics();
            last_stats_print = now;
        }
        
        // Save routing table every 5 minutes
        if (now - last_routing_table_save >= std::chrono::minutes(5)) {
            if (save_routing_table()) {
                LOG_DHT_DEBUG("Periodic routing table save completed");
            }
            last_routing_table_save = now;
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

void DhtClient::add_node(const DhtNode& node, bool confirmed) {
    std::lock_guard<std::mutex> ping_lock(pending_pings_mutex_);
    std::lock_guard<std::mutex> lock(routing_table_mutex_);

    int bucket_index = get_bucket_index(node.id);
    auto& bucket = routing_table_[bucket_index];

    LOG_DHT_DEBUG("Adding node " << node_id_to_hex(node.id) << " at " << node.peer.ip << ":" << node.peer.port 
                  << " to bucket " << bucket_index << " (confirmed=" << confirmed << ")");
        
    // Check if node already exists
    auto it = std::find_if(bucket.begin(), bucket.end(),
                          [&node](const DhtNode& existing) {
                              return existing.id == node.id;
                          });

    if (it != bucket.end()) {
        // Update existing node - mark as successful since it contacted us
        LOG_DHT_DEBUG("Node " << node_id_to_hex(node.id) << " already exists in bucket " << bucket_index << ", updating");
        it->peer = node.peer;
        if (confirmed) {
            it->mark_success();
        }
        return;
    }

    // Bucket has space - just add
    if (bucket.size() < K_BUCKET_SIZE) {
        DhtNode new_node = node;
        if (confirmed) {
            new_node.fail_count = 0;  // Node contacted us, so it's confirmed good
        }
        bucket.push_back(new_node);
        LOG_DHT_DEBUG("Added new node " << node_id_to_hex(node.id) << " to bucket " << bucket_index << " (size: " << bucket.size() << "/" << K_BUCKET_SIZE << ")");
        return;
    }

    // Bucket is full - first check for nodes with failures (stale nodes)
    auto worst_it = std::max_element(bucket.begin(), bucket.end(),
        [](const DhtNode& a, const DhtNode& b) {
            // Find node with highest fail_count
            return a.fail_count < b.fail_count;
        });
    
    if (worst_it != bucket.end() && worst_it->fail_count > 0) {
        // Found a stale node - replace it immediately
        LOG_DHT_DEBUG("Replacing stale node " << node_id_to_hex(worst_it->id) 
                      << " (fail_count=" << static_cast<int>(worst_it->fail_count) << ")"
                      << " with " << node_id_to_hex(node.id));
        DhtNode new_node = node;
        if (confirmed) {
            new_node.fail_count = 0;  // Node contacted us, so it's confirmed good
        }
        // else: keep fail_count = 0xff (unpinged) from constructor
        *worst_it = new_node;
        return;
    }

    // All nodes are good - find the "worst" good node for ping verification
    // Worst = highest RTT among nodes not already being pinged
    DhtNode* worst = nullptr;
    for (auto& existing : bucket) {
        if (nodes_being_replaced_.find(existing.id) == nodes_being_replaced_.end()) {
            if (!worst || existing.is_worse_than(*worst)) {
                worst = &existing;
            }
        }
    }
    
    if (!worst) {
        LOG_DHT_DEBUG("All nodes in bucket already have pending pings - dropping candidate " << node_id_to_hex(node.id));
        return;
    }
    
    // Initiate ping to worst node - if it doesn't respond, replace with candidate
    LOG_DHT_DEBUG("All nodes good, pinging worst node " << node_id_to_hex(worst->id) 
                  << " (rtt=" << worst->rtt << "ms) to verify");
    initiate_ping_verification(node, *worst, bucket_index);
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
    
    // Check if this is a ping verification response before normal processing
    handle_ping_verification_response(message.transaction_id, message.response_id, sender);
    
    // Add responder to routing table
    KrpcNode krpc_node(message.response_id, sender.ip, sender.port);
    DhtNode sender_node = krpc_node_to_dht_node(krpc_node);
    add_node(sender_node);
    
    // Add any nodes from the response (these are nodes we heard about, not confirmed)
    for (const auto& node : message.nodes) {
        DhtNode dht_node = krpc_node_to_dht_node(node);
        add_node(dht_node, false);  // Not confirmed - just heard about from another node
    }
    
    // Check if this is a response to a pending search (get_peers with peers)
    if (!message.peers.empty()) {
        handle_get_peers_response_for_search(message.transaction_id, sender, message.peers);
    }
    // Check if this is a response to a pending search (get_peers with nodes)
    else if (!message.nodes.empty()) {
        handle_get_peers_response_with_nodes(message.transaction_id, sender, message.nodes);
    }
    else {
        // Empty response (no peers, no nodes) - still need to mark as responded
        // This can happen when a node has no information about the info_hash
        handle_get_peers_empty_response(message.transaction_id, sender);
    }
    
    // Save write token if present (needed for announce_peer after traversal completes)
    if (!message.token.empty()) {
        std::lock_guard<std::mutex> lock(pending_searches_mutex_);
        auto trans_it = transaction_to_search_.find(message.transaction_id);
        if (trans_it != transaction_to_search_.end()) {
            auto search_it = pending_searches_.find(trans_it->second.info_hash_hex);
            if (search_it != pending_searches_.end()) {
                save_write_token(search_it->second, trans_it->second.queried_node_id, message.token);
            }
        }
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
    constexpr uint8_t MAX_FAIL_COUNT = 3;  // Remove after 3 consecutive failures
    
    size_t total_removed = 0;
    
    for (auto& bucket : routing_table_) {
        auto old_size = bucket.size();
        
        bucket.erase(std::remove_if(bucket.begin(), bucket.end(),
                                   [now, stale_threshold, MAX_FAIL_COUNT](const DhtNode& node) {
                                       // Remove if too many failures
                                       if (node.pinged() && node.fail_count >= MAX_FAIL_COUNT) {
                                           LOG_DHT_DEBUG("Removing failed node " << node_id_to_hex(node.id) 
                                                       << " (fail_count=" << static_cast<int>(node.fail_count) << ")");
                                           return true;
                                       }
                                       
                                       // Remove if never responded and too old
                                       if (!node.pinged() && now - node.last_seen > stale_threshold) {
                                           LOG_DHT_DEBUG("Removing unresponsive node " << node_id_to_hex(node.id) 
                                                       << " (never responded, age > 15min)");
                                           return true;
                                       }
                                       
                                       return false;
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

void DhtClient::print_statistics() {
    auto now = std::chrono::steady_clock::now();
    
    // Routing table statistics
    size_t filled_buckets = 0;
    size_t total_nodes = 0;
    size_t max_bucket_size = 0;
    size_t confirmed_nodes = 0;
    size_t unpinged_nodes = 0;
    size_t failed_nodes = 0;
    
    // Collect all nodes for best/worst analysis
    std::vector<std::pair<DhtNode, int>> all_nodes;  // node + bucket index
    
    {
        std::lock_guard<std::mutex> lock(routing_table_mutex_);
        for (size_t bucket_idx = 0; bucket_idx < routing_table_.size(); ++bucket_idx) {
            const auto& bucket = routing_table_[bucket_idx];
            if (!bucket.empty()) {
                filled_buckets++;
                total_nodes += bucket.size();
                max_bucket_size = (std::max)(max_bucket_size, bucket.size());
                
                for (const auto& node : bucket) {
                    all_nodes.emplace_back(node, static_cast<int>(bucket_idx));
                    
                    if (node.confirmed()) {
                        confirmed_nodes++;
                    } else if (!node.pinged()) {
                        unpinged_nodes++;
                    } else if (node.fail_count > 0) {
                        failed_nodes++;
                    }
                }
            }
        }
    }
    
    // Pending searches statistics
    size_t pending_searches = 0;
    size_t pending_announces = 0;
    size_t total_search_nodes = 0;
    size_t total_found_peers = 0;
    size_t total_write_tokens = 0;
    size_t active_transactions = 0;
    {
        std::lock_guard<std::mutex> search_lock(pending_searches_mutex_);
        pending_searches = pending_searches_.size();
        active_transactions = transaction_to_search_.size();
        for (const auto& [hash, search] : pending_searches_) {
            total_search_nodes += search.search_nodes.size();
            total_found_peers += search.found_peers.size();
            total_write_tokens += search.write_tokens.size();
            if (search.is_announce) {
                pending_announces++;
            }
        }
    }
    
    // Announced peers statistics
    size_t announced_peers_total = 0;
    size_t announced_peers_infohashes = 0;
    {
        std::lock_guard<std::mutex> peers_lock(announced_peers_mutex_);
        announced_peers_infohashes = announced_peers_.size();
        for (const auto& entry : announced_peers_) {
            announced_peers_total += entry.second.size();
        }
    }
    
    // Ping verification statistics
    size_t pending_pings = 0;
    size_t nodes_being_replaced = 0;
    {
        std::lock_guard<std::mutex> ping_lock(pending_pings_mutex_);
        pending_pings = pending_pings_.size();
        nodes_being_replaced = nodes_being_replaced_.size();
    }
    
    // Peer tokens statistics
    size_t peer_tokens_count = 0;
    {
        std::lock_guard<std::mutex> tokens_lock(peer_tokens_mutex_);
        peer_tokens_count = peer_tokens_.size();
    }
    
    // Print main statistics
    LOG_DHT_INFO("=== DHT GLOBAL STATISTICS ===");
    LOG_DHT_INFO("[ROUTING TABLE]");
    LOG_DHT_INFO("  Total nodes: " << total_nodes << " (confirmed: " << confirmed_nodes 
                 << ", unpinged: " << unpinged_nodes << ", failed: " << failed_nodes << ")");
    LOG_DHT_INFO("  Filled buckets: " << filled_buckets << "/" << routing_table_.size() 
                 << ", Max bucket size: " << max_bucket_size << "/" << K_BUCKET_SIZE);
    LOG_DHT_INFO("[ACTIVE OPERATIONS]");
    LOG_DHT_INFO("  Pending searches: " << pending_searches 
                 << " (announces: " << pending_announces 
                 << ", nodes: " << total_search_nodes 
                 << ", peers: " << total_found_peers 
                 << ", tokens: " << total_write_tokens << ")");
    LOG_DHT_INFO("  Active transactions: " << active_transactions);
    LOG_DHT_INFO("  Pending ping verifications: " << pending_pings 
                 << " (nodes being replaced: " << nodes_being_replaced << ")");
    LOG_DHT_INFO("[STORED DATA]");
    LOG_DHT_INFO("  Announced peers: " << announced_peers_total 
                 << " across " << announced_peers_infohashes << " infohashes");
    LOG_DHT_INFO("  Peer tokens: " << peer_tokens_count);
    
    // Best/Worst nodes analysis
    if (!all_nodes.empty()) {
        // Sort by quality: confirmed first, then by RTT (lower is better)
        std::sort(all_nodes.begin(), all_nodes.end(), 
            [](const std::pair<DhtNode, int>& a, const std::pair<DhtNode, int>& b) {
                // Confirmed nodes are better
                if (a.first.confirmed() != b.first.confirmed()) {
                    return a.first.confirmed();
                }
                // Lower fail_count is better
                if (a.first.fail_count != b.first.fail_count) {
                    return a.first.fail_count < b.first.fail_count;
                }
                // Lower RTT is better (0xffff = unknown, treat as worst)
                return a.first.rtt < b.first.rtt;
            });
        
        // Calculate RTT statistics (excluding unknown)
        uint32_t rtt_sum = 0;
        uint16_t rtt_min = 0xffff;
        uint16_t rtt_max = 0;
        size_t rtt_count = 0;
        for (const auto& [node, bucket_idx] : all_nodes) {
            if (node.rtt != 0xffff) {
                rtt_sum += node.rtt;
                rtt_min = (std::min)(rtt_min, node.rtt);
                rtt_max = (std::max)(rtt_max, node.rtt);
                rtt_count++;
            }
        }
        
        LOG_DHT_INFO("[RTT STATISTICS]");
        if (rtt_count > 0) {
            LOG_DHT_INFO("  Known RTT nodes: " << rtt_count << "/" << total_nodes);
            LOG_DHT_INFO("  RTT min/avg/max: " << rtt_min << "ms / " 
                         << (rtt_sum / rtt_count) << "ms / " << rtt_max << "ms");
        } else {
            LOG_DHT_INFO("  No RTT data available");
        }
        
        // Show top 5 best nodes
        LOG_DHT_INFO("[TOP 5 BEST NODES]");
        size_t best_count = (std::min)(size_t(5), all_nodes.size());
        for (size_t i = 0; i < best_count; ++i) {
            const auto& [node, bucket_idx] = all_nodes[i];
            auto age_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - node.last_seen).count();
            std::string status = node.confirmed() ? "confirmed" : 
                                (node.pinged() ? "pinged" : "unpinged");
            std::string rtt_str = (node.rtt == 0xffff) ? "N/A" : std::to_string(node.rtt) + "ms";
            
            LOG_DHT_INFO("  #" << (i + 1) << " " << node.peer.ip << ":" << node.peer.port 
                         << " | bucket:" << bucket_idx << " rtt:" << rtt_str 
                         << " fails:" << static_cast<int>(node.fail_count)
                         << " " << status << " age:" << age_seconds << "s");
        }
        
        // Show top 5 worst nodes
        LOG_DHT_INFO("[TOP 5 WORST NODES]");
        size_t worst_start = all_nodes.size() > 5 ? all_nodes.size() - 5 : 0;
        for (size_t i = all_nodes.size(); i > worst_start; --i) {
            const auto& [node, bucket_idx] = all_nodes[i - 1];
            auto age_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - node.last_seen).count();
            std::string status = node.confirmed() ? "confirmed" : 
                                (node.pinged() ? "pinged" : "unpinged");
            std::string rtt_str = (node.rtt == 0xffff) ? "N/A" : std::to_string(node.rtt) + "ms";
            
            LOG_DHT_INFO("  #" << (all_nodes.size() - i + 1) << " " << node.peer.ip << ":" << node.peer.port 
                         << " | bucket:" << bucket_idx << " rtt:" << rtt_str 
                         << " fails:" << static_cast<int>(node.fail_count)
                         << " " << status << " age:" << age_seconds << "s");
        }
    } else {
        LOG_DHT_INFO("  No nodes in routing table");
    }
    LOG_DHT_INFO("=== END DHT STATISTICS ===");
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

void DhtClient::cleanup_search_node_states() {
    std::lock_guard<std::mutex> lock(pending_searches_mutex_);
    constexpr size_t MAX_NODE_STATES = 200;  // Twice bigger than MAX_SEARCH_NODES

    for (auto& [hash_key, search] : pending_searches_) {
        if (search.is_finished) {
            continue;
        }

        // Skip cleanup if node_states is within acceptable limits
        if (search.node_states.size() <= MAX_NODE_STATES) {
            continue;
        }

        // Erase while iterating using iterator-based loop
        size_t removed = 0;
        auto it = search.node_states.begin();
        while (it != search.node_states.end()) {
            // В cleanup_search_node_states:
            if ((it->second & SearchNodeFlags::ABANDONED) && 
            ((it->second & (SearchNodeFlags::TIMED_OUT | SearchNodeFlags::RESPONDED)) ||
            !(it->second & SearchNodeFlags::QUERIED))) {  // Never queried = safe to remove immediately
                it = search.node_states.erase(it);
                removed++;
            } else {
                ++it;
            }
        }
        
        if (removed > 0) {
            LOG_DHT_DEBUG("Cleaned up " << removed << " abandoned nodes for search " << hash_key 
                          << " (remaining: " << search.node_states.size() << ")");
        }
    }
}

void DhtClient::cleanup_timed_out_search_requests() {
    std::vector<DeferredCallbacks> all_deferred;
    
    {
        std::lock_guard<std::mutex> lock(pending_searches_mutex_);

        if (pending_searches_.empty()) {
            return;
        }
        
        auto now = std::chrono::steady_clock::now();
        // - Short timeout (2s): Free up the slot by increasing branch_factor, but keep waiting for late response
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
                    // Check if this node was abandoned during truncation
                    auto state_it = search.node_states.find(trans_info.queried_node_id);
                    if (state_it != search.node_states.end() && 
                        (state_it->second & SearchNodeFlags::ABANDONED)) {
                        // Node was abandoned, skip short timeout processing
                        continue;
                    }
                    
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
                    
                    // Check if this node was abandoned during truncation
                    if (flags & SearchNodeFlags::ABANDONED) {
                        // Node was abandoned, invoke_count already decremented
                        // Mark as timed out so cleanup_search_node_states can remove it from node_states
                        flags |= SearchNodeFlags::TIMED_OUT;
                        transaction_to_search_.erase(trans_it);
                        continue;
                    }
                    
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
                    
                    // Mark the node as failed in routing table (BEP 5 compliance)
                    {
                        std::lock_guard<std::mutex> rt_lock(routing_table_mutex_);
                        int bucket_index = get_bucket_index(trans_info.queried_node_id);
                        auto& bucket = routing_table_[bucket_index];
                        auto node_it = std::find_if(bucket.begin(), bucket.end(),
                            [&trans_info](const DhtNode& n) { return n.id == trans_info.queried_node_id; });
                        if (node_it != bucket.end()) {
                            node_it->mark_failed();
                            LOG_DHT_DEBUG("Marked node " << node_id_to_hex(trans_info.queried_node_id) 
                                          << " as failed in routing table (fail_count=" 
                                          << static_cast<int>(node_it->fail_count) << ")");
                        }
                    }
                    
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
                DeferredCallbacks deferred;
                add_search_requests(search_it->second, deferred);
                if (deferred.should_invoke) {
                    all_deferred.push_back(std::move(deferred));
                }
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
    
    // Invoke all deferred callbacks outside the lock to avoid deadlock
    for (auto& deferred : all_deferred) {
        deferred.invoke();
    }
}

void DhtClient::handle_get_peers_empty_response(const std::string& transaction_id, const Peer& responder) {
    DeferredCallbacks deferred;
    {
        std::lock_guard<std::mutex> lock(pending_searches_mutex_);
        auto trans_it = transaction_to_search_.find(transaction_id);
        if (trans_it != transaction_to_search_.end()) {
            const auto& trans_info = trans_it->second;
            auto search_it = pending_searches_.find(trans_info.info_hash_hex);
            if (search_it != pending_searches_.end()) {
                auto& pending_search = search_it->second;

                // Check if this node was abandoned during truncation
                auto state_it = pending_search.node_states.find(trans_info.queried_node_id);
                if (state_it != pending_search.node_states.end() && 
                    (state_it->second & SearchNodeFlags::ABANDONED)) {
                    // Mark as responded so cleanup_search_node_states can remove it
                    state_it->second |= SearchNodeFlags::RESPONDED;
                    LOG_DHT_DEBUG("Ignoring empty response from abandoned node " 
                                  << node_id_to_hex(trans_info.queried_node_id));
                    return;
                }

                uint8_t& flags = pending_search.node_states[trans_info.queried_node_id];

                if (flags & SearchNodeFlags::RESPONDED) {
                    LOG_DHT_DEBUG("Ignoring duplicate response from node " << node_id_to_hex(trans_info.queried_node_id));
                    return;
                }
                
                // Decrement invoke count
                if (pending_search.invoke_count > 0) {
                    pending_search.invoke_count--;
                }
                
                // Restore branch_factor if had short timeout
                if (flags & SearchNodeFlags::SHORT_TIMEOUT) {
                    if (pending_search.branch_factor > static_cast<int>(ALPHA)) {
                        pending_search.branch_factor--;
                    }
                }
                
                // Mark as responded
                flags |= SearchNodeFlags::RESPONDED;
                
                LOG_DHT_DEBUG("Empty get_peers response from " << responder.ip << ":" << responder.port
                              << " for info_hash " << trans_info.info_hash_hex
                              << " (invoke_count now: " << pending_search.invoke_count << ")");
                
                // Continue search
                add_search_requests(pending_search, deferred);
            }
        }
    }
    
    deferred.invoke();
}

void DhtClient::handle_get_peers_response_for_search(const std::string& transaction_id, const Peer& responder, const std::vector<Peer>& peers) {
    DeferredCallbacks deferred_immediate;   // For new peers callbacks
    DeferredCallbacks deferred_completion;  // For search completion callbacks

    {
        std::lock_guard<std::mutex> lock(pending_searches_mutex_);
        auto trans_it = transaction_to_search_.find(transaction_id);
        if (trans_it != transaction_to_search_.end()) {
            const auto& trans_info = trans_it->second;
            auto search_it = pending_searches_.find(trans_info.info_hash_hex);
            if (search_it != pending_searches_.end()) {
                auto& pending_search = search_it->second;

                // Check if this node was abandoned during truncation
                auto state_it = pending_search.node_states.find(trans_info.queried_node_id);
                if (state_it != pending_search.node_states.end() && 
                    (state_it->second & SearchNodeFlags::ABANDONED)) {
                    // Mark as responded so cleanup_search_node_states can remove it
                    state_it->second |= SearchNodeFlags::RESPONDED;
                    LOG_DHT_DEBUG("Ignoring response from abandoned node " 
                                << node_id_to_hex(trans_info.queried_node_id)
                                << " - invoke_count already decremented during truncation");
                    return;
                }

                // Get flags for this node and mark as responded
                uint8_t& flags = pending_search.node_states[trans_info.queried_node_id];

                // Check if already responded (duplicate response)
                if (flags & SearchNodeFlags::RESPONDED) {
                    LOG_DHT_DEBUG("Ignoring duplicate response from node " 
                                << node_id_to_hex(trans_info.queried_node_id));
                    return;
                }
                
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
                    // Collect only new (non-duplicate) peers for immediate callback
                    std::vector<Peer> new_peers;
                    new_peers.reserve(peers.size());
                    
                    for (const auto& peer : peers) {
                        // Check if peer already exists in found_peers
                        auto it = std::find_if(pending_search.found_peers.begin(), 
                                            pending_search.found_peers.end(),
                                            [&peer](const Peer& p) { 
                                                return p.ip == peer.ip && p.port == peer.port; 
                                            });
                        if (it == pending_search.found_peers.end()) {
                            pending_search.found_peers.push_back(peer);
                            new_peers.push_back(peer);
                            LOG_DHT_DEBUG("  [new] found peer for hash(" << trans_info.info_hash_hex << ") = " << peer.ip << ":" << peer.port);
                        }
                    }
                    
                    // Collect immediate callbacks for new peers
                    if (!new_peers.empty()) {
                        LOG_DHT_DEBUG("Invoking " << pending_search.callbacks.size() << " callbacks with " 
                                    << new_peers.size() << " new peers for info_hash " << trans_info.info_hash_hex);
                        deferred_immediate.should_invoke = true;
                        deferred_immediate.peers = std::move(new_peers);
                        deferred_immediate.info_hash = pending_search.info_hash;
                        deferred_immediate.callbacks = pending_search.callbacks;
                    }
                    
                    LOG_DHT_DEBUG("Accumulated " << pending_search.found_peers.size() << " total peers for info_hash " << trans_info.info_hash_hex);
                }
                
                // Continue search - let add_search_requests determine when to finish
                add_search_requests(pending_search, deferred_completion);
            }
            
            // DON'T remove the transaction mapping here - it will be removed at the end of handle_krpc_response
            // This ensures all response data is fully processed before cleanup
        }
    }

    // Invoke all callbacks outside the lock to avoid deadlock
    deferred_immediate.invoke();
    deferred_completion.invoke();
}


void DhtClient::handle_get_peers_response_with_nodes(const std::string& transaction_id, const Peer& responder, const std::vector<KrpcNode>& nodes) {
    // This function is called when get_peers returns nodes instead of peers
    // Add the new nodes to search_nodes and continue the search
    
    DeferredCallbacks deferred;
    
    {
        std::lock_guard<std::mutex> lock(pending_searches_mutex_);
        
        auto trans_it = transaction_to_search_.find(transaction_id);
        if (trans_it != transaction_to_search_.end()) {
            const auto& trans_info = trans_it->second;
            auto search_it = pending_searches_.find(trans_info.info_hash_hex);
            if (search_it != pending_searches_.end()) {
                auto& pending_search = search_it->second;

                // Check if this node was abandoned during truncation
                auto state_it = pending_search.node_states.find(trans_info.queried_node_id);
                if (state_it != pending_search.node_states.end() && 
                    (state_it->second & SearchNodeFlags::ABANDONED)) {
                    // Mark as responded so cleanup_search_node_states can remove it
                    state_it->second |= SearchNodeFlags::RESPONDED;
                    LOG_DHT_DEBUG("Ignoring response from abandoned node " 
                                  << node_id_to_hex(trans_info.queried_node_id)
                                  << " - invoke_count already decremented during truncation");
                    return;
                }

                // Get flags for this node and mark as responded
                uint8_t& flags = pending_search.node_states[trans_info.queried_node_id];

                // Check if already responded (duplicate response)
                if (flags & SearchNodeFlags::RESPONDED) {
                    LOG_DHT_DEBUG("Ignoring duplicate response from node " 
                                << node_id_to_hex(trans_info.queried_node_id));
                    return;
                }
                
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
                add_search_requests(pending_search, deferred);
            }
            
            // DON'T remove the transaction mapping here - it will be removed at the end of handle_krpc_response
            // This ensures all response data is fully processed before cleanup
        }
    }
    
    // Invoke callbacks outside the lock to avoid deadlock
    deferred.invoke();
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
                // Mark as ABANDONED instead of removing - prevents double invoke_count decrement
                // when late response arrives (response handlers check this flag)
                state_it->second |= SearchNodeFlags::ABANDONED;
            }
        }
        search.search_nodes.resize(MAX_SEARCH_NODES);
    }
}

void DhtClient::save_write_token(PendingSearch& search, const NodeId& node_id, const std::string& token) {
    // Save the write token received from a node (BEP 5 compliant)
    // This token will be used later when sending announce_peer to this node
    
    if (token.empty()) {
        return;
    }
    
    // Only save token if we don't already have one from this node
    // (first token is usually the valid one)
    if (search.write_tokens.find(node_id) == search.write_tokens.end()) {
        search.write_tokens[node_id] = token;
        LOG_DHT_DEBUG("Saved write token from node " << node_id_to_hex(node_id) 
                      << " for info_hash " << node_id_to_hex(search.info_hash)
                      << " (total tokens: " << search.write_tokens.size() << ")");
    }
}

void DhtClient::send_announce_to_closest_nodes(PendingSearch& search) {
    // BEP 5: Send announce_peer to the k closest nodes that:
    // 1. Responded to our get_peers query
    // 2. Gave us a valid write token
    
    if (!search.is_announce) {
        return;
    }
    
    std::string hash_key = node_id_to_hex(search.info_hash);
    
    LOG_DHT_INFO("Sending announce_peer to closest nodes for info_hash " << hash_key 
                 << " on port " << search.announce_port);
    
    // Collect nodes that responded and have tokens, sorted by distance (closest first)
    std::vector<std::pair<DhtNode, std::string>> announce_targets;
    announce_targets.reserve(K_BUCKET_SIZE);
    
    for (const auto& node : search.search_nodes) {
        if (announce_targets.size() >= K_BUCKET_SIZE) {
            break;  // We have enough targets
        }
        
        // Check if node responded successfully
        auto state_it = search.node_states.find(node.id);
        if (state_it == search.node_states.end()) {
            continue;
        }
        if (!(state_it->second & SearchNodeFlags::RESPONDED)) {
            continue;  // Node didn't respond
        }
        
        // Check if we have a token from this node
        auto token_it = search.write_tokens.find(node.id);
        if (token_it == search.write_tokens.end()) {
            LOG_DHT_DEBUG("Node " << node_id_to_hex(node.id) << " responded but no token - skipping");
            continue;  // No token from this node
        }
        
        announce_targets.emplace_back(node, token_it->second);
    }
    
    if (announce_targets.empty()) {
        LOG_DHT_WARN("No nodes with tokens to announce to for info_hash " << hash_key);
        return;
    }
    
    LOG_DHT_INFO("Announcing to " << announce_targets.size() << " closest nodes with tokens");
    
    // Send announce_peer to each target
    for (const auto& [node, token] : announce_targets) {
        LOG_DHT_DEBUG("Sending announce_peer to node " << node_id_to_hex(node.id) 
                      << " at " << node.peer.ip << ":" << node.peer.port
                      << " with token (distance: " << get_bucket_index(node.id) << ")");
        
        send_krpc_announce_peer(node.peer, search.info_hash, search.announce_port, token);
    }
    
    LOG_DHT_INFO("Announce completed: sent announce_peer to " << announce_targets.size() 
                 << " nodes for info_hash " << hash_key);
}

bool DhtClient::add_search_requests(PendingSearch& search, DeferredCallbacks& deferred) {
    // Returns true if search is done (completed or should be finished)
    
    if (search.is_finished) {
        return true;
    }
    
    std::string hash_key = node_id_to_hex(search.info_hash);
    
    LOG_DHT_DEBUG("Adding search requests for info_hash " << hash_key);
    
    const int k = static_cast<int>(K_BUCKET_SIZE);  // Target number of results
    int loop_index = -1;
    int results_found = 0;       // Nodes that have responded
    int queries_in_flight = 0;   // Requests currently in flight
    int timed_out_count = 0;     // Nodes that timed out
    int queries_sent = 0;        // Queries sent this round
    
    // Iterate through search_nodes (sorted by distance, closest first)
    // Important: We must continue iterating to count results even when we can't send more requests
    for (auto& node : search.search_nodes) {
        loop_index++;

        // Stop if we have enough completed results
        if (results_found >= k) {
            break;
        }

        // Get flags for this node (0 if not in map, meaning just "known")
        auto state_it = search.node_states.find(node.id);
        uint8_t flags = (state_it != search.node_states.end()) ? state_it->second : 0;

        // Usually it doesn't happen, but if it does, we skip it
        if (flags & SearchNodeFlags::ABANDONED) {
            continue;
        }
        
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
        
        // Check if this node was already queried
        if (flags & SearchNodeFlags::QUERIED) {
            // Only count as in-flight if not responded yet
            // (TIMED_OUT already handled above, RESPONDED handled above too)
            // This case handles nodes that are QUERIED but still waiting for response
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
    
    LOG_DHT_DEBUG((search.is_announce ? "Announce" : "Search") << " [" << hash_key << "] progress [ms: " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - search.created_at).count() << "]:");
    LOG_DHT_DEBUG(" * search_nodes: " << search.search_nodes.size());
    LOG_DHT_DEBUG(" * queries_sent: " << queries_sent);
    LOG_DHT_DEBUG(" * invoke_count: " << search.invoke_count);
    LOG_DHT_DEBUG(" * branch_factor: " << search.branch_factor);
    LOG_DHT_DEBUG(" * results_found: " << results_found);
    LOG_DHT_DEBUG(" * queries_in_flight: " << queries_in_flight);
    LOG_DHT_DEBUG(" * timed_out: " << timed_out_count);
    LOG_DHT_DEBUG(" * peers_found: " << search.found_peers.size());
    LOG_DHT_DEBUG(" * callbacks: " << search.callbacks.size());
    LOG_DHT_DEBUG(" * loop_index: " << loop_index);
    LOG_DHT_DEBUG(" * node_states: " << search.node_states.size());
    
    if ((results_found >= k && queries_in_flight == 0) || search.invoke_count == 0) {
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - search.created_at
        ).count();
        
        // Count final stats for completion log
        int queried_total = 0, responded_total = 0, timed_out_total = 0, short_timeout_total = 0, abandoned_total = 0;
        for (const auto& [id, f] : search.node_states) {
            if (f & SearchNodeFlags::QUERIED) queried_total++;
            if (f & SearchNodeFlags::RESPONDED) responded_total++;
            if (f & SearchNodeFlags::TIMED_OUT) timed_out_total++;
            if (f & SearchNodeFlags::SHORT_TIMEOUT) short_timeout_total++;
            if (f & SearchNodeFlags::ABANDONED) abandoned_total++;
        }
        
        LOG_DHT_INFO("=== " << (search.is_announce ? "Announce" : "Search") << " Completed for info_hash " << hash_key << " ===");
        LOG_DHT_INFO("  Duration: " << duration_ms << "ms");
        LOG_DHT_INFO("  Total nodes queried: " << queried_total);
        LOG_DHT_INFO("  Total nodes responded: " << responded_total);
        LOG_DHT_INFO("  Total nodes timed out: " << timed_out_total);
        LOG_DHT_INFO("  Nodes with short timeout: " << short_timeout_total);
        LOG_DHT_INFO("  Nodes abandoned (truncation): " << abandoned_total);
        LOG_DHT_INFO("  Final branch_factor: " << search.branch_factor << " (initial: " << ALPHA << ")");
        if (search.is_announce) {
            LOG_DHT_INFO("  Write tokens collected: " << search.write_tokens.size());
            LOG_DHT_INFO("  Announce port: " << search.announce_port);
        } else {
            LOG_DHT_INFO("  Total peers found: " << search.found_peers.size());
            LOG_DHT_INFO("  Callbacks to invoke: " << search.callbacks.size());
        }
        
        // If this is an announce search, send announce_peer to k closest nodes with tokens
        if (search.is_announce) {
            send_announce_to_closest_nodes(search);
        }
        
        // Collect callbacks for deferred invocation (avoid deadlock - don't call user callbacks while holding mutex)
        deferred.should_invoke = true;
        deferred.callbacks = search.callbacks;
        deferred.peers = search.found_peers;
        deferred.info_hash = search.info_hash;
        
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
    // NOTE: pending_pings_mutex_ is already held by caller (add_node)
    
    std::string ping_transaction_id = KrpcProtocol::generate_transaction_id();
    
    LOG_DHT_DEBUG("Initiating ping verification: pinging OLD node " << node_id_to_hex(old_node.id) 
                  << " at " << old_node.peer.ip << ":" << old_node.peer.port 
                  << " to check if alive. Candidate " << node_id_to_hex(candidate_node.id) 
                  << " waiting to replace if old node fails. (transaction: " << ping_transaction_id << ")");
    
    // Store ping verification state and mark old node as being pinged
    pending_pings_.emplace(ping_transaction_id, PingVerification(candidate_node, old_node, bucket_index));
    nodes_being_replaced_.insert(old_node.id);
    
    // BEP 5: Send ping to the OLD node to verify it's still alive
    // If old node responds -> keep it, discard candidate
    // If old node times out -> replace with candidate
    auto message = KrpcProtocol::create_ping_query(ping_transaction_id, node_id_);
    send_krpc_message(message, old_node.peer);
}

void DhtClient::handle_ping_verification_response(const std::string& transaction_id, const NodeId& responder_id, const Peer& responder) {
    std::lock_guard<std::mutex> ping_lock(pending_pings_mutex_);
    
    auto it = pending_pings_.find(transaction_id);
    if (it != pending_pings_.end()) {
        const auto& verification = it->second;
        
        // Security check: Verify response comes from the IP we pinged
        if (responder.ip != verification.old_node.peer.ip) {
            LOG_DHT_WARN("Ping verification response from wrong IP " << responder.ip 
                         << " (expected " << verification.old_node.peer.ip << ") - ignoring");
            return;  // Don't remove from pending_pings_, let it timeout naturally
        }
        
        // BEP 5: We pinged the OLD node to check if it's still alive
        if (responder_id == verification.old_node.id) {
            // Calculate RTT
            auto rtt_duration = std::chrono::steady_clock::now() - verification.ping_sent_at;
            uint16_t rtt_ms = static_cast<uint16_t>(
                (std::min)(static_cast<int64_t>(0xfffe),
                        static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(rtt_duration).count())));
            
            // Old node responded - it's still alive! Keep it, discard the candidate.
            LOG_DHT_DEBUG("Old node " << node_id_to_hex(verification.old_node.id) 
                          << " responded to ping (rtt=" << rtt_ms << "ms) - keeping it, discarding candidate " 
                          << node_id_to_hex(verification.candidate_node.id));
            
            // Update old node in routing table
            {
                std::lock_guard<std::mutex> rt_lock(routing_table_mutex_);
                auto& bucket = routing_table_[verification.bucket_index];
                auto node_it = std::find_if(bucket.begin(), bucket.end(),
                    [&verification](const DhtNode& n) { return n.id == verification.old_node.id; });
                if (node_it != bucket.end()) {
                    node_it->mark_success();
                    node_it->update_rtt(rtt_ms);
                }
            }
            // Candidate is discarded (not added to routing table)
        } else {
            // Different node ID responded from the same IP:port!
            // This means the old node is gone and this IP now belongs to a different node.
            // Replace the old node with the candidate.
            LOG_DHT_DEBUG("Different node " << node_id_to_hex(responder_id) 
                         << " responded from " << responder.ip << ":" << responder.port 
                         << " (expected old node " << node_id_to_hex(verification.old_node.id) 
                         << ") - old node is gone, replacing with candidate " 
                         << node_id_to_hex(verification.candidate_node.id));
            
            // Replace old node with candidate
            DhtNode candidate = verification.candidate_node;
            candidate.mark_success();  // The responder just proved it's alive
            perform_replacement(candidate, verification.old_node, verification.bucket_index);
        }
        
        // Remove tracking entries
        nodes_being_replaced_.erase(verification.old_node.id);
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
            const auto& verification = it->second;
            
            // BEP 5: Old node didn't respond (timeout) - it's dead, replace with candidate!
            LOG_DHT_DEBUG("Old node " << node_id_to_hex(verification.old_node.id) 
                          << " timed out after 30s - replacing with candidate " << node_id_to_hex(verification.candidate_node.id));
            
            // Perform the replacement with a fresh candidate
            DhtNode fresh_candidate = verification.candidate_node;
            perform_replacement(fresh_candidate, verification.old_node, verification.bucket_index);
            
            // Remove tracking entries
            nodes_being_replaced_.erase(verification.old_node.id);
            
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

// Routing table persistence implementation
bool DhtClient::save_routing_table() {
    std::lock_guard<std::mutex> lock(routing_table_mutex_);
    
    try {
        nlohmann::json routing_data;
        routing_data["version"] = 1;
        routing_data["node_id"] = node_id_to_hex(node_id_);
        routing_data["saved_at"] = std::chrono::system_clock::now().time_since_epoch().count();
        
        nlohmann::json nodes_array = nlohmann::json::array();
        
        // Save only good nodes (confirmed with fail_count == 0)
        size_t saved_count = 0;
        for (const auto& bucket : routing_table_) {
            for (const auto& node : bucket) {
                // Only save confirmed good nodes
                if (node.confirmed()) {
                    nlohmann::json node_data;
                    node_data["id"] = node_id_to_hex(node.id);
                    node_data["ip"] = node.peer.ip;
                    node_data["port"] = node.peer.port;
                    
                    // Save RTT if known
                    if (node.rtt != 0xffff) {
                        node_data["rtt"] = node.rtt;
                    }
                    
                    nodes_array.push_back(node_data);
                    saved_count++;
                }
            }
        }
        
        routing_data["nodes"] = nodes_array;
        routing_data["count"] = saved_count;
        
        // Determine file path
        std::string file_path;
        #ifdef TESTING
            if (port_ == 0) {
                std::ostringstream oss;
                oss << "dht_routing_" << this << ".json";
                file_path = oss.str();
            } else {
                file_path = "dht_routing_" + std::to_string(port_) + ".json";
            }
        #else
            file_path = data_directory_ + "/dht_routing_" + std::to_string(port_) + ".json";
        #endif
        
        // Write to file
        std::ofstream file(file_path);
        if (!file.is_open()) {
            LOG_DHT_ERROR("Failed to open routing table file for writing: " << file_path);
            return false;
        }
        
        file << routing_data.dump(2);
        file.close();
        
        LOG_DHT_DEBUG("Saved " << saved_count << " confirmed nodes to " << file_path);
        return true;
        
    } catch (const std::exception& e) {
        LOG_DHT_ERROR("Exception while saving routing table: " << e.what());
        return false;
    }
}

bool DhtClient::load_routing_table() {
    std::lock_guard<std::mutex> lock(routing_table_mutex_);
    
    try {
        // Determine file path
        std::string file_path;
        #ifdef TESTING
            if (port_ == 0) {
                std::ostringstream oss;
                oss << "dht_routing_" << this << ".json";
                file_path = oss.str();
            } else {
                file_path = "dht_routing_" + std::to_string(port_) + ".json";
            }
        #else
            file_path = data_directory_ + "/dht_routing_" + std::to_string(port_) + ".json";
        #endif
        
        // Check if file exists
        std::ifstream file(file_path);
        if (!file.is_open()) {
            LOG_DHT_DEBUG("No saved routing table found at " << file_path);
            return false;
        }
        
        // Parse JSON
        nlohmann::json routing_data;
        file >> routing_data;
        file.close();
        
        // Validate format
        if (!routing_data.contains("version") || !routing_data.contains("nodes")) {
            LOG_DHT_WARN("Invalid routing table file format");
            return false;
        }
        
        int version = routing_data["version"];
        if (version != 1) {
            LOG_DHT_WARN("Unsupported routing table version: " << version);
            return false;
        }
        
        // Load nodes
        const auto& nodes_array = routing_data["nodes"];
        size_t loaded_count = 0;
        
        for (const auto& node_data : nodes_array) {
            try {
                std::string node_id_hex = node_data["id"];
                std::string ip = node_data["ip"];
                int port = node_data["port"];
                
                NodeId node_id = hex_to_node_id(node_id_hex);
                Peer peer(ip, port);
                DhtNode node(node_id, peer);
                
                // Restore RTT if available
                if (node_data.contains("rtt")) {
                    node.rtt = node_data["rtt"];
                }
                
                // Mark as confirmed (fail_count = 0)
                node.fail_count = 0;
                
                // Add to appropriate bucket
                int bucket_index = get_bucket_index(node.id);
                auto& bucket = routing_table_[bucket_index];
                
                // Check if bucket has space
                if (bucket.size() < K_BUCKET_SIZE) {
                    bucket.push_back(node);
                    loaded_count++;
                } else {
                    // Bucket full - try to replace a worse node
                    auto worst_it = std::max_element(bucket.begin(), bucket.end(),
                        [](const DhtNode& a, const DhtNode& b) {
                            return a.is_worse_than(b);
                        });
                    
                    if (worst_it != bucket.end() && worst_it->is_worse_than(node)) {
                        *worst_it = node;
                        loaded_count++;
                    }
                }
                
            } catch (const std::exception& e) {
                LOG_DHT_WARN("Failed to load node from routing table: " << e.what());
                continue;
            }
        }
        
        LOG_DHT_INFO("Loaded " << loaded_count << " nodes from routing table file");
        return loaded_count > 0;
        
    } catch (const std::exception& e) {
        LOG_DHT_ERROR("Exception while loading routing table: " << e.what());
        return false;
    }
}

void DhtClient::set_data_directory(const std::string& directory) {
    data_directory_ = directory;
    if (data_directory_.empty()) {
        data_directory_ = ".";
    }
    LOG_DHT_DEBUG("Data directory set to: " << data_directory_);
}

} // namespace librats 