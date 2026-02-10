#include "librats.h"
#include "librats_log_macros.h"

namespace librats {

    
// =========================================================================
// Automatic Reconnection System
// =========================================================================

void RatsClient::set_reconnect_enabled(bool enabled) {
    std::lock_guard<std::mutex> lock(reconnect_mutex_);
    reconnect_config_.enabled = enabled;
    LOG_CLIENT_INFO("Automatic reconnection " << (enabled ? "enabled" : "disabled"));
}

bool RatsClient::is_reconnect_enabled() const {
    std::lock_guard<std::mutex> lock(reconnect_mutex_);
    return reconnect_config_.enabled;
}

void RatsClient::set_reconnect_config(const ReconnectConfig& config) {
    std::lock_guard<std::mutex> lock(reconnect_mutex_);
    reconnect_config_ = config;
    LOG_CLIENT_INFO("Reconnection config updated: max_attempts=" << config.max_attempts 
                    << ", stable_threshold=" << config.stable_connection_threshold_seconds << "s");
}

ReconnectConfig RatsClient::get_reconnect_config() const {
    std::lock_guard<std::mutex> lock(reconnect_mutex_);
    return reconnect_config_;
}

size_t RatsClient::get_reconnect_queue_size() const {
    std::lock_guard<std::mutex> lock(reconnect_mutex_);
    return reconnect_queue_.size();
}

void RatsClient::clear_reconnect_queue() {
    std::lock_guard<std::mutex> lock(reconnect_mutex_);
    size_t cleared = reconnect_queue_.size();
    reconnect_queue_.clear();
    manual_disconnect_peers_.clear();
    LOG_CLIENT_INFO("Cleared " << cleared << " peers from reconnection queue");
}

std::vector<ReconnectInfo> RatsClient::get_reconnect_queue() const {
    std::lock_guard<std::mutex> lock(reconnect_mutex_);
    std::vector<ReconnectInfo> result;
    result.reserve(reconnect_queue_.size());
    for (const auto& pair : reconnect_queue_) {
        result.push_back(pair.second);
    }
    return result;
}

int RatsClient::get_retry_interval_seconds(int attempt, bool is_stable) const {
    // For stable peers, use faster first retry
    if (attempt == 0 && is_stable) {
        return reconnect_config_.stable_first_retry_seconds;
    }
    
    // Use configured intervals, defaulting to last interval if attempt exceeds array size
    const auto& intervals = reconnect_config_.retry_intervals_seconds;
    if (intervals.empty()) {
        return 30; // Default fallback
    }
    
    size_t index = static_cast<size_t>(attempt);
    if (index >= intervals.size()) {
        return intervals.back();
    }
    return intervals[index];
}

void RatsClient::schedule_reconnect(const RatsPeer& peer) {
    if (!running_.load()) {
        return;
    }
    
    // Check if reconnection is enabled
    {
        std::lock_guard<std::mutex> lock(reconnect_mutex_);
        if (!reconnect_config_.enabled) {
            LOG_CLIENT_DEBUG("Reconnection disabled, not scheduling reconnect for " << peer.peer_id);
            return;
        }
        
        // Check if this peer was manually disconnected
        if (manual_disconnect_peers_.find(peer.peer_id) != manual_disconnect_peers_.end()) {
            LOG_CLIENT_DEBUG("Peer " << peer.peer_id << " was manually disconnected, not scheduling reconnect");
            manual_disconnect_peers_.erase(peer.peer_id);
            return;
        }
        
        // Check if already in queue
        if (reconnect_queue_.find(peer.peer_id) != reconnect_queue_.end()) {
            LOG_CLIENT_DEBUG("Peer " << peer.peer_id << " already in reconnection queue");
            return;
        }
    }
    
    // Calculate connection duration
    auto now = std::chrono::steady_clock::now();
    auto connection_duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - peer.connected_at);
    
    // Determine if this was a stable connection
    bool is_stable = connection_duration.count() >= 
        (reconnect_config_.stable_connection_threshold_seconds * 1000);
    
    // Create reconnect info
    ReconnectInfo info(peer.peer_id, peer.ip, peer.port, connection_duration, is_stable);
    
    // Calculate first retry interval
    int first_retry_seconds = get_retry_interval_seconds(0, is_stable);
    info.next_attempt_time = now + std::chrono::seconds(first_retry_seconds);
    
    // Add to queue
    {
        std::lock_guard<std::mutex> lock(reconnect_mutex_);
        reconnect_queue_[peer.peer_id] = info;
    }
    
    LOG_CLIENT_INFO("Scheduled reconnection for peer " << peer.peer_id 
                    << " (" << peer.ip << ":" << peer.port << ")"
                    << " - stable=" << is_stable 
                    << ", connection_duration=" << connection_duration.count() << "ms"
                    << ", first_retry_in=" << first_retry_seconds << "s");
}

void RatsClient::remove_from_reconnect_queue(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(reconnect_mutex_);
    auto it = reconnect_queue_.find(peer_id);
    if (it != reconnect_queue_.end()) {
        LOG_CLIENT_DEBUG("Removed peer " << peer_id << " from reconnection queue");
        reconnect_queue_.erase(it);
    }
}

void RatsClient::process_reconnect_queue() {
    if (!running_.load()) {
        return;
    }
    
    // Get list of peers to attempt reconnection (copy to avoid holding lock during connect)
    std::vector<ReconnectInfo> peers_to_reconnect;
    
    {
        std::lock_guard<std::mutex> lock(reconnect_mutex_);
        
        if (!reconnect_config_.enabled || reconnect_queue_.empty()) {
            return;
        }
        
        auto now = std::chrono::steady_clock::now();
        
        for (auto& pair : reconnect_queue_) {
            ReconnectInfo& info = pair.second;
            
            // Check if it's time for next attempt
            if (now >= info.next_attempt_time) {
                peers_to_reconnect.push_back(info);
            }
        }
    }
    
    // Process reconnection attempts outside of lock
    for (const auto& info : peers_to_reconnect) {
        // Check if we're already connected to this peer
        std::string normalized_address = normalize_peer_address(info.ip, static_cast<int>(info.port));
        if (is_already_connected_to_address(normalized_address)) {
            LOG_CLIENT_INFO("Already reconnected to peer " << info.peer_id << ", removing from queue");
            remove_from_reconnect_queue(info.peer_id);
            continue;
        }
        
        // Check if peer limit is reached
        if (is_peer_limit_reached()) {
            LOG_CLIENT_DEBUG("Peer limit reached, skipping reconnection attempt for " << info.peer_id);
            continue;
        }
        
        LOG_CLIENT_INFO("Attempting reconnection to peer " << info.peer_id 
                        << " (" << info.ip << ":" << info.port << ")"
                        << " - attempt " << (info.attempt_count + 1) << "/" << reconnect_config_.max_attempts);
        
        // Attempt to connect
        bool connected = connect_to_peer(info.ip, static_cast<int>(info.port));
        
        if (connected) {
            LOG_CLIENT_INFO("Successfully reconnected to peer " << info.peer_id);
            remove_from_reconnect_queue(info.peer_id);
        } else {
            // Update attempt count and schedule next attempt
            std::lock_guard<std::mutex> lock(reconnect_mutex_);
            auto it = reconnect_queue_.find(info.peer_id);
            if (it != reconnect_queue_.end()) {
                it->second.attempt_count++;
                
                // Check if we've exceeded max attempts
                if (it->second.attempt_count >= reconnect_config_.max_attempts) {
                    LOG_CLIENT_INFO("Max reconnection attempts reached for peer " << info.peer_id 
                                    << ", removing from queue");
                    reconnect_queue_.erase(it);
                } else {
                    // Schedule next attempt
                    int next_interval = get_retry_interval_seconds(it->second.attempt_count, it->second.is_stable);
                    it->second.next_attempt_time = std::chrono::steady_clock::now() + 
                        std::chrono::seconds(next_interval);
                    LOG_CLIENT_DEBUG("Scheduled next reconnection attempt for " << info.peer_id 
                                     << " in " << next_interval << " seconds");
                }
            }
        }
    }
}

}