#include "librats.h"
#include "librats_log_macros.h"
#include "os.h"

namespace librats {

    
// =========================================================================
// Statistics and Information
// =========================================================================

nlohmann::json RatsClient::get_connection_statistics() const {
    nlohmann::json stats;
    
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        stats["total_peers"] = peers_.size();
        stats["validated_peers"] = get_peer_count_unlocked();
        stats["max_peers"] = max_peers_;
    }
    
    stats["running"] = is_running();
    stats["listen_port"] = listen_port_;
    stats["our_peer_id"] = get_our_peer_id();
    stats["encryption_enabled"] = is_encryption_enabled();
    
    // DHT statistics
    if (dht_client_ && dht_client_->is_running()) {
        stats["dht_running"] = true;
        stats["dht_routing_table_size"] = get_dht_routing_table_size();
    } else {
        stats["dht_running"] = false;
    }
    
    // mDNS statistics
    stats["mdns_running"] = is_mdns_running();
    
    // Reconnection statistics
    {
        std::lock_guard<std::mutex> lock(reconnect_mutex_);
        stats["reconnect_enabled"] = reconnect_config_.enabled;
        stats["reconnect_queue_size"] = reconnect_queue_.size();
        stats["reconnect_max_attempts"] = reconnect_config_.max_attempts;
    }
    
    return stats;
}

// Cached formatting helpers - computed once on first use
static const std::string& get_box_separator() {
    static const std::string separator = supports_unicode() ? 
        "════════════════════════════════════════════════════════════════════" :
        "=====================================================================";
    return separator;
}

static const std::string& get_box_vertical() {
    static const std::string vertical = supports_unicode() ? "│" : "|";
    return vertical;
}

static const std::string& get_checkmark() {
    static const std::string checkmark = supports_unicode() ? "✓" : "[*]";
    return checkmark;
}

void RatsClient::log_handshake_completion_unlocked(const RatsPeer& peer) {
    // Calculate connection duration
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - peer.connected_at);
    
    // Get current peer count (assumes peers_mutex_ is already locked)
    int current_peer_count = get_peer_count_unlocked();
    
    // Create visually appealing log output
    std::string connection_type = peer.is_outgoing ? "OUTGOING" : "INCOMING";
    const std::string& separator = get_box_separator();
    const std::string& vertical = get_box_vertical();
    const std::string& checkmark = get_checkmark();
    
    LOG_CLIENT_INFO("");
    LOG_CLIENT_INFO(separator);
    LOG_CLIENT_INFO(checkmark << " HANDSHAKE COMPLETED - NEW PEER CONNECTED");
    LOG_CLIENT_INFO(separator);
    LOG_CLIENT_INFO(vertical << " Peer ID       : " << peer.peer_id);
    LOG_CLIENT_INFO(vertical << " Address       : " << peer.ip << ":" << peer.port);
    LOG_CLIENT_INFO(vertical << " Connection    : " << connection_type);
    LOG_CLIENT_INFO(vertical << " Protocol Ver. : " << peer.version);
    LOG_CLIENT_INFO(vertical << " Socket        : " << peer.socket);
    LOG_CLIENT_INFO(vertical << " Duration      : " << duration.count() << "ms");
    LOG_CLIENT_INFO(vertical << " Network Peers : " << current_peer_count << "/" << max_peers_);
    
    LOG_CLIENT_INFO(separator);
    LOG_CLIENT_INFO("");
}

}