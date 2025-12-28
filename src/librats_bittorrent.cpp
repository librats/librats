#include "librats.h"

#ifdef RATS_SEARCH_FEATURES

// Logging macros for BitTorrent client
#define LOG_CLIENT_DEBUG(message) LOG_DEBUG("client", message)
#define LOG_CLIENT_INFO(message)  LOG_INFO("client", message)
#define LOG_CLIENT_WARN(message)  LOG_WARN("client", message)
#define LOG_CLIENT_ERROR(message) LOG_ERROR("client", message)

namespace librats {

//=============================================================================
// BitTorrent API Implementation (requires RATS_SEARCH_FEATURES)
//=============================================================================

bool RatsClient::enable_bittorrent(int listen_port) {
    if (bittorrent_client_) {
        LOG_CLIENT_WARN("BitTorrent is already enabled");
        return true;  // Already enabled
    }
    
    LOG_CLIENT_INFO("Enabling BitTorrent on port " << listen_port);
    
    bittorrent_client_ = std::make_unique<BitTorrentClient>();
    
    if (!bittorrent_client_->start(listen_port)) {
        LOG_CLIENT_ERROR("Failed to start BitTorrent client");
        bittorrent_client_.reset();
        return false;
    }
    
    // Integrate with DHT if available
    if (dht_client_ && dht_client_->is_running()) {
        bittorrent_client_->set_dht_client(dht_client_.get());
        LOG_CLIENT_INFO("BitTorrent integrated with DHT for peer discovery");
    }
    
    LOG_CLIENT_INFO("BitTorrent enabled successfully");
    return true;
}

void RatsClient::disable_bittorrent() {
    if (!bittorrent_client_) {
        return;
    }
    
    LOG_CLIENT_INFO("Disabling BitTorrent");
    bittorrent_client_->stop();
    bittorrent_client_.reset();
    LOG_CLIENT_INFO("BitTorrent disabled");
}

bool RatsClient::is_bittorrent_enabled() const {
    return bittorrent_client_ && bittorrent_client_->is_running();
}

std::shared_ptr<TorrentDownload> RatsClient::add_torrent(const std::string& torrent_file, 
                                                          const std::string& download_path) {
    if (!is_bittorrent_enabled()) {
        LOG_CLIENT_ERROR("BitTorrent is not enabled. Call enable_bittorrent() first.");
        return nullptr;
    }
    
    return bittorrent_client_->add_torrent(torrent_file, download_path);
}

std::shared_ptr<TorrentDownload> RatsClient::add_torrent(const TorrentInfo& torrent_info, 
                                                          const std::string& download_path) {
    if (!is_bittorrent_enabled()) {
        LOG_CLIENT_ERROR("BitTorrent is not enabled. Call enable_bittorrent() first.");
        return nullptr;
    }
    
    return bittorrent_client_->add_torrent(torrent_info, download_path);
}

std::shared_ptr<TorrentDownload> RatsClient::add_torrent_by_hash(const InfoHash& info_hash, 
                                                                   const std::string& download_path) {
    if (!is_bittorrent_enabled()) {
        LOG_CLIENT_ERROR("BitTorrent is not enabled. Call enable_bittorrent() first.");
        return nullptr;
    }
    
    return bittorrent_client_->add_torrent_by_hash(info_hash, download_path);
}

std::shared_ptr<TorrentDownload> RatsClient::add_torrent_by_hash(const std::string& info_hash_hex, 
                                                                   const std::string& download_path) {
    if (!is_bittorrent_enabled()) {
        LOG_CLIENT_ERROR("BitTorrent is not enabled. Call enable_bittorrent() first.");
        return nullptr;
    }
    
    return bittorrent_client_->add_torrent_by_hash(info_hash_hex, download_path);
}

bool RatsClient::remove_torrent(const InfoHash& info_hash) {
    if (!is_bittorrent_enabled()) {
        return false;
    }
    
    return bittorrent_client_->remove_torrent(info_hash);
}

std::shared_ptr<TorrentDownload> RatsClient::get_torrent(const InfoHash& info_hash) {
    if (!is_bittorrent_enabled()) {
        return nullptr;
    }
    
    return bittorrent_client_->get_torrent(info_hash);
}

std::vector<std::shared_ptr<TorrentDownload>> RatsClient::get_all_torrents() {
    if (!is_bittorrent_enabled()) {
        return {};
    }
    
    return bittorrent_client_->get_all_torrents();
}

size_t RatsClient::get_active_torrents_count() const {
    if (!is_bittorrent_enabled()) {
        return 0;
    }
    
    return bittorrent_client_->get_active_torrents_count();
}

std::pair<uint64_t, uint64_t> RatsClient::get_bittorrent_stats() const {
    if (!is_bittorrent_enabled()) {
        return {0, 0};
    }
    
    return {bittorrent_client_->get_total_downloaded(), 
            bittorrent_client_->get_total_uploaded()};
}

void RatsClient::get_torrent_metadata(const InfoHash& info_hash, 
                                      std::function<void(const TorrentInfo&, bool, const std::string&)> callback) {
    if (!is_bittorrent_enabled()) {
        LOG_CLIENT_ERROR("BitTorrent is not enabled. Call enable_bittorrent() first.");
        if (callback) {
            callback(TorrentInfo(), false, "BitTorrent is not enabled");
        }
        return;
    }
    
    bittorrent_client_->get_torrent_metadata_by_hash(info_hash, callback);
}

void RatsClient::get_torrent_metadata(const std::string& info_hash_hex, 
                                      std::function<void(const TorrentInfo&, bool, const std::string&)> callback) {
    if (!is_bittorrent_enabled()) {
        LOG_CLIENT_ERROR("BitTorrent is not enabled. Call enable_bittorrent() first.");
        if (callback) {
            callback(TorrentInfo(), false, "BitTorrent is not enabled");
        }
        return;
    }
    
    bittorrent_client_->get_torrent_metadata_by_hash(info_hash_hex, callback);
}

//=============================================================================
// Spider Mode API Implementation (requires RATS_SEARCH_FEATURES)
//=============================================================================

void RatsClient::set_spider_mode(bool enable) {
    if (!dht_client_) {
        LOG_CLIENT_WARN("DHT client not available, cannot set spider mode");
        return;
    }
    
    dht_client_->set_spider_mode(enable);
    LOG_CLIENT_INFO("Spider mode " << (enable ? "enabled" : "disabled"));
}

bool RatsClient::is_spider_mode() const {
    if (!dht_client_) {
        return false;
    }
    return dht_client_->is_spider_mode();
}

void RatsClient::set_spider_announce_callback(SpiderAnnounceCallback callback) {
    if (!dht_client_) {
        LOG_CLIENT_WARN("DHT client not available, cannot set spider callback");
        return;
    }
    
    // Wrap the callback to convert types from DhtClient format to RatsClient format
    dht_client_->set_spider_announce_callback(
        [callback](const InfoHash& info_hash, const Peer& peer) {
            if (callback) {
                std::string info_hash_hex = node_id_to_hex(info_hash);
                std::string peer_address = peer.ip + ":" + std::to_string(peer.port);
                callback(info_hash_hex, peer_address);
            }
        });
    
    LOG_CLIENT_DEBUG("Spider announce callback set");
}

void RatsClient::set_spider_ignore(bool ignore) {
    if (!dht_client_) {
        LOG_CLIENT_WARN("DHT client not available, cannot set spider ignore");
        return;
    }
    
    dht_client_->set_spider_ignore(ignore);
    LOG_CLIENT_DEBUG("Spider ignore mode " << (ignore ? "enabled" : "disabled"));
}

bool RatsClient::is_spider_ignoring() const {
    if (!dht_client_) {
        return false;
    }
    return dht_client_->is_spider_ignoring();
}

void RatsClient::spider_walk() {
    if (!dht_client_) {
        return;
    }
    
    dht_client_->spider_walk();
}

size_t RatsClient::get_spider_pool_size() const {
    if (!dht_client_) {
        return 0;
    }
    return dht_client_->get_spider_pool_size();
}

size_t RatsClient::get_spider_visited_count() const {
    if (!dht_client_) {
        return 0;
    }
    return dht_client_->get_spider_visited_count();
}

void RatsClient::clear_spider_state() {
    if (!dht_client_) {
        return;
    }
    dht_client_->clear_spider_state();
    LOG_CLIENT_DEBUG("Spider state cleared");
}

}

#endif // RATS_SEARCH_FEATURES
