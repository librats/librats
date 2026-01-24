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
    
    BtClientConfig config;
    config.listen_port = static_cast<uint16_t>(listen_port);
    config.enable_dht = (dht_client_ && dht_client_->is_running());
    
    bittorrent_client_ = std::make_unique<BitTorrentClient>(config);
    
    // Reuse librats DHT client instead of creating a new one
    if (dht_client_ && dht_client_->is_running()) {
        bittorrent_client_->set_external_dht(dht_client_.get());
        LOG_CLIENT_INFO("BitTorrent will reuse librats DHT client with " 
                        << dht_client_->get_routing_table_size() << " nodes");
    }
    
    bittorrent_client_->start();
    
    if (!bittorrent_client_->is_running()) {
        LOG_CLIENT_ERROR("Failed to start BitTorrent client");
        bittorrent_client_.reset();
        return false;
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
    
    return bittorrent_client_->add_torrent_file(torrent_file, download_path);
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
    
    // Create magnet-style URI from hash
    std::string hash_hex = info_hash_to_hex(info_hash);
    std::string magnet = "magnet:?xt=urn:btih:" + hash_hex;
    return bittorrent_client_->add_magnet(magnet, download_path);
}

std::shared_ptr<TorrentDownload> RatsClient::add_torrent_by_hash(const std::string& info_hash_hex, 
                                                                   const std::string& download_path) {
    if (!is_bittorrent_enabled()) {
        LOG_CLIENT_ERROR("BitTorrent is not enabled. Call enable_bittorrent() first.");
        return nullptr;
    }
    
    std::string magnet = "magnet:?xt=urn:btih:" + info_hash_hex;
    return bittorrent_client_->add_magnet(magnet, download_path);
}

bool RatsClient::remove_torrent(const InfoHash& info_hash) {
    if (!is_bittorrent_enabled()) {
        return false;
    }
    
    bittorrent_client_->remove_torrent(info_hash);
    return true;
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
    
    return bittorrent_client_->get_torrents();
}

size_t RatsClient::get_active_torrents_count() const {
    if (!is_bittorrent_enabled()) {
        return 0;
    }
    
    return bittorrent_client_->num_torrents();
}

std::pair<uint64_t, uint64_t> RatsClient::get_bittorrent_stats() const {
    if (!is_bittorrent_enabled()) {
        return {0, 0};
    }
    
    // Get stats from all torrents
    uint64_t total_downloaded = 0;
    uint64_t total_uploaded = 0;
    
    auto torrents = bittorrent_client_->get_torrents();
    for (const auto& t : torrents) {
        auto stats = t->stats();
        total_downloaded += stats.total_downloaded;
        total_uploaded += stats.total_uploaded;
    }
    
    return {total_downloaded, total_uploaded};
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
    
    // Add torrent in metadata-only mode, then retrieve info when complete
    std::string hash_hex = info_hash_to_hex(info_hash);
    std::string magnet = "magnet:?xt=urn:btih:" + hash_hex;
    auto torrent = bittorrent_client_->add_magnet(magnet, "");
    
    if (!torrent) {
        if (callback) {
            callback(TorrentInfo(), false, "Failed to add magnet link");
        }
        return;
    }
    
    // If metadata is already available, return immediately
    if (torrent->has_metadata()) {
        if (callback) {
            callback(*torrent->info(), true, "");
        }
        return;
    }
    
    // Set up async callback for when metadata is received
    if (callback) {
        torrent->set_metadata_callback(
            [callback](Torrent* t, bool success) {
                if (success && t->info()) {
                    callback(*t->info(), true, "");
                } else {
                    callback(TorrentInfo(), false, "Failed to download metadata");
                }
            }
        );
        
        LOG_CLIENT_INFO("Waiting for metadata download for " << hash_hex.substr(0, 8) << "...");
    }
}

void RatsClient::get_torrent_metadata(const std::string& info_hash_hex, 
                                      std::function<void(const TorrentInfo&, bool, const std::string&)> callback) {
    auto hash = hex_to_info_hash(info_hash_hex);
    get_torrent_metadata(hash, callback);
}

void RatsClient::get_torrent_metadata_from_peer(const InfoHash& info_hash,
                                                const std::string& peer_ip,
                                                uint16_t peer_port,
                                                std::function<void(const TorrentInfo&, bool, const std::string&)> callback) {
    if (!is_bittorrent_enabled()) {
        LOG_CLIENT_ERROR("BitTorrent is not enabled. Call enable_bittorrent() first.");
        if (callback) {
            callback(TorrentInfo(), false, "BitTorrent is not enabled");
        }
        return;
    }
    
    LOG_CLIENT_INFO("Fetching metadata from peer " << peer_ip << ":" << peer_port << " (fast path)");
    
    // Add magnet and immediately add the peer
    std::string hash_hex = info_hash_to_hex(info_hash);
    std::string magnet = "magnet:?xt=urn:btih:" + hash_hex;
    auto torrent = bittorrent_client_->add_magnet(magnet, "");
    
    if (!torrent) {
        if (callback) {
            callback(TorrentInfo(), false, "Failed to add magnet");
        }
        return;
    }
    
    // Add the specific peer for direct connection
    torrent->add_peer(peer_ip, peer_port);
    
    // If metadata is already available, return immediately
    if (torrent->has_metadata()) {
        if (callback) {
            callback(*torrent->info(), true, "");
        }
        return;
    }
    
    // Set up async callback for when metadata is received
    if (callback) {
        torrent->set_metadata_callback(
            [callback, peer_ip, peer_port](Torrent* t, bool success) {
                if (success && t->info()) {
                    callback(*t->info(), true, "");
                } else {
                    callback(TorrentInfo(), false, 
                             "Failed to download metadata from " + peer_ip + ":" + std::to_string(peer_port));
                }
            }
        );
        
        LOG_CLIENT_INFO("Waiting for metadata from " << peer_ip << ":" << peer_port);
    }
}

void RatsClient::get_torrent_metadata_from_peer(const std::string& info_hash_hex,
                                                const std::string& peer_ip,
                                                uint16_t peer_port,
                                                std::function<void(const TorrentInfo&, bool, const std::string&)> callback) {
    auto hash = hex_to_info_hash(info_hash_hex);
    get_torrent_metadata_from_peer(hash, peer_ip, peer_port, callback);
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
