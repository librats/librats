#include "librats.h"
#include "bt_create_torrent.h"
#include "fs.h"

#ifdef RATS_SEARCH_FEATURES

#include "librats_log_macros.h"

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

void RatsClient::set_resume_data_path(const std::string& path) {
    if (!bittorrent_client_) {
        LOG_CLIENT_WARN("Cannot set resume data path: BitTorrent not enabled");
        return;
    }
    
    bittorrent_client_->set_resume_data_path(path);
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
    
    // Add torrent in metadata-only mode (empty save_path), then retrieve info when complete
    std::string hash_hex = info_hash_to_hex(info_hash);
    std::string magnet = "magnet:?xt=urn:btih:" + hash_hex;
    auto torrent = bittorrent_client_->add_magnet(magnet, "");
    
    if (!torrent) {
        if (callback) {
            callback(TorrentInfo(), false, "Failed to add magnet link");
        }
        return;
    }
    
    // If metadata is already available, return immediately and cleanup
    if (torrent->has_metadata()) {
        if (callback) {
            callback(*torrent->info(), true, "");
        }
        // Cleanup metadata-only torrent (empty save_path means no download requested)
        if (torrent->save_path().empty()) {
            bittorrent_client_->mark_for_removal(info_hash);
        }
        return;
    }
    
    // Set up async callback for when metadata is received
    // Capture bittorrent_client_ and info_hash for cleanup after callback
    auto client = bittorrent_client_.get();
    torrent->set_metadata_callback(
        [callback, client, info_hash](Torrent* t, bool success) {
            // Invoke user callback first
            if (success && t->info()) {
                if (callback) {
                    callback(*t->info(), true, "");
                }
            } else {
                if (callback) {
                    callback(TorrentInfo(), false, "Failed to download metadata");
                }
            }
            
            // Cleanup metadata-only torrent (empty save_path means no download requested)
            // Using mark_for_removal to avoid deadlock (callback is called from I/O thread)
            if (client && t->save_path().empty()) {
                client->mark_for_removal(info_hash);
            }
        }
    );
    
    LOG_CLIENT_INFO("Waiting for metadata download for " << hash_hex.substr(0, 8) << "...");
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
    
    LOG_CLIENT_INFO("Fetching metadata from peer " << peer_ip << ":" << peer_port << " (fast path, no DHT)");
    
    // Add magnet in metadata-only mode (empty save_path) and immediately add the peer
    // skip_dht_search=true to avoid network-wide DHT queries - we only want this specific peer
    std::string hash_hex = info_hash_to_hex(info_hash);
    std::string magnet = "magnet:?xt=urn:btih:" + hash_hex;
    auto torrent = bittorrent_client_->add_magnet(magnet, "", true /* skip_dht_search */);
    
    if (!torrent) {
        if (callback) {
            callback(TorrentInfo(), false, "Failed to add magnet");
        }
        return;
    }
    
    // Add the specific peer for direct connection
    torrent->add_peer(peer_ip, peer_port);
    
    // If metadata is already available, return immediately and cleanup
    if (torrent->has_metadata()) {
        if (callback) {
            callback(*torrent->info(), true, "");
        }
        // Cleanup metadata-only torrent
        if (torrent->save_path().empty()) {
            bittorrent_client_->mark_for_removal(info_hash);
        }
        return;
    }
    
    // Set up async callback for when metadata is received
    // Capture bittorrent_client_ and info_hash for cleanup after callback
    auto client = bittorrent_client_.get();
    torrent->set_metadata_callback(
        [callback, client, info_hash, peer_ip, peer_port](Torrent* t, bool success) {
            // Invoke user callback first
            if (success && t->info()) {
                if (callback) {
                    callback(*t->info(), true, "");
                }
            } else {
                if (callback) {
                    callback(TorrentInfo(), false, 
                             "Failed to download metadata from " + peer_ip + ":" + std::to_string(peer_port));
                }
            }
            
            // Cleanup metadata-only torrent (empty save_path means no download requested)
            // Using mark_for_removal to avoid deadlock (callback is called from I/O thread)
            if (client && t->save_path().empty()) {
                client->mark_for_removal(info_hash);
            }
        }
    );
    
    LOG_CLIENT_INFO("Waiting for metadata from " << peer_ip << ":" << peer_port);
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

//=============================================================================
// Torrent Creation API Implementation (requires RATS_SEARCH_FEATURES)
//=============================================================================

std::optional<TorrentInfo> RatsClient::create_torrent_from_path(
    const std::string& path,
    const std::vector<std::string>& trackers,
    const std::string& comment,
    TorrentCreationProgressCallback progress_callback) {
    
    LOG_CLIENT_INFO("Creating torrent from path: " << path);
    
    TorrentCreatorConfig config;
    config.comment = comment;
    config.created_by = "librats";
    
    TorrentCreator creator(path, config);
    
    if (creator.num_files() == 0) {
        LOG_CLIENT_ERROR("No files found at path: " << path);
        return std::nullopt;
    }
    
    for (const auto& tracker : trackers) {
        creator.add_tracker(tracker);
    }
    
    // Convert progress callback
    PieceHashProgressCallback hash_callback = nullptr;
    if (progress_callback) {
        hash_callback = [progress_callback](uint32_t current, uint32_t total) {
            progress_callback(current, total);
        };
    }
    
    TorrentCreateError error;
    if (!creator.set_piece_hashes(hash_callback, &error)) {
        LOG_CLIENT_ERROR("Failed to compute piece hashes: " << error.message);
        return std::nullopt;
    }
    
    auto result = creator.generate_torrent_info(&error);
    if (!result) {
        LOG_CLIENT_ERROR("Failed to generate torrent: " << error.message);
        return std::nullopt;
    }
    
    LOG_CLIENT_INFO("Torrent created successfully: " << result->name() 
                    << " (" << result->num_files() << " files, " 
                    << result->total_size() << " bytes, "
                    << "info_hash: " << result->info_hash_hex().substr(0, 8) << "...)");
    
    return result;
}

std::vector<uint8_t> RatsClient::create_torrent_data(
    const std::string& path,
    const std::vector<std::string>& trackers,
    const std::string& comment,
    TorrentCreationProgressCallback progress_callback) {
    
    LOG_CLIENT_INFO("Creating torrent data from path: " << path);
    
    TorrentCreatorConfig config;
    config.comment = comment;
    config.created_by = "librats";
    
    TorrentCreator creator(path, config);
    
    if (creator.num_files() == 0) {
        LOG_CLIENT_ERROR("No files found at path: " << path);
        return {};
    }
    
    for (const auto& tracker : trackers) {
        creator.add_tracker(tracker);
    }
    
    // Convert progress callback
    PieceHashProgressCallback hash_callback = nullptr;
    if (progress_callback) {
        hash_callback = [progress_callback](uint32_t current, uint32_t total) {
            progress_callback(current, total);
        };
    }
    
    TorrentCreateError error;
    if (!creator.set_piece_hashes(hash_callback, &error)) {
        LOG_CLIENT_ERROR("Failed to compute piece hashes: " << error.message);
        return {};
    }
    
    auto data = creator.generate(&error);
    if (data.empty()) {
        LOG_CLIENT_ERROR("Failed to generate torrent: " << error.message);
        return {};
    }
    
    LOG_CLIENT_INFO("Torrent data created successfully: " << creator.name() 
                    << " (" << data.size() << " bytes)");
    
    return data;
}

bool RatsClient::create_torrent_file(
    const std::string& path,
    const std::string& output_file,
    const std::vector<std::string>& trackers,
    const std::string& comment,
    TorrentCreationProgressCallback progress_callback) {
    
    LOG_CLIENT_INFO("Creating torrent file from path: " << path << " -> " << output_file);
    
    TorrentCreatorConfig config;
    config.comment = comment;
    config.created_by = "librats";
    
    TorrentCreator creator(path, config);
    
    if (creator.num_files() == 0) {
        LOG_CLIENT_ERROR("No files found at path: " << path);
        return false;
    }
    
    for (const auto& tracker : trackers) {
        creator.add_tracker(tracker);
    }
    
    // Convert progress callback
    PieceHashProgressCallback hash_callback = nullptr;
    if (progress_callback) {
        hash_callback = [progress_callback](uint32_t current, uint32_t total) {
            progress_callback(current, total);
        };
    }
    
    TorrentCreateError error;
    if (!creator.set_piece_hashes(hash_callback, &error)) {
        LOG_CLIENT_ERROR("Failed to compute piece hashes: " << error.message);
        return false;
    }
    
    if (!creator.save_to_file(output_file, &error)) {
        LOG_CLIENT_ERROR("Failed to save torrent file: " << error.message);
        return false;
    }
    
    LOG_CLIENT_INFO("Torrent file created successfully: " << output_file);
    
    return true;
}

std::shared_ptr<TorrentDownload> RatsClient::create_and_seed_torrent(
    const std::string& path,
    const std::vector<std::string>& trackers,
    const std::string& comment,
    TorrentCreationProgressCallback progress_callback) {
    
    if (!is_bittorrent_enabled()) {
        LOG_CLIENT_ERROR("BitTorrent is not enabled. Call enable_bittorrent() first.");
        return nullptr;
    }
    
    LOG_CLIENT_INFO("Creating and seeding torrent from path: " << path);
    
    // Create torrent info
    auto torrent_info = create_torrent_from_path(path, trackers, comment, progress_callback);
    if (!torrent_info) {
        return nullptr;
    }
    
    // Determine save path (parent directory of the source)
    std::string save_path;
    if (is_directory(path.c_str())) {
        // For directories, save_path is the parent of the directory
        save_path = get_parent_directory(path);
        if (save_path.empty()) {
            save_path = ".";
        }
    } else {
        // For single files, save_path is the directory containing the file
        save_path = get_parent_directory(path);
        if (save_path.empty()) {
            save_path = ".";
        }
    }
    
    // Add torrent with seed_mode enabled (files are already complete)
    auto torrent = bittorrent_client_->add_torrent_for_seeding(*torrent_info, save_path);
    if (!torrent) {
        LOG_CLIENT_ERROR("Failed to add torrent for seeding");
        return nullptr;
    }
    
    LOG_CLIENT_INFO("Started seeding torrent: " << torrent_info->info_hash_hex().substr(0, 8) << "...");
    
    return torrent;
}

}

#endif // RATS_SEARCH_FEATURES
