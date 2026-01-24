#include "bt_client.h"

#include <chrono>

namespace librats {

//=============================================================================
// Constructor / Destructor
//=============================================================================

BtClient::BtClient()
    : peer_id_(generate_peer_id("-LR0001-"))
    , running_(false)
    , dht_running_(false) {
}

BtClient::BtClient(const BtClientConfig& config)
    : config_(config)
    , peer_id_(generate_peer_id("-LR0001-"))
    , running_(false)
    , dht_running_(false) {
}

BtClient::~BtClient() {
    stop();
}

//=============================================================================
// Lifecycle
//=============================================================================

void BtClient::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (running_) return;
    
    running_ = true;
    
    // Start tick thread
    tick_thread_ = std::thread(&BtClient::tick_loop, this);
    
    // Start listening for connections
    // TODO: Implement socket listener
    
    // Start DHT if enabled
    if (config_.enable_dht) {
        // TODO: Start DHT node
        dht_running_ = true;
    }
    
    if (on_alert_) {
        on_alert_("BitTorrent client started");
    }
}

void BtClient::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (!running_) return;
        
        running_ = false;
        dht_running_ = false;
        
        // Stop all torrents
        for (auto& [hash, torrent] : torrents_) {
            torrent->stop();
        }
    }
    
    // Wait for tick thread
    if (tick_thread_.joinable()) {
        tick_thread_.join();
    }
    
    if (on_alert_) {
        on_alert_("BitTorrent client stopped");
    }
}

//=============================================================================
// Torrent Management
//=============================================================================

Torrent::Ptr BtClient::add_torrent_file(const std::string& path,
                                         const std::string& save_path) {
    auto info = TorrentInfo::from_file(path);
    if (!info) {
        if (on_alert_) {
            on_alert_("Failed to parse torrent file: " + path);
        }
        return nullptr;
    }
    
    return add_torrent(*info, save_path);
}

Torrent::Ptr BtClient::add_torrent(const TorrentInfo& info,
                                    const std::string& save_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if already exists
    auto it = torrents_.find(info.info_hash());
    if (it != torrents_.end()) {
        return it->second;
    }
    
    auto torrent = create_torrent(info, save_path);
    torrents_[info.info_hash()] = torrent;
    
    if (running_) {
        torrent->start();
    }
    
    if (on_torrent_added_) {
        on_torrent_added_(torrent);
    }
    
    return torrent;
}

Torrent::Ptr BtClient::add_magnet(const std::string& magnet_uri,
                                   const std::string& save_path) {
    auto info = TorrentInfo::from_magnet(magnet_uri);
    if (!info) {
        if (on_alert_) {
            on_alert_("Failed to parse magnet URI");
        }
        return nullptr;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if already exists
    auto it = torrents_.find(info->info_hash());
    if (it != torrents_.end()) {
        return it->second;
    }
    
    // Create torrent without full metadata
    TorrentConfig torrent_config;
    torrent_config.save_path = save_path.empty() ? config_.download_path : save_path;
    torrent_config.max_connections = config_.max_connections_per_torrent;
    torrent_config.max_uploads = config_.max_uploads;
    
    auto torrent = std::make_shared<Torrent>(
        info->info_hash(),
        info->name(),
        torrent_config,
        peer_id_
    );
    
    torrents_[info->info_hash()] = torrent;
    
    if (running_) {
        torrent->start();
    }
    
    if (on_torrent_added_) {
        on_torrent_added_(torrent);
    }
    
    return torrent;
}

void BtClient::remove_torrent(const BtInfoHash& info_hash, bool delete_files) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = torrents_.find(info_hash);
    if (it == torrents_.end()) {
        return;
    }
    
    it->second->stop();
    
    if (delete_files) {
        // TODO: Delete downloaded files
    }
    
    torrents_.erase(it);
    
    if (on_torrent_removed_) {
        on_torrent_removed_(info_hash);
    }
}

Torrent::Ptr BtClient::get_torrent(const BtInfoHash& info_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = torrents_.find(info_hash);
    if (it != torrents_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<Torrent::Ptr> BtClient::get_torrents() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Torrent::Ptr> result;
    result.reserve(torrents_.size());
    for (const auto& [hash, torrent] : torrents_) {
        result.push_back(torrent);
    }
    return result;
}

size_t BtClient::num_torrents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return torrents_.size();
}

//=============================================================================
// Configuration
//=============================================================================

void BtClient::set_download_limit(uint64_t bytes_per_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.download_limit = bytes_per_sec;
}

void BtClient::set_upload_limit(uint64_t bytes_per_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.upload_limit = bytes_per_sec;
}

//=============================================================================
// Statistics
//=============================================================================

uint64_t BtClient::total_download_rate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t total = 0;
    for (const auto& [hash, torrent] : torrents_) {
        total += torrent->stats().download_rate;
    }
    return total;
}

uint64_t BtClient::total_upload_rate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t total = 0;
    for (const auto& [hash, torrent] : torrents_) {
        total += torrent->stats().upload_rate;
    }
    return total;
}

size_t BtClient::total_peers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t total = 0;
    for (const auto& [hash, torrent] : torrents_) {
        total += torrent->num_peers();
    }
    return total;
}

//=============================================================================
// DHT
//=============================================================================

void BtClient::add_dht_node(const std::string& /*host*/, uint16_t /*port*/) {
    // TODO: Add to DHT bootstrap nodes
}

size_t BtClient::dht_node_count() const {
    // TODO: Return actual DHT node count
    return 0;
}

//=============================================================================
// Internal Methods
//=============================================================================

void BtClient::tick_loop() {
    while (running_) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (auto& [hash, torrent] : torrents_) {
                torrent->tick();
            }
        }
        
        // Sleep for a bit
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

Torrent::Ptr BtClient::create_torrent(const TorrentInfo& info,
                                       const std::string& save_path) {
    TorrentConfig torrent_config;
    torrent_config.save_path = save_path.empty() ? config_.download_path : save_path;
    torrent_config.max_connections = config_.max_connections_per_torrent;
    torrent_config.max_uploads = config_.max_uploads;
    
    return std::make_shared<Torrent>(info, torrent_config, peer_id_);
}

} // namespace librats
