#include "bt_client.h"
#include "tracker.h"
#include "logger.h"

#include <chrono>
#include <algorithm>

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

void BtClient::set_external_dht(DhtClient* dht) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_) {
        LOG_WARN("BtClient", "Cannot set external DHT while client is running");
        return;
    }
    external_dht_ = dht;
    LOG_DEBUG("BtClient", "External DHT client set");
}

//=============================================================================
// Lifecycle
//=============================================================================

void BtClient::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (running_) return;
    
    running_ = true;
    
    // Initialize network manager
    BtNetworkConfig net_config;
    net_config.listen_port = config_.listen_port;
    net_config.max_connections = config_.max_connections;
    net_config.enable_incoming = true;
    net_config.peer_id = peer_id_;  // For incoming connections
    
    network_manager_ = std::make_unique<BtNetworkManager>(net_config);
    
    // Set network callbacks
    network_manager_->set_connected_callback(
        [this](const BtInfoHash& hash, std::shared_ptr<BtPeerConnection> conn, 
               socket_t sock, bool incoming) {
            on_peer_connected(hash, conn, sock, incoming);
        }
    );
    
    network_manager_->set_disconnected_callback(
        [this](const BtInfoHash& hash, BtPeerConnection* conn) {
            on_peer_disconnected(hash, conn);
        }
    );
    
    network_manager_->set_data_callback(
        [this](const BtInfoHash& hash, BtPeerConnection* conn, socket_t sock) {
            on_peer_data(hash, conn, sock);
        }
    );
    
    if (!network_manager_->start()) {
        LOG_ERROR("BtClient", "Failed to start network manager");
        running_ = false;
        return;
    }
    
    LOG_INFO("BtClient", "Network manager started, listening on port " + 
             std::to_string(network_manager_->listen_port()));
    
    // Start DHT if enabled
    if (config_.enable_dht) {
        if (external_dht_) {
            // Use external DHT client - check if it's already running
            if (external_dht_->is_running()) {
                dht_running_ = true;
                LOG_INFO("BtClient", "Using external DHT client with " + 
                         std::to_string(external_dht_->get_routing_table_size()) + " nodes");
            } else {
                LOG_WARN("BtClient", "External DHT client provided but not running");
            }
        } else {
            // Create and start our own DHT client
            dht_client_ = std::make_unique<DhtClient>(config_.listen_port, "");
            
            if (dht_client_->start()) {
                // Bootstrap with default nodes
                auto bootstrap_nodes = DhtClient::get_default_bootstrap_nodes();
                dht_client_->bootstrap(bootstrap_nodes);
                dht_running_ = true;
                
                LOG_INFO("BtClient", "DHT started with " + 
                         std::to_string(bootstrap_nodes.size()) + " bootstrap nodes");
            } else {
                LOG_ERROR("BtClient", "Failed to start DHT");
            }
        }
    }
    
    // Initialize timing
    last_dht_announce_ = std::chrono::steady_clock::now();
    last_tracker_announce_ = std::chrono::steady_clock::now();
    
    // Start tick thread
    tick_thread_ = std::thread(&BtClient::tick_loop, this);
    
    if (on_alert_) {
        on_alert_("BitTorrent client started on port " + 
                  std::to_string(network_manager_->listen_port()));
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
    
    // Stop network manager
    if (network_manager_) {
        network_manager_->stop();
        network_manager_.reset();
    }
    
    // Stop DHT (only if we own it - not external)
    if (dht_client_) {
        dht_client_->stop();
        dht_client_.reset();
    }
    // Note: external_dht_ is not stopped - lifecycle managed by caller
    
    // Clear tracker managers
    tracker_managers_.clear();
    
    // Clear torrents (already stopped above)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        torrents_.clear();
    }
    
    // Clear pending removals
    {
        std::lock_guard<std::mutex> lock(removal_mutex_);
        pending_removals_.clear();
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
    
    // Register with network manager
    if (network_manager_ && info.has_metadata()) {
        network_manager_->register_torrent(info.info_hash(), peer_id_, info.num_pieces());
    }
    
    // Create tracker manager
    tracker_managers_[info.info_hash()] = std::make_unique<TrackerManager>(info);
    
    if (running_) {
        torrent->start();
        
        // Announce to DHT
        if (dht_running_) {
            find_peers_dht(info.info_hash());
        }
        
        // Announce to trackers
        auto& tracker_mgr = tracker_managers_[info.info_hash()];
        if (tracker_mgr) {
            TrackerRequest req;
            req.info_hash = info.info_hash();
            req.peer_id = peer_id_;
            req.port = network_manager_ ? network_manager_->listen_port() : config_.listen_port;
            req.uploaded = 0;
            req.downloaded = 0;
            req.left = info.total_size();
            req.event = TrackerEvent::STARTED;
            req.numwant = 50;
            
            tracker_mgr->announce(req, [this, hash = info.info_hash()](
                const TrackerResponse& response, const std::string& tracker_url) {
                
                if (response.success && !response.peers.empty()) {
                    LOG_INFO("BtClient", "Got " + std::to_string(response.peers.size()) + 
                             " peers from tracker " + tracker_url);
                    
                    auto torrent = get_torrent(hash);
                    if (torrent) {
                        for (const auto& peer : response.peers) {
                            torrent->add_peer(peer.ip, peer.port);
                        }
                    }
                }
            });
        }
    }
    
    if (on_torrent_added_) {
        on_torrent_added_(torrent);
    }
    
    LOG_INFO("BtClient", "Added torrent: " + info.name() + " (" + 
             info_hash_to_hex(info.info_hash()).substr(0, 8) + "...)");
    
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
        
        // Find peers via DHT for metadata
        if (dht_running_) {
            find_peers_dht(info->info_hash());
        }
    }
    
    if (on_torrent_added_) {
        on_torrent_added_(torrent);
    }
    
    LOG_INFO("BtClient", "Added magnet: " + info->name() + " (" + 
             info_hash_to_hex(info->info_hash()).substr(0, 8) + "...)");
    
    return torrent;
}

void BtClient::remove_torrent(const BtInfoHash& info_hash, bool delete_files) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = torrents_.find(info_hash);
    if (it == torrents_.end()) {
        return;
    }
    
    it->second->stop();
    
    // Unregister from network manager
    if (network_manager_) {
        network_manager_->unregister_torrent(info_hash);
    }
    
    // Cancel any active DHT searches/announces for this torrent
    DhtClient* dht = external_dht_ ? external_dht_ : dht_client_.get();
    if (dht) {
        dht->cancel_search(info_hash);
    }
    
    // Remove tracker manager
    tracker_managers_.erase(info_hash);
    
    if (delete_files) {
        // TODO: Delete downloaded files
    }
    
    torrents_.erase(it);
    
    if (on_torrent_removed_) {
        on_torrent_removed_(info_hash);
    }
    
    LOG_INFO("BtClient", "Removed torrent: " + info_hash_to_hex(info_hash).substr(0, 8) + "...");
}

void BtClient::mark_for_removal(const BtInfoHash& info_hash) {
    std::lock_guard<std::mutex> lock(removal_mutex_);
    
    // Avoid duplicates
    for (const auto& hash : pending_removals_) {
        if (hash == info_hash) {
            return;
        }
    }
    
    pending_removals_.push_back(info_hash);
    LOG_DEBUG("BtClient", "Marked torrent for removal: " + 
              info_hash_to_hex(info_hash).substr(0, 8) + "...");
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

void BtClient::add_dht_node(const std::string& host, uint16_t port) {
    DhtClient* dht = external_dht_ ? external_dht_ : dht_client_.get();
    if (dht) {
        std::vector<Peer> nodes = {{host, port}};
        dht->bootstrap(nodes);
    }
}

size_t BtClient::dht_node_count() const {
    DhtClient* dht = external_dht_ ? external_dht_ : dht_client_.get();
    if (dht) {
        return dht->get_routing_table_size();
    }
    return 0;
}

void BtClient::announce_to_dht(const BtInfoHash& info_hash) {
    DhtClient* dht = external_dht_ ? external_dht_ : dht_client_.get();
    if (!dht || !dht_running_) {
        return;
    }
    
    // Convert BtInfoHash to InfoHash (they're the same type)
    InfoHash dht_hash;
    std::copy(info_hash.begin(), info_hash.end(), dht_hash.begin());
    
    uint16_t port = network_manager_ ? network_manager_->listen_port() : config_.listen_port;
    
    dht->announce_peer(dht_hash, port, 
        [this, info_hash](const std::vector<Peer>& peers, const InfoHash&) {
            on_dht_peers_found(peers, info_hash);
        }
    );
}

void BtClient::find_peers_dht(const BtInfoHash& info_hash) {
    DhtClient* dht = external_dht_ ? external_dht_ : dht_client_.get();
    if (!dht || !dht_running_) {
        return;
    }
    
    InfoHash dht_hash;
    std::copy(info_hash.begin(), info_hash.end(), dht_hash.begin());
    
    dht->find_peers(dht_hash, 
        [this, info_hash](const std::vector<Peer>& peers, const InfoHash&) {
            on_dht_peers_found(peers, info_hash);
        }
    );
    
    LOG_DEBUG("BtClient", "Started DHT peer search for " + 
              info_hash_to_hex(info_hash).substr(0, 8) + "...");
}

void BtClient::on_dht_peers_found(const std::vector<Peer>& peers, const InfoHash& info_hash) {
    if (peers.empty()) {
        return;
    }
    
    // Build peer list string for logging (show up to 5 peers)
    std::string peer_list;
    size_t show_count = std::min(peers.size(), static_cast<size_t>(5));
    for (size_t i = 0; i < show_count; ++i) {
        if (i > 0) peer_list += ", ";
        peer_list += peers[i].ip + ":" + std::to_string(peers[i].port);
    }
    if (peers.size() > 5) {
        peer_list += ", ...";
    }
    
    LOG_INFO("BtClient", "DHT found " + std::to_string(peers.size()) + " peers for " +
             node_id_to_hex(info_hash).substr(0, 8) + "...: " + peer_list);
    
    BtInfoHash bt_hash;
    std::copy(info_hash.begin(), info_hash.end(), bt_hash.begin());
    
    auto torrent = get_torrent(bt_hash);
    if (torrent) {
        for (const auto& peer : peers) {
            torrent->add_peer(peer.ip, peer.port);
        }
    }
}

//=============================================================================
// Internal Methods - Network Callbacks
//=============================================================================

void BtClient::on_peer_connected(const BtInfoHash& info_hash,
                                  std::shared_ptr<BtPeerConnection> connection,
                                  socket_t socket, bool is_incoming) {
    auto torrent = get_torrent(info_hash);
    if (!torrent) {
        LOG_DEBUG("BtClient", "Peer connected for unknown torrent");
        if (network_manager_) {
            network_manager_->close_connection(socket);
        }
        return;
    }
    
    LOG_INFO("BtClient", "Peer connected: " + connection->ip() + ":" + 
             std::to_string(connection->port()) + 
             (is_incoming ? " (incoming)" : " (outgoing)") +
             " state=" + peer_state_to_string(connection->state()));
    
    // NOTE: Do NOT call set_socket() here! The socket was already set by
    // NetworkManager when the connection was created. Calling set_socket()
    // again would reset the state from Connected back to Handshaking,
    // breaking the torrent download logic.
    
    // Hand connection to torrent - it will manage from here
    // Both network manager and torrent share ownership via shared_ptr
    // Torrent will setup callbacks and send extension handshake
    torrent->add_connection(connection);
}

void BtClient::on_peer_disconnected(const BtInfoHash& info_hash, 
                                     BtPeerConnection* connection) {
    LOG_DEBUG("BtClient", "Peer disconnected: " + connection->ip());
    
    // Remove connection from torrent
    auto torrent = get_torrent(info_hash);
    if (torrent) {
        torrent->remove_connection(connection);
    }
}

void BtClient::on_peer_data(const BtInfoHash& info_hash, 
                             BtPeerConnection* connection, 
                             socket_t socket) {
    // Data is already processed by connection->process_incoming()
    // Send data is already in connection->send_buffer() and will be
    // sent by NetworkManager's flush_send_buffer() - no action needed here
    (void)info_hash;
    (void)connection;
    (void)socket;
}

void BtClient::connect_pending_peers() {
    if (!network_manager_) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [hash, torrent] : torrents_) {
        if (!torrent->is_active()) continue;
        if (!torrent->has_metadata()) continue;
        
        // Get pending peers from torrent and initiate connections
        // The torrent stores pending_peers_ internally
        // We need to expose them or have torrent request connections
        
        auto info = torrent->info();
        if (!info) continue;
        
        // For now, we rely on torrent's add_peer which adds to pending_peers_
        // The connection is initiated here by calling network_manager_->connect_peer
    }
}

void BtClient::announce_torrents_to_trackers() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [hash, torrent] : torrents_) {
        if (!torrent->is_active()) continue;
        
        auto tracker_it = tracker_managers_.find(hash);
        if (tracker_it == tracker_managers_.end()) continue;
        
        auto& tracker_mgr = tracker_it->second;
        if (!tracker_mgr->should_announce()) continue;
        
        auto stats = torrent->stats();
        auto info = torrent->info();
        if (!info) continue;
        
        TrackerRequest req;
        req.info_hash = hash;
        req.peer_id = peer_id_;
        req.port = network_manager_ ? network_manager_->listen_port() : config_.listen_port;
        req.uploaded = stats.total_uploaded;
        req.downloaded = stats.total_downloaded;
        req.left = stats.total_size - stats.bytes_done;
        req.event = TrackerEvent::NONE;
        req.numwant = 50;
        
        tracker_mgr->announce(req, [this, hash](
            const TrackerResponse& response, const std::string& tracker_url) {
            
            if (response.success && !response.peers.empty()) {
                LOG_INFO("BtClient", "Got " + std::to_string(response.peers.size()) + 
                         " peers from tracker");
                
                auto torrent = get_torrent(hash);
                if (torrent) {
                    for (const auto& peer : response.peers) {
                        torrent->add_peer(peer.ip, peer.port);
                    }
                }
            }
        });
    }
}

//=============================================================================
// Internal Methods
//=============================================================================

void BtClient::tick_loop() {
    LOG_INFO("BtClient", "Tick loop started");
    
    while (running_) {
        auto now = std::chrono::steady_clock::now();
        
        // Process deferred removals (outside main mutex to avoid deadlocks)
        {
            std::vector<BtInfoHash> to_remove;
            {
                std::lock_guard<std::mutex> lock(removal_mutex_);
                to_remove = std::move(pending_removals_);
                pending_removals_.clear();
            }
            
            for (const auto& hash : to_remove) {
                remove_torrent(hash);
            }
        }
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // Tick all torrents
            for (auto& [hash, torrent] : torrents_) {
                torrent->tick();
            }
            
            // Connect pending peers (for both magnet and regular torrents)
            for (auto& [hash, torrent] : torrents_) {
                if (!torrent->is_active()) continue;
                
                auto pending = torrent->get_pending_peers();
                if (pending.empty()) continue;
                
                size_t connected = torrent->num_peers();
                size_t max_conn = config_.max_connections_per_torrent;
                
                // Connect to pending peers
                for (const auto& [ip, port] : pending) {
                    if (connected >= max_conn) break;
                    
                    // For magnet links without metadata, num_pieces is 0
                    uint32_t num_pieces = 0;
                    if (torrent->has_metadata() && torrent->info()) {
                        num_pieces = torrent->info()->num_pieces();
                    }
                    
                    if (network_manager_->connect_peer(ip, port, hash, peer_id_, num_pieces)) {
                        LOG_DEBUG("BtClient", "Connecting to peer " + ip + ":" + std::to_string(port));
                        ++connected;
                    }
                }
                
                // Clear pending peers after attempting connections
                torrent->clear_pending_peers();
            }
        }
        
        // Periodic DHT announces (every 15 minutes)
        auto dht_elapsed = std::chrono::duration_cast<std::chrono::minutes>(
            now - last_dht_announce_).count();
        if (dht_elapsed >= 15 && dht_running_) {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& [hash, torrent] : torrents_) {
                if (torrent->is_active()) {
                    announce_to_dht(hash);
                }
            }
            last_dht_announce_ = now;
        }
        
        // Periodic tracker announces (handled by tracker manager's should_announce)
        auto tracker_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_tracker_announce_).count();
        if (tracker_elapsed >= 30) {
            announce_torrents_to_trackers();
            last_tracker_announce_ = now;
        }
        
        // Sleep for a bit
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    LOG_INFO("BtClient", "Tick loop stopped");
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
