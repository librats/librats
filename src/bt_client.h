#pragma once

/**
 * @file bt_client.h
 * @brief BitTorrent client manager
 * 
 * High-level interface for managing multiple torrents,
 * listening for connections, and coordinating DHT/trackers.
 */

#include "bt_types.h"
#include "bt_torrent.h"
#include "bt_torrent_info.h"
#include "bt_resume_data.h"
#include "bt_network.h"
#include "dht.h"

#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <functional>
#include <thread>

namespace librats {

// Forward declarations
class TrackerManager;

//=============================================================================
// Client Configuration
//=============================================================================

/**
 * @brief Configuration for the BitTorrent client
 */
struct BtClientConfig {
    std::string download_path;          ///< Default download directory
    std::string resume_data_path;       ///< Directory for resume data files (if empty, uses download_path)
    uint16_t listen_port;               ///< Port for incoming connections (0 = random)
    size_t max_connections;             ///< Global max connections
    size_t max_connections_per_torrent; ///< Max connections per torrent
    size_t max_uploads;                 ///< Max upload slots per torrent
    uint64_t download_limit;            ///< Global download limit (bytes/sec, 0 = unlimited)
    uint64_t upload_limit;              ///< Global upload limit (bytes/sec, 0 = unlimited)
    bool enable_dht;                    ///< Enable DHT
    bool enable_pex;                    ///< Enable peer exchange
    bool enable_lsd;                    ///< Enable local service discovery
    std::string user_agent;             ///< Client user agent string
    
    BtClientConfig()
        : listen_port(6881)
        , max_connections(200)
        , max_connections_per_torrent(50)
        , max_uploads(4)
        , download_limit(0)
        , upload_limit(0)
        , enable_dht(true)
        , enable_pex(true)
        , enable_lsd(true)
        , user_agent("librats/1.0") {}
};

//=============================================================================
// BitTorrent Client
//=============================================================================

/**
 * @brief High-level BitTorrent client
 * 
 * Manages:
 * - Multiple torrents
 * - Incoming peer connections
 * - DHT node
 * - Tracker management
 * - Global rate limiting
 * 
 * Thread-safe: All public methods are protected.
 */
class BtClient {
public:
    //=========================================================================
    // Types
    //=========================================================================
    
    using TorrentAddedCallback = std::function<void(Torrent::Ptr)>;
    using TorrentRemovedCallback = std::function<void(const BtInfoHash&)>;
    using AlertCallback = std::function<void(const std::string&)>;
    
    //=========================================================================
    // Construction
    //=========================================================================
    
    /**
     * @brief Create a client with default config
     */
    BtClient();
    
    /**
     * @brief Create a client with custom config
     */
    explicit BtClient(const BtClientConfig& config);
    
    /**
     * @brief Destructor - stops all torrents
     */
    ~BtClient();
    
    // Non-copyable
    BtClient(const BtClient&) = delete;
    BtClient& operator=(const BtClient&) = delete;
    
    //=========================================================================
    // Lifecycle
    //=========================================================================
    
    /**
     * @brief Start the client
     * 
     * Begins listening for connections and starts DHT if enabled.
     */
    void start();
    
    /**
     * @brief Stop the client
     * 
     * Stops all torrents and closes connections.
     */
    void stop();
    
    /**
     * @brief Check if client is running
     */
    bool is_running() const { return running_; }
    
    //=========================================================================
    // Torrent Management
    //=========================================================================
    
    /**
     * @brief Set the resume data path for all new torrents
     * 
     * @param path Directory where resume data files will be stored
     */
    void set_resume_data_path(const std::string& path);
    
    /**
     * @brief Add a torrent from a .torrent file
     * 
     * @param path Path to .torrent file
     * @param save_path Directory to save files (empty = use default)
     * @return Torrent pointer, or nullptr on failure
     */
    Torrent::Ptr add_torrent_file(const std::string& path,
                                  const std::string& save_path = "");
    
    /**
     * @brief Add a torrent from TorrentInfo
     * 
     * @param info Torrent metadata
     * @param save_path Directory to save files
     * @return Torrent pointer
     */
    Torrent::Ptr add_torrent(const TorrentInfo& info,
                             const std::string& save_path = "");
    
    /**
     * @brief Add a torrent from magnet link
     * 
     * @param magnet_uri Magnet URI
     * @param save_path Directory to save files
     * @return Torrent pointer, or nullptr on failure
     */
    Torrent::Ptr add_magnet(const std::string& magnet_uri,
                            const std::string& save_path = "");
    
    /**
     * @brief Add a torrent with resume data for fast resume
     * 
     * @param info Torrent metadata
     * @param resume_data Resume data from previous session
     * @param save_path Directory to save files (uses resume_data.save_path if empty)
     * @return Torrent pointer
     */
    Torrent::Ptr add_torrent_with_resume(
        const TorrentInfo& info,
        const TorrentResumeData& resume_data,
        const std::string& save_path = "");
    
    /**
     * @brief Add a torrent and try to load resume data automatically
     * 
     * Looks for resume data in {save_path}/.resume/{info_hash}.resume
     * If found, applies it for fast resume. Otherwise, starts fresh.
     * 
     * @param info Torrent metadata
     * @param save_path Directory to save files
     * @param check_files If true and no resume data, verify existing files
     * @return Torrent pointer
     */
    Torrent::Ptr add_torrent_auto_resume(
        const TorrentInfo& info,
        const std::string& save_path = "",
        bool check_files = true);
    
    /**
     * @brief Add a torrent for seeding (seed_mode)
     * 
     * Use this when you have created a torrent from existing files and want to
     * start seeding immediately. All pieces are assumed to be complete.
     * 
     * This is the correct method to use after create_torrent_from_path().
     * 
     * @param info Torrent metadata (from create_torrent_from_path or similar)
     * @param save_path Directory where files are located
     * @return Torrent pointer
     */
    Torrent::Ptr add_torrent_for_seeding(
        const TorrentInfo& info,
        const std::string& save_path);
    
    /**
     * @brief Save resume data for all active torrents
     * 
     * Call this periodically or before shutdown to save progress.
     */
    void save_all_resume_data();
    
    /**
     * @brief Remove a torrent
     * 
     * @param info_hash Info hash of torrent to remove
     * @param delete_files Also delete downloaded files
     */
    void remove_torrent(const BtInfoHash& info_hash, bool delete_files = false);
    
    /**
     * @brief Mark a torrent for deferred removal
     * 
     * Thread-safe method that can be called from any thread/callback.
     * The actual removal happens in the tick loop to avoid deadlocks.
     * 
     * @param info_hash Info hash of torrent to remove
     */
    void mark_for_removal(const BtInfoHash& info_hash);
    
    /**
     * @brief Get a torrent by info hash
     */
    Torrent::Ptr get_torrent(const BtInfoHash& info_hash);
    
    /**
     * @brief Get all torrents
     */
    std::vector<Torrent::Ptr> get_torrents();
    
    /**
     * @brief Get number of torrents
     */
    size_t num_torrents() const;
    
    //=========================================================================
    // Configuration
    //=========================================================================
    
    /**
     * @brief Get current configuration
     */
    const BtClientConfig& config() const { return config_; }
    
    /**
     * @brief Set global download limit
     */
    void set_download_limit(uint64_t bytes_per_sec);
    
    /**
     * @brief Set global upload limit
     */
    void set_upload_limit(uint64_t bytes_per_sec);
    
    /**
     * @brief Get our peer ID
     */
    const PeerID& peer_id() const { return peer_id_; }
    
    /**
     * @brief Get listen port (actual port when running, configured port otherwise)
     */
    uint16_t listen_port() const { 
        if (network_manager_ && network_manager_->is_running()) {
            return network_manager_->listen_port();
        }
        return config_.listen_port; 
    }
    
    //=========================================================================
    // Callbacks
    //=========================================================================
    
    void set_torrent_added_callback(TorrentAddedCallback cb) { 
        on_torrent_added_ = std::move(cb); 
    }
    
    void set_torrent_removed_callback(TorrentRemovedCallback cb) { 
        on_torrent_removed_ = std::move(cb); 
    }
    
    void set_alert_callback(AlertCallback cb) { 
        on_alert_ = std::move(cb); 
    }
    
    //=========================================================================
    // Statistics
    //=========================================================================
    
    /**
     * @brief Get total download rate (all torrents)
     */
    uint64_t total_download_rate() const;
    
    /**
     * @brief Get total upload rate (all torrents)
     */
    uint64_t total_upload_rate() const;
    
    /**
     * @brief Get total connected peers
     */
    size_t total_peers() const;
    
    //=========================================================================
    // DHT
    //=========================================================================
    
    /**
     * @brief Check if DHT is running
     */
    bool dht_running() const { return dht_running_; }
    
    /**
     * @brief Set an external DHT client to use instead of creating one
     * 
     * Must be called before start(). The external DHT client's lifecycle
     * is managed by the caller - BtClient will not start or stop it.
     * 
     * @param dht External DHT client (must remain valid while BtClient is running)
     */
    void set_external_dht(DhtClient* dht);
    
    /**
     * @brief Get the DHT client (internal or external)
     */
    DhtClient* get_dht_client() { return external_dht_ ? external_dht_ : dht_client_.get(); }
    
    /**
     * @brief Add DHT bootstrap node
     */
    void add_dht_node(const std::string& host, uint16_t port);
    
    /**
     * @brief Get DHT node count
     */
    size_t dht_node_count() const;
    
    /**
     * @brief Announce torrent to DHT
     */
    void announce_to_dht(const BtInfoHash& info_hash);
    
    /**
     * @brief Find peers for torrent via DHT
     */
    void find_peers_dht(const BtInfoHash& info_hash);
    
    //=========================================================================
    // Network
    //=========================================================================
    
    /**
     * @brief Get the network manager
     */
    BtNetworkManager* network_manager() { return network_manager_.get(); }
    
private:
    //=========================================================================
    // Internal Methods
    //=========================================================================
    
    void tick_loop();
    Torrent::Ptr create_torrent(const TorrentInfo& info, const std::string& save_path);
    void on_dht_peers_found(const std::vector<Peer>& peers, const InfoHash& info_hash);
    void on_peer_connected(const BtInfoHash& info_hash, 
                           std::shared_ptr<BtPeerConnection> connection,
                           socket_t socket, bool is_incoming);
    void on_peer_disconnected(const BtInfoHash& info_hash, BtPeerConnection* connection);
    void on_peer_data(const BtInfoHash& info_hash, BtPeerConnection* connection, socket_t socket);
    void connect_pending_peers();
    void announce_torrents_to_trackers();
    
    //=========================================================================
    // Data Members
    //=========================================================================
    
    mutable std::mutex mutex_;
    
    BtClientConfig config_;
    PeerID peer_id_;
    
    std::atomic<bool> running_;
    std::atomic<bool> dht_running_;
    
    std::unordered_map<BtInfoHash, Torrent::Ptr, InfoHashHash> torrents_;
    
    std::thread tick_thread_;
    
    // DHT client (owned, if not using external)
    std::unique_ptr<DhtClient> dht_client_;
    
    // External DHT client (non-owning pointer, lifecycle managed externally)
    DhtClient* external_dht_ = nullptr;
    
    // Network manager
    std::unique_ptr<BtNetworkManager> network_manager_;
    
    // Tracker managers per torrent
    std::unordered_map<BtInfoHash, std::unique_ptr<TrackerManager>, InfoHashHash> tracker_managers_;
    
    // Announce timing
    std::chrono::steady_clock::time_point last_dht_announce_;
    std::chrono::steady_clock::time_point last_tracker_announce_;
    
    // Deferred removal queue (thread-safe, processed in tick_loop)
    mutable std::mutex removal_mutex_;
    std::vector<BtInfoHash> pending_removals_;
    
    // Callbacks
    TorrentAddedCallback on_torrent_added_;
    TorrentRemovedCallback on_torrent_removed_;
    AlertCallback on_alert_;
};

} // namespace librats
