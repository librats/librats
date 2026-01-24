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

#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <functional>
#include <thread>

namespace librats {

//=============================================================================
// InfoHashHash for unordered_map
//=============================================================================

struct InfoHashHash {
    size_t operator()(const BtInfoHash& hash) const {
        // Simple hash - combine first few bytes
        size_t result = 0;
        for (size_t i = 0; i < std::min(sizeof(size_t), hash.size()); ++i) {
            result = (result << 8) | hash[i];
        }
        return result;
    }
};

//=============================================================================
// Client Configuration
//=============================================================================

/**
 * @brief Configuration for the BitTorrent client
 */
struct BtClientConfig {
    std::string download_path;          ///< Default download directory
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
     * @brief Remove a torrent
     * 
     * @param info_hash Info hash of torrent to remove
     * @param delete_files Also delete downloaded files
     */
    void remove_torrent(const BtInfoHash& info_hash, bool delete_files = false);
    
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
     * @brief Get listen port
     */
    uint16_t listen_port() const { return config_.listen_port; }
    
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
     * @brief Add DHT bootstrap node
     */
    void add_dht_node(const std::string& host, uint16_t port);
    
    /**
     * @brief Get DHT node count
     */
    size_t dht_node_count() const;
    
private:
    //=========================================================================
    // Internal Methods
    //=========================================================================
    
    void tick_loop();
    Torrent::Ptr create_torrent(const TorrentInfo& info, const std::string& save_path);
    
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
    
    // Callbacks
    TorrentAddedCallback on_torrent_added_;
    TorrentRemovedCallback on_torrent_removed_;
    AlertCallback on_alert_;
};

} // namespace librats
