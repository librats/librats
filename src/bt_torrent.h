#pragma once

/**
 * @file bt_torrent.h
 * @brief Active torrent management
 * 
 * Manages the state of a torrent being downloaded or seeded,
 * including peer connections, piece management, and I/O.
 */

#include "bt_types.h"
#include "bt_bitfield.h"
#include "bt_torrent_info.h"
#include "bt_piece_picker.h"
#include "bt_peer_connection.h"
#include "bt_choker.h"
#include "disk_io.h"
#include "socket.h" // For Peer struct

// Forward declaration for resume data
namespace librats { struct TorrentResumeData; }

#include <memory>
#include <vector>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>

namespace librats {

//=============================================================================
// Torrent State
//=============================================================================

/**
 * @brief Current state of a torrent
 */
enum class TorrentState : uint8_t {
    Stopped,            ///< Not active
    CheckingFiles,      ///< Verifying existing data
    DownloadingMetadata,///< Getting metadata via ut_metadata
    Downloading,        ///< Downloading pieces
    Seeding,            ///< Complete, uploading to others
    Paused,             ///< Paused by user
    Error               ///< Error state
};

/**
 * @brief Convert state to string
 */
const char* torrent_state_to_string(TorrentState state);

//=============================================================================
// Torrent Statistics
//=============================================================================

/**
 * @brief Statistics for a torrent
 */
struct TorrentStats {
    // Progress
    uint64_t total_size;
    uint64_t bytes_done;
    uint32_t pieces_total;
    uint32_t pieces_done;
    float progress;             ///< 0.0 to 1.0
    
    // Transfer rates
    uint64_t download_rate;     ///< Bytes/sec
    uint64_t upload_rate;       ///< Bytes/sec
    uint64_t total_downloaded;
    uint64_t total_uploaded;
    
    // Peers
    uint32_t peers_connected;
    uint32_t peers_total;       ///< Known peers
    uint32_t seeders;
    uint32_t leechers;
    
    // Time
    std::chrono::steady_clock::time_point started_at;
    std::chrono::seconds eta;   ///< Estimated time remaining
    
    TorrentStats()
        : total_size(0), bytes_done(0)
        , pieces_total(0), pieces_done(0), progress(0.0f)
        , download_rate(0), upload_rate(0)
        , total_downloaded(0), total_uploaded(0)
        , peers_connected(0), peers_total(0)
        , seeders(0), leechers(0)
        , eta(0) {}
};

//=============================================================================
// Torrent Configuration
//=============================================================================

/**
 * @brief Configuration for a torrent
 */
struct TorrentConfig {
    std::string save_path;              ///< Directory to save files
    std::string resume_data_path;       ///< Directory for resume data (if empty, uses save_path)
    size_t max_connections;             ///< Max peer connections (0 = unlimited)
    size_t max_uploads;                 ///< Max upload slots
    uint64_t download_limit;            ///< Bytes/sec (0 = unlimited)
    uint64_t upload_limit;              ///< Bytes/sec (0 = unlimited)
    bool sequential_download;           ///< Download pieces in order
    bool seed_mode;                     ///< Assume files are complete
    
    TorrentConfig()
        : max_connections(50)
        , max_uploads(4)
        , download_limit(0)
        , upload_limit(0)
        , sequential_download(false)
        , seed_mode(false) {}
    
    /// Get the path to use for resume data (resume_data_path if set, otherwise save_path)
    const std::string& get_resume_path() const {
        return resume_data_path.empty() ? save_path : resume_data_path;
    }
};

//=============================================================================
// Torrent
//=============================================================================

/**
 * @brief Manages an active torrent
 * 
 * This class coordinates all aspects of downloading/seeding a torrent:
 * - Peer connection management
 * - Piece selection and requesting
 * - Disk I/O for reading/writing pieces
 * - Tracker and DHT announces
 * - Choking algorithm
 * 
 * Thread-safe: Most methods are protected by a mutex.
 */
class Torrent : public std::enable_shared_from_this<Torrent> {
public:
    //=========================================================================
    // Types
    //=========================================================================
    
    using Ptr = std::shared_ptr<Torrent>;
    
    /// Callback for state changes
    using StateCallback = std::function<void(Torrent*, TorrentState)>;
    
    /// Callback for piece completion
    using PieceCallback = std::function<void(Torrent*, uint32_t piece)>;
    
    /// Callback for completion
    using CompleteCallback = std::function<void(Torrent*)>;
    
    /// Callback for errors
    using ErrorCallback = std::function<void(Torrent*, const std::string&)>;
    
    /// Callback for metadata received (for magnet links)
    using MetadataCallback = std::function<void(Torrent*, bool success)>;
    
    /// Callback for progress updates (downloaded bytes, total bytes, percentage)
    using ProgressCallback = std::function<void(uint64_t downloaded, uint64_t total, double percentage)>;
    
    /// Callback for torrent completion (name)
    using TorrentCompleteCallback = std::function<void(const std::string& name)>;
    
    /// Callback for metadata received with TorrentInfo (for rats-search compatibility)
    using MetadataCompleteCallback = std::function<void(const TorrentInfo& info)>;
    
    /// Callback for peer connected (peer info)
    using PeerConnectedCallback = std::function<void(const Peer& peer)>;
    
    /// Callback for peer disconnected (peer info)
    using PeerDisconnectedCallback = std::function<void(const Peer& peer)>;
    
    //=========================================================================
    // Construction
    //=========================================================================
    
    /**
     * @brief Create a torrent from TorrentInfo
     * 
     * @param info Torrent metadata
     * @param config Configuration
     * @param our_peer_id Our peer ID
     */
    Torrent(const TorrentInfo& info,
            const TorrentConfig& config,
            const PeerID& our_peer_id);
    
    /**
     * @brief Create a torrent from magnet link (no metadata yet)
     * 
     * @param info_hash Info hash from magnet
     * @param name Display name (may be empty)
     * @param config Configuration
     * @param our_peer_id Our peer ID
     */
    Torrent(const BtInfoHash& info_hash,
            const std::string& name,
            const TorrentConfig& config,
            const PeerID& our_peer_id);
    
    ~Torrent();
    
    // Non-copyable
    Torrent(const Torrent&) = delete;
    Torrent& operator=(const Torrent&) = delete;
    
    //=========================================================================
    // Lifecycle
    //=========================================================================
    
    /**
     * @brief Start the torrent
     */
    void start();
    
    /**
     * @brief Stop the torrent
     */
    void stop();
    
    /**
     * @brief Pause the torrent
     */
    void pause();
    
    /**
     * @brief Resume a paused torrent
     */
    void resume();
    
    /**
     * @brief Force a recheck of files
     */
    void recheck();
    
    //=========================================================================
    // State
    //=========================================================================
    
    /**
     * @brief Get current state
     */
    TorrentState state() const { return state_; }
    
    /**
     * @brief Check if torrent is active (downloading or seeding)
     */
    bool is_active() const;
    
    /**
     * @brief Check if download is complete
     */
    bool is_complete() const;
    
    /**
     * @brief Check if we have metadata
     */
    bool has_metadata() const;
    
    //=========================================================================
    // Info
    //=========================================================================
    
    /**
     * @brief Get info hash
     */
    const BtInfoHash& info_hash() const { return info_hash_; }
    
    /**
     * @brief Get info hash as hex
     */
    std::string info_hash_hex() const { return info_hash_to_hex(info_hash_); }
    
    /**
     * @brief Get torrent name
     */
    const std::string& name() const { return name_; }
    
    /**
     * @brief Get torrent info (metadata)
     */
    const TorrentInfo* info() const { return info_.get(); }
    
    /**
     * @brief Get torrent info reference (for rats-search compatibility)
     * @note Returns a static empty TorrentInfo if metadata not available
     */
    const TorrentInfo& get_torrent_info() const;
    
    /**
     * @brief Get save path
     */
    const std::string& save_path() const { return config_.save_path; }
    
    //=========================================================================
    // Progress and Speed Accessors (rats-search compatibility)
    //=========================================================================
    
    /**
     * @brief Get total downloaded bytes
     */
    uint64_t downloaded_bytes() const;
    
    /**
     * @brief Get download progress as percentage (0-100)
     */
    double progress_percentage() const;
    
    /**
     * @brief Get current download speed in bytes/sec
     */
    double download_speed() const;
    
    //=========================================================================
    // Statistics
    //=========================================================================
    
    /**
     * @brief Get current statistics
     */
    TorrentStats stats() const;
    
    /**
     * @brief Get have bitfield
     */
    Bitfield get_have_bitfield() const;
    
    //=========================================================================
    // Peer Management
    //=========================================================================
    
    /**
     * @brief Add a peer to connect to
     * 
     * @param ip Peer IP address
     * @param port Peer port
     */
    void add_peer(const std::string& ip, uint16_t port);
    
    /**
     * @brief Add peers from tracker response
     * 
     * @param peers List of (ip, port) pairs
     */
    void add_peers(const std::vector<std::pair<std::string, uint16_t>>& peers);
    
    /**
     * @brief Get number of connected peers
     */
    size_t num_peers() const;
    
    /**
     * @brief Get list of peer connections
     */
    std::vector<BtPeerConnection*> peers() const;
    
    /**
     * @brief Get pending peers to connect to
     * @return List of (ip, port) pairs
     */
    std::vector<std::pair<std::string, uint16_t>> get_pending_peers() const;
    
    /**
     * @brief Clear pending peers
     */
    void clear_pending_peers();
    
    /**
     * @brief Add an established connection
     * Called by BtClient when network manager establishes a connection
     */
    void add_connection(std::shared_ptr<BtPeerConnection> connection);
    
    /**
     * @brief Remove a connection by pointer
     */
    void remove_connection(BtPeerConnection* connection);
    
    //=========================================================================
    // Configuration
    //=========================================================================
    
    /**
     * @brief Set sequential download mode
     */
    void set_sequential(bool sequential);
    
    /**
     * @brief Set download rate limit
     */
    void set_download_limit(uint64_t bytes_per_sec);
    
    /**
     * @brief Set upload rate limit
     */
    void set_upload_limit(uint64_t bytes_per_sec);
    
    /**
     * @brief Get current config
     */
    const TorrentConfig& config() const { return config_; }
    
    //=========================================================================
    // Callbacks
    //=========================================================================
    
    void set_state_callback(StateCallback cb) { on_state_change_ = std::move(cb); }
    void set_piece_callback(PieceCallback cb) { on_piece_complete_ = std::move(cb); }
    void set_complete_callback(CompleteCallback cb) { on_complete_ = std::move(cb); }
    void set_error_callback(ErrorCallback cb) { on_error_ = std::move(cb); }
    void set_metadata_callback(MetadataCallback cb) { on_metadata_received_ = std::move(cb); }
    
    // Extended callbacks (rats-search compatibility)
    void set_progress_callback(ProgressCallback cb) { on_progress_ = std::move(cb); }
    void set_torrent_complete_callback(TorrentCompleteCallback cb) { on_torrent_complete_ = std::move(cb); }
    void set_metadata_complete_callback(MetadataCompleteCallback cb) { on_metadata_complete_ = std::move(cb); }
    void set_peer_connected_callback(PeerConnectedCallback cb) { on_peer_connected_ext_ = std::move(cb); }
    void set_peer_disconnected_callback(PeerDisconnectedCallback cb) { on_peer_disconnected_ext_ = std::move(cb); }
    
    //=========================================================================
    // Metadata (for magnet links)
    //=========================================================================
    
    /**
     * @brief Set metadata received from peers
     * 
     * @param metadata Raw info dict bytes
     * @return true if valid
     */
    bool set_metadata(const std::vector<uint8_t>& metadata);
    
    //=========================================================================
    // Resume Data (Fast Resume)
    //=========================================================================
    
    /**
     * @brief Generate resume data for this torrent
     * 
     * Resume data can be saved to disk and used to quickly resume 
     * downloading without re-verifying existing pieces.
     * 
     * @return Resume data structure
     */
    TorrentResumeData generate_resume_data() const;
    
    /**
     * @brief Save resume data to the default path
     * 
     * Saves to {save_path}/.resume/{info_hash}.resume
     * 
     * @return true on success
     */
    bool save_resume_data();
    
    /**
     * @brief Save resume data to a specific path
     * 
     * @param path Path to save the resume file
     * @return true on success
     */
    bool save_resume_data(const std::string& path);
    
    /**
     * @brief Load resume data and apply it to this torrent
     * 
     * This should be called before start() to apply saved state.
     * Will set have_pieces_ bitfield and restore unfinished pieces.
     * 
     * @param resume_data Resume data to apply
     * @return true if resume data was valid and applied
     */
    bool load_resume_data(const TorrentResumeData& resume_data);
    
    /**
     * @brief Try to load resume data from the default path
     * 
     * Looks for {save_path}/.resume/{info_hash}.resume
     * 
     * @return true if resume data was found and applied
     */
    bool try_load_resume_data();
    
    //=========================================================================
    // File Verification (Recheck)
    //=========================================================================
    
    /**
     * @brief Check which pieces are already complete on disk
     * 
     * Reads and verifies hashes for all pieces. This is called during
     * recheck() or when resuming without resume data.
     * 
     * @param progress_callback Optional callback for progress updates
     *        Parameters: (current_piece, total_pieces)
     */
    void check_files(std::function<void(uint32_t, uint32_t)> progress_callback = nullptr);
    
    /**
     * @brief Check files asynchronously
     * 
     * @param completion_callback Called when checking is complete
     *        Parameters: (num_pieces_have, num_pieces_total)
     * @param progress_callback Optional callback for progress updates
     */
    void check_files_async(
        std::function<void(uint32_t, uint32_t)> completion_callback,
        std::function<void(uint32_t, uint32_t)> progress_callback = nullptr);
    
    //=========================================================================
    // Tick (called periodically)
    //=========================================================================
    
    /**
     * @brief Process periodic tasks
     * 
     * Should be called regularly (e.g., every 100ms)
     */
    void tick();
    
private:
    //=========================================================================
    // Internal Methods
    //=========================================================================
    
    void set_state(TorrentState new_state);
    
    // Unlocked versions (call when mutex is already held)
    bool is_complete_unlocked() const;
    bool has_metadata_unlocked() const;
    void on_peer_connected(BtPeerConnection* peer);
    void on_peer_disconnected(BtPeerConnection* peer);
    void on_peer_message(BtPeerConnection* peer, const BtMessage& msg);
    void on_piece_received(uint32_t piece, uint32_t begin, const std::vector<uint8_t>& data);
    void on_piece_verified(uint32_t piece, bool valid);
    void request_pieces();
    void request_blocks_from_peer(BtPeerConnection* peer);
    void run_choker();
    void update_stats();
    
    // Disk I/O helpers
    std::vector<FileMappingInfo> get_file_mappings() const;
    void write_block_to_disk(const BlockInfo& block, const std::vector<uint8_t>& data);
    void read_piece_from_disk(uint32_t piece, BtPeerConnection* peer, 
                               uint32_t begin, uint32_t length);
    void verify_piece_hash(uint32_t piece);
    
    // Extension protocol helpers
    void send_extension_handshake(BtPeerConnection* peer);
    void on_extension_message(BtPeerConnection* peer, uint8_t ext_id, 
                               const std::vector<uint8_t>& payload);
    void on_extension_handshake(BtPeerConnection* peer, 
                                 const std::vector<uint8_t>& payload);
    void request_metadata(BtPeerConnection* peer);
    void on_metadata_message(BtPeerConnection* peer, 
                              const std::vector<uint8_t>& payload);
    void on_metadata_complete();
    size_t find_bencode_end(const std::vector<uint8_t>& data);
    
    // Resume/recheck helpers
    void verify_piece_hash_sync(uint32_t piece, bool& valid);
    void on_file_check_complete(uint32_t pieces_have);
    
    //=========================================================================
    // Data Members
    //=========================================================================
    
    mutable std::mutex mutex_;
    
    // Identity
    BtInfoHash info_hash_;
    std::string name_;
    PeerID our_peer_id_;
    
    // Metadata
    std::unique_ptr<TorrentInfo> info_;
    
    // Configuration
    TorrentConfig config_;
    
    // State
    std::atomic<TorrentState> state_;
    std::string error_message_;
    
    // Piece management
    std::unique_ptr<PiecePicker> picker_;
    Bitfield have_pieces_;
    // Note: Blocks are written directly to disk as they arrive (no in-memory buffering)
    // This prevents memory bloat when downloading from many peers simultaneously
    
    // Peers
    std::vector<std::shared_ptr<BtPeerConnection>> connections_;
    std::vector<std::pair<std::string, uint16_t>> pending_peers_;
    
    // Choking
    Choker choker_;
    
    // Statistics
    TorrentStats stats_;
    std::chrono::steady_clock::time_point last_stats_update_;
    std::chrono::steady_clock::time_point last_choker_run_;
    
    // Time tracking for resume data
    int64_t added_time_ = 0;          ///< When torrent was added (Unix time)
    int64_t completed_time_ = 0;      ///< When download completed (Unix time)
    int64_t active_time_ = 0;         ///< Seconds spent actively downloading
    int64_t seeding_time_ = 0;        ///< Seconds spent seeding
    std::chrono::steady_clock::time_point last_activity_check_;
    
    // Callbacks
    StateCallback on_state_change_;
    PieceCallback on_piece_complete_;
    CompleteCallback on_complete_;
    ErrorCallback on_error_;
    MetadataCallback on_metadata_received_;
    
    // Extended callbacks (rats-search compatibility)
    ProgressCallback on_progress_;
    TorrentCompleteCallback on_torrent_complete_;
    MetadataCompleteCallback on_metadata_complete_;
    PeerConnectedCallback on_peer_connected_ext_;
    PeerDisconnectedCallback on_peer_disconnected_ext_;
    
    // Metadata exchange (for magnet links)
    std::vector<uint8_t> metadata_buffer_;
    std::vector<bool> metadata_pieces_received_;
    std::unordered_map<BtPeerConnection*, size_t> peer_metadata_size_;
    std::unordered_map<BtPeerConnection*, uint8_t> peer_ut_metadata_id_;
    std::chrono::steady_clock::time_point metadata_download_started_;
    static constexpr int METADATA_TIMEOUT_SECONDS = 120;  // 2 minutes timeout
};

} // namespace librats
