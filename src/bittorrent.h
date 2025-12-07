#pragma once

#include "bencode.h"
#include "sha1.h"
#include "socket.h"
#include "dht.h"
#include "logger.h"
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <array>
#include <algorithm>  // Add this for std::all_of
#include <condition_variable>

namespace librats {

// Forward declarations
class BitTorrentClient;
class TorrentDownload;
class PeerConnection;
class MetadataDownload;
class TrackerManager;

//=============================================================================
// LOCK ORDERING DOCUMENTATION
//=============================================================================
// To prevent deadlocks, always acquire locks in the following order:
//
// BitTorrentClient level:
//   torrents_mutex_ -> metadata_mutex_
//
// TorrentDownload level:
//   peers_mutex_ -> pieces_mutex_ -> files_mutex_
//
// PeerConnection level:
//   requests_mutex_ (independent, only used within PeerConnection)
//
// MetadataDownload level:
//   mutex_ (never call callbacks while holding this mutex!)
//
// Cross-class lock ordering:
//   BitTorrentClient::torrents_mutex_ 
//   -> TorrentDownload::peers_mutex_
//   -> TorrentDownload::pieces_mutex_
//   -> TorrentDownload::files_mutex_
//   -> PeerConnection::requests_mutex_
//=============================================================================

// Type aliases
using InfoHash = std::array<uint8_t, 20>;
using PieceIndex = uint32_t;
using BlockIndex = uint32_t;
using PeerID = std::array<uint8_t, 20>;

// Constants
constexpr size_t BLOCK_SIZE = 16384;  // 16KB standard block size
constexpr size_t MAX_PIECE_SIZE = 2 * 1024 * 1024;  // 2MB max piece size
constexpr size_t HANDSHAKE_TIMEOUT_MS = 30000;  // 30 seconds
constexpr size_t REQUEST_TIMEOUT_MS = 60000;    // 60 seconds
constexpr size_t MAX_REQUESTS_PER_PEER = 10;    // Maximum concurrent requests per peer
constexpr size_t MAX_PEERS_PER_TORRENT = 50;    // Maximum peers per torrent

// BitTorrent protocol constants
constexpr uint8_t BITTORRENT_PROTOCOL_ID[] = "BitTorrent protocol";
constexpr size_t BITTORRENT_PROTOCOL_ID_LENGTH = 19;

// File information structure
struct FileInfo {
    std::string path;
    uint64_t length;
    uint64_t offset;  // Offset within the torrent
    
    FileInfo(const std::string& p, uint64_t len, uint64_t off) 
        : path(p), length(len), offset(off) {}
};

// Piece information
struct PieceInfo {
    PieceIndex index;
    std::array<uint8_t, 20> hash;
    uint32_t length;
    bool verified;
    std::vector<bool> blocks_downloaded;  // Track which blocks are downloaded (received)
    std::vector<bool> blocks_requested;   // Track which blocks are requested globally (sent but not received)
    std::vector<uint8_t> data;
    
    PieceInfo(PieceIndex idx, const std::array<uint8_t, 20>& h, uint32_t len)
        : index(idx), hash(h), length(len), verified(false) {
        uint32_t num_blocks = (length + BLOCK_SIZE - 1) / BLOCK_SIZE;
        blocks_downloaded.resize(num_blocks, false);
        blocks_requested.resize(num_blocks, false);
        // Don't pre-allocate data - allocate lazily when downloading starts
    }
    
    bool is_complete() const {
        return std::all_of(blocks_downloaded.begin(), blocks_downloaded.end(), [](bool b) { return b; });
    }
    
    uint32_t get_num_blocks() const {
        return static_cast<uint32_t>(blocks_downloaded.size());
    }
    
    // Check if all blocks have been requested (or downloaded)
    bool all_blocks_requested() const {
        for (size_t i = 0; i < blocks_downloaded.size(); ++i) {
            if (!blocks_downloaded[i] && !blocks_requested[i]) {
                return false;
            }
        }
        return true;
    }
    
    // Reset requested status for blocks that weren't received (for timeout/disconnect)
    void reset_unreceived_requests() {
        for (size_t i = 0; i < blocks_requested.size(); ++i) {
            if (blocks_requested[i] && !blocks_downloaded[i]) {
                blocks_requested[i] = false;
            }
        }
    }
    
    // Ensure data buffer is allocated
    void ensure_data_allocated() {
        if (data.empty()) {
            data.resize(length);
        }
    }
    
    // Free data buffer after piece is written to disk
    void free_data() {
        data.clear();
        data.shrink_to_fit();
    }
};

// Torrent file parser and information holder
class TorrentInfo {
public:
    TorrentInfo();
    ~TorrentInfo();
    
    // Parse torrent from file
    bool load_from_file(const std::string& torrent_file);
    
    // Parse torrent from bencode data
    bool load_from_bencode(const BencodeValue& torrent_data);
    
    // Parse torrent from raw data
    bool load_from_data(const std::vector<uint8_t>& data);
    
    // Getters
    const InfoHash& get_info_hash() const { return info_hash_; }
    const std::string& get_name() const { return name_; }
    uint64_t get_total_length() const { return total_length_; }
    uint32_t get_piece_length() const { return piece_length_; }
    uint32_t get_num_pieces() const { return static_cast<uint32_t>(piece_hashes_.size()); }
    const std::vector<std::array<uint8_t, 20>>& get_piece_hashes() const { return piece_hashes_; }
    const std::vector<FileInfo>& get_files() const { return files_; }
    const std::string& get_announce() const { return announce_; }
    const std::vector<std::string>& get_announce_list() const { return announce_list_; }
    bool is_single_file() const { return files_.size() == 1; }
    bool is_private() const { return private_; }
    
    // Calculate piece length for specific piece
    uint32_t get_piece_length(PieceIndex piece_index) const;
    
    // Validate torrent info
    bool is_valid() const;
    
    // Create a minimal torrent info for metadata exchange only (BEP 9)
    static TorrentInfo create_for_metadata_exchange(const InfoHash& info_hash);
    
private:
    InfoHash info_hash_;
    std::string name_;
    uint64_t total_length_;
    uint32_t piece_length_;
    std::vector<std::array<uint8_t, 20>> piece_hashes_;
    std::vector<FileInfo> files_;
    std::string announce_;
    std::vector<std::string> announce_list_;
    bool private_;
    
    bool parse_info_dict(const BencodeValue& info_dict);
    void calculate_info_hash(const BencodeValue& info_dict);
    void build_file_list(const BencodeValue& info_dict);
};

// BitTorrent peer wire protocol message types
enum class MessageType : uint8_t {
    CHOKE = 0,
    UNCHOKE = 1,
    INTERESTED = 2,
    NOT_INTERESTED = 3,
    HAVE = 4,
    BITFIELD = 5,
    REQUEST = 6,
    PIECE = 7,
    CANCEL = 8,
    PORT = 9,
    EXTENDED = 20
};

// Extended message types (BEP 10)
enum class ExtendedMessageType : uint8_t {
    HANDSHAKE = 0,
    UT_METADATA = 1  // Our local ID for ut_metadata extension
};

// Metadata message types (BEP 9)
enum class MetadataMessageType : uint8_t {
    REQUEST = 0,
    DATA = 1,
    REJECT = 2
};

// Metadata constants
constexpr size_t METADATA_PIECE_SIZE = 16384;  // 16KB metadata pieces
constexpr size_t MAX_METADATA_SIZE = 10 * 1024 * 1024;  // 10MB max metadata size

// BitTorrent peer wire protocol messages
struct PeerMessage {
    MessageType type;
    std::vector<uint8_t> payload;
    
    PeerMessage(MessageType t) : type(t) {}
    PeerMessage(MessageType t, const std::vector<uint8_t>& p) : type(t), payload(p) {}
    
    // Serialize message to wire format
    std::vector<uint8_t> serialize() const;
    
    // Create specific message types
    static PeerMessage create_choke();
    static PeerMessage create_unchoke();
    static PeerMessage create_interested();
    static PeerMessage create_not_interested();
    static PeerMessage create_have(PieceIndex piece_index);
    static PeerMessage create_bitfield(const std::vector<bool>& bitfield);
    static PeerMessage create_request(PieceIndex piece_index, uint32_t offset, uint32_t length);
    static PeerMessage create_piece(PieceIndex piece_index, uint32_t offset, const std::vector<uint8_t>& data);
    static PeerMessage create_cancel(PieceIndex piece_index, uint32_t offset, uint32_t length);
    static PeerMessage create_port(uint16_t port);
};

// Peer request tracking
struct PeerRequest {
    PieceIndex piece_index;
    uint32_t offset;
    uint32_t length;
    std::chrono::steady_clock::time_point requested_at;
    
    PeerRequest(PieceIndex piece, uint32_t off, uint32_t len)
        : piece_index(piece), offset(off), length(len), 
          requested_at(std::chrono::steady_clock::now()) {}
};

// Peer connection state
enum class PeerState {
    CONNECTING,
    HANDSHAKING,
    CONNECTED,
    DISCONNECTED,
    ERROR
};

// Individual peer connection for BitTorrent protocol
class PeerConnection {
public:
    PeerConnection(TorrentDownload* torrent, const Peer& peer_info, socket_t socket = INVALID_SOCKET_VALUE);
    ~PeerConnection();
    
    // Connection management
    bool connect();
    void disconnect();
    bool is_connected() const { return state_.load() == PeerState::CONNECTED; }
    PeerState get_state() const { return state_.load(); }
    
    // Message handling
    bool send_message(const PeerMessage& message);
    void process_messages();
    
    // Seeding support
    void send_bitfield();  // Send our bitfield to peer after handshake
    
    // Piece requests
    bool request_piece_block(PieceIndex piece_index, uint32_t offset, uint32_t length);
    bool is_block_requested(PieceIndex piece_index, uint32_t offset) const;
    void cancel_request(PieceIndex piece_index, uint32_t offset, uint32_t length);
    void cancel_all_requests();
    
    // Peer state
    bool is_choked() const { return peer_choked_; }
    bool is_interested() const { return am_interested_; }
    bool peer_is_interested() const { return peer_interested_; }
    bool am_choking() const { return am_choking_; }
    
    void set_interested(bool interested);
    void set_choke(bool choke);
    
    // Bitfield management
    bool has_piece(PieceIndex piece_index) const;
    const std::vector<bool>& get_bitfield() const { return peer_bitfield_; }
    void update_bitfield(const std::vector<bool>& bitfield);
    
    // Statistics
    uint64_t get_downloaded() const { return downloaded_bytes_; }
    uint64_t get_uploaded() const { return uploaded_bytes_; }
    size_t get_pending_requests() const { return pending_requests_.size(); }
    
    // Peer info
    const Peer& get_peer_info() const { return peer_info_; }
    const PeerID& get_peer_id() const { return peer_id_; }
    
    // Extension protocol (BEP 10)
    bool supports_extensions() const { return supports_extensions_; }
    bool supports_metadata_exchange() const { return supports_metadata_exchange_; }
    uint8_t get_peer_metadata_extension_id() const { return peer_ut_metadata_id_; }
    
    // Metadata exchange (BEP 9)
    void request_metadata_piece(uint32_t piece_index);
    size_t get_peer_metadata_size() const { return peer_metadata_size_; }
    
private:
    TorrentDownload* torrent_;
    Peer peer_info_;
    socket_t socket_;
    std::atomic<PeerState> state_;  // Atomic to allow thread-safe reads without lock
    std::thread connection_thread_;
    std::atomic<bool> should_disconnect_;
    bool handshake_completed_;  // Track if handshake is already done (for incoming connections)
    
    // Conditional variables for immediate shutdown
    std::condition_variable shutdown_cv_;
    std::mutex shutdown_mutex_;
    
    // Peer state
    PeerID peer_id_;
    bool peer_choked_;
    bool am_choked_;
    bool peer_interested_;
    bool am_interested_;
    bool am_choking_;
    std::vector<bool> peer_bitfield_;
    
    // Request tracking
    std::vector<PeerRequest> pending_requests_;
    mutable std::mutex requests_mutex_;
    
    // Statistics
    std::atomic<uint64_t> downloaded_bytes_;
    std::atomic<uint64_t> uploaded_bytes_;
    
    // Message buffer
    std::vector<uint8_t> message_buffer_;
    size_t expected_message_length_;
    
    // Extension protocol support (BEP 10)
    bool supports_extensions_;
    bool supports_metadata_exchange_;
    uint8_t peer_ut_metadata_id_;  // Peer's extension ID for ut_metadata
    size_t peer_metadata_size_;
    
    void connection_loop();
    bool perform_handshake();
    bool send_handshake();
    bool receive_handshake();
    
    // Message parsing
    std::unique_ptr<PeerMessage> parse_message(const std::vector<uint8_t>& data);
    void handle_message(const PeerMessage& message);
    
    // Specific message handlers
    void handle_choke();
    void handle_unchoke();
    void handle_interested();
    void handle_not_interested();
    void handle_have(const std::vector<uint8_t>& payload);
    void handle_bitfield(const std::vector<uint8_t>& payload);
    void handle_request(const std::vector<uint8_t>& payload);
    void handle_piece(const std::vector<uint8_t>& payload);
    void handle_cancel(const std::vector<uint8_t>& payload);
    void handle_extended(const std::vector<uint8_t>& payload);
    
    // Extended message handlers (BEP 10)
    void handle_extended_handshake(const std::vector<uint8_t>& payload);
    void handle_metadata_message(const std::vector<uint8_t>& payload);
    void send_extended_handshake();
    
    // Utility
    void cleanup_expired_requests();
    bool read_data(std::vector<uint8_t>& buffer, size_t length);
    bool write_data(const std::vector<uint8_t>& data);
};

// Download progress callback types
using ProgressCallback = std::function<void(uint64_t downloaded, uint64_t total, double percentage)>;
using PieceCompleteCallback = std::function<void(PieceIndex piece_index)>;
using TorrentCompleteCallback = std::function<void(const std::string& torrent_name)>;
using PeerConnectedCallback = std::function<void(const Peer& peer)>;
using PeerDisconnectedCallback = std::function<void(const Peer& peer)>;
using MetadataCompleteCallback = std::function<void(const TorrentInfo& torrent_info)>;

// Metadata download coordinator (BEP 9)
class MetadataDownload {
public:
    MetadataDownload(const InfoHash& info_hash, size_t metadata_size);
    ~MetadataDownload();
    
    // Store a metadata piece from a peer
    bool store_metadata_piece(uint32_t piece_index, const std::vector<uint8_t>& data);
    
    // Check if we have all metadata pieces
    bool is_complete() const;
    
    // Get the reconstructed metadata
    std::vector<uint8_t> get_metadata() const;
    
    // Verify metadata hash matches expected info hash
    bool verify_metadata() const;
    
    // Get next piece to request
    uint32_t get_next_piece_to_request() const;
    
    // Check if a piece is complete
    bool is_piece_complete(uint32_t piece_index) const;
    
    // Get metadata info
    const InfoHash& get_info_hash() const { return info_hash_; }
    size_t get_metadata_size() const { return metadata_size_; }
    uint32_t get_num_pieces() const { return num_pieces_; }
    
    // Set completion callback
    void set_completion_callback(MetadataCompleteCallback callback) { completion_callback_ = callback; }
    
private:
    InfoHash info_hash_;
    size_t metadata_size_;
    uint32_t num_pieces_;
    std::vector<std::vector<uint8_t>> pieces_;
    std::vector<bool> pieces_complete_;
    mutable std::mutex mutex_;
    MetadataCompleteCallback completion_callback_;
    
    // Internal versions without lock (called when mutex is already held)
    bool verify_metadata_unlocked() const;
    std::vector<uint8_t> get_metadata_unlocked() const;
};

// Individual torrent download
class TorrentDownload {
public:
    TorrentDownload(const TorrentInfo& torrent_info, const std::string& download_path);
    ~TorrentDownload();
    
    // Control
    bool start();
    void stop();
    void pause();
    void resume();
    bool is_running() const { return running_; }
    bool is_paused() const { return paused_; }
    bool is_complete() const;
    
    // Peer management
    bool add_peer(const Peer& peer);
    bool add_peer(const Peer& peer, socket_t existing_socket);  // For incoming connections
    void remove_peer(const Peer& peer);
    size_t get_peer_count() const;
    std::vector<Peer> get_connected_peers() const;
    
    // Piece management
    bool is_piece_complete(PieceIndex piece_index) const;
    bool is_piece_downloading(PieceIndex piece_index) const;
    std::vector<PieceIndex> get_available_pieces() const;
    std::vector<PieceIndex> get_needed_pieces(const std::vector<bool>& peer_bitfield) const;
    
    // Piece data handling
    bool store_piece_block(PieceIndex piece_index, uint32_t offset, const std::vector<uint8_t>& data);
    bool verify_piece(PieceIndex piece_index);
    void write_piece_to_disk(PieceIndex piece_index);
    bool read_piece_from_disk(PieceIndex piece_index, std::vector<uint8_t>& data);  // For seeding
    void reset_block_request(PieceIndex piece_index, uint32_t block_index);  // Reset timed-out block request
    
    // Statistics and progress
    uint64_t get_downloaded_bytes() const;
    uint64_t get_uploaded_bytes() const;
    double get_progress_percentage() const;
    uint32_t get_completed_pieces() const;
    std::vector<bool> get_piece_bitfield() const;
    
    // Callbacks
    void set_progress_callback(ProgressCallback callback) { progress_callback_ = callback; }
    void set_piece_complete_callback(PieceCompleteCallback callback) { piece_complete_callback_ = callback; }
    void set_torrent_complete_callback(TorrentCompleteCallback callback) { torrent_complete_callback_ = callback; }
    void set_peer_connected_callback(PeerConnectedCallback callback) { peer_connected_callback_ = callback; }
    void set_peer_disconnected_callback(PeerDisconnectedCallback callback) { peer_disconnected_callback_ = callback; }
    void set_metadata_complete_callback(MetadataCompleteCallback callback) { metadata_complete_callback_ = callback; }
    
    // Torrent info access
    const TorrentInfo& get_torrent_info() const { return torrent_info_; }
    const std::string& get_download_path() const { return download_path_; }
    
    // DHT integration
    void announce_to_dht(DhtClient* dht_client);
    void request_peers_from_dht(DhtClient* dht_client);
    
    // Tracker integration
    void announce_to_trackers();
    void request_peers_from_trackers();
    TrackerManager* get_tracker_manager() const { return tracker_manager_.get(); }
    
    // Metadata download (BEP 9)
    MetadataDownload* get_metadata_download() const { return metadata_download_.get(); }
    void set_metadata_download(std::shared_ptr<MetadataDownload> metadata_download);
    
private:
    TorrentInfo torrent_info_;
    std::string download_path_;
    std::atomic<bool> running_;
    std::atomic<bool> paused_;
    
    // Piece management
    std::vector<std::unique_ptr<PieceInfo>> pieces_;
    std::vector<bool> piece_completed_;
    std::vector<bool> piece_downloading_;
    mutable std::mutex pieces_mutex_;
    
    // Peer connections
    std::vector<std::unique_ptr<PeerConnection>> peer_connections_;
    mutable std::mutex peers_mutex_;
    
    // Download management
    std::thread download_thread_;
    std::thread peer_management_thread_;
    
    // Conditional variables for immediate shutdown
    std::condition_variable shutdown_cv_;
    std::mutex shutdown_mutex_;
    
    // File handling (using fs module, no persistent handles needed)
    mutable std::mutex files_mutex_;
    
    // Callbacks
    ProgressCallback progress_callback_;
    PieceCompleteCallback piece_complete_callback_;
    TorrentCompleteCallback torrent_complete_callback_;
    PeerConnectedCallback peer_connected_callback_;
    PeerDisconnectedCallback peer_disconnected_callback_;
    MetadataCompleteCallback metadata_complete_callback_;
    
    // Statistics
    std::atomic<uint64_t> total_downloaded_;
    std::atomic<uint64_t> total_uploaded_;
    
    // Metadata download (BEP 9)
    std::shared_ptr<MetadataDownload> metadata_download_;
    
    // Tracker manager
    std::unique_ptr<TrackerManager> tracker_manager_;
    PeerID our_peer_id_;
    
    void download_loop();
    void peer_management_loop();
    void schedule_piece_requests();
    void cleanup_disconnected_peers();
    
    // Seeding support
    void notify_peers_have_piece(PieceIndex piece_index);  // Broadcast HAVE to all peers
    
    // File operations
    bool open_files();
    void close_files();
    bool create_directory_structure();
    
    // Piece selection strategy
    std::vector<PieceIndex> select_pieces_for_download();
    PieceIndex select_rarest_piece(const std::vector<bool>& available_pieces);
    
    // Progress tracking
    void update_progress();
    void on_piece_completed(PieceIndex piece_index);
    void check_torrent_completion();
};

// Main BitTorrent client
class BitTorrentClient {
public:
    BitTorrentClient();
    ~BitTorrentClient();
    
    // Client control
    bool start(int listen_port = 0);
    void stop();
    bool is_running() const { return running_; }
    
    // Torrent management
    std::shared_ptr<TorrentDownload> add_torrent(const std::string& torrent_file, const std::string& download_path);
    std::shared_ptr<TorrentDownload> add_torrent(const TorrentInfo& torrent_info, const std::string& download_path);
    std::shared_ptr<TorrentDownload> add_torrent_by_hash(const InfoHash& info_hash, const std::string& download_path);
    std::shared_ptr<TorrentDownload> add_torrent_by_hash(const std::string& info_hash_hex, const std::string& download_path);
    bool remove_torrent(const InfoHash& info_hash);
    std::shared_ptr<TorrentDownload> get_torrent(const InfoHash& info_hash);
    std::vector<std::shared_ptr<TorrentDownload>> get_all_torrents();
    
    // DHT integration
    void set_dht_client(DhtClient* dht_client) { dht_client_ = dht_client; }
    DhtClient* get_dht_client() const { return dht_client_; }
    
    // Peer discovery from DHT
    void discover_peers_for_torrent(const InfoHash& info_hash);
    void announce_torrent_to_dht(const InfoHash& info_hash);
    
    // Statistics
    size_t get_active_torrents_count() const;
    uint64_t get_total_downloaded() const;
    uint64_t get_total_uploaded() const;
    
    // Configuration
    void set_max_connections_per_torrent(size_t max_connections) { max_connections_per_torrent_ = max_connections; }
    void set_download_rate_limit(uint64_t bytes_per_second) { download_rate_limit_ = bytes_per_second; }
    void set_upload_rate_limit(uint64_t bytes_per_second) { upload_rate_limit_ = bytes_per_second; }
    
    // Callbacks for torrent events
    void set_torrent_added_callback(std::function<void(const InfoHash&)> callback) { torrent_added_callback_ = callback; }
    void set_torrent_completed_callback(std::function<void(const InfoHash&)> callback) { torrent_completed_callback_ = callback; }
    void set_torrent_removed_callback(std::function<void(const InfoHash&)> callback) { torrent_removed_callback_ = callback; }
    
    // Metadata download management (BEP 9)
    std::shared_ptr<MetadataDownload> get_metadata_download(const InfoHash& info_hash);
    void register_metadata_download(const InfoHash& info_hash, std::shared_ptr<MetadataDownload> metadata_download);
    void complete_metadata_download(const InfoHash& info_hash, const TorrentInfo& torrent_info, const std::string& download_path);
    
    // Get torrent metadata without downloading (BEP 9)
    using MetadataRetrievalCallback = std::function<void(const TorrentInfo& torrent_info, bool success, const std::string& error_message)>;
    void get_torrent_metadata_by_hash(const InfoHash& info_hash, MetadataRetrievalCallback callback);
    void get_torrent_metadata_by_hash(const std::string& info_hash_hex, MetadataRetrievalCallback callback);
    
private:
    std::atomic<bool> running_;
    int listen_port_;
    socket_t listen_socket_;
    
    // Torrents
    std::map<InfoHash, std::shared_ptr<TorrentDownload>> torrents_;
    mutable std::mutex torrents_mutex_;
    
    // Metadata downloads (BEP 9)
    std::map<InfoHash, std::shared_ptr<MetadataDownload>> metadata_downloads_;
    std::map<InfoHash, std::string> metadata_download_paths_;  // Store download path for later
    std::map<InfoHash, std::shared_ptr<TorrentDownload>> metadata_only_torrents_;  // Temporary torrents for metadata retrieval
    std::map<InfoHash, MetadataRetrievalCallback> metadata_retrieval_callbacks_;  // Callbacks for metadata retrieval
    mutable std::mutex metadata_mutex_;
    
    // DHT integration
    DhtClient* dht_client_;
    
    // Networking
    std::thread incoming_connections_thread_;
    
    // Conditional variables for immediate shutdown
    std::condition_variable shutdown_cv_;
    std::mutex shutdown_mutex_;
    
    // Configuration
    size_t max_connections_per_torrent_;
    uint64_t download_rate_limit_;
    uint64_t upload_rate_limit_;
    
    // Callbacks
    std::function<void(const InfoHash&)> torrent_added_callback_;
    std::function<void(const InfoHash&)> torrent_completed_callback_;
    std::function<void(const InfoHash&)> torrent_removed_callback_;
    
    void handle_incoming_connections();
    void handle_incoming_connection(socket_t client_socket);
    bool perform_incoming_handshake(socket_t socket, InfoHash& info_hash, PeerID& peer_id);
};

// Utility functions
InfoHash calculate_info_hash(const BencodeValue& info_dict);
std::string info_hash_to_hex(const InfoHash& hash);
InfoHash hex_to_info_hash(const std::string& hex);
PeerID generate_peer_id();
std::vector<uint8_t> create_handshake_message(const InfoHash& info_hash, const PeerID& peer_id);
bool parse_handshake_message(const std::vector<uint8_t>& data, InfoHash& info_hash, PeerID& peer_id);

} // namespace librats 