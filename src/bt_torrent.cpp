#include "bt_torrent.h"
#include "bt_extension.h"
#include "bencode.h"
#include "disk_io.h"
#include "logger.h"
#include <algorithm>
#include <cctype>
#include <cstring>

namespace librats {

//=============================================================================
// Helpers
//=============================================================================

const char* torrent_state_to_string(TorrentState state) {
    switch (state) {
        case TorrentState::Stopped: return "Stopped";
        case TorrentState::CheckingFiles: return "CheckingFiles";
        case TorrentState::DownloadingMetadata: return "DownloadingMetadata";
        case TorrentState::Downloading: return "Downloading";
        case TorrentState::Seeding: return "Seeding";
        case TorrentState::Paused: return "Paused";
        case TorrentState::Error: return "Error";
        default: return "Unknown";
    }
}

//=============================================================================
// Constructor / Destructor
//=============================================================================

Torrent::Torrent(const TorrentInfo& info,
                 const TorrentConfig& config,
                 const PeerID& our_peer_id)
    : info_hash_(info.info_hash())
    , name_(info.name())
    , our_peer_id_(our_peer_id)
    , info_(std::make_unique<TorrentInfo>(info))
    , config_(config)
    , state_(TorrentState::Stopped)
    , have_pieces_(info.num_pieces()) {
    
    LOG_INFO("Torrent", "Creating torrent '" + name_ + "' with " + 
             std::to_string(info.num_pieces()) + " pieces, total size=" + 
             std::to_string(info.total_size()) + " bytes");
    
    // Initialize piece picker
    uint32_t last_piece_len = info.piece_size(info.num_pieces() - 1);
    picker_ = std::make_unique<PiecePicker>(
        info.num_pieces(), 
        info.piece_length(),
        last_piece_len
    );
    
    if (config_.sequential_download) {
        picker_->set_mode(PickerMode::Sequential);
        LOG_DEBUG("Torrent", "Sequential download mode enabled");
    }
    
    // Configure choker
    ChokerConfig choker_config;
    choker_config.max_uploads = config_.max_uploads;
    choker_.set_config(choker_config);
    
    stats_.total_size = info.total_size();
    stats_.pieces_total = info.num_pieces();
    
    LOG_DEBUG("Torrent", "Torrent '" + name_ + "' initialized successfully");
}

Torrent::Torrent(const BtInfoHash& info_hash,
                 const std::string& name,
                 const TorrentConfig& config,
                 const PeerID& our_peer_id)
    : info_hash_(info_hash)
    , name_(name)
    , our_peer_id_(our_peer_id)
    , config_(config)
    , state_(TorrentState::Stopped)
    , have_pieces_(0) {
    
    LOG_INFO("Torrent", "Creating torrent '" + name + "' from magnet link (no metadata yet), info_hash=" + 
             info_hash_to_hex(info_hash).substr(0, 16) + "...");
    
    // No picker until we have metadata
    
    ChokerConfig choker_config;
    choker_config.max_uploads = config_.max_uploads;
    choker_.set_config(choker_config);
    
    LOG_DEBUG("Torrent", "Torrent '" + name + "' initialized (awaiting metadata)");
}

Torrent::~Torrent() {
    LOG_DEBUG("Torrent", "Destroying torrent '" + name_ + "'");
    stop();
}

//=============================================================================
// Lifecycle
//=============================================================================

void Torrent::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    LOG_INFO("Torrent", "Starting torrent '" + name_ + "'");
    
    if (state_ == TorrentState::Downloading || 
        state_ == TorrentState::Seeding) {
        LOG_DEBUG("Torrent", "Torrent '" + name_ + "' already active, ignoring start()");
        return;
    }
    
    stats_.started_at = std::chrono::steady_clock::now();
    last_stats_update_ = std::chrono::steady_clock::now();
    last_choker_run_ = std::chrono::steady_clock::now();
    
    if (!info_ || !info_->has_metadata()) {
        // No metadata yet - need to download it from peers
        LOG_INFO("Torrent", "No metadata available, starting metadata download for '" + name_ + "'");
        metadata_download_started_ = std::chrono::steady_clock::now();
        set_state(TorrentState::DownloadingMetadata);
    } else if (config_.seed_mode || is_complete_unlocked()) {
        LOG_INFO("Torrent", "Torrent '" + name_ + "' is complete, entering seeding mode");
        set_state(TorrentState::Seeding);
        choker_.set_seed_mode(true);
    } else {
        LOG_INFO("Torrent", "Starting download for '" + name_ + "'");
        set_state(TorrentState::Downloading);
    }
}

void Torrent::stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    LOG_INFO("Torrent", "Stopping torrent '" + name_ + "'");
    
    // Disconnect all peers
    size_t num_connections = connections_.size();
    for (auto& conn : connections_) {
        conn->close();
    }
    connections_.clear();
    LOG_DEBUG("Torrent", "Disconnected " + std::to_string(num_connections) + " peers");
    
    // Clear pending peers
    size_t num_pending = pending_peers_.size();
    pending_peers_.clear();
    LOG_DEBUG("Torrent", "Cleared " + std::to_string(num_pending) + " pending peers");
    
    // Clear metadata exchange state
    metadata_buffer_.clear();
    metadata_pieces_received_.clear();
    peer_metadata_size_.clear();
    peer_ut_metadata_id_.clear();
    
    set_state(TorrentState::Stopped);
    
    // Clear callbacks to prevent dangling pointer issues after stop
    // Note: Keeping on_state_change_ until after set_state() call above
    on_state_change_ = nullptr;
    on_piece_complete_ = nullptr;
    on_complete_ = nullptr;
    on_error_ = nullptr;
    on_metadata_received_ = nullptr;
    
    LOG_INFO("Torrent", "Torrent '" + name_ + "' stopped");
}

void Torrent::pause() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (state_ == TorrentState::Downloading ||
        state_ == TorrentState::Seeding) {
        LOG_INFO("Torrent", "Pausing torrent '" + name_ + "' (was " + 
                 torrent_state_to_string(state_) + ")");
        set_state(TorrentState::Paused);
    } else {
        LOG_DEBUG("Torrent", "Cannot pause torrent '" + name_ + "' in state " + 
                  torrent_state_to_string(state_));
    }
}

void Torrent::resume() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (state_ == TorrentState::Paused) {
        if (is_complete_unlocked()) {
            LOG_INFO("Torrent", "Resuming torrent '" + name_ + "' in seeding mode");
            set_state(TorrentState::Seeding);
        } else {
            LOG_INFO("Torrent", "Resuming torrent '" + name_ + "' in downloading mode");
            set_state(TorrentState::Downloading);
        }
    } else {
        LOG_DEBUG("Torrent", "Cannot resume torrent '" + name_ + "' in state " + 
                  torrent_state_to_string(state_));
    }
}

void Torrent::recheck() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    LOG_INFO("Torrent", "Starting recheck for torrent '" + name_ + "'");
    
    // Would trigger file checking
    set_state(TorrentState::CheckingFiles);
    
    // Reset have bitfield
    if (info_) {
        have_pieces_ = Bitfield(info_->num_pieces());
        picker_->set_have_bitfield(have_pieces_);
        LOG_DEBUG("Torrent", "Reset bitfield for " + std::to_string(info_->num_pieces()) + " pieces");
    }
    
    // TODO: Actually verify files
    LOG_WARN("Torrent", "File verification not yet implemented");
}

//=============================================================================
// State
//=============================================================================

bool Torrent::is_active() const {
    TorrentState s = state_;
    return s == TorrentState::Downloading || 
           s == TorrentState::Seeding ||
           s == TorrentState::DownloadingMetadata;
}

bool Torrent::is_complete() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return is_complete_unlocked();
}

bool Torrent::is_complete_unlocked() const {
    return picker_ && picker_->is_complete();
}

bool Torrent::has_metadata() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return has_metadata_unlocked();
}

bool Torrent::has_metadata_unlocked() const {
    return info_ != nullptr && info_->has_metadata();
}

void Torrent::set_state(TorrentState new_state) {
    TorrentState old_state = state_.exchange(new_state);
    if (old_state != new_state) {
        LOG_DEBUG("Torrent", "State change: " + std::string(torrent_state_to_string(old_state)) + 
                  " -> " + std::string(torrent_state_to_string(new_state)) + 
                  " for '" + name_ + "'");
        if (on_state_change_) {
            on_state_change_(this, new_state);
        }
    }
}

//=============================================================================
// Statistics
//=============================================================================

TorrentStats Torrent::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

Bitfield Torrent::get_have_bitfield() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (picker_) {
        return picker_->get_have_bitfield();
    }
    return have_pieces_;
}

//=============================================================================
// Peer Management
//=============================================================================

void Torrent::add_peer(const std::string& ip, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if already connected
    for (const auto& conn : connections_) {
        if (conn->ip() == ip && conn->port() == port) {
            LOG_DEBUG("Torrent", "Peer " + ip + ":" + std::to_string(port) + " already connected");
            return;
        }
    }
    
    // Check if already pending
    for (const auto& peer : pending_peers_) {
        if (peer.first == ip && peer.second == port) {
            LOG_DEBUG("Torrent", "Peer " + ip + ":" + std::to_string(port) + " already pending");
            return;
        }
    }
    
    pending_peers_.emplace_back(ip, port);
    LOG_DEBUG("Torrent", "Added pending peer " + ip + ":" + std::to_string(port) + 
              " (total pending=" + std::to_string(pending_peers_.size()) + ")");
}

void Torrent::add_peers(const std::vector<std::pair<std::string, uint16_t>>& peers) {
    for (const auto& peer : peers) {
        add_peer(peer.first, peer.second);
    }
}

size_t Torrent::num_peers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connections_.size();
}

std::vector<BtPeerConnection*> Torrent::peers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<BtPeerConnection*> result;
    result.reserve(connections_.size());
    for (const auto& conn : connections_) {
        result.push_back(conn.get());
    }
    return result;
}

std::vector<std::pair<std::string, uint16_t>> Torrent::get_pending_peers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_peers_;
}

void Torrent::clear_pending_peers() {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_peers_.clear();
}

void Torrent::add_connection(std::shared_ptr<BtPeerConnection> connection) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!connection) return;
    
    LOG_DEBUG("Torrent", "Adding connection from " + connection->ip() + ":" + 
              std::to_string(connection->port()));
    
    // Remove from pending if present
    auto it = std::remove_if(pending_peers_.begin(), pending_peers_.end(),
        [&](const auto& p) {
            return p.first == connection->ip() && p.second == connection->port();
        });
    pending_peers_.erase(it, pending_peers_.end());
    
    // Setup callbacks
    BtPeerConnection* conn_ptr = connection.get();
    
    connection->set_message_callback(
        [this](BtPeerConnection* peer, const BtMessage& msg) {
            on_peer_message(peer, msg);
        }
    );
    
    connection->set_state_callback(
        [this](BtPeerConnection* peer, PeerConnectionState state) {
            if (state == PeerConnectionState::Disconnected ||
                state == PeerConnectionState::Closing) {
                on_peer_disconnected(peer);
            } else if (state == PeerConnectionState::Connected) {
                on_peer_connected(peer);
            }
        }
    );
    
    // Add to picker for availability tracking
    if (picker_ && connection->is_connected()) {
        picker_->add_peer(conn_ptr, connection->peer_pieces());
    }
    
    connections_.push_back(connection);  // shared_ptr - just copy
    
    // Notify peer we're connected and setup extension handshake
    on_peer_connected(conn_ptr);
}

void Torrent::remove_connection(BtPeerConnection* connection) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = std::find_if(connections_.begin(), connections_.end(),
        [connection](const auto& conn) {
            return conn.get() == connection;
        });
    
    if (it != connections_.end()) {
        LOG_DEBUG("Torrent", "Removing connection from " + connection->ip() + ":" + 
                  std::to_string(connection->port()));
        on_peer_disconnected(connection);
        connections_.erase(it);
        LOG_DEBUG("Torrent", "Active connections: " + std::to_string(connections_.size()));
    } else {
        LOG_DEBUG("Torrent", "Connection not found for removal: " + connection->ip());
    }
}

//=============================================================================
// Configuration
//=============================================================================

void Torrent::set_sequential(bool sequential) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.sequential_download = sequential;
    LOG_INFO("Torrent", "Sequential download " + std::string(sequential ? "enabled" : "disabled") + 
             " for '" + name_ + "'");
    if (picker_) {
        picker_->set_mode(sequential ? PickerMode::Sequential : PickerMode::RarestFirst);
    }
}

void Torrent::set_download_limit(uint64_t bytes_per_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.download_limit = bytes_per_sec;
    LOG_INFO("Torrent", "Download limit set to " + std::to_string(bytes_per_sec) + 
             " bytes/sec for '" + name_ + "'");
}

void Torrent::set_upload_limit(uint64_t bytes_per_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.upload_limit = bytes_per_sec;
    LOG_INFO("Torrent", "Upload limit set to " + std::to_string(bytes_per_sec) + 
             " bytes/sec for '" + name_ + "'");
}

//=============================================================================
// Metadata
//=============================================================================

bool Torrent::set_metadata(const std::vector<uint8_t>& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    LOG_INFO("Torrent", "Setting metadata (" + std::to_string(metadata.size()) + " bytes)");
    
    auto new_info = TorrentInfo::from_info_dict(metadata, info_hash_);
    if (!new_info) {
        LOG_ERROR("Torrent", "Failed to parse metadata - info_hash mismatch or invalid data");
        return false;
    }
    
    info_ = std::make_unique<TorrentInfo>(*new_info);
    name_ = info_->name();
    LOG_INFO("Torrent", "Metadata parsed successfully: name='" + name_ + "'");
    
    // Initialize pieces
    have_pieces_ = Bitfield(info_->num_pieces());
    
    uint32_t last_piece_len = info_->piece_size(info_->num_pieces() - 1);
    picker_ = std::make_unique<PiecePicker>(
        info_->num_pieces(),
        info_->piece_length(),
        last_piece_len
    );
    
    if (config_.sequential_download) {
        picker_->set_mode(PickerMode::Sequential);
    }
    
    stats_.total_size = info_->total_size();
    stats_.pieces_total = info_->num_pieces();
    
    LOG_DEBUG("Torrent", "Torrent stats: " + std::to_string(info_->num_pieces()) + " pieces, " +
              std::to_string(info_->total_size()) + " bytes total");
    
    // CRITICAL: Initialize existing peer connections with the new metadata
    // This is necessary because peers connected during DownloadingMetadata state
    // were not added to the picker (it didn't exist yet).
    // Following standard pattern: torrent::init() -> peer_connection::init()
    
    // In metadata-only mode (empty save_path), we skip sending INTERESTED and bitfield
    // because we're not going to download anything - just needed the metadata
    const bool metadata_only = config_.save_path.empty();
    
    LOG_DEBUG("Torrent", "Initializing " + std::to_string(connections_.size()) + 
              " existing connections with metadata" + 
              (metadata_only ? " (metadata-only mode)" : ""));
    
    for (auto& conn : connections_) {
        if (!conn->is_connected()) continue;
        
        // Update peer's bitfield size to match the torrent
        // This is needed because peer may have sent Bitfield/HaveAll before we had metadata
        conn->set_torrent_info(info_hash_, info_->num_pieces());
        
        // Skip download-related initialization in metadata-only mode
        if (metadata_only) {
            continue;
        }
        
        // Get peer's pieces (now correctly sized)
        const auto& peer_pieces = conn->peer_pieces();
        
        // Add peer to picker for availability tracking
        picker_->add_peer(conn.get(), peer_pieces);
        
        // Check if this peer has pieces we need (either via bitfield or peer_has_all flag)
        bool is_interesting = false;
        if (conn->peer_has_all()) {
            // Peer has everything, we have nothing - definitely interesting!
            is_interesting = true;
            LOG_DEBUG("Torrent", "Peer " + conn->ip() + " has all pieces (HaveAll)");
        } else if (picker_->is_interesting(peer_pieces)) {
            is_interesting = true;
        }
        
        if (is_interesting) {
            // Send INTERESTED to peer so they will (hopefully) unchoke us
            if (!conn->am_interested()) {
                LOG_DEBUG("Torrent", "Peer " + conn->ip() + " has pieces we need, sending interested");
                conn->send_interested();
            }
        }
        
        // Send our bitfield to the peer (we have no pieces yet, but protocol requires it)
        conn->send_bitfield(have_pieces_);
    }
    
    set_state(TorrentState::Downloading);
    
    return true;
}

//=============================================================================
// Tick
//=============================================================================

void Torrent::tick() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!is_active()) {
        return;
    }
    
    auto now = std::chrono::steady_clock::now();
    
    // Check metadata download timeout
    if (state_ == TorrentState::DownloadingMetadata) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - metadata_download_started_).count();
        
        if (elapsed >= METADATA_TIMEOUT_SECONDS) {
            LOG_WARN("Torrent", "Metadata download timeout for " + 
                     info_hash_to_hex(info_hash_).substr(0, 8) + "...");
            
            // Notify callback of failure
            if (on_metadata_received_) {
                on_metadata_received_(this, false);
            }
            
            // Clear metadata state
            metadata_buffer_.clear();
            metadata_pieces_received_.clear();
            peer_metadata_size_.clear();
            peer_ut_metadata_id_.clear();
            
            // Set error state
            error_message_ = "Metadata download timeout";
            set_state(TorrentState::Error);
            
            return;
        }
    }
    
    // Run choker periodically
    if (choker_.should_rechoke()) {
        run_choker();
        last_choker_run_ = now;
    }
    
    // Request pieces from peers
    request_pieces();
    
    // Update statistics
    auto stats_interval = std::chrono::seconds(1);
    if ((now - last_stats_update_) >= stats_interval) {
        update_stats();
        last_stats_update_ = now;
    }
    
    // TODO: Connect to pending peers
    // TODO: Announce to trackers
    // TODO: DHT announces
}

//=============================================================================
// Internal Methods
//=============================================================================

void Torrent::on_peer_connected(BtPeerConnection* peer) {
    LOG_DEBUG("Torrent", "Peer " + peer->ip() + " connected, has_metadata=" + 
              (has_metadata_unlocked() ? "true" : "false"));
    
    // Send extension handshake if peer supports it
    if (peer->peer_extensions().extension_protocol) {
        send_extension_handshake(peer);
    }
    
    // Send bitfield if we have pieces
    if (picker_ && picker_->num_have() > 0) {
        peer->send_bitfield(picker_->get_have_bitfield());
    }
    
    // Check if peer already received extension handshake before we set up callbacks
    // This happens because network data arrives before Torrent takes ownership
    if (state_ == TorrentState::DownloadingMetadata && 
        peer->extension_handshake_received() && 
        peer->peer_metadata_size() > 0 && 
        peer->peer_ut_metadata_id() != 0) {
        
        LOG_DEBUG("Torrent", "Peer " + peer->ip() + 
                  " already has extension handshake data: metadata_size=" + 
                  std::to_string(peer->peer_metadata_size()) + 
                  " ut_metadata_id=" + std::to_string(peer->peer_ut_metadata_id()));
        
        // Store peer's metadata info and request metadata
        peer_metadata_size_[peer] = peer->peer_metadata_size();
        peer_ut_metadata_id_[peer] = peer->peer_ut_metadata_id();
        request_metadata(peer);
    }
}

void Torrent::on_peer_disconnected(BtPeerConnection* peer) {
    LOG_DEBUG("Torrent", "Peer " + peer->ip() + " disconnected");
    
    // Cancel pending requests
    if (picker_) {
        picker_->cancel_peer_requests(peer);
        LOG_DEBUG("Torrent", "Cancelled pending requests for peer " + peer->ip());
    }
    
    // Remove from availability
    if (picker_) {
        picker_->remove_peer(peer);
    }
    
    // Clear metadata tracking for this peer
    peer_metadata_size_.erase(peer);
    peer_ut_metadata_id_.erase(peer);
}

void Torrent::on_peer_message(BtPeerConnection* peer, const BtMessage& msg) {
    // Log all message types for debugging
    switch (msg.type) {
        case BtMessageType::Bitfield:
            if (msg.bitfield) {
                LOG_DEBUG("Torrent", "on_peer_message: Bitfield from " + peer->ip() + 
                          ", bits_set=" + std::to_string(msg.bitfield->count()));
            }
            if (msg.bitfield && picker_) {
                picker_->add_peer(peer, *msg.bitfield);
                
                // Check if interesting
                if (picker_->is_interesting(*msg.bitfield)) {
                    peer->send_interested();
                }
            }
            break;
            
        case BtMessageType::Have:
            LOG_DEBUG("Torrent", "on_peer_message: Have piece=" + std::to_string(msg.have_piece) + 
                      " from " + peer->ip());
            if (picker_) {
                picker_->peer_has_piece(peer, msg.have_piece);
            }
            break;
            
        case BtMessageType::Piece:
            if (msg.piece) {
                LOG_DEBUG("Torrent", "on_peer_message: Piece idx=" + std::to_string(msg.piece->piece_index) + 
                          " begin=" + std::to_string(msg.piece->begin) + 
                          " len=" + std::to_string(msg.piece->data.size()) + " from " + peer->ip());
                on_piece_received(msg.piece->piece_index, msg.piece->begin, msg.piece->data);
            }
            break;
            
        case BtMessageType::Request:
            // Peer is requesting a block from us
            if (msg.request) {
                LOG_DEBUG("Torrent", "on_peer_message: Request piece=" + std::to_string(msg.request->piece_index) + 
                          " begin=" + std::to_string(msg.request->begin) + 
                          " len=" + std::to_string(msg.request->length) + " from " + peer->ip());
            }
            if (msg.request && !peer->am_choking() && have_pieces_.get_bit(msg.request->piece_index)) {
                // Read from disk and send piece data to peer
                read_piece_from_disk(msg.request->piece_index, peer, 
                                    msg.request->begin, msg.request->length);
            }
            break;
            
        case BtMessageType::Unchoke:
            // Peer unchoked us - can start requesting
            LOG_DEBUG("Torrent", "on_peer_message: Unchoke from " + peer->ip());
            break;
            
        case BtMessageType::Choke:
            // Peer choked us - stop requesting
            LOG_DEBUG("Torrent", "on_peer_message: Choke from " + peer->ip());
            if (picker_) {
                picker_->cancel_peer_requests(peer);
            }
            break;
            
        case BtMessageType::Interested:
            LOG_DEBUG("Torrent", "on_peer_message: Interested from " + peer->ip());
            break;
            
        case BtMessageType::NotInterested:
            LOG_DEBUG("Torrent", "on_peer_message: NotInterested from " + peer->ip());
            break;
            
        case BtMessageType::Extended:
            LOG_DEBUG("Torrent", "on_peer_message: Extended ext_id=" + std::to_string(msg.extension_id) + 
                      " payload=" + std::to_string(msg.extension_payload.size()) + " bytes from " + peer->ip());
            // Handle extension protocol messages
            on_extension_message(peer, msg.extension_id, msg.extension_payload);
            break;
            
        default:
            LOG_DEBUG("Torrent", "on_peer_message: Unknown type from " + peer->ip());
            break;
    }
}

void Torrent::on_piece_received(uint32_t piece, uint32_t begin, 
                                const std::vector<uint8_t>& data) {
    if (!picker_ || !info_) {
        LOG_WARN("Torrent", "Received piece data but picker/info not initialized");
        return;
    }
    
    LOG_DEBUG("Torrent", "Block received: piece=" + std::to_string(piece) + 
              " offset=" + std::to_string(begin) + " len=" + std::to_string(data.size()));
    
    BlockInfo block(piece, begin, static_cast<uint32_t>(data.size()));
    
    // Buffer the block
    auto& buffer = piece_buffers_[piece];
    if (buffer.empty()) {
        buffer.resize(info_->piece_size(piece));
    }
    
    if (begin + data.size() <= buffer.size()) {
        std::copy(data.begin(), data.end(), buffer.begin() + begin);
    }
    
    // Mark block as finished
    bool piece_complete = picker_->mark_finished(block);
    
    if (piece_complete) {
        LOG_INFO("Torrent", "Piece " + std::to_string(piece) + " complete, writing to disk and verifying");
        
        // Write piece to disk first, then verify hash
        auto& buffer = piece_buffers_[piece];
        write_piece_to_disk(piece, buffer);
        
        // Verify hash asynchronously (callback will call on_piece_verified)
        verify_piece_hash(piece);
    }
}

void Torrent::on_piece_verified(uint32_t piece, bool valid) {
    if (!picker_) return;
    
    if (valid) {
        LOG_INFO("Torrent", "Piece " + std::to_string(piece) + " verified successfully (" +
                 std::to_string(picker_->num_have() + 1) + "/" + 
                 std::to_string(stats_.pieces_total) + ")");
        
        picker_->mark_have(piece);
        have_pieces_.set_bit(piece);
        
        // Piece already written to disk before verification
        // Clear buffer
        piece_buffers_.erase(piece);
        
        // Notify
        if (on_piece_complete_) {
            on_piece_complete_(this, piece);
        }
        
        // Broadcast HAVE to peers
        for (auto& conn : connections_) {
            conn->send_have(piece);
        }
        
        // Check if complete
        if (picker_->is_complete()) {
            LOG_INFO("Torrent", "Download complete for '" + name_ + "'!");
            set_state(TorrentState::Seeding);
            choker_.set_seed_mode(true);
            
            if (on_complete_) {
                on_complete_(this);
            }
        }
        
        ++stats_.pieces_done;
    } else {
        LOG_WARN("Torrent", "Piece " + std::to_string(piece) + " hash verification FAILED, will re-download");
        // Hash check failed - re-download
        // TODO: Reset piece state
    }
}

void Torrent::request_pieces() {
    if (!picker_) return;
    
    for (auto& conn : connections_) {
        if (!conn->is_connected()) continue;
        if (conn->peer_choking()) continue;
        
        while (conn->can_request()) {
            auto blocks = picker_->pick_pieces(conn->peer_pieces(), 1, conn.get());
            if (blocks.empty()) break;
            
            const auto& block = blocks[0].block;
            conn->send_request(block.piece_index, block.offset, block.length);
        }
    }
}

void Torrent::run_choker() {
    std::vector<ChokePeerInfo> peer_infos;
    peer_infos.reserve(connections_.size());
    
    for (auto& conn : connections_) {
        if (!conn->is_connected()) continue;
        
        ChokePeerInfo info;
        info.connection = conn.get();
        info.download_rate = conn->stats().download_rate();
        info.upload_rate = conn->stats().upload_rate();
        info.am_choking = conn->am_choking();
        info.am_interested = conn->am_interested();
        info.peer_interested = conn->peer_interested();
        info.connected_at = conn->stats().connected_at;
        
        peer_infos.push_back(info);
    }
    
    auto result = choker_.run(peer_infos);
    
    if (!result.to_choke.empty() || !result.to_unchoke.empty()) {
        LOG_DEBUG("Torrent", "Choker: choking " + std::to_string(result.to_choke.size()) + 
                  " peers, unchoking " + std::to_string(result.to_unchoke.size()) + " peers");
    }
    
    for (auto* peer : result.to_choke) {
        LOG_DEBUG("Torrent", "Choking peer " + peer->ip());
        peer->send_choke();
    }
    
    for (auto* peer : result.to_unchoke) {
        LOG_DEBUG("Torrent", "Unchoking peer " + peer->ip());
        peer->send_unchoke();
    }
}

void Torrent::update_stats() {
    if (picker_) {
        stats_.pieces_done = picker_->num_have();
        stats_.progress = static_cast<float>(stats_.pieces_done) / 
                          static_cast<float>(stats_.pieces_total);
        
        // Calculate bytes done
        if (info_) {
            uint64_t bytes = 0;
            for (uint32_t i = 0; i < stats_.pieces_done; ++i) {
                bytes += info_->piece_size(i);
            }
            stats_.bytes_done = bytes;
        }
    }
    
    stats_.peers_connected = static_cast<uint32_t>(connections_.size());
    stats_.peers_total = static_cast<uint32_t>(
        connections_.size() + pending_peers_.size());
    
    // Count seeders/leechers
    stats_.seeders = 0;
    stats_.leechers = 0;
    for (const auto& conn : connections_) {
        if (conn->peer_pieces().all_set()) {
            ++stats_.seeders;
        } else {
            ++stats_.leechers;
        }
    }
    
    // Calculate rates
    uint64_t total_dl = 0, total_ul = 0;
    for (const auto& conn : connections_) {
        total_dl += static_cast<uint64_t>(conn->stats().download_rate());
        total_ul += static_cast<uint64_t>(conn->stats().upload_rate());
    }
    stats_.download_rate = total_dl;
    stats_.upload_rate = total_ul;
    
    // Calculate ETA
    if (stats_.download_rate > 0 && stats_.bytes_done < stats_.total_size) {
        uint64_t remaining = stats_.total_size - stats_.bytes_done;
        stats_.eta = std::chrono::seconds(remaining / stats_.download_rate);
    }
}

//=============================================================================
// Disk I/O Helpers
//=============================================================================

std::vector<FileMappingInfo> Torrent::get_file_mappings() const {
    std::vector<FileMappingInfo> mappings;
    
    if (!info_) return mappings;
    
    const auto& files = info_->files().files();
    mappings.reserve(files.size());
    
    for (const auto& file : files) {
        FileMappingInfo mapping;
        mapping.path = file.path;
        mapping.length = static_cast<uint64_t>(file.size);
        mapping.torrent_offset = static_cast<uint64_t>(file.offset);
        mappings.push_back(mapping);
    }
    
    return mappings;
}

void Torrent::write_piece_to_disk(uint32_t piece, const std::vector<uint8_t>& data) {
    if (!info_) return;
    
    LOG_DEBUG("Torrent", "Writing piece " + std::to_string(piece) + " to disk (" + 
              std::to_string(data.size()) + " bytes)");
    
    auto mappings = get_file_mappings();
    auto weak_self = weak_from_this();
    
    DiskIO::instance().async_write_block(
        config_.save_path,
        mappings,
        piece,
        info_->piece_length(),
        0,  // write entire piece from offset 0
        data,
        [weak_self, piece](bool success) {
            auto self = weak_self.lock();
            if (!self) return;
            
            if (!success) {
                // Handle write error
                if (self->on_error_) {
                    self->on_error_(self.get(), "Failed to write piece " + std::to_string(piece));
                }
            }
        }
    );
}

void Torrent::read_piece_from_disk(uint32_t piece, BtPeerConnection* peer,
                                    uint32_t begin, uint32_t length) {
    if (!info_) return;
    
    LOG_DEBUG("Torrent", "Reading piece " + std::to_string(piece) + " from disk for peer " + 
              peer->ip() + " (offset=" + std::to_string(begin) + ", len=" + std::to_string(length) + ")");
    
    auto mappings = get_file_mappings();
    auto weak_self = weak_from_this();
    uint32_t actual_length = info_->piece_size(piece);
    
    DiskIO::instance().async_read_piece(
        config_.save_path,
        mappings,
        piece,
        info_->piece_length(),
        actual_length,
        [weak_self, peer, piece, begin, length](bool success, const std::vector<uint8_t>& data) {
            auto self = weak_self.lock();
            if (!self) return;
            
            if (success && data.size() >= begin + length) {
                // Send the requested block to peer
                peer->send_piece(piece, begin, data.data() + begin, length);
            }
        }
    );
}

void Torrent::verify_piece_hash(uint32_t piece) {
    if (!info_) return;
    
    LOG_DEBUG("Torrent", "Verifying hash for piece " + std::to_string(piece));
    
    auto mappings = get_file_mappings();
    auto weak_self = weak_from_this();
    uint32_t actual_length = info_->piece_size(piece);
    
    DiskIO::instance().async_hash_piece(
        config_.save_path,
        mappings,
        piece,
        info_->piece_length(),
        actual_length,
        [weak_self, piece](bool success, const std::string& calculated_hash) {
            auto self = weak_self.lock();
            if (!self) return;
            
            if (!success) {
                self->on_piece_verified(piece, false);
                return;
            }
            
            // Compare with expected hash
            auto expected_hash = self->info_->piece_hash(piece);
            std::string expected_hex;
            for (uint8_t b : expected_hash) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", b);
                expected_hex += hex;
            }
            
            bool valid = (calculated_hash == expected_hex);
            self->on_piece_verified(piece, valid);
        }
    );
}

//=============================================================================
// Extension Protocol Methods
//=============================================================================

void Torrent::send_extension_handshake(BtPeerConnection* peer) {
    // Create extension handshake
    BencodeValue handshake = BencodeValue::create_dict();
    
    // Build 'm' dictionary with extension name -> message ID
    BencodeValue m = BencodeValue::create_dict();
    m["ut_metadata"] = BencodeValue(static_cast<int64_t>(BT_EXT_UT_METADATA_ID));
    m["ut_pex"] = BencodeValue(static_cast<int64_t>(BT_EXT_UT_PEX_ID));
    handshake["m"] = m;
    
    // Add metadata_size if we have metadata
    if (info_ && info_->has_metadata()) {
        // We'd need the raw info dict size here
        // For now, skip this - we're mainly interested in receiving metadata
    }
    
    // Add client ID
    handshake["v"] = BencodeValue("librats/1.0");
    
    // Encode and send as extended message ID 0 (handshake)
    auto payload = handshake.encode();
    peer->send_extended(0, payload);
    
    LOG_DEBUG("Torrent", "Sent extension handshake to " + peer->ip());
}

void Torrent::on_extension_message(BtPeerConnection* peer, uint8_t ext_id, 
                                    const std::vector<uint8_t>& payload) {
    LOG_DEBUG("Torrent", "on_extension_message: ext_id=" + std::to_string(ext_id) + 
              " payload=" + std::to_string(payload.size()) + " bytes from " + peer->ip() +
              " (state=" + std::string(torrent_state_to_string(state_)) + ")");
    
    if (ext_id == 0) {
        // Extension handshake
        LOG_DEBUG("Torrent", "Processing extension handshake from " + peer->ip());
        on_extension_handshake(peer, payload);
    } else if (ext_id == BT_EXT_UT_METADATA_ID) {
        // ut_metadata message (our local ID = 1)
        if (state_ == TorrentState::DownloadingMetadata) {
            LOG_DEBUG("Torrent", "Processing ut_metadata message from " + peer->ip());
            on_metadata_message(peer, payload);
        } else {
            LOG_DEBUG("Torrent", "Ignoring ut_metadata message (already have metadata)");
        }
    } else if (ext_id == BT_EXT_UT_PEX_ID) {
        // ut_pex message (our local ID = 2)
        LOG_DEBUG("Torrent", "Received ut_pex message from " + peer->ip() + " (not implemented)");
        // TODO: Handle PEX for peer discovery
    } else {
        LOG_DEBUG("Torrent", "Unknown extension message ext_id=" + std::to_string(ext_id) + 
                  " from " + peer->ip());
    }
}

void Torrent::on_extension_handshake(BtPeerConnection* peer, 
                                      const std::vector<uint8_t>& payload) {
    BencodeValue decoded;
    try {
        decoded = BencodeDecoder::decode(payload);
    } catch (...) {
        LOG_WARN("Torrent", "Failed to decode extension handshake from " + peer->ip());
        return;
    }
    
    if (!decoded.is_dict()) {
        return;
    }
    
    const auto& dict = decoded.as_dict();
    
    // Extract metadata_size if present (for magnet links)
    auto metadata_size_it = dict.find("metadata_size");
    if (metadata_size_it != dict.end() && metadata_size_it->second.is_integer()) {
        size_t metadata_size = static_cast<size_t>(metadata_size_it->second.as_integer());
        LOG_INFO("Torrent", "Peer " + peer->ip() + " has metadata, size=" + 
                 std::to_string(metadata_size));
        
        // If we're downloading metadata, store this info and start requesting
        if (state_ == TorrentState::DownloadingMetadata && metadata_size > 0) {
            // Store metadata size for this peer
            peer_metadata_size_[peer] = metadata_size;
            
            // Parse the peer's ut_metadata ID from 'm' dict
            auto m_it = dict.find("m");
            if (m_it != dict.end() && m_it->second.is_dict()) {
                const auto& m = m_it->second.as_dict();
                auto ut_meta_it = m.find("ut_metadata");
                if (ut_meta_it != m.end() && ut_meta_it->second.is_integer()) {
                    uint8_t peer_ut_metadata_id = static_cast<uint8_t>(ut_meta_it->second.as_integer());
                    peer_ut_metadata_id_[peer] = peer_ut_metadata_id;
                    
                    LOG_DEBUG("Torrent", "Peer " + peer->ip() + " ut_metadata ID = " + 
                              std::to_string(peer_ut_metadata_id));
                    
                    // Start requesting metadata pieces
                    request_metadata(peer);
                }
            }
        }
    }
    
    LOG_DEBUG("Torrent", "Received extension handshake from " + peer->ip());
}

void Torrent::request_metadata(BtPeerConnection* peer) {
    if (has_metadata_unlocked()) {
        LOG_DEBUG("Torrent", "request_metadata: already have metadata, skipping");
        return;  // Already have metadata
    }
    
    auto size_it = peer_metadata_size_.find(peer);
    auto id_it = peer_ut_metadata_id_.find(peer);
    
    if (size_it == peer_metadata_size_.end() || id_it == peer_ut_metadata_id_.end()) {
        LOG_DEBUG("Torrent", "request_metadata: no metadata info for peer " + peer->ip() + 
                  " (size_found=" + (size_it != peer_metadata_size_.end() ? "yes" : "no") +
                  ", id_found=" + (id_it != peer_ut_metadata_id_.end() ? "yes" : "no") + ")");
        return;  // Don't have peer's metadata info
    }
    
    size_t metadata_size = size_it->second;
    uint8_t peer_ut_id = id_it->second;
    
    // Calculate number of pieces (16KB each)
    uint32_t num_pieces = static_cast<uint32_t>((metadata_size + BT_METADATA_PIECE_SIZE - 1) / BT_METADATA_PIECE_SIZE);
    
    // Initialize metadata buffer if needed
    if (metadata_buffer_.empty()) {
        metadata_buffer_.resize(metadata_size);
        metadata_pieces_received_.resize(num_pieces, false);
    }
    
    // Request pieces we don't have yet
    for (uint32_t piece = 0; piece < num_pieces; ++piece) {
        if (!metadata_pieces_received_[piece]) {
            // Create request message
            BencodeValue req = BencodeValue::create_dict();
            req["msg_type"] = BencodeValue(static_cast<int64_t>(0));  // Request
            req["piece"] = BencodeValue(static_cast<int64_t>(piece));
            
            auto req_payload = req.encode();
            peer->send_extended(peer_ut_id, req_payload);
            
            LOG_DEBUG("Torrent", "Requesting metadata piece " + std::to_string(piece) + 
                      " from " + peer->ip());
            break;  // Request one piece at a time for now
        }
    }
}

void Torrent::on_metadata_message(BtPeerConnection* peer,
                                   const std::vector<uint8_t>& payload) {
    LOG_DEBUG("Torrent", "on_metadata_message: " + std::to_string(payload.size()) + 
              " bytes from " + peer->ip());
    
    // Parse the bencoded message
    BencodeValue decoded;
    try {
        decoded = BencodeDecoder::decode(payload);
    } catch (...) {
        LOG_WARN("Torrent", "Failed to decode metadata message from " + peer->ip());
        return;
    }
    
    if (!decoded.is_dict()) {
        LOG_WARN("Torrent", "Metadata message is not a dict from " + peer->ip());
        return;
    }
    
    const auto& dict = decoded.as_dict();
    
    auto msg_type_it = dict.find("msg_type");
    if (msg_type_it == dict.end() || !msg_type_it->second.is_integer()) {
        LOG_WARN("Torrent", "Metadata message missing msg_type from " + peer->ip());
        return;
    }
    
    int msg_type = static_cast<int>(msg_type_it->second.as_integer());
    LOG_DEBUG("Torrent", "on_metadata_message: msg_type=" + std::to_string(msg_type) + 
              " (0=request, 1=data, 2=reject) from " + peer->ip());
    
    if (msg_type == 1) {  // Data
        auto piece_it = dict.find("piece");
        if (piece_it == dict.end() || !piece_it->second.is_integer()) {
            return;
        }
        
        uint32_t piece = static_cast<uint32_t>(piece_it->second.as_integer());
        
        // Find where the data starts (after the bencoded dict)
        size_t dict_end = find_bencode_end(payload);
        if (dict_end >= payload.size()) {
            return;
        }
        
        // Copy data to buffer
        size_t offset = static_cast<size_t>(piece) * BT_METADATA_PIECE_SIZE;
        size_t data_size = payload.size() - dict_end;
        
        if (offset + data_size <= metadata_buffer_.size()) {
            std::memcpy(metadata_buffer_.data() + offset, payload.data() + dict_end, data_size);
            
            if (piece < metadata_pieces_received_.size()) {
                metadata_pieces_received_[piece] = true;
            }
            
            LOG_DEBUG("Torrent", "Received metadata piece " + std::to_string(piece) + 
                      " (" + std::to_string(data_size) + " bytes)");
            
            // Check if we have all pieces
            bool complete = true;
            for (bool received : metadata_pieces_received_) {
                if (!received) {
                    complete = false;
                    break;
                }
            }
            
            if (complete) {
                on_metadata_complete();
            } else {
                // Request next piece
                request_metadata(peer);
            }
        }
    } else if (msg_type == 2) {  // Reject
        LOG_DEBUG("Torrent", "Peer " + peer->ip() + " rejected metadata request");
    }
}

size_t Torrent::find_bencode_end(const std::vector<uint8_t>& data) {
    // Find the end of a bencoded dictionary
    int depth = 0;
    for (size_t i = 0; i < data.size(); ++i) {
        if (data[i] == 'd' || data[i] == 'l') {
            ++depth;
        } else if (data[i] == 'e') {
            --depth;
            if (depth == 0) {
                return i + 1;
            }
        } else if (std::isdigit(data[i])) {
            // Skip string
            size_t len = 0;
            while (i < data.size() && std::isdigit(data[i])) {
                len = len * 10 + (data[i] - '0');
                ++i;
            }
            if (i < data.size() && data[i] == ':') {
                i += len;  // Skip the string content
            }
        } else if (data[i] == 'i') {
            // Skip integer
            while (i < data.size() && data[i] != 'e') {
                ++i;
            }
        }
    }
    return data.size();
}

void Torrent::on_metadata_complete() {
    LOG_INFO("Torrent", "Metadata download complete!");
    
    // Validate and set metadata
    if (set_metadata(metadata_buffer_)) {
        LOG_INFO("Torrent", "Metadata validated, starting download of " + name_);
        
        // Clear metadata tracking data
        metadata_buffer_.clear();
        metadata_pieces_received_.clear();
        peer_metadata_size_.clear();
        peer_ut_metadata_id_.clear();
        
        // State transition happens in set_metadata()
        
        // Notify callback that metadata was received successfully
        if (on_metadata_received_) {
            on_metadata_received_(this, true);
        }
    } else {
        LOG_ERROR("Torrent", "Metadata validation failed");
        
        // Notify callback of failure
        if (on_metadata_received_) {
            on_metadata_received_(this, false);
        }
        
        // Could retry from other peers
        metadata_buffer_.clear();
        metadata_pieces_received_.clear();
    }
}

} // namespace librats
