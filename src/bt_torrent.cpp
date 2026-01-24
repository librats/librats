#include "bt_torrent.h"
#include <algorithm>

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
    
    // Initialize piece picker
    uint32_t last_piece_len = info.piece_size(info.num_pieces() - 1);
    picker_ = std::make_unique<PiecePicker>(
        info.num_pieces(), 
        info.piece_length(),
        last_piece_len
    );
    
    if (config_.sequential_download) {
        picker_->set_mode(PickerMode::Sequential);
    }
    
    // Configure choker
    ChokerConfig choker_config;
    choker_config.max_uploads = config_.max_uploads;
    choker_.set_config(choker_config);
    
    stats_.total_size = info.total_size();
    stats_.pieces_total = info.num_pieces();
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
    
    // No picker until we have metadata
    
    ChokerConfig choker_config;
    choker_config.max_uploads = config_.max_uploads;
    choker_.set_config(choker_config);
}

Torrent::~Torrent() {
    stop();
}

//=============================================================================
// Lifecycle
//=============================================================================

void Torrent::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (state_ == TorrentState::Downloading || 
        state_ == TorrentState::Seeding) {
        return;
    }
    
    stats_.started_at = std::chrono::steady_clock::now();
    last_stats_update_ = std::chrono::steady_clock::now();
    last_choker_run_ = std::chrono::steady_clock::now();
    
    if (!info_) {
        set_state(TorrentState::DownloadingMetadata);
    } else if (config_.seed_mode || is_complete()) {
        set_state(TorrentState::Seeding);
        choker_.set_seed_mode(true);
    } else {
        set_state(TorrentState::Downloading);
    }
}

void Torrent::stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Disconnect all peers
    for (auto& conn : connections_) {
        conn->close();
    }
    connections_.clear();
    
    set_state(TorrentState::Stopped);
}

void Torrent::pause() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (state_ == TorrentState::Downloading ||
        state_ == TorrentState::Seeding) {
        set_state(TorrentState::Paused);
    }
}

void Torrent::resume() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (state_ == TorrentState::Paused) {
        if (is_complete()) {
            set_state(TorrentState::Seeding);
        } else {
            set_state(TorrentState::Downloading);
        }
    }
}

void Torrent::recheck() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Would trigger file checking
    set_state(TorrentState::CheckingFiles);
    
    // Reset have bitfield
    if (info_) {
        have_pieces_ = Bitfield(info_->num_pieces());
        picker_->set_have_bitfield(have_pieces_);
    }
    
    // TODO: Actually verify files
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
    return picker_ && picker_->is_complete();
}

bool Torrent::has_metadata() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return info_ != nullptr && info_->has_metadata();
}

void Torrent::set_state(TorrentState new_state) {
    TorrentState old_state = state_.exchange(new_state);
    if (old_state != new_state && on_state_change_) {
        on_state_change_(this, new_state);
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
            return;
        }
    }
    
    // Check if already pending
    for (const auto& peer : pending_peers_) {
        if (peer.first == ip && peer.second == port) {
            return;
        }
    }
    
    pending_peers_.emplace_back(ip, port);
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

//=============================================================================
// Configuration
//=============================================================================

void Torrent::set_sequential(bool sequential) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.sequential_download = sequential;
    if (picker_) {
        picker_->set_mode(sequential ? PickerMode::Sequential : PickerMode::RarestFirst);
    }
}

void Torrent::set_download_limit(uint64_t bytes_per_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.download_limit = bytes_per_sec;
}

void Torrent::set_upload_limit(uint64_t bytes_per_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.upload_limit = bytes_per_sec;
}

//=============================================================================
// Metadata
//=============================================================================

bool Torrent::set_metadata(const std::vector<uint8_t>& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto new_info = TorrentInfo::from_info_dict(metadata, info_hash_);
    if (!new_info) {
        return false;
    }
    
    info_ = std::make_unique<TorrentInfo>(*new_info);
    name_ = info_->name();
    
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
    // Send bitfield
    if (picker_ && picker_->num_have() > 0) {
        peer->send_bitfield(picker_->get_have_bitfield());
    }
}

void Torrent::on_peer_disconnected(BtPeerConnection* peer) {
    // Cancel pending requests
    if (picker_) {
        picker_->cancel_peer_requests(peer);
    }
    
    // Remove from availability
    if (picker_) {
        picker_->remove_peer(peer);
    }
}

void Torrent::on_peer_message(BtPeerConnection* peer, const BtMessage& msg) {
    switch (msg.type) {
        case BtMessageType::Bitfield:
            if (msg.bitfield && picker_) {
                picker_->add_peer(peer, *msg.bitfield);
                
                // Check if interesting
                if (picker_->is_interesting(*msg.bitfield)) {
                    peer->send_interested();
                }
            }
            break;
            
        case BtMessageType::Have:
            if (picker_) {
                picker_->peer_has_piece(peer, msg.have_piece);
            }
            break;
            
        case BtMessageType::Piece:
            if (msg.piece) {
                on_piece_received(msg.piece->piece_index, msg.piece->begin, msg.piece->data);
            }
            break;
            
        case BtMessageType::Request:
            // Peer is requesting a block from us
            if (msg.request && !peer->am_choking()) {
                // TODO: Read from disk and send
            }
            break;
            
        case BtMessageType::Unchoke:
            // Peer unchoked us - can start requesting
            break;
            
        case BtMessageType::Choke:
            // Peer choked us - stop requesting
            if (picker_) {
                picker_->cancel_peer_requests(peer);
            }
            break;
            
        default:
            break;
    }
}

void Torrent::on_piece_received(uint32_t piece, uint32_t begin, 
                                const std::vector<uint8_t>& data) {
    if (!picker_ || !info_) {
        return;
    }
    
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
        // Verify hash
        // TODO: Actually hash and verify
        on_piece_verified(piece, true);
    }
}

void Torrent::on_piece_verified(uint32_t piece, bool valid) {
    if (!picker_) return;
    
    if (valid) {
        picker_->mark_have(piece);
        have_pieces_.set_bit(piece);
        
        // Write to disk
        // TODO: Async disk write
        
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
            set_state(TorrentState::Seeding);
            choker_.set_seed_mode(true);
            
            if (on_complete_) {
                on_complete_(this);
            }
        }
        
        ++stats_.pieces_done;
    } else {
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
    
    for (auto* peer : result.to_choke) {
        peer->send_choke();
    }
    
    for (auto* peer : result.to_unchoke) {
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

} // namespace librats
