#include "bt_piece_picker.h"
#include "logger.h"
#include <algorithm>
#include <random>
#include <chrono>

namespace librats {

//=============================================================================
// Constructors
//=============================================================================

PiecePicker::PiecePicker(uint32_t num_pieces, uint32_t piece_length, uint32_t last_piece_length)
    : num_pieces_(num_pieces)
    , piece_length_(piece_length)
    , last_piece_length_(last_piece_length)
    , mode_(PickerMode::RarestFirst)
    , endgame_enabled_(true)
    , in_endgame_(false)
    , pieces_(num_pieces)
    , num_have_(0)
    , num_downloading_(0)
    , sequential_cursor_(0) {
}

PiecePicker::~PiecePicker() = default;

PiecePicker::PiecePicker(PiecePicker&& other) noexcept
    : num_pieces_(other.num_pieces_)
    , piece_length_(other.piece_length_)
    , last_piece_length_(other.last_piece_length_)
    , mode_(other.mode_)
    , endgame_enabled_(other.endgame_enabled_)
    , in_endgame_(other.in_endgame_)
    , pieces_(std::move(other.pieces_))
    , downloading_(std::move(other.downloading_))
    , peer_pieces_(std::move(other.peer_pieces_))
    , num_have_(other.num_have_)
    , num_downloading_(other.num_downloading_)
    , sequential_cursor_(other.sequential_cursor_) {
}

PiecePicker& PiecePicker::operator=(PiecePicker&& other) noexcept {
    if (this != &other) {
        std::lock_guard<std::mutex> lock(mutex_);
        num_pieces_ = other.num_pieces_;
        piece_length_ = other.piece_length_;
        last_piece_length_ = other.last_piece_length_;
        mode_ = other.mode_;
        endgame_enabled_ = other.endgame_enabled_;
        in_endgame_ = other.in_endgame_;
        pieces_ = std::move(other.pieces_);
        downloading_ = std::move(other.downloading_);
        peer_pieces_ = std::move(other.peer_pieces_);
        num_have_ = other.num_have_;
        num_downloading_ = other.num_downloading_;
        sequential_cursor_ = other.sequential_cursor_;
    }
    return *this;
}

//=============================================================================
// Configuration
//=============================================================================

void PiecePicker::set_mode(PickerMode mode) {
    std::lock_guard<std::mutex> lock(mutex_);
    mode_ = mode;
}

PickerMode PiecePicker::mode() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return mode_;
}

void PiecePicker::set_piece_priority(uint32_t piece, PiecePriority priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (piece < num_pieces_) {
        pieces_[piece].priority = priority;
    }
}

PiecePriority PiecePicker::piece_priority(uint32_t piece) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (piece < num_pieces_) {
        return pieces_[piece].priority;
    }
    return PiecePriority::Normal;
}

void PiecePicker::set_piece_priority_range(uint32_t start, uint32_t end, PiecePriority priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    end = std::min(end, num_pieces_);
    for (uint32_t i = start; i < end; ++i) {
        pieces_[i].priority = priority;
    }
}

//=============================================================================
// Piece State Management
//=============================================================================

void PiecePicker::mark_have(uint32_t piece) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (piece >= num_pieces_) return;
    
    if (!pieces_[piece].have) {
        pieces_[piece].have = true;
        ++num_have_;
        
        // Remove from downloading if present
        if (pieces_[piece].downloading) {
            remove_downloading(piece);
        }
    }
}

bool PiecePicker::have_piece(uint32_t piece) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (piece >= num_pieces_) return false;
    return pieces_[piece].have;
}

Bitfield PiecePicker::get_have_bitfield() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Bitfield bf(num_pieces_);
    for (uint32_t i = 0; i < num_pieces_; ++i) {
        if (pieces_[i].have) {
            bf.set_bit(i);
        }
    }
    return bf;
}

void PiecePicker::set_have_bitfield(const Bitfield& have) {
    std::lock_guard<std::mutex> lock(mutex_);
    num_have_ = 0;
    for (uint32_t i = 0; i < num_pieces_ && i < have.size(); ++i) {
        pieces_[i].have = have.get_bit(i);
        if (pieces_[i].have) {
            ++num_have_;
        }
    }
}

uint32_t PiecePicker::num_have() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return num_have_;
}

uint32_t PiecePicker::num_want() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return num_pieces_ - num_have_;
}

bool PiecePicker::is_complete() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return num_have_ == num_pieces_;
}

//=============================================================================
// Peer Availability
//=============================================================================

void PiecePicker::add_peer(void* peer_id, const Bitfield& bitfield) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Store peer's bitfield
    peer_pieces_[peer_id] = bitfield;
    
    // Update availability counts
    for (size_t i = 0; i < bitfield.size() && i < num_pieces_; ++i) {
        if (bitfield.get_bit(i)) {
            ++pieces_[i].availability;
        }
    }
}

void PiecePicker::remove_peer(void* peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = peer_pieces_.find(peer_id);
    if (it == peer_pieces_.end()) return;
    
    // Decrease availability for pieces this peer had
    const Bitfield& bitfield = it->second;
    for (size_t i = 0; i < bitfield.size() && i < num_pieces_; ++i) {
        if (bitfield.get_bit(i) && pieces_[i].availability > 0) {
            --pieces_[i].availability;
        }
    }
    
    // Cancel any requests to this peer
    for (auto& dp : downloading_) {
        for (auto& block : dp.blocks) {
            if (block.peer == peer_id && block.state == BlockState::Requested) {
                block.state = BlockState::None;
                block.peer = nullptr;
            }
        }
    }
    
    peer_pieces_.erase(it);
}

void PiecePicker::peer_has_piece(void* peer_id, uint32_t piece) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (piece >= num_pieces_) return;
    
    auto it = peer_pieces_.find(peer_id);
    if (it == peer_pieces_.end()) {
        // Create empty bitfield for this peer
        peer_pieces_[peer_id] = Bitfield(num_pieces_);
        it = peer_pieces_.find(peer_id);
    }
    
    if (!it->second.get_bit(piece)) {
        it->second.set_bit(piece);
        ++pieces_[piece].availability;
    }
}

uint32_t PiecePicker::availability(uint32_t piece) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (piece >= num_pieces_) return 0;
    return pieces_[piece].availability;
}

//=============================================================================
// Piece Picking
//=============================================================================

std::vector<BlockRequest> PiecePicker::pick_pieces(
    const Bitfield& peer_bitfield,
    size_t num_blocks,
    void* peer_id) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<BlockRequest> result;
    
    if (num_blocks == 0) return result;
    
    // First, try to complete pieces already being downloaded
    for (auto& dp : downloading_) {
        if (result.size() >= num_blocks) break;
        
        uint32_t piece = dp.piece_index;
        if (!peer_bitfield.get_bit(piece)) continue;
        
        // Find unrequested blocks in this piece
        for (size_t i = 0; i < dp.blocks.size() && result.size() < num_blocks; ++i) {
            auto& block = dp.blocks[i];
            
            bool can_request = false;
            if (block.state == BlockState::None) {
                can_request = true;
            } else if (in_endgame_ && block.state == BlockState::Requested && block.peer != peer_id) {
                // In endgame, request from multiple peers
                can_request = true;
            }
            
            if (can_request) {
                BlockInfo info(piece, static_cast<uint32_t>(i) * BT_BLOCK_SIZE, 
                              block_size(piece, static_cast<uint32_t>(i)));
                result.emplace_back(info, peer_id);
                
                block.state = BlockState::Requested;
                block.peer = peer_id;
            }
        }
    }
    
    // Then, pick new pieces
    while (result.size() < num_blocks) {
        uint32_t piece = UINT32_MAX;
        
        switch (mode_) {
            case PickerMode::RarestFirst:
                piece = pick_rarest(peer_bitfield);
                break;
            case PickerMode::Sequential:
                piece = pick_sequential(peer_bitfield);
                break;
            case PickerMode::Random:
                piece = pick_random(peer_bitfield);
                break;
        }
        
        if (piece == UINT32_MAX) break;  // No more pieces available
        
        // Start downloading this piece
        auto* dp = get_or_create_downloading(piece);
        if (!dp) break;
        
        // Pick blocks from this piece
        for (size_t i = 0; i < dp->blocks.size() && result.size() < num_blocks; ++i) {
            auto& block = dp->blocks[i];
            if (block.state == BlockState::None) {
                BlockInfo info(piece, static_cast<uint32_t>(i) * BT_BLOCK_SIZE,
                              block_size(piece, static_cast<uint32_t>(i)));
                result.emplace_back(info, peer_id);
                
                block.state = BlockState::Requested;
                block.peer = peer_id;
            }
        }
    }
    
    return result;
}

std::optional<uint32_t> PiecePicker::pick_piece(const Bitfield& peer_bitfield) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint32_t piece = UINT32_MAX;
    
    switch (mode_) {
        case PickerMode::RarestFirst:
            piece = pick_rarest(peer_bitfield);
            break;
        case PickerMode::Sequential:
            piece = pick_sequential(peer_bitfield);
            break;
        case PickerMode::Random:
            piece = pick_random(peer_bitfield);
            break;
    }
    
    if (piece == UINT32_MAX) {
        return std::nullopt;
    }
    return piece;
}

bool PiecePicker::is_interesting(const Bitfield& peer_bitfield) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (uint32_t i = 0; i < num_pieces_; ++i) {
        if (!pieces_[i].have && 
            pieces_[i].priority != PiecePriority::Skip &&
            peer_bitfield.get_bit(i)) {
            return true;
        }
    }
    return false;
}

//=============================================================================
// Block Management
//=============================================================================

void PiecePicker::mark_requested(const BlockInfo& block, void* peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto* dp = get_or_create_downloading(block.piece_index);
    if (!dp) return;
    
    size_t block_idx = block.offset / BT_BLOCK_SIZE;
    if (block_idx < dp->blocks.size()) {
        dp->blocks[block_idx].state = BlockState::Requested;
        dp->blocks[block_idx].peer = peer_id;
    }
}

void PiecePicker::mark_writing(const BlockInfo& block) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto* dp = find_downloading(block.piece_index);
    if (!dp) return;
    
    size_t block_idx = block.offset / BT_BLOCK_SIZE;
    if (block_idx < dp->blocks.size()) {
        dp->blocks[block_idx].state = BlockState::Writing;
    }
}

bool PiecePicker::mark_finished(const BlockInfo& block) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto* dp = find_downloading(block.piece_index);
    if (!dp) {
        LOG_WARN("PiecePicker", "mark_finished: piece " + std::to_string(block.piece_index) + 
                 " not in downloading list!");
        return false;
    }
    
    size_t block_idx = block.offset / BT_BLOCK_SIZE;
    if (block_idx >= dp->blocks.size()) {
        LOG_WARN("PiecePicker", "mark_finished: block index " + std::to_string(block_idx) + 
                 " >= blocks.size " + std::to_string(dp->blocks.size()));
        return false;
    }
    
    dp->blocks[block_idx].state = BlockState::Finished;
    dp->blocks[block_idx].peer = nullptr;
    
    // Check if piece is complete
    size_t finished_count = 0;
    for (const auto& b : dp->blocks) {
        if (b.state == BlockState::Finished) {
            ++finished_count;
        }
    }
    
    bool complete = (finished_count == dp->blocks.size());
    
    LOG_DEBUG("PiecePicker", "mark_finished: piece=" + std::to_string(block.piece_index) + 
              " block=" + std::to_string(block_idx) + 
              " finished=" + std::to_string(finished_count) + "/" + std::to_string(dp->blocks.size()) +
              (complete ? " COMPLETE!" : ""));
    
    if (complete) {
        check_endgame();
    }
    
    return complete;
}

void PiecePicker::cancel_request(const BlockInfo& block, void* peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto* dp = find_downloading(block.piece_index);
    if (!dp) return;
    
    size_t block_idx = block.offset / BT_BLOCK_SIZE;
    if (block_idx < dp->blocks.size()) {
        auto& b = dp->blocks[block_idx];
        if (b.state == BlockState::Requested && b.peer == peer_id) {
            b.state = BlockState::None;
            b.peer = nullptr;
        }
    }
}

void PiecePicker::cancel_peer_requests(void* peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& dp : downloading_) {
        for (auto& b : dp.blocks) {
            if (b.peer == peer_id && b.state == BlockState::Requested) {
                b.state = BlockState::None;
                b.peer = nullptr;
            }
        }
    }
}

void PiecePicker::abort_download(const BlockInfo& block, void* peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto* dp = find_downloading(block.piece_index);
    if (!dp) return;
    
    // Find the block within the piece
    uint32_t block_index = block.offset / BT_BLOCK_SIZE;
    if (block_index >= dp->blocks.size()) return;
    
    auto& b = dp->blocks[block_index];
    
    // Only abort if it matches the peer (or peer_id is null)
    if (b.state == BlockState::Requested && 
        (peer_id == nullptr || b.peer == peer_id)) {
        b.state = BlockState::None;
        b.peer = nullptr;
    }
}

BlockState PiecePicker::block_state(const BlockInfo& block) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    const auto* dp = find_downloading(block.piece_index);
    if (!dp) {
        // If piece is marked as have, all blocks are finished
        if (block.piece_index < num_pieces_ && pieces_[block.piece_index].have) {
            return BlockState::Finished;
        }
        return BlockState::None;
    }
    
    size_t block_idx = block.offset / BT_BLOCK_SIZE;
    if (block_idx < dp->blocks.size()) {
        return dp->blocks[block_idx].state;
    }
    return BlockState::None;
}

//=============================================================================
// Endgame Mode
//=============================================================================

bool PiecePicker::in_endgame_mode() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return in_endgame_;
}

void PiecePicker::set_endgame_mode(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    endgame_enabled_ = enable;
    if (!enable) {
        in_endgame_ = false;
    }
}

void PiecePicker::check_endgame() {
    // Called with lock held
    if (!endgame_enabled_ || in_endgame_) return;
    
    // Enter endgame when we have most pieces and only a few blocks left
    uint32_t remaining_pieces = num_pieces_ - num_have_;
    
    // Endgame threshold: less than 5% of pieces remaining, or less than 10 pieces
    if (remaining_pieces <= num_pieces_ / 20 || remaining_pieces <= 10) {
        in_endgame_ = true;
    }
}

//=============================================================================
// Statistics
//=============================================================================

size_t PiecePicker::num_downloading() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return downloading_.size();
}

std::vector<DownloadingPiece> PiecePicker::downloading_pieces() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<DownloadingPiece> result;
    result.reserve(downloading_.size());
    
    for (const auto& dp : downloading_) {
        DownloadingPiece info;
        info.piece_index = dp.piece_index;
        info.blocks_total = static_cast<uint16_t>(dp.blocks.size());
        
        for (const auto& b : dp.blocks) {
            switch (b.state) {
                case BlockState::Requested:
                    ++info.blocks_requested;
                    break;
                case BlockState::Writing:
                    ++info.blocks_writing;
                    break;
                case BlockState::Finished:
                    ++info.blocks_finished;
                    break;
                default:
                    break;
            }
        }
        
        result.push_back(info);
    }
    
    return result;
}

std::optional<DownloadingPiece> PiecePicker::get_downloading_piece(uint32_t piece) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    const auto* dp = find_downloading(piece);
    if (!dp) return std::nullopt;
    
    DownloadingPiece info;
    info.piece_index = dp->piece_index;
    info.blocks_total = static_cast<uint16_t>(dp->blocks.size());
    
    for (const auto& b : dp->blocks) {
        switch (b.state) {
            case BlockState::Requested:
                ++info.blocks_requested;
                break;
            case BlockState::Writing:
                ++info.blocks_writing;
                break;
            case BlockState::Finished:
                ++info.blocks_finished;
                break;
            default:
                break;
        }
    }
    
    return info;
}

//=============================================================================
// Utility
//=============================================================================

uint32_t PiecePicker::blocks_in_piece(uint32_t piece) const {
    if (piece >= num_pieces_) return 0;
    
    uint32_t piece_size = (piece == num_pieces_ - 1) ? last_piece_length_ : piece_length_;
    return (piece_size + BT_BLOCK_SIZE - 1) / BT_BLOCK_SIZE;
}

uint32_t PiecePicker::block_size(uint32_t piece, uint32_t block_index) const {
    if (piece >= num_pieces_) return 0;
    
    uint32_t piece_size = (piece == num_pieces_ - 1) ? last_piece_length_ : piece_length_;
    uint32_t offset = block_index * BT_BLOCK_SIZE;
    
    if (offset >= piece_size) return 0;
    return std::min(BT_BLOCK_SIZE, piece_size - offset);
}

//=============================================================================
// Internal Methods
//=============================================================================

uint32_t PiecePicker::pick_rarest(const Bitfield& peer_bitfield) const {
    // Find rarest piece that peer has and we don't
    uint32_t best_piece = UINT32_MAX;
    uint32_t best_availability = UINT32_MAX;
    
    // Add some randomization among pieces with same availability
    std::vector<uint32_t> candidates;
    
    for (uint32_t i = 0; i < num_pieces_; ++i) {
        const auto& piece = pieces_[i];
        
        // Skip pieces we have, are downloading, or don't want
        if (piece.have || piece.downloading || piece.priority == PiecePriority::Skip) {
            continue;
        }
        
        // Skip pieces peer doesn't have
        if (!peer_bitfield.get_bit(i)) {
            continue;
        }
        
        if (piece.availability < best_availability) {
            best_availability = piece.availability;
            candidates.clear();
            candidates.push_back(i);
        } else if (piece.availability == best_availability) {
            candidates.push_back(i);
        }
    }
    
    if (candidates.empty()) {
        return UINT32_MAX;
    }
    
    // Return random piece among equally rare ones
    if (candidates.size() == 1) {
        return candidates[0];
    }
    
    static thread_local std::mt19937 gen(
        static_cast<unsigned>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<size_t> dis(0, candidates.size() - 1);
    return candidates[dis(gen)];
}

uint32_t PiecePicker::pick_sequential(const Bitfield& peer_bitfield) const {
    // Start from cursor and find next available piece
    for (uint32_t i = 0; i < num_pieces_; ++i) {
        uint32_t piece = (sequential_cursor_ + i) % num_pieces_;
        const auto& ps = pieces_[piece];
        
        if (ps.have || ps.downloading || ps.priority == PiecePriority::Skip) {
            continue;
        }
        
        if (peer_bitfield.get_bit(piece)) {
            return piece;
        }
    }
    
    return UINT32_MAX;
}

uint32_t PiecePicker::pick_random(const Bitfield& peer_bitfield) const {
    std::vector<uint32_t> candidates;
    
    for (uint32_t i = 0; i < num_pieces_; ++i) {
        const auto& piece = pieces_[i];
        
        if (piece.have || piece.downloading || piece.priority == PiecePriority::Skip) {
            continue;
        }
        
        if (peer_bitfield.get_bit(i)) {
            candidates.push_back(i);
        }
    }
    
    if (candidates.empty()) {
        return UINT32_MAX;
    }
    
    static thread_local std::mt19937 gen(
        static_cast<unsigned>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<size_t> dis(0, candidates.size() - 1);
    return candidates[dis(gen)];
}

PiecePicker::DownloadingPieceState* PiecePicker::get_or_create_downloading(uint32_t piece) {
    // Called with lock held
    if (piece >= num_pieces_) return nullptr;
    
    // Check if already downloading
    for (auto& dp : downloading_) {
        if (dp.piece_index == piece) {
            return &dp;
        }
    }
    
    // Create new downloading piece
    uint32_t num_blocks = blocks_in_piece(piece);
    downloading_.emplace_back(piece, num_blocks);
    pieces_[piece].downloading = true;
    ++num_downloading_;
    
    return &downloading_.back();
}

PiecePicker::DownloadingPieceState* PiecePicker::find_downloading(uint32_t piece) {
    for (auto& dp : downloading_) {
        if (dp.piece_index == piece) {
            return &dp;
        }
    }
    return nullptr;
}

const PiecePicker::DownloadingPieceState* PiecePicker::find_downloading(uint32_t piece) const {
    for (const auto& dp : downloading_) {
        if (dp.piece_index == piece) {
            return &dp;
        }
    }
    return nullptr;
}

void PiecePicker::remove_downloading(uint32_t piece) {
    // Called with lock held
    auto it = std::find_if(downloading_.begin(), downloading_.end(),
        [piece](const DownloadingPieceState& dp) { return dp.piece_index == piece; });
    
    if (it != downloading_.end()) {
        pieces_[piece].downloading = false;
        downloading_.erase(it);
        if (num_downloading_ > 0) --num_downloading_;
    }
}

} // namespace librats
