#include "bittorrent/piece_picker.h"
#include "bittorrent/types.h"  // kBlockSize

#include <algorithm>

namespace librats::bittorrent {

PiecePicker::PiecePicker(std::uint32_t num_pieces, std::uint32_t piece_length, std::int64_t total_size)
    : num_pieces_(num_pieces)
    , piece_length_(piece_length)
    , total_size_(total_size)
    , availability_(num_pieces, 0)
    , priority_(num_pieces, PiecePriority::Normal)
    , have_(num_pieces, false)
    , pieces_left_(num_pieces)
    , rng_(std::random_device{}()) {}

// ---- geometry ----

std::uint32_t PiecePicker::piece_size(std::uint32_t piece) const noexcept {
    if (piece + 1 < num_pieces_) return piece_length_;
    const std::int64_t tail = total_size_ - std::int64_t(piece) * piece_length_;
    if (tail <= 0) return 0;
    return std::uint32_t(std::min<std::int64_t>(tail, piece_length_));
}

std::uint32_t PiecePicker::blocks_in_piece(std::uint32_t piece) const noexcept {
    return (piece_size(piece) + kBlockSize - 1) / kBlockSize;
}

std::uint32_t PiecePicker::block_size(std::uint32_t piece, std::uint32_t block) const noexcept {
    const std::uint32_t ps = piece_size(piece);
    const std::uint32_t off = block * kBlockSize;
    return std::min(kBlockSize, ps - off);
}

// ---- our progress ----

void PiecePicker::we_have(std::uint32_t piece) {
    if (have_.get(piece)) return;
    have_.set(piece);
    ++num_have_;
    if (priority_[piece] != PiecePriority::DontDownload && pieces_left_ > 0) --pieces_left_;
    downloading_.erase(piece);
    rarest_dirty_ = true;
}

void PiecePicker::we_have_all() {
    for (std::uint32_t p = 0; p < num_pieces_; ++p) we_have(p);
}

void PiecePicker::set_have_bitfield(const Bitfield& have) {
    for (std::uint32_t p = 0; p < num_pieces_; ++p)
        if (have.size() > p && have.get(p)) we_have(p);
}

// ---- priorities ----

void PiecePicker::set_piece_priority(std::uint32_t piece, PiecePriority priority) {
    const PiecePriority old = priority_[piece];
    if (old == priority) return;
    if (!have_.get(piece)) {
        const bool was_wanted = old != PiecePriority::DontDownload;
        const bool now_wanted = priority != PiecePriority::DontDownload;
        if (was_wanted && !now_wanted) { --pieces_left_; downloading_.erase(piece); }
        else if (!was_wanted && now_wanted) ++pieces_left_;
    }
    priority_[piece] = priority;
    rarest_dirty_ = true;
}

// ---- availability ----

void PiecePicker::peer_has_piece(std::uint32_t piece) { ++availability_[piece]; rarest_dirty_ = true; }
void PiecePicker::peer_lost_piece(std::uint32_t piece) {
    if (availability_[piece] > 0) --availability_[piece];
    rarest_dirty_ = true;
}
void PiecePicker::inc_availability(const Bitfield& peer_have) {
    for (std::uint32_t p = 0; p < num_pieces_; ++p) if (peer_have.size() > p && peer_have.get(p)) ++availability_[p];
    rarest_dirty_ = true;
}
void PiecePicker::dec_availability(const Bitfield& peer_have) {
    for (std::uint32_t p = 0; p < num_pieces_; ++p)
        if (peer_have.size() > p && peer_have.get(p) && availability_[p] > 0) --availability_[p];
    rarest_dirty_ = true;
}
void PiecePicker::inc_availability_all() {
    for (auto& a : availability_) ++a;
    rarest_dirty_ = true;
}
void PiecePicker::dec_availability_all() {
    for (auto& a : availability_) if (a > 0) --a;
    rarest_dirty_ = true;
}

// ---- block state machine ----

PiecePicker::DownloadingPiece& PiecePicker::downloading_for(std::uint32_t piece) {
    auto it = downloading_.find(piece);
    if (it != downloading_.end()) return it->second;
    DownloadingPiece dp;
    dp.blocks.resize(blocks_in_piece(piece));
    return downloading_.emplace(piece, std::move(dp)).first->second;
}

void PiecePicker::mark_requested(const PieceBlock& b, const void* peer) {
    DownloadingPiece& dp = downloading_for(b.piece);
    Block& blk = dp.blocks[b.block];
    if (blk.state == BlockState::None) {
        blk.state = BlockState::Requested;
        ++dp.num_requested;
    }
    if (std::find(blk.peers.begin(), blk.peers.end(), peer) == blk.peers.end())
        blk.peers.push_back(peer);
}

void PiecePicker::mark_writing(const PieceBlock& b) {
    auto it = downloading_.find(b.piece);
    if (it == downloading_.end()) return;
    Block& blk = it->second.blocks[b.block];
    if (blk.state == BlockState::Requested) { --it->second.num_requested; blk.state = BlockState::Writing; ++it->second.num_writing; }
}

bool PiecePicker::mark_finished(const PieceBlock& b) {
    DownloadingPiece& dp = downloading_for(b.piece);
    Block& blk = dp.blocks[b.block];
    if (blk.state == BlockState::Requested) --dp.num_requested;
    else if (blk.state == BlockState::Writing) --dp.num_writing;
    if (blk.state != BlockState::Finished) { blk.state = BlockState::Finished; ++dp.num_finished; }
    blk.peers.clear();
    return dp.num_finished == dp.blocks.size();
}

void PiecePicker::abort_block(const PieceBlock& b, const void* peer) {
    auto it = downloading_.find(b.piece);
    if (it == downloading_.end()) return;
    Block& blk = it->second.blocks[b.block];
    blk.peers.erase(std::remove(blk.peers.begin(), blk.peers.end(), peer), blk.peers.end());
    if (blk.state == BlockState::Requested && blk.peers.empty()) {
        blk.state = BlockState::None;
        --it->second.num_requested;
    }
}

void PiecePicker::cancel_peer(const void* peer) {
    for (auto& [piece, dp] : downloading_) {
        for (auto& blk : dp.blocks) {
            blk.peers.erase(std::remove(blk.peers.begin(), blk.peers.end(), peer), blk.peers.end());
            if (blk.state == BlockState::Requested && blk.peers.empty()) {
                blk.state = BlockState::None;
                --dp.num_requested;
            }
        }
    }
}

void PiecePicker::restore_piece(std::uint32_t piece) {
    downloading_.erase(piece);  // drop all block progress; piece becomes fresh
}

BlockState PiecePicker::block_state(std::uint32_t piece, std::uint32_t block) const {
    if (have_.get(piece)) return BlockState::Finished;
    auto it = downloading_.find(piece);
    if (it == downloading_.end()) return BlockState::None;
    return it->second.blocks[block].state;
}

bool PiecePicker::is_interesting(const Bitfield& peer_have) const {
    for (std::uint32_t p = 0; p < num_pieces_; ++p)
        if (wanted(p) && peer_have.size() > p && peer_have.get(p)) return true;
    return false;
}

// ---- picking ----

void PiecePicker::append_free_blocks(std::uint32_t piece, int count, const void* peer,
                                     std::vector<PieceBlock>& out) const {
    const std::uint32_t nblocks = blocks_in_piece(piece);
    auto it = downloading_.find(piece);
    for (std::uint32_t b = 0; b < nblocks && int(out.size()) < count; ++b) {
        if (it == downloading_.end() || it->second.blocks[b].state == BlockState::None)
            out.push_back(PieceBlock{piece, b});
    }
}

void PiecePicker::rebuild_rarest_order() {
    rarest_order_.clear();
    for (std::uint32_t p = 0; p < num_pieces_; ++p) if (wanted(p)) rarest_order_.push_back(p);

    // Primary: higher priority first. Secondary: lower availability first (rarest).
    std::sort(rarest_order_.begin(), rarest_order_.end(), [this](std::uint32_t a, std::uint32_t b) {
        if (priority_[a] != priority_[b]) return priority_[a] > priority_[b];
        return availability_[a] < availability_[b];
    });

    // Shuffle within equal (priority, availability) runs so peers don't all pick the
    // same piece — without disturbing the rarest-first ordering between runs.
    std::size_t i = 0;
    while (i < rarest_order_.size()) {
        std::size_t j = i + 1;
        while (j < rarest_order_.size()
               && priority_[rarest_order_[j]] == priority_[rarest_order_[i]]
               && availability_[rarest_order_[j]] == availability_[rarest_order_[i]]) {
            ++j;
        }
        std::shuffle(rarest_order_.begin() + std::ptrdiff_t(i), rarest_order_.begin() + std::ptrdiff_t(j), rng_);
        i = j;
    }
    rarest_dirty_ = false;
}

std::vector<PieceBlock> PiecePicker::pick_blocks(const Bitfield& peer_have, int count, const void* peer) {
    std::vector<PieceBlock> result;
    if (count <= 0) return result;

    auto peer_has = [&](std::uint32_t p) { return peer_have.size() > p && peer_have.get(p); };

    // 1) Finish pieces already in progress that this peer can serve.
    for (const auto& [piece, dp] : downloading_) {
        if (int(result.size()) >= count) break;
        if (!wanted(piece) || !peer_has(piece)) continue;
        append_free_blocks(piece, count, peer, result);
    }
    if (int(result.size()) >= count) return result;

    // 2) Start new pieces, ordered by the active strategy.
    auto try_new_piece = [&](std::uint32_t p) {
        if (!wanted(p) || !peer_has(p) || downloading_.count(p)) return;
        append_free_blocks(p, count, peer, result);
    };
    switch (mode_) {
        case PickMode::Sequential:
            for (std::uint32_t p = 0; p < num_pieces_ && int(result.size()) < count; ++p) try_new_piece(p);
            break;
        case PickMode::Random: {
            std::vector<std::uint32_t> cand;
            for (std::uint32_t p = 0; p < num_pieces_; ++p)
                if (wanted(p) && peer_has(p) && !downloading_.count(p)) cand.push_back(p);
            std::shuffle(cand.begin(), cand.end(), rng_);
            for (std::uint32_t p : cand) { if (int(result.size()) >= count) break; try_new_piece(p); }
            break;
        }
        case PickMode::RarestFirst:
            if (rarest_dirty_) rebuild_rarest_order();
            for (std::uint32_t p : rarest_order_) { if (int(result.size()) >= count) break; try_new_piece(p); }
            break;
    }
    if (int(result.size()) >= count) return result;

    // 3) End-game: every needed block this peer can offer is already requested
    // elsewhere — re-request outstanding blocks (but not ones already on this peer).
    bool used_endgame = false;
    for (const auto& [piece, dp] : downloading_) {
        if (int(result.size()) >= count) break;
        if (!wanted(piece) || !peer_has(piece)) continue;
        const std::uint32_t nblocks = blocks_in_piece(piece);
        for (std::uint32_t b = 0; b < nblocks && int(result.size()) < count; ++b) {
            const Block& blk = dp.blocks[b];
            if (blk.state != BlockState::Requested) continue;
            if (std::find(blk.peers.begin(), blk.peers.end(), peer) != blk.peers.end()) continue;
            result.push_back(PieceBlock{piece, b});
            used_endgame = true;
        }
    }
    if (used_endgame) endgame_ = true;
    return result;
}

} // namespace librats::bittorrent
