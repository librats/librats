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
    , order_pos_(num_pieces, 0)
    , in_order_(num_pieces, 0)
    , rng_(std::random_device{}()) {
    // Every piece starts wanted (Normal priority, not-have, availability 0), so it
    // all begins life in the single bucket {Normal, 0}.
    for (std::uint32_t p = 0; p < num_pieces_; ++p) order_insert(p);
}

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
    order_remove(piece);  // no longer wanted — pull it out of the rarest index
    have_.set(piece);
    ++num_have_;
    if (priority_[piece] != PiecePriority::DontDownload && pieces_left_ > 0) --pieces_left_;
    downloading_.erase(piece);
    // Advance the sequential cursor over any now-contiguous prefix of have pieces.
    while (seq_cursor_ < num_pieces_ && have_.get(seq_cursor_)) ++seq_cursor_;
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
    order_remove(piece);  // remove under the OLD key before the priority changes
    if (!have_.get(piece)) {
        const bool was_wanted = old != PiecePriority::DontDownload;
        const bool now_wanted = priority != PiecePriority::DontDownload;
        if (was_wanted && !now_wanted) { --pieces_left_; downloading_.erase(piece); }
        else if (!was_wanted && now_wanted) ++pieces_left_;
    }
    priority_[piece] = priority;
    order_insert(piece);  // re-file under the new key (no-op if it is now unwanted)
}

// ---- availability ----

void PiecePicker::peer_has_piece(std::uint32_t piece)  { avail_add(piece, +1); }
void PiecePicker::peer_lost_piece(std::uint32_t piece) { avail_add(piece, -1); }
void PiecePicker::inc_availability(const Bitfield& peer_have) {
    for (std::uint32_t p = 0; p < num_pieces_; ++p)
        if (peer_have.size() > p && peer_have.get(p)) avail_add(p, +1);
}
void PiecePicker::dec_availability(const Bitfield& peer_have) {
    for (std::uint32_t p = 0; p < num_pieces_; ++p)
        if (peer_have.size() > p && peer_have.get(p)) avail_add(p, -1);
}
// A seed has every piece. Bumping every piece's availability (O(n) plus a bucket
// move each) is wasted work: since a seed shifts *all* pieces equally, the
// rarest-first ordering is unchanged, so the bucket index (keyed on the per-peer
// count) needs no update at all. Track seeds as one counter instead — the
// effective availability of a piece is availability_[p] + seeds_ — making a seed
// joining or leaving O(1). (Mirrors libtorrent's m_seeds.)
void PiecePicker::inc_availability_all() { ++seeds_; }
void PiecePicker::dec_availability_all() { if (seeds_ > 0) --seeds_; }

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

std::vector<const void*> PiecePicker::mark_writing(const PieceBlock& b, const void* peer) {
    std::vector<const void*> others;
    auto it = downloading_.find(b.piece);
    if (it == downloading_.end()) return others;
    Block& blk = it->second.blocks[b.block];
    if (blk.state == BlockState::Requested) {
        --it->second.num_requested;
        blk.state = BlockState::Writing;
        ++it->second.num_writing;
        // Hand back the *other* requesters (end-game) so the caller can CANCEL the
        // now-redundant duplicate requests, then drop the requester set — the block
        // is in flight to disk and must not be picked or re-requested again.
        for (const void* p : blk.peers)
            if (p != peer) others.push_back(p);
        blk.peers.clear();
    }
    return others;
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

void PiecePicker::order_insert(std::uint32_t piece) {
    if (in_order_[piece] || !wanted(piece)) return;
    std::vector<std::uint32_t>& bucket = order_[order_key(piece)];
    order_pos_[piece] = std::uint32_t(bucket.size());
    bucket.push_back(piece);
    in_order_[piece] = 1;
}

void PiecePicker::order_remove(std::uint32_t piece) {
    if (!in_order_[piece]) return;
    auto it = order_.find(order_key(piece));  // key must match the one used at insert
    std::vector<std::uint32_t>& bucket = it->second;
    const std::uint32_t pos  = order_pos_[piece];
    const std::uint32_t last = bucket.back();
    bucket[pos] = last;            // swap the tail piece into the vacated slot...
    order_pos_[last] = pos;        // ...and fix up its recorded position
    bucket.pop_back();
    if (bucket.empty()) order_.erase(it);  // keep the map free of empty buckets
    in_order_[piece] = 0;
}

void PiecePicker::avail_add(std::uint32_t piece, int delta) {
    // Remove under the current key, change availability, then re-file under the new
    // key — an O(log n) bucket move. (For a have/unwanted piece the index ops are
    // no-ops; we still track its availability count.)
    order_remove(piece);
    if (delta >= 0) {
        availability_[piece] += std::uint32_t(delta);
    } else {
        const std::uint32_t d = std::uint32_t(-delta);
        availability_[piece] = availability_[piece] > d ? availability_[piece] - d : 0;
    }
    order_insert(piece);
}

std::vector<PieceBlock> PiecePicker::pick_blocks(const Bitfield& peer_have, int count, const void* peer) {
    std::vector<PieceBlock> result;
    if (count <= 0) return result;

    auto peer_has = [&](std::uint32_t p) { return peer_have.size() > p && peer_have.get(p); };

    // 1) Finish pieces already in progress that this peer can serve. In sequential
    // mode finish the earliest partial first (streaming order); otherwise the map
    // order is fine. (downloading_ is small — bounded by peers × pieces-in-flight.)
    auto take_partial = [&](std::uint32_t piece) {
        if (int(result.size()) >= count) return;
        if (!wanted(piece) || !peer_has(piece)) return;
        append_free_blocks(piece, count, peer, result);
    };
    if (mode_ == PickMode::Sequential) {
        std::vector<std::uint32_t> partials;
        partials.reserve(downloading_.size());
        for (const auto& kv : downloading_) partials.push_back(kv.first);
        std::sort(partials.begin(), partials.end());
        for (std::uint32_t piece : partials) {
            if (int(result.size()) >= count) break;
            take_partial(piece);
        }
    } else {
        for (const auto& [piece, dp] : downloading_) {
            if (int(result.size()) >= count) break;
            take_partial(piece);
        }
    }
    if (int(result.size()) >= count) return result;

    // 2) Start new pieces, ordered by the active strategy.
    auto try_new_piece = [&](std::uint32_t p) {
        if (!wanted(p) || !peer_has(p) || downloading_.count(p)) return;
        append_free_blocks(p, count, peer, result);
    };
    switch (mode_) {
        case PickMode::Sequential:
            // Start at the cursor: every piece below it is already have, so there
            // is nothing to pick there. This keeps the hot refill path off the
            // completed prefix instead of rescanning it from 0 every time.
            for (std::uint32_t p = seq_cursor_; p < num_pieces_ && int(result.size()) < count; ++p)
                try_new_piece(p);
            break;
        case PickMode::Random: {
            // Walk the rarest-first buckets — which already hold exactly the wanted
            // pieces — in a shuffled order, each entered at a random offset. That is
            // a random spread without scanning or allocating across all pieces (the
            // bucket set is small: one per distinct (priority, availability)).
            std::vector<std::vector<std::uint32_t>*> bkts;
            bkts.reserve(order_.size());
            for (auto& kv : order_) if (!kv.second.empty()) bkts.push_back(&kv.second);
            std::shuffle(bkts.begin(), bkts.end(), rng_);
            for (auto* bucket : bkts) {
                if (int(result.size()) >= count) break;
                const std::size_t n     = bucket->size();
                const std::size_t start = std::uniform_int_distribution<std::size_t>(0, n - 1)(rng_);
                for (std::size_t k = 0; k < n && int(result.size()) < count; ++k)
                    try_new_piece((*bucket)[(start + k) % n]);
            }
            break;
        }
        case PickMode::RarestFirst:
            // Buckets are visited best-first (highest priority, then rarest). Within
            // a bucket every piece is equally good, so start at a random offset and
            // wrap around: this spreads concurrent peers across the rarest pieces
            // instead of all converging on the same one — without any sorting here.
            for (auto& [key, bucket] : order_) {
                if (int(result.size()) >= count) break;
                if (bucket.empty()) continue;
                const std::size_t n     = bucket.size();
                const std::size_t start = std::uniform_int_distribution<std::size_t>(0, n - 1)(rng_);
                for (std::size_t k = 0; k < n && int(result.size()) < count; ++k)
                    try_new_piece(bucket[(start + k) % n]);
            }
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
