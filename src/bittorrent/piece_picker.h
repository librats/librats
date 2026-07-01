#pragma once

/**
 * @file piece_picker.h
 * @brief Decides which blocks to request next — the download strategy core.
 *
 * The picker tracks, for every piece: how many connected peers have it
 * (availability), our download priority for it, whether we already have it, and
 * — for pieces in progress — the per-block state machine
 * (None → Requested → Writing → Finished). pick_blocks() turns all of that into
 * a concrete list of blocks to ask a given peer for, honouring:
 *
 *   1. partial pieces first  — finish what's already started;
 *   2. the active strategy   — rarest-first (default), sequential or random;
 *   3. end-game              — once every needed block is already in flight,
 *                              re-request outstanding blocks from other peers.
 *
 * pick_blocks() is a pure query: it never mutates state. The caller commits its
 * choices with mark_requested(), so the two-queue request pipeline (reserved vs
 * in-flight) stays in the peer connection. Owned by one torrent on the network
 * thread — not thread-safe by design.
 */

#include "bittorrent/bitfield.h"

#include <cstdint>
#include <map>
#include <random>
#include <unordered_map>
#include <utility>
#include <vector>

namespace librats::bittorrent {

enum class PiecePriority : std::uint8_t {
    DontDownload = 0,  ///< excluded from picking
    Normal       = 1,
    High         = 2,
};

enum class PickMode : std::uint8_t {
    RarestFirst,  ///< default — fewest-available pieces first
    Sequential,   ///< lowest piece index first (streaming)
    Random,
};

enum class BlockState : std::uint8_t {
    None,       ///< not requested
    Requested,  ///< asked a peer, awaiting data
    Writing,    ///< received, being written to disk
    Finished,   ///< on disk
};

/// A single 16 KiB block, identified by its piece and its index within it.
struct PieceBlock {
    std::uint32_t piece = 0;
    std::uint32_t block = 0;
    bool operator==(const PieceBlock& o) const noexcept { return piece == o.piece && block == o.block; }
    bool operator!=(const PieceBlock& o) const noexcept { return !(*this == o); }
};

class PiecePicker {
public:
    PiecePicker(std::uint32_t num_pieces, std::uint32_t piece_length, std::int64_t total_size);

    // ---- geometry ----
    std::uint32_t num_pieces()       const noexcept { return num_pieces_; }
    std::uint32_t piece_length()     const noexcept { return piece_length_; }
    std::uint32_t piece_size(std::uint32_t piece)      const noexcept;
    std::uint32_t blocks_in_piece(std::uint32_t piece) const noexcept;
    std::uint32_t block_size(std::uint32_t piece, std::uint32_t block) const noexcept;

    // ---- our progress ----
    void          we_have(std::uint32_t piece);
    void          we_have_all();
    bool          have_piece(std::uint32_t piece) const noexcept { return have_.get(piece); }
    std::uint32_t num_have() const noexcept { return num_have_; }
    bool          is_finished() const noexcept { return pieces_left_ == 0; }
    Bitfield      have_bitfield() const { return have_; }
    void          set_have_bitfield(const Bitfield& have);

    // ---- priorities ----
    void          set_piece_priority(std::uint32_t piece, PiecePriority priority);
    PiecePriority piece_priority(std::uint32_t piece) const noexcept { return priority_[piece]; }

    // ---- strategy ----
    void     set_mode(PickMode mode) noexcept { mode_ = mode; }
    PickMode mode() const noexcept { return mode_; }

    // ---- peer availability ----
    void          peer_has_piece(std::uint32_t piece);
    void          peer_lost_piece(std::uint32_t piece);
    void          inc_availability(const Bitfield& peer_have);
    void          dec_availability(const Bitfield& peer_have);
    void          inc_availability_all();   ///< a seed joined
    void          dec_availability_all();
    /// Effective availability: per-peer count plus the number of connected seeds
    /// (seeds are tracked as one counter — see inc_availability_all).
    std::uint32_t availability(std::uint32_t piece) const noexcept { return availability_[piece] + seeds_; }

    // ---- block state machine ----
    /// Up to @p count blocks that @p peer (holding @p peer_have) can serve and we
    /// still need. Pure query — commit with mark_requested().
    std::vector<PieceBlock> pick_blocks(const Bitfield& peer_have, int count, const void* peer);

    void mark_requested(const PieceBlock& b, const void* peer);
    /// Mark a received block as being written to disk. Returns the *other* peers
    /// that also had this block requested (end-game duplicates) so the caller can
    /// send them CANCEL; the block's requester set is then cleared. Empty in the
    /// common, non-end-game case where only the delivering peer had it.
    std::vector<const void*> mark_writing(const PieceBlock& b, const void* peer);
    /// Mark a block on disk. Returns true if this completed the piece (all blocks
    /// finished → ready to hash).
    bool mark_finished(const PieceBlock& b);
    /// A request failed/was rejected: drop @p peer from the block, freeing it if no
    /// other peer is still on it.
    void abort_block(const PieceBlock& b, const void* peer);
    /// A peer vanished: free every block it had outstanding.
    void cancel_peer(const void* peer);
    /// Hash check failed: throw away a piece's block progress so it is re-downloaded.
    void restore_piece(std::uint32_t piece);

    BlockState block_state(std::uint32_t piece, std::uint32_t block) const;
    bool       is_interesting(const Bitfield& peer_have) const;
    /// True if @p piece is one we still want (not have, not DontDownload). O(1).
    /// A peer that has this piece is therefore interesting to us — this lets the
    /// interest update on a single HAVE stay O(1) instead of rescanning the whole
    /// bitfield through is_interesting().
    bool       piece_interesting(std::uint32_t piece) const noexcept {
        return piece < num_pieces_ && wanted(piece);
    }
    bool       in_endgame() const noexcept { return endgame_; }
    std::size_t num_downloading() const noexcept { return downloading_.size(); }

private:
    struct Block {
        BlockState                  state = BlockState::None;
        std::vector<const void*>    peers;   ///< requesters (>1 only in end-game)
    };
    struct DownloadingPiece {
        std::vector<Block> blocks;
        std::uint16_t      num_requested = 0;
        std::uint16_t      num_writing   = 0;
        std::uint16_t      num_finished  = 0;
    };

    bool wanted(std::uint32_t piece) const noexcept {
        return priority_[piece] != PiecePriority::DontDownload && !have_.get(piece);
    }
    DownloadingPiece& downloading_for(std::uint32_t piece);
    void append_free_blocks(std::uint32_t piece, int count, const void* peer,
                            std::vector<PieceBlock>& out) const;

    // ---- incremental rarest-first index ----
    // Every wanted & not-yet-have piece sits in a bucket keyed by
    // (priority desc, availability asc). A single availability or priority change
    // is an O(log n) bucket move (order_remove + order_insert) instead of a full
    // re-sort; pick_blocks() walks the buckets in map order, which is exactly
    // best-first (highest priority, then rarest).
    std::pair<int, std::uint32_t> order_key(std::uint32_t piece) const noexcept {
        // Negate priority so the higher enum value (High) compares *less* and is
        // visited first by the ascending std::map.
        return { -int(priority_[piece]), availability_[piece] };
    }
    void order_insert(std::uint32_t piece);   ///< add piece to its bucket (if wanted & absent)
    void order_remove(std::uint32_t piece);   ///< pull piece out of its current bucket (if present)
    void avail_add(std::uint32_t piece, int delta);  ///< change availability, keeping the index sorted

    std::uint32_t num_pieces_;
    std::uint32_t piece_length_;
    std::int64_t  total_size_;

    std::vector<std::uint32_t>  availability_;
    std::vector<PiecePriority>  priority_;
    Bitfield                    have_;
    std::uint32_t               num_have_    = 0;
    std::uint32_t               pieces_left_ = 0;   ///< wanted & not-yet-have
    PickMode                    mode_        = PickMode::RarestFirst;
    bool                        endgame_     = false;
    // Sequential cursor: every piece with index < seq_cursor_ is already `have`,
    // so a sequential pick can start here instead of rescanning the completed
    // prefix from 0 on every refill. Maintained only in we_have() (advances
    // monotonically, O(n) total over the whole download).
    std::uint32_t               seq_cursor_  = 0;
    // Number of connected seeds (peers that have everything). Tracked as one
    // counter instead of +1 on every piece; folded into availability().
    std::uint32_t               seeds_       = 0;

    std::unordered_map<std::uint32_t, DownloadingPiece> downloading_;

    // Incremental rarest-first index: (priority desc, availability asc) -> pieces.
    // order_pos_[p] is p's slot within its bucket (for O(1) swap-removal);
    // in_order_[p] records whether p is currently bucketed at all.
    std::map<std::pair<int, std::uint32_t>, std::vector<std::uint32_t>> order_;
    std::vector<std::uint32_t> order_pos_;
    std::vector<std::uint8_t>  in_order_;
    mutable std::mt19937       rng_;
};

} // namespace librats::bittorrent
