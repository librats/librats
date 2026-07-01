#include <gtest/gtest.h>

#include "bittorrent/piece_picker.h"
#include "bittorrent/types.h"

#include <algorithm>
#include <set>

using namespace librats::bittorrent;

namespace {

// Distinct dummy peer identities.
const void* const PEER_A = reinterpret_cast<const void*>(0x1);
const void* const PEER_B = reinterpret_cast<const void*>(0x2);

// A peer that has every piece.
Bitfield seeder(std::uint32_t n) { return Bitfield(n, true); }

constexpr std::uint32_t kPiece = 32768;  // 2 blocks of 16 KiB per piece

} // namespace

TEST(BtPiecePicker, Geometry) {
    PiecePicker pp(3, kPiece, std::int64_t(kPiece) * 2 + 5000);  // last piece short
    EXPECT_EQ(pp.num_pieces(), 3u);
    EXPECT_EQ(pp.piece_size(0), kPiece);
    EXPECT_EQ(pp.piece_size(2), 5000u);
    EXPECT_EQ(pp.blocks_in_piece(0), 2u);
    EXPECT_EQ(pp.blocks_in_piece(2), 1u);
    EXPECT_EQ(pp.block_size(0, 0), kBlockSize);
    EXPECT_EQ(pp.block_size(0, 1), kBlockSize);
    EXPECT_EQ(pp.block_size(2, 0), 5000u);
}

TEST(BtPiecePicker, HaveAndFinished) {
    PiecePicker pp(4, kPiece, std::int64_t(kPiece) * 4);
    EXPECT_FALSE(pp.is_finished());
    EXPECT_EQ(pp.num_have(), 0u);

    pp.we_have(1);
    EXPECT_TRUE(pp.have_piece(1));
    EXPECT_EQ(pp.num_have(), 1u);
    EXPECT_FALSE(pp.is_finished());

    pp.we_have_all();
    EXPECT_EQ(pp.num_have(), 4u);
    EXPECT_TRUE(pp.is_finished());
}

TEST(BtPiecePicker, SetHaveBitfield) {
    PiecePicker pp(4, kPiece, std::int64_t(kPiece) * 4);
    Bitfield have(4, false);
    have.set(0);
    have.set(2);
    pp.set_have_bitfield(have);
    EXPECT_EQ(pp.num_have(), 2u);
    EXPECT_TRUE(pp.have_piece(0));
    EXPECT_FALSE(pp.have_piece(1));
    EXPECT_TRUE(pp.have_piece(2));
}

TEST(BtPiecePicker, Availability) {
    PiecePicker pp(3, kPiece, std::int64_t(kPiece) * 3);
    pp.peer_has_piece(1);
    pp.peer_has_piece(1);
    EXPECT_EQ(pp.availability(1), 2u);
    pp.peer_lost_piece(1);
    EXPECT_EQ(pp.availability(1), 1u);

    Bitfield bf(3, false);
    bf.set(0);
    bf.set(2);
    pp.inc_availability(bf);
    EXPECT_EQ(pp.availability(0), 1u);
    EXPECT_EQ(pp.availability(2), 1u);
    pp.dec_availability(bf);
    EXPECT_EQ(pp.availability(0), 0u);

    pp.inc_availability_all();
    EXPECT_EQ(pp.availability(0), 1u);
    EXPECT_EQ(pp.availability(1), 2u);
}

TEST(BtPiecePicker, RarestFirstPicksRarest) {
    PiecePicker pp(4, kPiece, std::int64_t(kPiece) * 4);
    // Distinct availabilities so order is unambiguous: piece 1 is rarest.
    for (int i = 0; i < 3; ++i) pp.peer_has_piece(0);
    pp.peer_has_piece(1);
    for (int i = 0; i < 2; ++i) pp.peer_has_piece(2);
    for (int i = 0; i < 4; ++i) pp.peer_has_piece(3);

    auto picked = pp.pick_blocks(seeder(4), 1, PEER_A);
    ASSERT_EQ(picked.size(), 1u);
    EXPECT_EQ(picked[0].piece, 1u);  // availability 1, the rarest
}

TEST(BtPiecePicker, HighPriorityBeatsRarity) {
    PiecePicker pp(3, kPiece, std::int64_t(kPiece) * 3);
    pp.peer_has_piece(0);                      // availability 1 (rarest)
    for (int i = 0; i < 5; ++i) pp.peer_has_piece(2);
    pp.set_piece_priority(2, PiecePriority::High);

    auto picked = pp.pick_blocks(seeder(3), 1, PEER_A);
    ASSERT_FALSE(picked.empty());
    EXPECT_EQ(picked[0].piece, 2u);            // High priority wins over rarer piece 0
}

TEST(BtPiecePicker, SequentialPicksLowestIndex) {
    PiecePicker pp(4, kPiece, std::int64_t(kPiece) * 4);
    pp.set_mode(PickMode::Sequential);
    auto picked = pp.pick_blocks(seeder(4), 1, PEER_A);
    ASSERT_EQ(picked.size(), 1u);
    EXPECT_EQ(picked[0].piece, 0u);
    EXPECT_EQ(picked[0].block, 0u);
}

TEST(BtPiecePicker, DontDownloadIsSkipped) {
    PiecePicker pp(3, kPiece, std::int64_t(kPiece) * 3);
    pp.set_mode(PickMode::Sequential);
    pp.set_piece_priority(0, PiecePriority::DontDownload);

    auto picked = pp.pick_blocks(seeder(3), 1, PEER_A);
    ASSERT_FALSE(picked.empty());
    EXPECT_EQ(picked[0].piece, 1u);  // piece 0 excluded
}

TEST(BtPiecePicker, OnlyPicksBlocksPeerHas) {
    PiecePicker pp(3, kPiece, std::int64_t(kPiece) * 3);
    pp.set_mode(PickMode::Sequential);
    Bitfield only2(3, false);
    only2.set(2);
    auto picked = pp.pick_blocks(only2, 4, PEER_A);
    ASSERT_FALSE(picked.empty());
    for (const auto& b : picked) EXPECT_EQ(b.piece, 2u);
}

TEST(BtPiecePicker, IsInteresting) {
    PiecePicker pp(2, kPiece, std::int64_t(kPiece) * 2);
    Bitfield has0(2, false);
    has0.set(0);
    EXPECT_TRUE(pp.is_interesting(has0));
    pp.we_have(0);
    EXPECT_FALSE(pp.is_interesting(has0));  // we already have the only piece it offers
}

TEST(BtPiecePicker, PieceInteresting) {
    // The O(1) single-piece interest query used on each incoming HAVE. It must
    // agree with is_interesting() for a peer holding exactly that one piece.
    PiecePicker pp(3, kPiece, std::int64_t(kPiece) * 3);
    EXPECT_TRUE(pp.piece_interesting(0));   // fresh, wanted piece
    EXPECT_TRUE(pp.piece_interesting(2));

    pp.we_have(1);
    EXPECT_FALSE(pp.piece_interesting(1));   // already have it — not interesting

    pp.set_piece_priority(2, PiecePriority::DontDownload);
    EXPECT_FALSE(pp.piece_interesting(2));   // excluded from download

    EXPECT_FALSE(pp.piece_interesting(3));   // out of range → false, no OOB access
    EXPECT_TRUE(pp.piece_interesting(0));    // piece 0 still wanted
}

TEST(BtPiecePicker, BlockStateMachine) {
    PiecePicker pp(1, kPiece, kPiece);  // 1 piece, 2 blocks
    PieceBlock b0{0, 0}, b1{0, 1};

    EXPECT_EQ(pp.block_state(0, 0), BlockState::None);
    pp.mark_requested(b0, PEER_A);
    EXPECT_EQ(pp.block_state(0, 0), BlockState::Requested);
    pp.mark_writing(b0, PEER_A);
    EXPECT_EQ(pp.block_state(0, 0), BlockState::Writing);
    EXPECT_FALSE(pp.mark_finished(b0));  // piece not complete yet (block 1 outstanding)
    EXPECT_EQ(pp.block_state(0, 0), BlockState::Finished);

    pp.mark_requested(b1, PEER_A);
    EXPECT_TRUE(pp.mark_finished(b1));   // now the whole piece is finished
}

TEST(BtPiecePicker, DoesNotRepickRequestedBlocks) {
    PiecePicker pp(1, kPiece, kPiece);  // 2 blocks
    auto first = pp.pick_blocks(seeder(1), 2, PEER_A);
    ASSERT_EQ(first.size(), 2u);
    for (const auto& b : first) pp.mark_requested(b, PEER_A);

    // A second, different peer should find nothing free (not yet end-game-eligible
    // because it IS — all blocks are requested; see EndGame test). Here we confirm
    // the same peer won't be handed its own outstanding blocks again.
    auto again = pp.pick_blocks(seeder(1), 2, PEER_A);
    EXPECT_TRUE(again.empty());
}

TEST(BtPiecePicker, PrefersPartialPieces) {
    PiecePicker pp(4, kPiece, std::int64_t(kPiece) * 4);
    pp.set_mode(PickMode::Sequential);
    // Start piece 2 (request block 0); its block 1 is still free.
    pp.mark_requested(PieceBlock{2, 0}, PEER_A);

    auto picked = pp.pick_blocks(seeder(4), 1, PEER_B);
    ASSERT_EQ(picked.size(), 1u);
    EXPECT_EQ(picked[0].piece, 2u);  // finish the partial before starting piece 0
    EXPECT_EQ(picked[0].block, 1u);
}

TEST(BtPiecePicker, AbortFreesBlock) {
    PiecePicker pp(1, kPiece, kPiece);
    PieceBlock b{0, 0};
    pp.mark_requested(b, PEER_A);
    pp.abort_block(b, PEER_A);
    EXPECT_EQ(pp.block_state(0, 0), BlockState::None);
}

TEST(BtPiecePicker, CancelPeerFreesItsBlocks) {
    PiecePicker pp(1, kPiece, kPiece);
    pp.mark_requested(PieceBlock{0, 0}, PEER_A);
    pp.mark_requested(PieceBlock{0, 1}, PEER_B);
    pp.cancel_peer(PEER_A);
    EXPECT_EQ(pp.block_state(0, 0), BlockState::None);       // A's block freed
    EXPECT_EQ(pp.block_state(0, 1), BlockState::Requested);  // B's untouched
}

TEST(BtPiecePicker, RestorePieceResets) {
    PiecePicker pp(1, kPiece, kPiece);
    pp.mark_requested(PieceBlock{0, 0}, PEER_A);
    pp.mark_finished(PieceBlock{0, 0});
    pp.restore_piece(0);
    EXPECT_EQ(pp.block_state(0, 0), BlockState::None);
    EXPECT_EQ(pp.num_downloading(), 0u);
}

TEST(BtPiecePicker, EndGameReRequestsOutstanding) {
    PiecePicker pp(1, kPiece, kPiece);  // 2 blocks, single piece
    auto a = pp.pick_blocks(seeder(1), 2, PEER_A);
    ASSERT_EQ(a.size(), 2u);
    for (const auto& b : a) pp.mark_requested(b, PEER_A);
    EXPECT_FALSE(pp.in_endgame());

    // Peer B has nothing free left; end-game lets it re-request A's blocks.
    auto b = pp.pick_blocks(seeder(1), 2, PEER_B);
    EXPECT_EQ(b.size(), 2u);
    EXPECT_TRUE(pp.in_endgame());
}

TEST(BtPiecePicker, EndGameMarkWritingCancelsOtherPeers) {
    PiecePicker pp(1, kPiece, kPiece);  // 2 blocks, single piece
    const PieceBlock b0{0, 0};
    // End-game: both peers have the same block outstanding.
    pp.mark_requested(b0, PEER_A);
    pp.mark_requested(b0, PEER_B);

    // The block arrives from A: B is handed back so the caller can CANCEL its now
    // redundant request, and the requester set is cleared (block is being written).
    auto others = pp.mark_writing(b0, PEER_A);
    ASSERT_EQ(others.size(), 1u);
    EXPECT_EQ(others[0], PEER_B);
    EXPECT_EQ(pp.block_state(0, 0), BlockState::Writing);

    // A duplicate arrival from B (its PIECE crossing our CANCEL) is a no-op: the
    // block is already Writing, so there is nothing left to cancel.
    auto none = pp.mark_writing(b0, PEER_B);
    EXPECT_TRUE(none.empty());
}

TEST(BtPiecePicker, MarkWritingNoDuplicatesReturnsEmpty) {
    PiecePicker pp(1, kPiece, kPiece);
    const PieceBlock b0{0, 0};
    pp.mark_requested(b0, PEER_A);          // the common case: a single requester
    auto others = pp.mark_writing(b0, PEER_A);
    EXPECT_TRUE(others.empty());            // nothing to cancel
}

// The rarest-first index is maintained incrementally (a single HAVE is an O(log n)
// bucket move, not a full re-sort). These tests pin that the index still reflects
// the true rarest piece after availability churn — i.e. the incremental moves stay
// consistent with a from-scratch sort.

TEST(BtPiecePicker, IncrementalRarestUpdateAfterChanges) {
    PiecePicker pp(3, kPiece, std::int64_t(kPiece) * 3);
    pp.peer_has_piece(1); pp.peer_has_piece(1);  // piece 1 -> availability 2
    pp.peer_has_piece(2); pp.peer_has_piece(2);  // piece 2 -> availability 2
    pp.peer_has_piece(0);                         // piece 0 -> availability 1 (rarest)
    {
        auto picked = pp.pick_blocks(seeder(3), 1, PEER_A);
        ASSERT_FALSE(picked.empty());
        EXPECT_EQ(picked[0].piece, 0u);
    }
    // Now flip it: piece 0 becomes common, piece 2 becomes the rarest. No explicit
    // rebuild happens — the bucket moves alone must produce the new ordering.
    pp.peer_has_piece(0); pp.peer_has_piece(0); pp.peer_has_piece(0);  // piece 0 -> 4
    pp.peer_lost_piece(2);                                              // piece 2 -> 1 (rarest)
    {
        auto picked = pp.pick_blocks(seeder(3), 1, PEER_B);
        ASSERT_FALSE(picked.empty());
        EXPECT_EQ(picked[0].piece, 2u);
    }
}

TEST(BtPiecePicker, IndexSurvivesHaveAndAvailabilityChurn) {
    PiecePicker pp(4, kPiece, std::int64_t(kPiece) * 4);
    pp.peer_has_piece(0); pp.peer_has_piece(1); pp.peer_has_piece(2); pp.peer_has_piece(3);
    pp.we_have(0);  // pieces 0 and 2 leave the index (no longer wanted)
    pp.we_have(2);
    // Churn availability around the removed pieces — swap-removal bookkeeping must
    // not corrupt the surviving buckets.
    pp.peer_lost_piece(1);                       // piece 1 -> availability 0
    pp.peer_has_piece(3); pp.peer_has_piece(3);  // piece 3 -> availability 3
    auto picked = pp.pick_blocks(seeder(4), 1, PEER_A);
    ASSERT_FALSE(picked.empty());
    EXPECT_EQ(picked[0].piece, 1u);  // only 1 and 3 remain wanted; 1 is rarer
}

TEST(BtPiecePicker, RarestFillsAcrossEqualAvailabilityBucket) {
    // All five pieces share one bucket (availability 0). Filling 6 blocks must draw
    // from three distinct pieces (2 blocks each) with no duplicates, despite the
    // random in-bucket rotation.
    PiecePicker pp(5, kPiece, std::int64_t(kPiece) * 5);
    auto picked = pp.pick_blocks(seeder(5), 6, PEER_A);
    ASSERT_EQ(picked.size(), 6u);
    std::set<std::pair<std::uint32_t, std::uint32_t>> uniq;
    for (const auto& b : picked) uniq.insert({b.piece, b.block});
    EXPECT_EQ(uniq.size(), 6u);  // all distinct (piece, block)
}

TEST(BtPiecePicker, PriorityChangeUpdatesPiecesLeft) {
    PiecePicker pp(3, kPiece, std::int64_t(kPiece) * 3);
    EXPECT_FALSE(pp.is_finished());
    pp.set_piece_priority(0, PiecePriority::DontDownload);
    pp.set_piece_priority(1, PiecePriority::DontDownload);
    pp.set_piece_priority(2, PiecePriority::DontDownload);
    EXPECT_TRUE(pp.is_finished());  // nothing wanted => finished
}
