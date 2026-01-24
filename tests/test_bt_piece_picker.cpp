#include <gtest/gtest.h>
#include "bt_piece_picker.h"

using namespace librats;

//=============================================================================
// Construction Tests
//=============================================================================

TEST(BtPiecePickerTest, Construction) {
    PiecePicker picker(100, 16384, 8000);
    
    EXPECT_EQ(picker.num_pieces(), 100);
    EXPECT_EQ(picker.piece_length(), 16384);
    EXPECT_EQ(picker.num_have(), 0);
    EXPECT_EQ(picker.num_want(), 100);
    EXPECT_FALSE(picker.is_complete());
}

TEST(BtPiecePickerTest, BlocksInPiece) {
    // 16 KB pieces, last piece 8 KB
    PiecePicker picker(10, 16384, 8000);
    
    // Normal piece: 16384 / 16384 = 1 block
    EXPECT_EQ(picker.blocks_in_piece(0), 1);
    
    // Last piece: ceil(8000 / 16384) = 1 block
    EXPECT_EQ(picker.blocks_in_piece(9), 1);
}

TEST(BtPiecePickerTest, BlocksInLargePiece) {
    // 256 KB pieces (16 blocks of 16 KB each)
    PiecePicker picker(10, 262144, 100000);
    
    // Normal piece: ceil(262144 / 16384) = 16 blocks
    EXPECT_EQ(picker.blocks_in_piece(0), 16);
    
    // Last piece: ceil(100000 / 16384) = 7 blocks
    EXPECT_EQ(picker.blocks_in_piece(9), 7);
}

TEST(BtPiecePickerTest, BlockSize) {
    // 50000 byte pieces, last piece 30000 bytes
    PiecePicker picker(5, 50000, 30000);
    
    // First block in normal piece
    EXPECT_EQ(picker.block_size(0, 0), 16384);
    EXPECT_EQ(picker.block_size(0, 1), 16384);
    EXPECT_EQ(picker.block_size(0, 2), 16384);
    EXPECT_EQ(picker.block_size(0, 3), 50000 - 3 * 16384);  // 848 bytes
    
    // Last piece, last block
    // 30000 bytes = 1 full block + partial
    EXPECT_EQ(picker.block_size(4, 0), 16384);
    EXPECT_EQ(picker.block_size(4, 1), 30000 - 16384);  // 13616 bytes
}

//=============================================================================
// Have State Tests
//=============================================================================

TEST(BtPiecePickerTest, MarkHave) {
    PiecePicker picker(10, 16384, 16384);
    
    picker.mark_have(5);
    
    EXPECT_TRUE(picker.have_piece(5));
    EXPECT_FALSE(picker.have_piece(4));
    EXPECT_FALSE(picker.have_piece(6));
    EXPECT_EQ(picker.num_have(), 1);
    EXPECT_EQ(picker.num_want(), 9);
}

TEST(BtPiecePickerTest, HaveBitfield) {
    PiecePicker picker(10, 16384, 16384);
    
    picker.mark_have(0);
    picker.mark_have(5);
    picker.mark_have(9);
    
    Bitfield bf = picker.get_have_bitfield();
    EXPECT_EQ(bf.size(), 10);
    EXPECT_TRUE(bf.get_bit(0));
    EXPECT_FALSE(bf.get_bit(1));
    EXPECT_TRUE(bf.get_bit(5));
    EXPECT_TRUE(bf.get_bit(9));
}

TEST(BtPiecePickerTest, SetHaveBitfield) {
    PiecePicker picker(10, 16384, 16384);
    
    Bitfield bf(10);
    bf.set_bit(1);
    bf.set_bit(3);
    bf.set_bit(7);
    
    picker.set_have_bitfield(bf);
    
    EXPECT_EQ(picker.num_have(), 3);
    EXPECT_TRUE(picker.have_piece(1));
    EXPECT_TRUE(picker.have_piece(3));
    EXPECT_TRUE(picker.have_piece(7));
    EXPECT_FALSE(picker.have_piece(0));
}

TEST(BtPiecePickerTest, Complete) {
    PiecePicker picker(3, 16384, 16384);
    
    EXPECT_FALSE(picker.is_complete());
    
    picker.mark_have(0);
    picker.mark_have(1);
    EXPECT_FALSE(picker.is_complete());
    
    picker.mark_have(2);
    EXPECT_TRUE(picker.is_complete());
}

//=============================================================================
// Priority Tests
//=============================================================================

TEST(BtPiecePickerTest, PiecePriority) {
    PiecePicker picker(10, 16384, 16384);
    
    EXPECT_EQ(picker.piece_priority(0), PiecePriority::Normal);
    
    picker.set_piece_priority(5, PiecePriority::High);
    EXPECT_EQ(picker.piece_priority(5), PiecePriority::High);
    
    picker.set_piece_priority(5, PiecePriority::Skip);
    EXPECT_EQ(picker.piece_priority(5), PiecePriority::Skip);
}

TEST(BtPiecePickerTest, PiecePriorityRange) {
    PiecePicker picker(10, 16384, 16384);
    
    picker.set_piece_priority_range(3, 7, PiecePriority::High);
    
    EXPECT_EQ(picker.piece_priority(2), PiecePriority::Normal);
    EXPECT_EQ(picker.piece_priority(3), PiecePriority::High);
    EXPECT_EQ(picker.piece_priority(6), PiecePriority::High);
    EXPECT_EQ(picker.piece_priority(7), PiecePriority::Normal);
}

//=============================================================================
// Peer Availability Tests
//=============================================================================

TEST(BtPiecePickerTest, AddPeer) {
    PiecePicker picker(10, 16384, 16384);
    
    Bitfield peer_bf(10);
    peer_bf.set_bit(0);
    peer_bf.set_bit(5);
    peer_bf.set_bit(9);
    
    void* peer1 = reinterpret_cast<void*>(1);
    picker.add_peer(peer1, peer_bf);
    
    EXPECT_EQ(picker.availability(0), 1);
    EXPECT_EQ(picker.availability(1), 0);
    EXPECT_EQ(picker.availability(5), 1);
    EXPECT_EQ(picker.availability(9), 1);
}

TEST(BtPiecePickerTest, MultiplePeers) {
    PiecePicker picker(10, 16384, 16384);
    
    Bitfield peer1_bf(10);
    peer1_bf.set_bit(0);
    peer1_bf.set_bit(5);
    
    Bitfield peer2_bf(10);
    peer2_bf.set_bit(0);
    peer2_bf.set_bit(3);
    peer2_bf.set_bit(5);
    
    void* peer1 = reinterpret_cast<void*>(1);
    void* peer2 = reinterpret_cast<void*>(2);
    
    picker.add_peer(peer1, peer1_bf);
    picker.add_peer(peer2, peer2_bf);
    
    EXPECT_EQ(picker.availability(0), 2);
    EXPECT_EQ(picker.availability(3), 1);
    EXPECT_EQ(picker.availability(5), 2);
    EXPECT_EQ(picker.availability(7), 0);
}

TEST(BtPiecePickerTest, RemovePeer) {
    PiecePicker picker(10, 16384, 16384);
    
    Bitfield peer_bf(10);
    peer_bf.set_bit(0);
    peer_bf.set_bit(5);
    
    void* peer1 = reinterpret_cast<void*>(1);
    picker.add_peer(peer1, peer_bf);
    
    EXPECT_EQ(picker.availability(0), 1);
    EXPECT_EQ(picker.availability(5), 1);
    
    picker.remove_peer(peer1);
    
    EXPECT_EQ(picker.availability(0), 0);
    EXPECT_EQ(picker.availability(5), 0);
}

TEST(BtPiecePickerTest, PeerHasPiece) {
    PiecePicker picker(10, 16384, 16384);
    
    void* peer1 = reinterpret_cast<void*>(1);
    
    Bitfield empty_bf(10);
    picker.add_peer(peer1, empty_bf);
    
    EXPECT_EQ(picker.availability(5), 0);
    
    picker.peer_has_piece(peer1, 5);
    
    EXPECT_EQ(picker.availability(5), 1);
}

//=============================================================================
// Piece Picking Tests
//=============================================================================

TEST(BtPiecePickerTest, IsInteresting) {
    PiecePicker picker(10, 16384, 16384);
    
    // Peer has pieces 0, 5
    Bitfield peer_bf(10);
    peer_bf.set_bit(0);
    peer_bf.set_bit(5);
    
    EXPECT_TRUE(picker.is_interesting(peer_bf));
    
    // Mark those pieces as have
    picker.mark_have(0);
    picker.mark_have(5);
    
    EXPECT_FALSE(picker.is_interesting(peer_bf));
}

TEST(BtPiecePickerTest, PickPieceRarestFirst) {
    PiecePicker picker(10, 16384, 16384);
    picker.set_mode(PickerMode::RarestFirst);
    
    // Peer 1 has pieces 0, 1, 2
    Bitfield peer1_bf(10);
    peer1_bf.set_bit(0);
    peer1_bf.set_bit(1);
    peer1_bf.set_bit(2);
    
    // Peer 2 has pieces 0, 1
    Bitfield peer2_bf(10);
    peer2_bf.set_bit(0);
    peer2_bf.set_bit(1);
    
    void* peer1 = reinterpret_cast<void*>(1);
    void* peer2 = reinterpret_cast<void*>(2);
    
    picker.add_peer(peer1, peer1_bf);
    picker.add_peer(peer2, peer2_bf);
    
    // Piece 2 has availability 1, pieces 0,1 have availability 2
    // Should pick piece 2 (rarest)
    auto picked = picker.pick_piece(peer1_bf);
    ASSERT_TRUE(picked.has_value());
    EXPECT_EQ(*picked, 2);
}

TEST(BtPiecePickerTest, PickPieceSequential) {
    PiecePicker picker(10, 16384, 16384);
    picker.set_mode(PickerMode::Sequential);
    
    Bitfield peer_bf(10, true);  // Peer has all pieces
    
    void* peer1 = reinterpret_cast<void*>(1);
    picker.add_peer(peer1, peer_bf);
    
    // Should pick piece 0 first
    auto picked = picker.pick_piece(peer_bf);
    ASSERT_TRUE(picked.has_value());
    EXPECT_EQ(*picked, 0);
}

TEST(BtPiecePickerTest, PickPiecesReturnsBlocks) {
    // 4 pieces, each 32KB (2 blocks per piece)
    PiecePicker picker(4, 32768, 32768);
    
    Bitfield peer_bf(4, true);  // Peer has all pieces
    void* peer1 = reinterpret_cast<void*>(1);
    picker.add_peer(peer1, peer_bf);
    
    // Request 3 blocks
    auto blocks = picker.pick_pieces(peer_bf, 3, peer1);
    
    ASSERT_EQ(blocks.size(), 3);
    
    // All blocks should be valid
    for (const auto& req : blocks) {
        EXPECT_LT(req.block.piece_index, 4);
        EXPECT_EQ(req.block.offset % BT_BLOCK_SIZE, 0);
        EXPECT_GT(req.block.length, 0);
        EXPECT_LE(req.block.length, BT_BLOCK_SIZE);
    }
}

TEST(BtPiecePickerTest, SkippedPiecesNotPicked) {
    PiecePicker picker(5, 16384, 16384);
    
    // Skip pieces 0, 1, 2
    picker.set_piece_priority(0, PiecePriority::Skip);
    picker.set_piece_priority(1, PiecePriority::Skip);
    picker.set_piece_priority(2, PiecePriority::Skip);
    
    Bitfield peer_bf(5, true);
    void* peer1 = reinterpret_cast<void*>(1);
    picker.add_peer(peer1, peer_bf);
    
    auto picked = picker.pick_piece(peer_bf);
    ASSERT_TRUE(picked.has_value());
    EXPECT_GE(*picked, 3);  // Should be 3 or 4
}

//=============================================================================
// Block State Tests
//=============================================================================

TEST(BtPiecePickerTest, BlockStateTransitions) {
    PiecePicker picker(5, 32768, 32768);  // 2 blocks per piece
    
    Bitfield peer_bf(5, true);
    void* peer1 = reinterpret_cast<void*>(1);
    picker.add_peer(peer1, peer_bf);
    
    // Pick blocks
    auto blocks = picker.pick_pieces(peer_bf, 2, peer1);
    ASSERT_EQ(blocks.size(), 2);
    
    BlockInfo block0 = blocks[0].block;
    
    // Should be requested
    EXPECT_EQ(picker.block_state(block0), BlockState::Requested);
    
    // Mark as writing
    picker.mark_writing(block0);
    EXPECT_EQ(picker.block_state(block0), BlockState::Writing);
    
    // Mark as finished
    picker.mark_finished(block0);
    EXPECT_EQ(picker.block_state(block0), BlockState::Finished);
}

TEST(BtPiecePickerTest, CancelRequest) {
    PiecePicker picker(5, 16384, 16384);
    
    Bitfield peer_bf(5, true);
    void* peer1 = reinterpret_cast<void*>(1);
    picker.add_peer(peer1, peer_bf);
    
    auto blocks = picker.pick_pieces(peer_bf, 1, peer1);
    ASSERT_EQ(blocks.size(), 1);
    
    BlockInfo block = blocks[0].block;
    EXPECT_EQ(picker.block_state(block), BlockState::Requested);
    
    picker.cancel_request(block, peer1);
    EXPECT_EQ(picker.block_state(block), BlockState::None);
}

//=============================================================================
// Downloading Piece Tracking
//=============================================================================

TEST(BtPiecePickerTest, DownloadingPieces) {
    PiecePicker picker(10, 32768, 32768);  // 2 blocks per piece
    
    Bitfield peer_bf(10, true);
    void* peer1 = reinterpret_cast<void*>(1);
    picker.add_peer(peer1, peer_bf);
    
    EXPECT_EQ(picker.num_downloading(), 0);
    
    // Start downloading a piece
    auto blocks = picker.pick_pieces(peer_bf, 1, peer1);
    ASSERT_FALSE(blocks.empty());
    
    EXPECT_EQ(picker.num_downloading(), 1);
    
    auto downloading = picker.downloading_pieces();
    ASSERT_EQ(downloading.size(), 1);
    EXPECT_EQ(downloading[0].blocks_total, 2);
    EXPECT_EQ(downloading[0].blocks_requested, 1);
}

TEST(BtPiecePickerTest, PieceCompletionRemovesFromDownloading) {
    PiecePicker picker(5, 16384, 16384);  // 1 block per piece
    
    Bitfield peer_bf(5, true);
    void* peer1 = reinterpret_cast<void*>(1);
    picker.add_peer(peer1, peer_bf);
    
    auto blocks = picker.pick_pieces(peer_bf, 1, peer1);
    ASSERT_EQ(blocks.size(), 1);
    
    uint32_t piece = blocks[0].block.piece_index;
    EXPECT_EQ(picker.num_downloading(), 1);
    
    // Complete the piece
    bool complete = picker.mark_finished(blocks[0].block);
    EXPECT_TRUE(complete);
    
    // Mark piece as have
    picker.mark_have(piece);
    
    // Should be removed from downloading
    EXPECT_EQ(picker.num_downloading(), 0);
    EXPECT_TRUE(picker.have_piece(piece));
}

//=============================================================================
// Endgame Mode Tests
//=============================================================================

TEST(BtPiecePickerTest, EndgameMode) {
    PiecePicker picker(10, 16384, 16384);
    
    EXPECT_FALSE(picker.in_endgame_mode());
    
    // Mark most pieces as have
    for (uint32_t i = 0; i < 9; ++i) {
        picker.mark_have(i);
    }
    
    // Start downloading last piece
    Bitfield peer_bf(10, true);
    void* peer1 = reinterpret_cast<void*>(1);
    picker.add_peer(peer1, peer_bf);
    
    auto blocks = picker.pick_pieces(peer_bf, 1, peer1);
    
    // Mark one block finished to trigger endgame check
    if (!blocks.empty()) {
        picker.mark_finished(blocks[0].block);
    }
    
    EXPECT_TRUE(picker.in_endgame_mode());
}

TEST(BtPiecePickerTest, DisableEndgame) {
    PiecePicker picker(10, 16384, 16384);
    
    picker.set_endgame_mode(false);
    
    // Mark most pieces as have
    for (uint32_t i = 0; i < 9; ++i) {
        picker.mark_have(i);
    }
    
    // Start downloading last piece
    Bitfield peer_bf(10, true);
    void* peer1 = reinterpret_cast<void*>(1);
    picker.add_peer(peer1, peer_bf);
    
    auto blocks = picker.pick_pieces(peer_bf, 1, peer1);
    if (!blocks.empty()) {
        picker.mark_finished(blocks[0].block);
    }
    
    // Should not enter endgame
    EXPECT_FALSE(picker.in_endgame_mode());
}

//=============================================================================
// Edge Cases
//=============================================================================

TEST(BtPiecePickerTest, PickFromEmptyPeer) {
    PiecePicker picker(10, 16384, 16384);
    
    Bitfield empty_bf(10);  // Peer has nothing
    
    auto picked = picker.pick_piece(empty_bf);
    EXPECT_FALSE(picked.has_value());
    
    void* peer1 = reinterpret_cast<void*>(1);
    auto blocks = picker.pick_pieces(empty_bf, 5, peer1);
    EXPECT_TRUE(blocks.empty());
}

TEST(BtPiecePickerTest, AllPiecesHave) {
    PiecePicker picker(5, 16384, 16384);
    
    for (uint32_t i = 0; i < 5; ++i) {
        picker.mark_have(i);
    }
    
    Bitfield peer_bf(5, true);
    
    EXPECT_FALSE(picker.is_interesting(peer_bf));
    
    auto picked = picker.pick_piece(peer_bf);
    EXPECT_FALSE(picked.has_value());
}

TEST(BtPiecePickerTest, OutOfBoundsHandling) {
    PiecePicker picker(10, 16384, 16384);
    
    // Out of bounds piece operations should not crash
    picker.mark_have(100);
    EXPECT_FALSE(picker.have_piece(100));
    
    picker.set_piece_priority(100, PiecePriority::High);
    EXPECT_EQ(picker.piece_priority(100), PiecePriority::Normal);  // Default
    
    EXPECT_EQ(picker.availability(100), 0);
    EXPECT_EQ(picker.blocks_in_piece(100), 0);
}

//=============================================================================
// Mode Switching
//=============================================================================

TEST(BtPiecePickerTest, ModeSwitching) {
    PiecePicker picker(10, 16384, 16384);
    
    EXPECT_EQ(picker.mode(), PickerMode::RarestFirst);
    
    picker.set_mode(PickerMode::Sequential);
    EXPECT_EQ(picker.mode(), PickerMode::Sequential);
    
    picker.set_mode(PickerMode::Random);
    EXPECT_EQ(picker.mode(), PickerMode::Random);
}
