#include <gtest/gtest.h>

#include <cstdint>
#include <limits>

#include "bittorrent/file_storage.h"

using namespace librats::bittorrent;

TEST(BtFileStorage, EmptyIsInvalid) {
    FileStorage fs;
    EXPECT_FALSE(fs.is_valid());
    EXPECT_EQ(fs.total_size(), 0);
    EXPECT_EQ(fs.num_pieces(), 0u);
}

TEST(BtFileStorage, SingleFilePieceSizing) {
    FileStorage fs;
    fs.set_piece_length(1024);
    fs.set_name("file.bin");
    fs.add_file("file.bin", 2500);  // 2 full pieces + 452

    EXPECT_TRUE(fs.is_valid());
    EXPECT_EQ(fs.total_size(), 2500);
    EXPECT_EQ(fs.num_files(), 1u);
    EXPECT_EQ(fs.num_pieces(), 3u);
    EXPECT_EQ(fs.piece_size(0), 1024u);
    EXPECT_EQ(fs.piece_size(1), 1024u);
    EXPECT_EQ(fs.piece_size(2), 452u);   // short final piece
}

TEST(BtFileStorage, ExactMultipleHasNoShortPiece) {
    FileStorage fs;
    fs.set_piece_length(1000);
    fs.add_file("a", 3000);
    EXPECT_EQ(fs.num_pieces(), 3u);
    EXPECT_EQ(fs.piece_size(2), 1000u);
}

TEST(BtFileStorage, BlocksInPiece) {
    FileStorage fs;
    fs.set_piece_length(40 * 1024);  // 40 KiB = 2.5 blocks of 16 KiB
    fs.add_file("a", 40 * 1024);
    EXPECT_EQ(fs.blocks_in_piece(0), 3u);
}

TEST(BtFileStorage, FileOffsetsAreCumulative) {
    FileStorage fs;
    fs.set_piece_length(1024);
    fs.add_file("dir/a", 100);
    fs.add_file("dir/b", 200);
    fs.add_file("dir/c", 50);
    EXPECT_EQ(fs.file_at(0).offset, 0);
    EXPECT_EQ(fs.file_at(1).offset, 100);
    EXPECT_EQ(fs.file_at(2).offset, 300);
    EXPECT_EQ(fs.total_size(), 350);
}

TEST(BtFileStorage, MapBlockWithinSingleFile) {
    FileStorage fs;
    fs.set_piece_length(1024);
    fs.add_file("a", 4096);

    auto slices = fs.map_block(1, 0, 1024);  // piece 1 → bytes [1024,2048) of file 0
    ASSERT_EQ(slices.size(), 1u);
    EXPECT_EQ(slices[0].file_index, 0u);
    EXPECT_EQ(slices[0].offset, 1024);
    EXPECT_EQ(slices[0].size, 1024);
}

TEST(BtFileStorage, MapBlockAcrossFileBoundary) {
    FileStorage fs;
    fs.set_piece_length(1024);
    fs.add_file("a", 1500);   // [0,1500)
    fs.add_file("b", 1500);   // [1500,3000)

    // Piece 1 = torrent bytes [1024,2048) = 1024 bytes: 476 from 'a' [1024,1500),
    // then 548 from 'b' [1500,2048).
    auto slices = fs.map_block(1, 0, 1024);
    ASSERT_EQ(slices.size(), 2u);
    EXPECT_EQ(slices[0].file_index, 0u);
    EXPECT_EQ(slices[0].offset, 1024);
    EXPECT_EQ(slices[0].size, 476);
    EXPECT_EQ(slices[1].file_index, 1u);
    EXPECT_EQ(slices[1].offset, 0);
    EXPECT_EQ(slices[1].size, 548);
}

TEST(BtFileStorage, MapBlockClampsToTotalSize) {
    FileStorage fs;
    fs.set_piece_length(1024);
    fs.add_file("a", 1500);

    // Last piece is only 476 bytes; asking for a full block clamps.
    auto slices = fs.map_block(1, 0, 1024);
    ASSERT_EQ(slices.size(), 1u);
    EXPECT_EQ(slices[0].size, 476);
}

TEST(BtFileStorage, AddFileSucceedsForNormalSize) {
    FileStorage fs;
    EXPECT_TRUE(fs.add_file("a", 100));
    EXPECT_TRUE(fs.add_file("b", 0));   // zero-length is valid
    EXPECT_EQ(fs.total_size(), 100);
    EXPECT_EQ(fs.num_files(), 2u);
}

TEST(BtFileStorage, AddFileRejectsNegativeSize) {
    FileStorage fs;
    EXPECT_FALSE(fs.add_file("a", -1));
    // Rejected file must leave the layout completely unchanged.
    EXPECT_EQ(fs.num_files(), 0u);
    EXPECT_EQ(fs.total_size(), 0);
}

TEST(BtFileStorage, AddFileRejectsInt64Overflow) {
    constexpr std::int64_t kMax = std::numeric_limits<std::int64_t>::max();
    FileStorage fs;
    ASSERT_TRUE(fs.add_file("a", kMax - 10));   // near the ceiling

    // A second file whose size would push the running total past INT64_MAX must
    // be rejected instead of wrapping around into UB / a garbage total.
    EXPECT_FALSE(fs.add_file("b", 100));
    EXPECT_EQ(fs.num_files(), 1u);              // 'b' not added
    EXPECT_EQ(fs.total_size(), kMax - 10);      // total untouched

    // A file that exactly fits the remaining headroom still succeeds.
    EXPECT_TRUE(fs.add_file("c", 10));
    EXPECT_EQ(fs.total_size(), kMax);
}

TEST(BtFileStorage, MapBlockSkipsZeroLengthFiles) {
    FileStorage fs;
    fs.set_piece_length(1024);
    fs.add_file("a", 100);
    fs.add_file("empty", 0);   // shares offset 100 with the next file
    fs.add_file("b", 100);

    auto slices = fs.map_block(0, 50, 100);  // bytes [50,150): 50 from 'a', 50 from 'b'
    ASSERT_EQ(slices.size(), 2u);
    EXPECT_EQ(slices[0].file_index, 0u);
    EXPECT_EQ(slices[0].size, 50);
    EXPECT_EQ(slices[1].file_index, 2u);     // 'b', not the empty file
    EXPECT_EQ(slices[1].offset, 0);
    EXPECT_EQ(slices[1].size, 50);
}
