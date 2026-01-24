#include <gtest/gtest.h>
#include "bt_file_storage.h"

using namespace librats;

//=============================================================================
// Construction Tests
//=============================================================================

TEST(BtFileStorageTest, DefaultConstructor) {
    FileStorage fs;
    EXPECT_EQ(fs.num_files(), 0);
    EXPECT_EQ(fs.total_size(), 0);
    EXPECT_EQ(fs.piece_length(), 0);
    EXPECT_EQ(fs.num_pieces(), 0);
    EXPECT_TRUE(fs.empty());
    EXPECT_FALSE(fs.is_finalized());
}

TEST(BtFileStorageTest, ConstructorWithPieceLength) {
    FileStorage fs(16384);
    EXPECT_EQ(fs.piece_length(), 16384);
    EXPECT_EQ(fs.num_files(), 0);
}

//=============================================================================
// File Management Tests
//=============================================================================

TEST(BtFileStorageTest, AddSingleFile) {
    FileStorage fs(16384);
    fs.add_file("test.txt", 1000);
    fs.finalize();
    
    EXPECT_EQ(fs.num_files(), 1);
    EXPECT_EQ(fs.total_size(), 1000);
    EXPECT_EQ(fs.num_pieces(), 1);
    
    const FileEntry& entry = fs.file_at(0);
    EXPECT_EQ(entry.path, "test.txt");
    EXPECT_EQ(entry.size, 1000);
    EXPECT_EQ(entry.offset, 0);
}

TEST(BtFileStorageTest, AddMultipleFiles) {
    FileStorage fs(16384);
    fs.add_file("file1.txt", 10000);
    fs.add_file("file2.txt", 20000);
    fs.add_file("file3.txt", 5000);
    fs.finalize();
    
    EXPECT_EQ(fs.num_files(), 3);
    EXPECT_EQ(fs.total_size(), 35000);
    
    EXPECT_EQ(fs.file_at(0).offset, 0);
    EXPECT_EQ(fs.file_at(1).offset, 10000);
    EXPECT_EQ(fs.file_at(2).offset, 30000);
}

TEST(BtFileStorageTest, AddFileWithAttributes) {
    FileStorage fs(16384);
    fs.add_file("script.sh", 500, false, true, false);  // executable
    fs.add_file("hidden.txt", 300, false, false, true); // hidden
    fs.add_file(".padding", 100, true, false, false);   // pad file
    fs.finalize();
    
    EXPECT_TRUE(fs.file_at(0).executable);
    EXPECT_FALSE(fs.file_at(0).hidden);
    
    EXPECT_FALSE(fs.file_at(1).executable);
    EXPECT_TRUE(fs.file_at(1).hidden);
    
    EXPECT_TRUE(fs.file_at(2).pad_file);
}

TEST(BtFileStorageTest, NumPiecesCalculation) {
    FileStorage fs(16384);  // 16 KB pieces
    
    // Exactly one piece
    fs.add_file("file.txt", 16384);
    fs.finalize();
    EXPECT_EQ(fs.num_pieces(), 1);
}

TEST(BtFileStorageTest, NumPiecesWithRemainder) {
    FileStorage fs(16384);  // 16 KB pieces
    
    // One full piece + partial
    fs.add_file("file.txt", 20000);
    fs.finalize();
    EXPECT_EQ(fs.num_pieces(), 2);
}

TEST(BtFileStorageTest, PieceSize) {
    FileStorage fs(16384);
    fs.add_file("file.txt", 40000);  // 2 full pieces + partial
    fs.finalize();
    
    EXPECT_EQ(fs.num_pieces(), 3);
    EXPECT_EQ(fs.piece_size(0), 16384);
    EXPECT_EQ(fs.piece_size(1), 16384);
    EXPECT_EQ(fs.piece_size(2), 40000 - 2 * 16384);  // 7232 bytes
}

TEST(BtFileStorageTest, PieceSizeExact) {
    FileStorage fs(16384);
    fs.add_file("file.txt", 32768);  // Exactly 2 pieces
    fs.finalize();
    
    EXPECT_EQ(fs.num_pieces(), 2);
    EXPECT_EQ(fs.piece_size(0), 16384);
    EXPECT_EQ(fs.piece_size(1), 16384);
}

//=============================================================================
// Piece-to-File Mapping Tests
//=============================================================================

TEST(BtFileStorageTest, MapBlockSingleFile) {
    FileStorage fs(16384);
    fs.add_file("file.txt", 50000);
    fs.finalize();
    
    // Map first block of first piece
    auto slices = fs.map_block(0, 0, 16384);
    ASSERT_EQ(slices.size(), 1);
    EXPECT_EQ(slices[0].file_index, 0);
    EXPECT_EQ(slices[0].offset, 0);
    EXPECT_EQ(slices[0].size, 16384);
}

TEST(BtFileStorageTest, MapBlockSpansFiles) {
    FileStorage fs(16384);
    fs.add_file("file1.txt", 10000);
    fs.add_file("file2.txt", 10000);
    fs.finalize();
    
    // Map block that spans both files
    auto slices = fs.map_block(0, 0, 16384);
    ASSERT_EQ(slices.size(), 2);
    
    // First file: 0-10000
    EXPECT_EQ(slices[0].file_index, 0);
    EXPECT_EQ(slices[0].offset, 0);
    EXPECT_EQ(slices[0].size, 10000);
    
    // Second file: 0-6384
    EXPECT_EQ(slices[1].file_index, 1);
    EXPECT_EQ(slices[1].offset, 0);
    EXPECT_EQ(slices[1].size, 6384);
}

TEST(BtFileStorageTest, MapBlockMiddleOfPiece) {
    FileStorage fs(16384);
    fs.add_file("file.txt", 50000);
    fs.finalize();
    
    // Map from middle of piece 1
    auto slices = fs.map_block(1, 8000, 8000);
    ASSERT_EQ(slices.size(), 1);
    EXPECT_EQ(slices[0].file_index, 0);
    EXPECT_EQ(slices[0].offset, 16384 + 8000);  // Piece 1 + offset
    EXPECT_EQ(slices[0].size, 8000);
}

TEST(BtFileStorageTest, MapBlockClampedToEnd) {
    FileStorage fs(16384);
    fs.add_file("file.txt", 20000);
    fs.finalize();
    
    // Try to map beyond file end
    auto slices = fs.map_block(1, 0, 16384);
    ASSERT_EQ(slices.size(), 1);
    EXPECT_EQ(slices[0].size, 20000 - 16384);  // Only remaining bytes
}

TEST(BtFileStorageTest, MapBlockSkipsPadFiles) {
    FileStorage fs(16384);
    fs.add_file("file1.txt", 10000);
    fs.add_file(".pad", 6384, true);  // Padding to align next file
    fs.add_file("file2.txt", 10000);
    fs.finalize();
    
    // Map full piece - should skip pad file
    auto slices = fs.map_block(0, 0, 16384);
    ASSERT_EQ(slices.size(), 1);  // Only file1, pad is skipped
    EXPECT_EQ(slices[0].file_index, 0);
    EXPECT_EQ(slices[0].size, 10000);
}

//=============================================================================
// File-at-Offset Tests
//=============================================================================

TEST(BtFileStorageTest, FileAtOffset) {
    FileStorage fs(16384);
    fs.add_file("file1.txt", 10000);  // 0-10000
    fs.add_file("file2.txt", 20000);  // 10000-30000
    fs.add_file("file3.txt", 5000);   // 30000-35000
    fs.finalize();
    
    EXPECT_EQ(fs.file_at_offset(0), 0);
    EXPECT_EQ(fs.file_at_offset(5000), 0);
    EXPECT_EQ(fs.file_at_offset(9999), 0);
    EXPECT_EQ(fs.file_at_offset(10000), 1);
    EXPECT_EQ(fs.file_at_offset(25000), 1);
    EXPECT_EQ(fs.file_at_offset(30000), 2);
    EXPECT_EQ(fs.file_at_offset(34999), 2);
}

TEST(BtFileStorageTest, FileAtOffsetOutOfRange) {
    FileStorage fs(16384);
    fs.add_file("file.txt", 1000);
    fs.finalize();
    
    EXPECT_EQ(fs.file_at_offset(-1), fs.num_files());
    EXPECT_EQ(fs.file_at_offset(1000), fs.num_files());  // Exactly at end
    EXPECT_EQ(fs.file_at_offset(2000), fs.num_files());
}

TEST(BtFileStorageTest, FileAtPiece) {
    FileStorage fs(16384);
    fs.add_file("file1.txt", 40000);  // Spans pieces 0, 1, 2
    fs.add_file("file2.txt", 20000);  // Starts in piece 2
    fs.finalize();
    
    EXPECT_EQ(fs.file_at_piece(0), 0);
    EXPECT_EQ(fs.file_at_piece(1), 0);
    EXPECT_EQ(fs.file_at_piece(2), 0);  // file1 extends into piece 2
}

//=============================================================================
// File-to-Piece Mapping Tests
//=============================================================================

TEST(BtFileStorageTest, MapFile) {
    FileStorage fs(16384);
    fs.add_file("file.txt", 50000);
    fs.finalize();
    
    auto pos = fs.map_file(0, 0, 1000);
    EXPECT_EQ(pos.piece, 0);
    EXPECT_EQ(pos.offset, 0);
    EXPECT_EQ(pos.length, 1000);
    
    // Offset in middle of piece 1
    pos = fs.map_file(0, 20000, 500);
    EXPECT_EQ(pos.piece, 1);
    EXPECT_EQ(pos.offset, 20000 - 16384);  // 3616
    EXPECT_EQ(pos.length, 500);
}

TEST(BtFileStorageTest, MapFileSecondFile) {
    FileStorage fs(16384);
    fs.add_file("file1.txt", 10000);
    fs.add_file("file2.txt", 20000);
    fs.finalize();
    
    // Map start of second file
    auto pos = fs.map_file(1, 0, 1000);
    EXPECT_EQ(pos.piece, 0);  // Still in piece 0 (10000 / 16384 = 0)
    EXPECT_EQ(pos.offset, 10000);  // Offset within piece 0
    EXPECT_EQ(pos.length, 1000);
}

TEST(BtFileStorageTest, FileFirstLastPiece) {
    FileStorage fs(16384);
    fs.add_file("file1.txt", 40000);  // Pieces 0, 1, 2 (partial)
    fs.add_file("file2.txt", 20000);  // Pieces 2 (partial), 3 (partial)
    fs.finalize();
    
    EXPECT_EQ(fs.file_first_piece(0), 0);
    EXPECT_EQ(fs.file_last_piece(0), 2);
    EXPECT_EQ(fs.file_num_pieces(0), 3);
    
    EXPECT_EQ(fs.file_first_piece(1), 2);  // Starts at byte 40000
    EXPECT_EQ(fs.file_last_piece(1), 3);
    EXPECT_EQ(fs.file_num_pieces(1), 2);
}

//=============================================================================
// Name Tests
//=============================================================================

TEST(BtFileStorageTest, SetName) {
    FileStorage fs(16384);
    fs.set_name("MyTorrent");
    fs.add_file("file.txt", 1000);
    fs.finalize();
    
    EXPECT_EQ(fs.name(), "MyTorrent");
}

//=============================================================================
// Edge Cases
//=============================================================================

TEST(BtFileStorageTest, EmptyFile) {
    FileStorage fs(16384);
    fs.add_file("empty.txt", 0);
    fs.add_file("real.txt", 1000);
    fs.finalize();
    
    EXPECT_EQ(fs.num_files(), 2);
    EXPECT_EQ(fs.total_size(), 1000);
    EXPECT_EQ(fs.file_at(0).size, 0);
    EXPECT_EQ(fs.file_at(1).offset, 0);  // Starts at 0 since empty file has no size
}

TEST(BtFileStorageTest, VeryLargeFile) {
    FileStorage fs(16384);
    int64_t large_size = 10LL * 1024 * 1024 * 1024;  // 10 GB
    fs.add_file("large.bin", large_size);
    fs.finalize();
    
    EXPECT_EQ(fs.total_size(), large_size);
    EXPECT_EQ(fs.num_pieces(), (large_size + 16383) / 16384);
}

TEST(BtFileStorageTest, ManySmallFiles) {
    FileStorage fs(16384);
    
    for (int i = 0; i < 1000; ++i) {
        fs.add_file("file" + std::to_string(i) + ".txt", 100);
    }
    fs.finalize();
    
    EXPECT_EQ(fs.num_files(), 1000);
    EXPECT_EQ(fs.total_size(), 100000);
    
    // Check offset calculation
    EXPECT_EQ(fs.file_at(500).offset, 50000);
}

TEST(BtFileStorageTest, MapBlockEmptyResult) {
    FileStorage fs(16384);
    fs.add_file("file.txt", 1000);
    fs.finalize();
    
    // Piece doesn't exist
    auto slices = fs.map_block(10, 0, 1000);
    EXPECT_TRUE(slices.empty());
}

TEST(BtFileStorageTest, NotFinalized) {
    FileStorage fs(16384);
    fs.add_file("file.txt", 50000);
    // Don't call finalize()
    
    EXPECT_FALSE(fs.is_finalized());
    EXPECT_EQ(fs.num_pieces(), 0);  // Not calculated yet
    
    // map_block should return empty
    auto slices = fs.map_block(0, 0, 16384);
    EXPECT_TRUE(slices.empty());
}
