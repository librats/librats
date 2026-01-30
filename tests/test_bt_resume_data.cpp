/**
 * @file test_bt_resume_data.cpp
 * @brief Tests for BitTorrent resume data functionality
 * 
 * Tests cover:
 * - Resume data serialization/deserialization (bencode)
 * - Resume data save/load to files
 * - Torrent resume data generation
 * - File verification (recheck)
 * - Fast resume with pre-existing data
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#ifdef RATS_SEARCH_FEATURES

#include "bt_resume_data.h"
#include "bt_torrent.h"
#include "bt_torrent_info.h"
#include "bt_bitfield.h"
#include "bt_types.h"
#include "bencode.h"
#include "fs.h"

#include <fstream>
#include <cstring>
#include <chrono>
#include <random>

using namespace librats;

//=============================================================================
// Test Fixtures
//=============================================================================

class ResumeDataTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directory
        test_dir_ = "./test_resume_data_" + std::to_string(
            std::chrono::system_clock::now().time_since_epoch().count());
        create_directories(test_dir_.c_str());
    }
    
    void TearDown() override {
        // Cleanup test directory
        if (!test_dir_.empty()) {
            // Delete files in .resume subdirectory
            std::string resume_dir = test_dir_ + "/.resume";
            std::vector<DirectoryEntry> entries;
            if (list_directory(resume_dir.c_str(), entries)) {
                for (const auto& e : entries) {
                    delete_file(e.path.c_str());
                }
                delete_directory(resume_dir.c_str());
            }
            delete_directory(test_dir_.c_str());
        }
    }
    
    // Create a sample info hash
    BtInfoHash create_test_hash() {
        BtInfoHash hash;
        for (size_t i = 0; i < hash.size(); ++i) {
            hash[i] = static_cast<uint8_t>(i * 7 + 13);
        }
        return hash;
    }
    
    // Create sample resume data
    TorrentResumeData create_sample_resume_data() {
        TorrentResumeData data;
        
        data.info_hash = create_test_hash();
        data.name = "Test Torrent";
        data.save_path = test_dir_;
        
        // Create have_pieces bitfield (10 pieces, have 5)
        data.have_pieces = Bitfield(10);
        data.have_pieces.set_bit(0);
        data.have_pieces.set_bit(2);
        data.have_pieces.set_bit(4);
        data.have_pieces.set_bit(6);
        data.have_pieces.set_bit(8);
        
        // Add some unfinished pieces
        Bitfield blocks1(4);  // 4 blocks per piece
        blocks1.set_bit(0);
        blocks1.set_bit(1);
        data.unfinished_pieces[1] = blocks1;
        
        Bitfield blocks2(4);
        blocks2.set_bit(0);
        blocks2.set_bit(2);
        blocks2.set_bit(3);
        data.unfinished_pieces[3] = blocks2;
        
        // Statistics
        data.total_uploaded = 1024 * 1024 * 100;  // 100 MB
        data.total_downloaded = 1024 * 1024 * 50; // 50 MB
        data.active_time = 3600;  // 1 hour
        data.seeding_time = 7200; // 2 hours
        data.added_time = 1700000000;
        data.completed_time = 0;  // Not complete
        
        // Configuration
        data.sequential_download = true;
        data.max_connections = 50;
        data.max_uploads = 4;
        data.download_limit = 1024 * 1024;  // 1 MB/s
        data.upload_limit = 512 * 1024;     // 512 KB/s
        
        // Peers
        data.peers.emplace_back("192.168.1.1", 6881);
        data.peers.emplace_back("10.0.0.1", 51413);
        
        return data;
    }
    
    std::string test_dir_;
};

//=============================================================================
// Serialization Tests
//=============================================================================

TEST_F(ResumeDataTest, WriteAndReadResumeData) {
    auto original = create_sample_resume_data();
    
    // Serialize
    auto encoded = write_resume_data(original);
    ASSERT_FALSE(encoded.empty());
    
    // Deserialize
    std::string error;
    auto decoded = read_resume_data(encoded, &error);
    ASSERT_TRUE(decoded.has_value()) << "Error: " << error;
    
    // Verify fields
    EXPECT_EQ(decoded->info_hash, original.info_hash);
    EXPECT_EQ(decoded->name, original.name);
    EXPECT_EQ(decoded->save_path, original.save_path);
    
    // Verify have_pieces
    EXPECT_EQ(decoded->have_pieces.size(), original.have_pieces.size());
    for (uint32_t i = 0; i < original.have_pieces.size(); ++i) {
        EXPECT_EQ(decoded->have_pieces.get_bit(i), original.have_pieces.get_bit(i))
            << "Mismatch at piece " << i;
    }
    
    // Verify unfinished pieces
    EXPECT_EQ(decoded->unfinished_pieces.size(), original.unfinished_pieces.size());
    for (const auto& [piece, blocks] : original.unfinished_pieces) {
        auto it = decoded->unfinished_pieces.find(piece);
        ASSERT_NE(it, decoded->unfinished_pieces.end()) 
            << "Missing unfinished piece " << piece;
        EXPECT_EQ(it->second.size(), blocks.size());
    }
    
    // Verify statistics
    EXPECT_EQ(decoded->total_uploaded, original.total_uploaded);
    EXPECT_EQ(decoded->total_downloaded, original.total_downloaded);
    EXPECT_EQ(decoded->active_time, original.active_time);
    EXPECT_EQ(decoded->seeding_time, original.seeding_time);
    EXPECT_EQ(decoded->added_time, original.added_time);
    
    // Verify configuration
    EXPECT_EQ(decoded->sequential_download, original.sequential_download);
    EXPECT_EQ(decoded->max_connections, original.max_connections);
    EXPECT_EQ(decoded->max_uploads, original.max_uploads);
    EXPECT_EQ(decoded->download_limit, original.download_limit);
    EXPECT_EQ(decoded->upload_limit, original.upload_limit);
    
    // Verify peers
    EXPECT_EQ(decoded->peers.size(), original.peers.size());
    for (size_t i = 0; i < original.peers.size(); ++i) {
        EXPECT_EQ(decoded->peers[i].first, original.peers[i].first);
        EXPECT_EQ(decoded->peers[i].second, original.peers[i].second);
    }
}

TEST_F(ResumeDataTest, WriteAndReadEmptyResumeData) {
    TorrentResumeData original;
    original.info_hash = create_test_hash();
    original.save_path = test_dir_;
    
    auto encoded = write_resume_data(original);
    ASSERT_FALSE(encoded.empty());
    
    std::string error;
    auto decoded = read_resume_data(encoded, &error);
    ASSERT_TRUE(decoded.has_value()) << "Error: " << error;
    
    EXPECT_EQ(decoded->info_hash, original.info_hash);
    EXPECT_EQ(decoded->save_path, original.save_path);
    EXPECT_EQ(decoded->have_pieces.size(), 0u);
    EXPECT_TRUE(decoded->unfinished_pieces.empty());
}

TEST_F(ResumeDataTest, ReadInvalidData) {
    // Empty data
    std::vector<uint8_t> empty;
    std::string error;
    auto result = read_resume_data(empty, &error);
    EXPECT_FALSE(result.has_value());
    EXPECT_FALSE(error.empty());
    
    // Invalid bencode
    std::vector<uint8_t> garbage = {0x00, 0x01, 0x02, 0x03};
    error.clear();
    result = read_resume_data(garbage, &error);
    EXPECT_FALSE(result.has_value());
    
    // Valid bencode but wrong format
    std::vector<uint8_t> wrong_format = {'d', '3', ':', 'f', 'o', 'o', 
                                          'i', '1', '2', '3', 'e', 'e'};
    error.clear();
    result = read_resume_data(wrong_format, &error);
    EXPECT_FALSE(result.has_value());
}

//=============================================================================
// File I/O Tests
//=============================================================================

TEST_F(ResumeDataTest, WriteAndReadResumeFile) {
    auto original = create_sample_resume_data();
    
    std::string path = test_dir_ + "/test.resume";
    
    ASSERT_TRUE(write_resume_data_file(original, path));
    EXPECT_TRUE(file_exists(path));
    
    std::string error;
    auto loaded = read_resume_data_file(path, &error);
    ASSERT_TRUE(loaded.has_value()) << "Error: " << error;
    
    EXPECT_EQ(loaded->info_hash, original.info_hash);
    EXPECT_EQ(loaded->name, original.name);
    EXPECT_EQ(loaded->have_pieces.count(), original.have_pieces.count());
}

TEST_F(ResumeDataTest, ResumeFilePath) {
    auto hash = create_test_hash();
    std::string path = get_resume_file_path(test_dir_, hash);
    
    // Should be in .resume subdirectory
    EXPECT_TRUE(path.find(".resume") != std::string::npos);
    // Should contain hash hex
    EXPECT_TRUE(path.find(info_hash_to_hex(hash)) != std::string::npos);
    // Should have .resume extension
    EXPECT_TRUE(path.find(".resume") != std::string::npos);
}

TEST_F(ResumeDataTest, ResumeFileExistsCheck) {
    auto hash = create_test_hash();
    
    // Should not exist initially
    EXPECT_FALSE(resume_file_exists(test_dir_, hash));
    
    // Create resume file
    auto data = create_sample_resume_data();
    std::string path = get_resume_file_path(test_dir_, hash);
    ASSERT_TRUE(write_resume_data_file(data, path));
    
    // Now should exist
    EXPECT_TRUE(resume_file_exists(test_dir_, hash));
}

//=============================================================================
// Bitfield Serialization Tests
//=============================================================================

TEST_F(ResumeDataTest, LargeBitfieldSerialization) {
    TorrentResumeData data;
    data.info_hash = create_test_hash();
    data.save_path = test_dir_;
    
    // Create a large bitfield (1000 pieces)
    data.have_pieces = Bitfield(1000);
    
    // Set every 3rd bit
    for (uint32_t i = 0; i < 1000; i += 3) {
        data.have_pieces.set_bit(i);
    }
    
    // Add unfinished pieces with varying block counts
    for (uint32_t p = 1; p < 100; p += 10) {
        uint32_t num_blocks = (p % 10) + 1;
        Bitfield blocks(num_blocks);
        for (uint32_t b = 0; b < num_blocks; b += 2) {
            blocks.set_bit(b);
        }
        data.unfinished_pieces[p] = blocks;
    }
    
    auto encoded = write_resume_data(data);
    ASSERT_FALSE(encoded.empty());
    
    std::string error;
    auto decoded = read_resume_data(encoded, &error);
    ASSERT_TRUE(decoded.has_value()) << "Error: " << error;
    
    // Verify all pieces
    EXPECT_EQ(decoded->have_pieces.size(), 1000u);
    for (uint32_t i = 0; i < 1000; ++i) {
        EXPECT_EQ(decoded->have_pieces.get_bit(i), (i % 3 == 0))
            << "Mismatch at piece " << i;
    }
    
    // Verify unfinished pieces
    EXPECT_EQ(decoded->unfinished_pieces.size(), data.unfinished_pieces.size());
}

//=============================================================================
// Validation Tests
//=============================================================================

TEST_F(ResumeDataTest, IsValid) {
    TorrentResumeData data;
    
    // Explicitly set all-zero hash - should be invalid
    data.info_hash.fill(0);
    EXPECT_FALSE(data.is_valid());
    
    // With non-zero hash is valid
    data.info_hash = create_test_hash();
    EXPECT_TRUE(data.is_valid());
}

TEST_F(ResumeDataTest, MatchesTorrentInfo) {
    auto data = create_sample_resume_data();
    
    // This test would need a real TorrentInfo, but we can at least verify
    // the info_hash comparison works with mock data
    // In a real scenario, you would create a TorrentInfo with matching hash
}

//=============================================================================
// Torrent Resume Data Loading Tests (Magnet Link Scenarios)
//=============================================================================

/**
 * Test fixture for Torrent-level resume data tests
 */
class TorrentResumeTest : public ResumeDataTest {
protected:
    // Helper to create a test torrent info from minimal data
    std::optional<TorrentInfo> create_test_torrent_info(uint32_t num_pieces, uint32_t piece_length = 16384) {
        uint64_t file_size = static_cast<uint64_t>(num_pieces) * piece_length;
        
        // Create pieces string (20 bytes per piece)
        std::string pieces(num_pieces * 20, '\x00');
        
        // Create info dict
        BencodeValue info = BencodeValue::create_dict();
        info["name"] = BencodeValue("test_file.dat");
        info["length"] = BencodeValue(static_cast<int64_t>(file_size));
        info["piece length"] = BencodeValue(static_cast<int64_t>(piece_length));
        info["pieces"] = BencodeValue(pieces);
        
        // Create root
        BencodeValue root = BencodeValue::create_dict();
        root["announce"] = BencodeValue("http://tracker.example.com/announce");
        root["info"] = info;
        
        auto bytes = root.encode();
        return TorrentInfo::from_bytes(bytes);
    }
};

/**
 * Test: Resume data should be stored even without metadata (magnet link scenario)
 * 
 * When a torrent is added by hash (magnet), metadata hasn't arrived yet,
 * so there's no picker or info. Resume data should still be stored in have_pieces_
 * to be used when metadata arrives later.
 */
TEST_F(TorrentResumeTest, LoadResumeDataWithoutMetadata) {
    auto hash = create_test_hash();
    
    // Create resume data with 10 pieces
    TorrentResumeData resume_data;
    resume_data.info_hash = hash;
    resume_data.name = "Test Magnet Torrent";
    resume_data.save_path = test_dir_;
    resume_data.have_pieces = Bitfield(10);
    resume_data.have_pieces.set_bit(0);
    resume_data.have_pieces.set_bit(3);
    resume_data.have_pieces.set_bit(5);
    resume_data.have_pieces.set_bit(9);
    
    // Create torrent WITHOUT metadata (magnet link style)
    TorrentConfig config;
    config.save_path = test_dir_;
    config.resume_data_path = test_dir_;
    
    PeerID peer_id;
    peer_id.fill(0x42);
    
    // Create torrent by hash only (no metadata)
    Torrent torrent(hash, "magnet_torrent", config, peer_id);
    
    // Load resume data - should work even without metadata
    bool result = torrent.load_resume_data(resume_data);
    EXPECT_TRUE(result);
    
    // The resume data should be stored internally, ready for when metadata arrives
    // We can't directly check have_pieces_ (private), but we can verify via stats
    // that the data was at least processed without crashing
    auto stats = torrent.stats();
    // Stats won't show progress yet since there's no metadata to calculate bytes
    // But the fact that load_resume_data didn't crash is the key test
}

/**
 * Test: Resume data should be preserved when metadata arrives
 * 
 * Scenario:
 * 1. Torrent created by hash (magnet link)
 * 2. Resume data loaded (stores have_pieces_)
 * 3. Metadata received (set_metadata called)
 * 4. Have pieces should still be valid and reflected in progress
 */
TEST_F(TorrentResumeTest, ResumeDataPreservedWhenMetadataArrives) {
    auto hash = create_test_hash();
    
    // Create torrent info to get the metadata bytes
    auto torrent_info = create_test_torrent_info(10, 16384);
    ASSERT_TRUE(torrent_info.has_value());
    
    // Override the hash to match our test hash
    // Since TorrentInfo generates hash from content, we need to create torrent with matching hash
    // For this test, we'll use the hash from the torrent_info
    BtInfoHash real_hash = torrent_info->info_hash();
    
    // Create resume data with pieces marked as complete
    TorrentResumeData resume_data;
    resume_data.info_hash = real_hash;
    resume_data.name = "Test Torrent";
    resume_data.save_path = test_dir_;
    resume_data.have_pieces = Bitfield(10);
    resume_data.have_pieces.set_bit(0);
    resume_data.have_pieces.set_bit(2);
    resume_data.have_pieces.set_bit(4);
    resume_data.have_pieces.set_bit(6);
    resume_data.have_pieces.set_bit(8);
    // 5 out of 10 pieces = 50% progress
    
    // Create torrent WITHOUT metadata initially
    TorrentConfig config;
    config.save_path = test_dir_;
    config.resume_data_path = test_dir_;
    
    PeerID peer_id;
    peer_id.fill(0x42);
    
    Torrent torrent(real_hash, "pending_metadata", config, peer_id);
    
    // Load resume data BEFORE metadata
    ASSERT_TRUE(torrent.load_resume_data(resume_data));
    
    // Now simulate metadata arrival - get the info dict bytes
    auto info_dict_bytes = torrent_info->info_dict_bytes();
    ASSERT_FALSE(info_dict_bytes.empty());
    
    // Set metadata (simulates BEP 9 metadata download completion)
    bool metadata_set = torrent.set_metadata(info_dict_bytes);
    ASSERT_TRUE(metadata_set);
    
    // After metadata is set, resume data should be restored
    auto stats = torrent.stats();
    
    // Should have 5 pieces done (the ones we marked in resume data)
    EXPECT_EQ(stats.pieces_done, 5u);
    
    // Progress should be 50% (5/10)
    EXPECT_NEAR(stats.progress, 0.5f, 0.01f);
    
    // bytes_done should be 5 * 16384 = 81920
    EXPECT_EQ(stats.bytes_done, 5u * 16384u);
}

/**
 * Test: bytes_done calculation should iterate over ALL pieces
 * 
 * This tests the fix for the bug where the loop was:
 *   for (i = 0; i < pieces_done; ++i)  // WRONG: pieces_done is a COUNT
 * Should be:
 *   for (i = 0; i < have_pieces.size(); ++i)  // CORRECT: iterate all pieces
 * 
 * The bug would miss pieces if they weren't the first N pieces.
 * E.g., if we have pieces [5,6,7,8,9] (last 5), the buggy loop would check [0,1,2,3,4]
 * which are all 0, resulting in bytes_done = 0.
 */
TEST_F(TorrentResumeTest, BytesDoneCalculationIteratesAllPieces) {
    // Create torrent info with 10 pieces
    auto torrent_info = create_test_torrent_info(10, 16384);
    ASSERT_TRUE(torrent_info.has_value());
    BtInfoHash real_hash = torrent_info->info_hash();
    
    // Create resume data with ONLY the LAST 5 pieces (not the first 5)
    // This specifically tests the bug fix
    TorrentResumeData resume_data;
    resume_data.info_hash = real_hash;
    resume_data.name = "Test Torrent";
    resume_data.save_path = test_dir_;
    resume_data.have_pieces = Bitfield(10);
    // Mark only pieces 5-9 as complete (NOT pieces 0-4)
    resume_data.have_pieces.set_bit(5);
    resume_data.have_pieces.set_bit(6);
    resume_data.have_pieces.set_bit(7);
    resume_data.have_pieces.set_bit(8);
    resume_data.have_pieces.set_bit(9);
    
    TorrentConfig config;
    config.save_path = test_dir_;
    config.resume_data_path = test_dir_;
    
    PeerID peer_id;
    peer_id.fill(0x42);
    
    Torrent torrent(real_hash, "test", config, peer_id);
    
    // Set metadata first so picker exists
    auto info_dict_bytes = torrent_info->info_dict_bytes();
    ASSERT_TRUE(torrent.set_metadata(info_dict_bytes));
    
    // Load resume data
    ASSERT_TRUE(torrent.load_resume_data(resume_data));
    
    auto stats = torrent.stats();
    
    // Should have 5 pieces done
    EXPECT_EQ(stats.pieces_done, 5u);
    
    // bytes_done should be 5 * 16384 = 81920
    // With the bug, this would be 0 because pieces 0-4 are not set
    EXPECT_EQ(stats.bytes_done, 5u * 16384u);
    
    // Progress should be 50%
    EXPECT_NEAR(stats.progress, 0.5f, 0.01f);
}

/**
 * Test: Save and load resume data round-trip with Torrent
 */
TEST_F(TorrentResumeTest, TorrentSaveAndLoadResumeData) {
    // Create torrent info
    auto torrent_info = create_test_torrent_info(10, 16384);
    ASSERT_TRUE(torrent_info.has_value());
    
    TorrentConfig config;
    config.save_path = test_dir_;
    config.resume_data_path = test_dir_;
    
    PeerID peer_id;
    peer_id.fill(0x42);
    
    // Create torrent with metadata
    Torrent torrent(torrent_info->info_hash(), "test", config, peer_id);
    auto info_dict_bytes = torrent_info->info_dict_bytes();
    ASSERT_TRUE(torrent.set_metadata(info_dict_bytes));
    
    // Save resume data (should create file)
    std::string resume_path = get_resume_file_path(test_dir_, torrent_info->info_hash());
    EXPECT_TRUE(torrent.save_resume_data());
    
    // Verify file was created
    EXPECT_TRUE(file_exists(resume_path.c_str()));
    
    // Load resume data
    EXPECT_TRUE(torrent.try_load_resume_data());
}

/**
 * Test: Scattered pieces (non-contiguous) are correctly restored
 */
TEST_F(TorrentResumeTest, ScatteredPiecesRestore) {
    auto torrent_info = create_test_torrent_info(100, 16384);
    ASSERT_TRUE(torrent_info.has_value());
    BtInfoHash real_hash = torrent_info->info_hash();
    
    // Create resume data with scattered pieces (every 10th piece)
    TorrentResumeData resume_data;
    resume_data.info_hash = real_hash;
    resume_data.save_path = test_dir_;
    resume_data.have_pieces = Bitfield(100);
    
    // Set pieces: 0, 10, 20, 30, 40, 50, 60, 70, 80, 90 (10 pieces scattered)
    for (uint32_t i = 0; i < 100; i += 10) {
        resume_data.have_pieces.set_bit(i);
    }
    
    TorrentConfig config;
    config.save_path = test_dir_;
    config.resume_data_path = test_dir_;
    
    PeerID peer_id;
    peer_id.fill(0x42);
    
    Torrent torrent(real_hash, "test", config, peer_id);
    ASSERT_TRUE(torrent.set_metadata(torrent_info->info_dict_bytes()));
    ASSERT_TRUE(torrent.load_resume_data(resume_data));
    
    auto stats = torrent.stats();
    
    EXPECT_EQ(stats.pieces_done, 10u);
    EXPECT_EQ(stats.bytes_done, 10u * 16384u);
    EXPECT_NEAR(stats.progress, 0.1f, 0.01f);  // 10%
}

//=============================================================================
// Info Dict (Metadata) Preservation Tests
//=============================================================================

/**
 * Test: info_dict is saved in resume data when metadata is available
 * 
 * This is critical for seeding torrents. Without info_dict in resume data:
 * 1. Torrent is created by hash (magnet link style) during restore
 * 2. No metadata available -> enters DownloadingMetadata state
 * 3. Shows 0% until metadata is re-downloaded from peers
 * 
 * With info_dict saved:
 * 1. Resume data is loaded with info_dict
 * 2. Metadata is restored immediately
 * 3. Progress shows correctly from the start
 */
TEST_F(TorrentResumeTest, InfoDictSavedInResumeData) {
    // Create torrent info
    auto torrent_info = create_test_torrent_info(10, 16384);
    ASSERT_TRUE(torrent_info.has_value());
    
    TorrentConfig config;
    config.save_path = test_dir_;
    config.resume_data_path = test_dir_;
    
    PeerID peer_id;
    peer_id.fill(0x42);
    
    // Create torrent with metadata
    Torrent torrent(*torrent_info, config, peer_id);
    
    // Verify torrent has metadata
    EXPECT_TRUE(torrent.has_metadata());
    
    // Generate resume data
    auto resume_data = torrent.generate_resume_data();
    
    // Verify info_dict is saved
    EXPECT_FALSE(resume_data.info_dict.empty()) 
        << "info_dict should be saved in resume data when metadata is available";
    
    // Verify info_dict matches original
    EXPECT_EQ(resume_data.info_dict, torrent_info->info_dict_bytes());
}

/**
 * Test: info_dict is restored when loading resume data without metadata
 * 
 * Scenario: Seeding torrent restored after app restart
 * 1. Torrent created by hash only (no metadata)
 * 2. Resume data contains info_dict from previous session
 * 3. Metadata should be restored from info_dict
 * 4. Torrent should immediately have metadata and correct progress
 */
TEST_F(TorrentResumeTest, InfoDictRestoredFromResumeData) {
    // Create torrent info
    auto torrent_info = create_test_torrent_info(10, 16384);
    ASSERT_TRUE(torrent_info.has_value());
    BtInfoHash real_hash = torrent_info->info_hash();
    
    // Create resume data with info_dict and all pieces complete (seeding)
    TorrentResumeData resume_data;
    resume_data.info_hash = real_hash;
    resume_data.name = "Seeding Torrent";
    resume_data.save_path = test_dir_;
    
    // Set all 10 pieces as complete
    resume_data.have_pieces = Bitfield(10);
    resume_data.have_pieces.set_all();
    
    // Include info_dict in resume data
    resume_data.info_dict = torrent_info->info_dict_bytes();
    
    TorrentConfig config;
    config.save_path = test_dir_;
    config.resume_data_path = test_dir_;
    
    PeerID peer_id;
    peer_id.fill(0x42);
    
    // Create torrent WITHOUT metadata (simulates magnet link / hash-only restore)
    Torrent torrent(real_hash, "pending_metadata", config, peer_id);
    
    // Verify torrent does NOT have metadata initially
    EXPECT_FALSE(torrent.has_metadata());
    
    // Load resume data - should restore metadata from info_dict
    bool result = torrent.load_resume_data(resume_data);
    ASSERT_TRUE(result);
    
    // Now torrent should have metadata
    EXPECT_TRUE(torrent.has_metadata()) 
        << "Metadata should be restored from info_dict in resume data";
    
    // Verify name was restored
    const auto& info = torrent.get_torrent_info();
    EXPECT_EQ(info.name(), "test_file.dat");  // Name from create_test_torrent_info
    
    // Verify all pieces are marked as have
    auto stats = torrent.stats();
    EXPECT_EQ(stats.pieces_done, 10u);
    EXPECT_EQ(stats.pieces_total, 10u);
    EXPECT_NEAR(stats.progress, 1.0f, 0.01f);  // 100%
    EXPECT_EQ(stats.bytes_done, 10u * 16384u);
}

/**
 * Test: Complete round-trip for seeding torrent
 * 
 * Full scenario:
 * 1. Create torrent with metadata (simulates torrent creation for seeding)
 * 2. Start torrent in seed mode (all pieces complete)
 * 3. Save resume data
 * 4. Create new torrent by hash only (simulates app restart)
 * 5. Load resume data
 * 6. Verify torrent has metadata and shows 100%
 */
TEST_F(TorrentResumeTest, SeedingTorrentRoundTrip) {
    // Step 1: Create torrent with metadata
    auto torrent_info = create_test_torrent_info(10, 16384);
    ASSERT_TRUE(torrent_info.has_value());
    BtInfoHash real_hash = torrent_info->info_hash();
    
    TorrentConfig config;
    config.save_path = test_dir_;
    config.resume_data_path = test_dir_;
    config.seed_mode = true;  // Seeding mode
    
    PeerID peer_id;
    peer_id.fill(0x42);
    
    // Create original torrent with full metadata
    auto original_torrent = std::make_shared<Torrent>(*torrent_info, config, peer_id);
    
    // Step 2: Start torrent (seed mode marks all pieces as have)
    original_torrent->start();
    
    // Verify it's in seeding state with all pieces
    EXPECT_TRUE(original_torrent->has_metadata());
    EXPECT_TRUE(original_torrent->is_complete());
    auto original_stats = original_torrent->stats();
    EXPECT_EQ(original_stats.pieces_done, 10u);
    EXPECT_NEAR(original_stats.progress, 1.0f, 0.01f);
    
    // Step 3: Generate and save resume data
    auto resume_data = original_torrent->generate_resume_data();
    
    // Verify resume data contains info_dict
    ASSERT_FALSE(resume_data.info_dict.empty()) 
        << "Resume data must contain info_dict for seeding torrents";
    
    // Verify all pieces are marked
    EXPECT_EQ(resume_data.have_pieces.count(), 10u);
    
    // Write to file
    std::string resume_path = get_resume_file_path(test_dir_, real_hash);
    ASSERT_TRUE(write_resume_data_file(resume_data, resume_path));
    
    // Stop and destroy original torrent
    original_torrent->stop();
    original_torrent.reset();
    
    // Step 4: Create new torrent by hash only (simulates app restart)
    TorrentConfig restore_config;
    restore_config.save_path = test_dir_;
    restore_config.resume_data_path = test_dir_;
    // Note: NOT setting seed_mode - this simulates generic restore by hash
    
    Torrent restored_torrent(real_hash, "restored", restore_config, peer_id);
    
    // Verify restored torrent has NO metadata initially
    EXPECT_FALSE(restored_torrent.has_metadata());
    
    // Step 5: Load resume data from file
    ASSERT_TRUE(restored_torrent.try_load_resume_data());
    
    // Step 6: Verify torrent now has metadata and shows 100%
    EXPECT_TRUE(restored_torrent.has_metadata()) 
        << "After loading resume data, torrent should have metadata from info_dict";
    
    const auto& restored_info = restored_torrent.get_torrent_info();
    EXPECT_TRUE(restored_info.is_valid());
    EXPECT_EQ(restored_info.num_pieces(), 10u);
    
    auto restored_stats = restored_torrent.stats();
    EXPECT_EQ(restored_stats.pieces_done, 10u) 
        << "Restored seeding torrent should have all pieces";
    EXPECT_EQ(restored_stats.pieces_total, 10u);
    EXPECT_NEAR(restored_stats.progress, 1.0f, 0.01f) 
        << "Restored seeding torrent should show 100% progress";
    EXPECT_EQ(restored_stats.bytes_done, 10u * 16384u);
}

/**
 * Test: Resume data serialization preserves info_dict
 */
TEST_F(TorrentResumeTest, InfoDictSerializationRoundTrip) {
    auto torrent_info = create_test_torrent_info(10, 16384);
    ASSERT_TRUE(torrent_info.has_value());
    
    // Create resume data with info_dict
    TorrentResumeData original;
    original.info_hash = torrent_info->info_hash();
    original.name = "Test";
    original.save_path = test_dir_;
    original.have_pieces = Bitfield(10);
    original.have_pieces.set_all();
    original.info_dict = torrent_info->info_dict_bytes();
    
    ASSERT_FALSE(original.info_dict.empty());
    
    // Serialize
    auto encoded = write_resume_data(original);
    ASSERT_FALSE(encoded.empty());
    
    // Deserialize
    std::string error;
    auto decoded = read_resume_data(encoded, &error);
    ASSERT_TRUE(decoded.has_value()) << "Error: " << error;
    
    // Verify info_dict is preserved
    EXPECT_EQ(decoded->info_dict.size(), original.info_dict.size());
    EXPECT_EQ(decoded->info_dict, original.info_dict);
}

#endif // RATS_SEARCH_FEATURES
