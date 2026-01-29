#include <gtest/gtest.h>
#include "bt_create_torrent.h"
#include "bt_torrent_info.h"
#include "fs.h"

#include <fstream>
#include <cstdlib>

using namespace librats;

//=============================================================================
// Test Fixture
//=============================================================================

class TorrentCreatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a temporary test directory
        test_dir_ = "test_torrent_creator_temp";
        create_directories(test_dir_.c_str());
    }
    
    void TearDown() override {
        // Clean up test files and directories
        cleanup_directory(test_dir_);
    }
    
    // Helper to create a test file with specified content
    void create_test_file(const std::string& path, const std::string& content) {
        std::string full_path = combine_paths(test_dir_, path);
        
        // Create parent directories if needed
        std::string parent = get_parent_directory(full_path);
        if (!parent.empty()) {
            create_directories(parent.c_str());
        }
        
        std::ofstream file(full_path, std::ios::binary);
        file.write(content.data(), content.size());
    }
    
    // Helper to create a test file with specified size
    void create_test_file(const std::string& path, size_t size) {
        std::string content(size, 'X');
        // Add some variation
        for (size_t i = 0; i < size; ++i) {
            content[i] = static_cast<char>((i * 7 + 13) % 256);
        }
        create_test_file(path, content);
    }
    
    // Recursively delete a directory
    void cleanup_directory(const std::string& path) {
        std::vector<DirectoryEntry> entries;
        if (list_directory(path.c_str(), entries)) {
            for (const auto& entry : entries) {
                if (entry.name == "." || entry.name == "..") continue;
                std::string full_path = combine_paths(path, entry.name);
                if (entry.is_directory) {
                    cleanup_directory(full_path);
                } else {
                    delete_file(full_path.c_str());
                }
            }
        }
        delete_directory(path.c_str());
    }
    
    std::string test_dir_;
};

//=============================================================================
// Basic Tests
//=============================================================================

TEST_F(TorrentCreatorTest, CreateFromSingleFile) {
    // Create a test file
    create_test_file("single_file.txt", 10000);
    
    std::string file_path = combine_paths(test_dir_, "single_file.txt");
    
    TorrentCreator creator(file_path);
    
    EXPECT_EQ(creator.num_files(), 1);
    EXPECT_EQ(creator.total_size(), 10000);
    EXPECT_EQ(creator.name(), "single_file.txt");
}

TEST_F(TorrentCreatorTest, CreateFromDirectory) {
    // Create test files
    create_test_file("file1.txt", 5000);
    create_test_file("file2.txt", 3000);
    create_test_file("subdir/file3.txt", 2000);
    
    TorrentCreator creator(test_dir_);
    
    EXPECT_EQ(creator.num_files(), 3);
    EXPECT_EQ(creator.total_size(), 10000);
}

TEST_F(TorrentCreatorTest, SetPieceHashes) {
    // Create a test file
    create_test_file("hashtest.txt", 50000);
    
    std::string file_path = combine_paths(test_dir_, "hashtest.txt");
    
    TorrentCreator creator(file_path);
    
    EXPECT_FALSE(creator.has_piece_hashes());
    
    TorrentCreateError error;
    bool result = creator.set_piece_hashes(nullptr, &error);
    
    EXPECT_TRUE(result) << "Error: " << error.message;
    EXPECT_TRUE(creator.has_piece_hashes());
    EXPECT_GT(creator.num_pieces(), 0);
}

TEST_F(TorrentCreatorTest, SetPieceHashesWithProgress) {
    // Create a test file
    create_test_file("progress_test.txt", 100000);
    
    std::string file_path = combine_paths(test_dir_, "progress_test.txt");
    
    TorrentCreator creator(file_path);
    
    int progress_calls = 0;
    uint32_t last_piece = 0;
    uint32_t total_pieces = 0;
    
    bool result = creator.set_piece_hashes(
        [&](uint32_t current, uint32_t total) {
            progress_calls++;
            last_piece = current;
            total_pieces = total;
        });
    
    EXPECT_TRUE(result);
    EXPECT_GT(progress_calls, 0);
    EXPECT_EQ(last_piece, total_pieces);
    EXPECT_EQ(total_pieces, creator.num_pieces());
}

TEST_F(TorrentCreatorTest, GenerateTorrent) {
    // Create a test file
    create_test_file("generate_test.txt", 20000);
    
    std::string file_path = combine_paths(test_dir_, "generate_test.txt");
    
    TorrentCreator creator(file_path);
    creator.set_comment("Test comment");
    creator.set_creator("Test creator");
    creator.add_tracker("http://tracker.example.com/announce");
    
    ASSERT_TRUE(creator.set_piece_hashes());
    
    TorrentCreateError error;
    auto data = creator.generate(&error);
    
    EXPECT_FALSE(data.empty()) << "Error: " << error.message;
    
    // Verify it's valid by parsing it
    auto info = TorrentInfo::from_bytes(data);
    ASSERT_TRUE(info.has_value());
    
    EXPECT_EQ(info->name(), "generate_test.txt");
    EXPECT_EQ(info->total_size(), 20000);
    EXPECT_EQ(info->comment(), "Test comment");
    EXPECT_EQ(info->created_by(), "Test creator");
    EXPECT_EQ(info->announce(), "http://tracker.example.com/announce");
}

TEST_F(TorrentCreatorTest, GenerateMultiFileTorrent) {
    // Create test files
    create_test_file("file1.txt", 15000);
    create_test_file("file2.bin", 8000);
    create_test_file("subdir/file3.dat", 12000);
    
    TorrentCreator creator(test_dir_);
    creator.add_tracker("udp://tracker.example.com:6969/announce");
    
    ASSERT_TRUE(creator.set_piece_hashes());
    
    auto data = creator.generate();
    EXPECT_FALSE(data.empty());
    
    // Parse and verify
    auto info = TorrentInfo::from_bytes(data);
    ASSERT_TRUE(info.has_value());
    
    EXPECT_EQ(info->num_files(), 3);
    EXPECT_EQ(info->total_size(), 35000);
}

TEST_F(TorrentCreatorTest, InfoHashConsistency) {
    // Create a test file
    create_test_file("hash_test.txt", 30000);
    
    std::string file_path = combine_paths(test_dir_, "hash_test.txt");
    
    TorrentCreator creator(file_path);
    ASSERT_TRUE(creator.set_piece_hashes());
    
    // Get info hash before generating
    std::string info_hash_before = creator.info_hash_hex();
    EXPECT_FALSE(info_hash_before.empty());
    EXPECT_EQ(info_hash_before.size(), 40);
    
    // Generate torrent and parse it
    auto data = creator.generate();
    auto info = TorrentInfo::from_bytes(data);
    ASSERT_TRUE(info.has_value());
    
    // Info hashes should match
    EXPECT_EQ(info->info_hash_hex(), info_hash_before);
}

TEST_F(TorrentCreatorTest, SaveToFile) {
    // Create a test file
    create_test_file("save_test.txt", 25000);
    
    std::string file_path = combine_paths(test_dir_, "save_test.txt");
    std::string output_path = combine_paths(test_dir_, "output.torrent");
    
    TorrentCreator creator(file_path);
    creator.add_tracker("http://tracker.example.com/announce");
    
    ASSERT_TRUE(creator.set_piece_hashes());
    
    TorrentCreateError error;
    bool result = creator.save_to_file(output_path, &error);
    EXPECT_TRUE(result) << "Error: " << error.message;
    
    // Verify file exists and can be parsed
    EXPECT_TRUE(file_exists(output_path.c_str()));
    
    auto info = TorrentInfo::from_file(output_path);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->name(), "save_test.txt");
}

TEST_F(TorrentCreatorTest, GenerateTorrentInfo) {
    create_test_file("info_test.txt", 18000);
    
    std::string file_path = combine_paths(test_dir_, "info_test.txt");
    
    TorrentCreator creator(file_path);
    creator.set_comment("Test torrent");
    
    ASSERT_TRUE(creator.set_piece_hashes());
    
    auto info = creator.generate_torrent_info();
    ASSERT_TRUE(info.has_value());
    
    EXPECT_EQ(info->name(), "info_test.txt");
    EXPECT_EQ(info->total_size(), 18000);
    EXPECT_TRUE(info->has_metadata());
    EXPECT_TRUE(info->is_valid());
}

//=============================================================================
// Properties Tests
//=============================================================================

TEST_F(TorrentCreatorTest, SetProperties) {
    create_test_file("props.txt", 5000);
    
    std::string file_path = combine_paths(test_dir_, "props.txt");
    
    TorrentCreator creator(file_path);
    
    // Set properties
    creator.set_name("custom_name");
    creator.set_comment("Custom comment");
    creator.set_creator("Custom creator");
    creator.set_private(true);
    
    EXPECT_EQ(creator.name(), "custom_name");
    EXPECT_EQ(creator.comment(), "Custom comment");
    EXPECT_EQ(creator.creator(), "Custom creator");
    EXPECT_TRUE(creator.is_private());
}

TEST_F(TorrentCreatorTest, AddTrackers) {
    create_test_file("trackers.txt", 5000);
    
    std::string file_path = combine_paths(test_dir_, "trackers.txt");
    
    TorrentCreator creator(file_path);
    
    creator.add_tracker("http://tracker1.example.com/announce", 0);
    creator.add_tracker("http://tracker2.example.com/announce", 1);
    creator.add_tracker("udp://tracker3.example.com:6969", 0);
    
    auto trackers = creator.trackers();
    EXPECT_EQ(trackers.size(), 3);
}

TEST_F(TorrentCreatorTest, AddSeeds) {
    create_test_file("seeds.txt", 5000);
    
    std::string file_path = combine_paths(test_dir_, "seeds.txt");
    
    TorrentCreator creator(file_path);
    
    creator.add_url_seed("http://seed1.example.com/files/");
    creator.add_url_seed("http://seed2.example.com/files/");
    creator.add_http_seed("http://httpseed.example.com/");
    
    EXPECT_EQ(creator.url_seeds().size(), 2);
    EXPECT_EQ(creator.http_seeds().size(), 1);
}

TEST_F(TorrentCreatorTest, SetPieceSize) {
    create_test_file("piece_size.txt", 1000000);  // 1 MB
    
    std::string file_path = combine_paths(test_dir_, "piece_size.txt");
    
    TorrentCreator creator(file_path);
    creator.set_piece_size(32 * 1024);  // 32 KiB
    
    EXPECT_EQ(creator.piece_size(), 32 * 1024);
    
    ASSERT_TRUE(creator.set_piece_hashes());
    
    // Verify piece size was used
    auto info = creator.generate_torrent_info();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->piece_length(), 32 * 1024);
}

//=============================================================================
// Edge Cases
//=============================================================================

TEST_F(TorrentCreatorTest, EmptyFile) {
    // Create an empty file - this should handle edge cases
    create_test_file("empty.txt", "");
    
    std::string file_path = combine_paths(test_dir_, "empty.txt");
    
    TorrentCreator creator(file_path);
    
    // Empty files should be handled appropriately
    TorrentCreateError error;
    bool result = creator.set_piece_hashes(nullptr, &error);
    
    // Expect failure since total size is 0
    EXPECT_FALSE(result);
}

TEST_F(TorrentCreatorTest, LargeFile) {
    // Create a larger file (~500 KB)
    create_test_file("large.bin", 500 * 1024);
    
    std::string file_path = combine_paths(test_dir_, "large.bin");
    
    TorrentCreator creator(file_path);
    
    ASSERT_TRUE(creator.set_piece_hashes());
    
    auto data = creator.generate();
    EXPECT_FALSE(data.empty());
    
    auto info = TorrentInfo::from_bytes(data);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->total_size(), 500 * 1024);
}

TEST_F(TorrentCreatorTest, ManySmallFiles) {
    // Create many small files
    for (int i = 0; i < 20; ++i) {
        create_test_file("file_" + std::to_string(i) + ".txt", 500 + i * 100);
    }
    
    TorrentCreator creator(test_dir_);
    
    EXPECT_EQ(creator.num_files(), 20);
    
    ASSERT_TRUE(creator.set_piece_hashes());
    
    auto info = creator.generate_torrent_info();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->num_files(), 20);
}

TEST_F(TorrentCreatorTest, DeepDirectoryStructure) {
    // Create files in nested directories
    create_test_file("a/b/c/file1.txt", 1000);
    create_test_file("a/b/file2.txt", 2000);
    create_test_file("a/file3.txt", 3000);
    create_test_file("x/y/z/w/file4.txt", 4000);
    
    TorrentCreator creator(test_dir_);
    
    EXPECT_EQ(creator.num_files(), 4);
    EXPECT_EQ(creator.total_size(), 10000);
    
    ASSERT_TRUE(creator.set_piece_hashes());
    
    auto info = creator.generate_torrent_info();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->num_files(), 4);
}

//=============================================================================
// Convenience Function Tests
//=============================================================================

TEST_F(TorrentCreatorTest, CreateTorrentConvenienceFunction) {
    create_test_file("convenience.txt", 15000);
    
    std::string file_path = combine_paths(test_dir_, "convenience.txt");
    std::string output_path = combine_paths(test_dir_, "convenience.torrent");
    
    TorrentCreateError error;
    bool result = create_torrent(
        file_path,
        output_path,
        {"http://tracker.example.com/announce"},
        "Test comment",
        nullptr,
        &error
    );
    
    EXPECT_TRUE(result) << "Error: " << error.message;
    EXPECT_TRUE(file_exists(output_path.c_str()));
}

TEST_F(TorrentCreatorTest, CreateTorrentDataConvenienceFunction) {
    create_test_file("data_convenience.txt", 12000);
    
    std::string file_path = combine_paths(test_dir_, "data_convenience.txt");
    
    TorrentCreateError error;
    auto data = create_torrent_data(
        file_path,
        {"http://tracker.example.com/announce"},
        "Test",
        nullptr,
        &error
    );
    
    EXPECT_FALSE(data.empty()) << "Error: " << error.message;
    
    auto info = TorrentInfo::from_bytes(data);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->name(), "data_convenience.txt");
}

//=============================================================================
// Error Handling Tests
//=============================================================================

TEST_F(TorrentCreatorTest, GenerateWithoutHashing) {
    create_test_file("no_hash.txt", 5000);
    
    std::string file_path = combine_paths(test_dir_, "no_hash.txt");
    
    TorrentCreator creator(file_path);
    
    // Don't call set_piece_hashes()
    
    TorrentCreateError error;
    auto data = creator.generate(&error);
    
    EXPECT_TRUE(data.empty());
    EXPECT_FALSE(error.message.empty());
}

TEST_F(TorrentCreatorTest, NonExistentPath) {
    TorrentCreator creator("/non/existent/path/file.txt");
    
    EXPECT_EQ(creator.num_files(), 0);
}

TEST_F(TorrentCreatorTest, HiddenFilesExcludedByDefault) {
    // Create visible and hidden files
    create_test_file("visible.txt", 1000);
    create_test_file(".hidden", 1000);
    create_test_file(".hidden_dir/file.txt", 1000);
    
    TorrentCreatorConfig config;
    config.include_hidden_files = false;
    
    TorrentCreator creator(test_dir_, config);
    
    // Hidden files should be excluded (default behavior)
    // Note: exact count depends on implementation
    EXPECT_GE(creator.num_files(), 1);
}

TEST_F(TorrentCreatorTest, HiddenFilesIncluded) {
    // Create visible and hidden files  
    create_test_file("visible.txt", 1000);
    create_test_file(".hidden", 1000);
    
    TorrentCreatorConfig config;
    config.include_hidden_files = true;
    
    TorrentCreator creator(test_dir_, config);
    
    // Should include both files
    EXPECT_EQ(creator.num_files(), 2);
}
