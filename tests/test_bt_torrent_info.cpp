#include <gtest/gtest.h>
#include "bt_torrent_info.h"
#include "bencode.h"

using namespace librats;

//=============================================================================
// Helper Functions
//=============================================================================

// Create a minimal valid .torrent file bytes
std::vector<uint8_t> create_minimal_torrent(
    const std::string& name = "test.txt",
    int64_t length = 1000,
    uint32_t piece_length = 16384,
    const std::string& announce = "http://tracker.example.com/announce") {
    
    // Calculate number of pieces
    uint32_t num_pieces = static_cast<uint32_t>((length + piece_length - 1) / piece_length);
    
    // Create fake piece hashes (20 bytes each)
    std::string pieces(num_pieces * 20, '\0');
    for (size_t i = 0; i < pieces.size(); ++i) {
        pieces[i] = static_cast<char>(i % 256);
    }
    
    // Build info dictionary
    BencodeValue info = BencodeValue::create_dict();
    info["name"] = BencodeValue(name);
    info["length"] = BencodeValue(length);
    info["piece length"] = BencodeValue(static_cast<int64_t>(piece_length));
    info["pieces"] = BencodeValue(pieces);
    
    // Build root dictionary
    BencodeValue root = BencodeValue::create_dict();
    root["announce"] = BencodeValue(announce);
    root["info"] = info;
    
    return root.encode();
}

// Create a multi-file torrent
std::vector<uint8_t> create_multifile_torrent(
    const std::string& name = "MyTorrent",
    const std::vector<std::pair<std::string, int64_t>>& files = {
        {"file1.txt", 10000},
        {"subdir/file2.txt", 20000}
    },
    uint32_t piece_length = 16384) {
    
    // Calculate total size
    int64_t total_size = 0;
    for (const auto& file : files) {
        total_size += file.second;
    }
    
    // Calculate number of pieces
    uint32_t num_pieces = static_cast<uint32_t>((total_size + piece_length - 1) / piece_length);
    
    // Create fake piece hashes
    std::string pieces(num_pieces * 20, '\0');
    for (size_t i = 0; i < pieces.size(); ++i) {
        pieces[i] = static_cast<char>(i % 256);
    }
    
    // Build files list
    BencodeValue files_list = BencodeValue::create_list();
    for (const auto& file : files) {
        BencodeValue file_entry = BencodeValue::create_dict();
        file_entry["length"] = BencodeValue(file.second);
        
        // Split path into components
        BencodeValue path_list = BencodeValue::create_list();
        std::string path = file.first;
        size_t pos = 0;
        while ((pos = path.find('/')) != std::string::npos) {
            path_list.push_back(BencodeValue(path.substr(0, pos)));
            path = path.substr(pos + 1);
        }
        path_list.push_back(BencodeValue(path));
        
        file_entry["path"] = path_list;
        files_list.push_back(file_entry);
    }
    
    // Build info dictionary
    BencodeValue info = BencodeValue::create_dict();
    info["name"] = BencodeValue(name);
    info["piece length"] = BencodeValue(static_cast<int64_t>(piece_length));
    info["pieces"] = BencodeValue(pieces);
    info["files"] = files_list;
    
    // Build root dictionary
    BencodeValue root = BencodeValue::create_dict();
    root["announce"] = BencodeValue("http://tracker.example.com/announce");
    root["info"] = info;
    
    return root.encode();
}

//=============================================================================
// Construction Tests
//=============================================================================

TEST(BtTorrentInfoTest, DefaultConstructor) {
    TorrentInfo info;
    EXPECT_FALSE(info.is_valid());
    EXPECT_FALSE(info.has_metadata());
    EXPECT_TRUE(info.name().empty());
    EXPECT_EQ(info.num_files(), 0);
    EXPECT_EQ(info.num_pieces(), 0);
}

//=============================================================================
// Parsing Tests - Single File
//=============================================================================

TEST(BtTorrentInfoTest, ParseSingleFileTorrent) {
    auto torrent_bytes = create_minimal_torrent("test.txt", 50000, 16384);
    
    TorrentParseError error;
    auto info = TorrentInfo::from_bytes(torrent_bytes, &error);
    
    ASSERT_TRUE(info.has_value()) << "Parse failed: " << error.message;
    EXPECT_TRUE(info->is_valid());
    EXPECT_TRUE(info->has_metadata());
    EXPECT_EQ(info->name(), "test.txt");
    EXPECT_EQ(info->total_size(), 50000);
    EXPECT_EQ(info->num_files(), 1);
    EXPECT_EQ(info->piece_length(), 16384);
    EXPECT_EQ(info->num_pieces(), 4);  // ceil(50000 / 16384)
}

TEST(BtTorrentInfoTest, ParseSingleFileTorrentFileInfo) {
    auto torrent_bytes = create_minimal_torrent("document.pdf", 100000);
    
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    const auto& files = info->files();
    EXPECT_EQ(files.num_files(), 1);
    EXPECT_EQ(files.file_at(0).path, "document.pdf");
    EXPECT_EQ(files.file_at(0).size, 100000);
    EXPECT_EQ(files.file_at(0).offset, 0);
}

//=============================================================================
// Parsing Tests - Multi File
//=============================================================================

TEST(BtTorrentInfoTest, ParseMultiFileTorrent) {
    auto torrent_bytes = create_multifile_torrent("MyAlbum", {
        {"song1.mp3", 5000000},
        {"song2.mp3", 4500000},
        {"cover.jpg", 100000}
    });
    
    TorrentParseError error;
    auto info = TorrentInfo::from_bytes(torrent_bytes, &error);
    
    ASSERT_TRUE(info.has_value()) << "Parse failed: " << error.message;
    EXPECT_TRUE(info->is_valid());
    EXPECT_EQ(info->name(), "MyAlbum");
    EXPECT_EQ(info->num_files(), 3);
    EXPECT_EQ(info->total_size(), 5000000 + 4500000 + 100000);
    
    const auto& files = info->files();
    EXPECT_EQ(files.file_at(0).path, "song1.mp3");
    EXPECT_EQ(files.file_at(0).size, 5000000);
    EXPECT_EQ(files.file_at(1).path, "song2.mp3");
    EXPECT_EQ(files.file_at(2).path, "cover.jpg");
}

TEST(BtTorrentInfoTest, ParseMultiFileWithSubdirectories) {
    auto torrent_bytes = create_multifile_torrent("Project", {
        {"README.md", 1000},
        {"src/main.cpp", 5000},
        {"src/utils/helper.cpp", 3000}
    });
    
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    const auto& files = info->files();
    EXPECT_EQ(files.file_at(0).path, "README.md");
    EXPECT_EQ(files.file_at(1).path, "src/main.cpp");
    EXPECT_EQ(files.file_at(2).path, "src/utils/helper.cpp");
}

//=============================================================================
// Info Hash Tests
//=============================================================================

TEST(BtTorrentInfoTest, InfoHashIsConsistent) {
    auto torrent_bytes = create_minimal_torrent();
    
    auto info1 = TorrentInfo::from_bytes(torrent_bytes);
    auto info2 = TorrentInfo::from_bytes(torrent_bytes);
    
    ASSERT_TRUE(info1.has_value());
    ASSERT_TRUE(info2.has_value());
    
    // Same torrent data should produce same hash
    EXPECT_EQ(info1->info_hash(), info2->info_hash());
    EXPECT_EQ(info1->info_hash_hex(), info2->info_hash_hex());
    
    // Hash should be 40 hex characters
    EXPECT_EQ(info1->info_hash_hex().size(), 40);
}

TEST(BtTorrentInfoTest, DifferentTorrentsDifferentHashes) {
    auto torrent1 = create_minimal_torrent("file1.txt", 1000);
    auto torrent2 = create_minimal_torrent("file2.txt", 2000);
    
    auto info1 = TorrentInfo::from_bytes(torrent1);
    auto info2 = TorrentInfo::from_bytes(torrent2);
    
    ASSERT_TRUE(info1.has_value());
    ASSERT_TRUE(info2.has_value());
    
    EXPECT_NE(info1->info_hash(), info2->info_hash());
}

//=============================================================================
// Piece Hash Tests
//=============================================================================

TEST(BtTorrentInfoTest, PieceHashes) {
    auto torrent_bytes = create_minimal_torrent("test.txt", 50000, 16384);
    
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    // Should have 4 pieces
    EXPECT_EQ(info->num_pieces(), 4);
    EXPECT_EQ(info->piece_hashes().size(), 4 * 20);
    
    // Get individual piece hash
    auto hash = info->piece_hash(0);
    EXPECT_EQ(hash.size(), 20);
    
    // Out of range returns zero hash
    auto invalid_hash = info->piece_hash(100);
    bool all_zero = true;
    for (uint8_t b : invalid_hash) {
        if (b != 0) all_zero = false;
    }
    EXPECT_TRUE(all_zero);
}

//=============================================================================
// Tracker Tests
//=============================================================================

TEST(BtTorrentInfoTest, SingleTracker) {
    auto torrent_bytes = create_minimal_torrent("test.txt", 1000, 16384, 
        "http://tracker.example.com:6969/announce");
    
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    EXPECT_EQ(info->announce(), "http://tracker.example.com:6969/announce");
    
    auto all = info->all_trackers();
    EXPECT_EQ(all.size(), 1);
    EXPECT_EQ(all[0], "http://tracker.example.com:6969/announce");
}

//=============================================================================
// Magnet URI Tests
//=============================================================================

TEST(BtTorrentInfoTest, ToMagnetUri) {
    auto torrent_bytes = create_minimal_torrent("Ubuntu.iso", 1000000);
    
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    std::string magnet = info->to_magnet_uri();
    
    // Should start with magnet:?xt=urn:btih:
    EXPECT_TRUE(magnet.find("magnet:?xt=urn:btih:") == 0);
    
    // Should contain the info hash
    EXPECT_TRUE(magnet.find(info->info_hash_hex()) != std::string::npos);
    
    // Should contain the display name
    EXPECT_TRUE(magnet.find("dn=Ubuntu.iso") != std::string::npos);
}

TEST(BtTorrentInfoTest, FromMagnetUri) {
    std::string magnet = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567"
                         "&dn=Test+File"
                         "&tr=http://tracker1.example.com/announce"
                         "&tr=http://tracker2.example.com/announce";
    
    TorrentParseError error;
    auto info = TorrentInfo::from_magnet(magnet, &error);
    
    ASSERT_TRUE(info.has_value()) << "Parse failed: " << error.message;
    EXPECT_TRUE(info->is_valid());
    EXPECT_FALSE(info->has_metadata());  // No full metadata from magnet
    
    EXPECT_EQ(info->name(), "Test File");
    EXPECT_EQ(info->info_hash_hex(), "0123456789abcdef0123456789abcdef01234567");
    
    auto trackers = info->all_trackers();
    EXPECT_EQ(trackers.size(), 2);
}

TEST(BtTorrentInfoTest, MagnetUriParsing) {
    std::string magnet = "magnet:?xt=urn:btih:abcdef0123456789abcdef0123456789abcdef01"
                         "&dn=My%20Torrent"
                         "&tr=http%3A%2F%2Ftracker.example.com%2Fannounce";
    
    auto parsed = MagnetUri::parse(magnet);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->is_valid());
    EXPECT_EQ(parsed->display_name, "My Torrent");
    EXPECT_EQ(parsed->trackers.size(), 1);
    EXPECT_EQ(parsed->trackers[0], "http://tracker.example.com/announce");
}

TEST(BtTorrentInfoTest, InvalidMagnetUri) {
    auto result = MagnetUri::parse("not a magnet uri");
    EXPECT_FALSE(result.has_value());
    
    auto info = TorrentInfo::from_magnet("invalid");
    EXPECT_FALSE(info.has_value());
}

//=============================================================================
// Error Handling Tests
//=============================================================================

TEST(BtTorrentInfoTest, EmptyData) {
    TorrentParseError error;
    auto info = TorrentInfo::from_bytes({}, &error);
    
    EXPECT_FALSE(info.has_value());
    EXPECT_FALSE(error.message.empty());
}

TEST(BtTorrentInfoTest, InvalidBencode) {
    TorrentParseError error;
    std::vector<uint8_t> garbage = {'n', 'o', 't', ' ', 'b', 'e', 'n', 'c', 'o', 'd', 'e'};
    auto info = TorrentInfo::from_bytes(garbage, &error);
    
    EXPECT_FALSE(info.has_value());
}

TEST(BtTorrentInfoTest, MissingInfoDict) {
    // Create torrent without info dict
    BencodeValue root = BencodeValue::create_dict();
    root["announce"] = BencodeValue("http://tracker.example.com");
    // No "info" key
    
    TorrentParseError error;
    auto info = TorrentInfo::from_bytes(root.encode(), &error);
    
    EXPECT_FALSE(info.has_value());
    EXPECT_TRUE(error.message.find("info") != std::string::npos);
}

//=============================================================================
// Copy/Move Tests
//=============================================================================

TEST(BtTorrentInfoTest, CopyConstructor) {
    auto torrent_bytes = create_minimal_torrent();
    auto original = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(original.has_value());
    
    TorrentInfo copy(*original);
    
    EXPECT_EQ(copy.info_hash(), original->info_hash());
    EXPECT_EQ(copy.name(), original->name());
    EXPECT_EQ(copy.num_files(), original->num_files());
    EXPECT_EQ(copy.total_size(), original->total_size());
}

TEST(BtTorrentInfoTest, MoveConstructor) {
    auto torrent_bytes = create_minimal_torrent();
    auto original = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(original.has_value());
    
    BtInfoHash original_hash = original->info_hash();
    std::string original_name = original->name();
    
    TorrentInfo moved(std::move(*original));
    
    EXPECT_EQ(moved.info_hash(), original_hash);
    EXPECT_EQ(moved.name(), original_name);
    EXPECT_TRUE(moved.has_metadata());
}

//=============================================================================
// Piece Size Tests
//=============================================================================

TEST(BtTorrentInfoTest, PieceSize) {
    auto torrent_bytes = create_minimal_torrent("test.txt", 40000, 16384);
    
    auto info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(info.has_value());
    
    // 40000 bytes / 16384 = 2 full pieces + 1 partial
    EXPECT_EQ(info->num_pieces(), 3);
    EXPECT_EQ(info->piece_size(0), 16384);
    EXPECT_EQ(info->piece_size(1), 16384);
    EXPECT_EQ(info->piece_size(2), 40000 - 2 * 16384);  // 7232
}

//=============================================================================
// Metadata Update Tests (for magnet links)
//=============================================================================

TEST(BtTorrentInfoTest, SetMetadata) {
    // Create a full torrent
    auto torrent_bytes = create_minimal_torrent("test.txt", 50000);
    auto full_info = TorrentInfo::from_bytes(torrent_bytes);
    ASSERT_TRUE(full_info.has_value());
    
    // Create magnet-only info
    std::string magnet = full_info->to_magnet_uri();
    auto magnet_info = TorrentInfo::from_magnet(magnet);
    ASSERT_TRUE(magnet_info.has_value());
    
    EXPECT_FALSE(magnet_info->has_metadata());
    EXPECT_EQ(magnet_info->num_files(), 0);
    
    // Set metadata
    bool success = magnet_info->set_metadata(full_info->info_dict_bytes());
    EXPECT_TRUE(success);
    EXPECT_TRUE(magnet_info->has_metadata());
    EXPECT_EQ(magnet_info->num_files(), 1);
    EXPECT_EQ(magnet_info->total_size(), 50000);
}

TEST(BtTorrentInfoTest, SetMetadataWrongHash) {
    // Create a magnet with one hash
    std::string magnet = "magnet:?xt=urn:btih:0000000000000000000000000000000000000000";
    auto info = TorrentInfo::from_magnet(magnet);
    ASSERT_TRUE(info.has_value());
    
    // Try to set metadata with different hash
    auto other_torrent = create_minimal_torrent();
    auto other_info = TorrentInfo::from_bytes(other_torrent);
    ASSERT_TRUE(other_info.has_value());
    
    // This should fail - hash doesn't match
    bool success = info->set_metadata(other_info->info_dict_bytes());
    EXPECT_FALSE(success);
    EXPECT_FALSE(info->has_metadata());
}
