#include <gtest/gtest.h>
#include "bittorrent.h"
#include "librats.h"
#include "bencode.h"
#include "fs.h"
#include <memory>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>

class BitTorrentTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize socket library for testing
        librats::init_socket_library();
        
        // Create test directory
        test_dir_ = "test_bittorrent_temp";
        librats::create_directories(test_dir_.c_str());
    }
    
    void TearDown() override {
        librats::cleanup_socket_library();
        
        // Clean up test directory
        cleanup_test_directory(test_dir_);
    }
    
    void cleanup_test_directory(const std::string& dir) {
        std::vector<librats::DirectoryEntry> entries;
        if (librats::list_directory(dir.c_str(), entries)) {
            for (const auto& entry : entries) {
                if (entry.is_directory) {
                    cleanup_test_directory(entry.path);
                    librats::delete_directory(entry.path.c_str());
                } else {
                    librats::delete_file(entry.path.c_str());
                }
            }
        }
        librats::delete_directory(dir.c_str());
    }
    
    // Helper to create a simple test torrent
    librats::BencodeValue create_test_torrent_bencode(const std::string& name, 
                                                      uint64_t file_size,
                                                      uint32_t piece_length) {
        using namespace librats;
        
        // Create info dictionary
        BencodeDict info_dict;
        info_dict["name"] = BencodeValue(name);
        info_dict["length"] = BencodeValue(static_cast<int64_t>(file_size));
        info_dict["piece length"] = BencodeValue(static_cast<int64_t>(piece_length));
        
        // Generate dummy piece hashes
        size_t num_pieces = (file_size + piece_length - 1) / piece_length;
        std::string pieces_data;
        for (size_t i = 0; i < num_pieces; ++i) {
            // Each piece hash is 20 bytes
            for (int j = 0; j < 20; ++j) {
                pieces_data += static_cast<char>((i + j) % 256);
            }
        }
        info_dict["pieces"] = BencodeValue(pieces_data);
        
        // Create main torrent dictionary
        BencodeDict torrent_dict;
        torrent_dict["info"] = BencodeValue(info_dict);
        torrent_dict["announce"] = BencodeValue(std::string("http://tracker.example.com:6969/announce"));
        
        return BencodeValue(torrent_dict);
    }
    
    std::string test_dir_;
};

// Test TorrentInfo creation and basic functionality
TEST_F(BitTorrentTest, TorrentInfoCreation) {
    librats::TorrentInfo torrent_info;
    
    // Initially should be invalid
    EXPECT_FALSE(torrent_info.is_valid());
    EXPECT_EQ(torrent_info.get_name(), "");
    EXPECT_EQ(torrent_info.get_total_length(), 0);
    EXPECT_EQ(torrent_info.get_num_pieces(), 0);
}

// Test BitTorrent client creation
TEST_F(BitTorrentTest, BitTorrentClientCreation) {
    auto bt_client = std::make_unique<librats::BitTorrentClient>();
    
    EXPECT_FALSE(bt_client->is_running());
    EXPECT_EQ(bt_client->get_active_torrents_count(), 0);
    EXPECT_EQ(bt_client->get_total_downloaded(), 0);
    EXPECT_EQ(bt_client->get_total_uploaded(), 0);
}

// Test BitTorrent client start/stop
TEST_F(BitTorrentTest, BitTorrentClientStartStop) {
    auto bt_client = std::make_unique<librats::BitTorrentClient>();
    
    // Start on a high port to avoid conflicts
    EXPECT_TRUE(bt_client->start(58881));
    EXPECT_TRUE(bt_client->is_running());
    
    bt_client->stop();
    EXPECT_FALSE(bt_client->is_running());
}

// Test RatsClient BitTorrent integration
TEST_F(BitTorrentTest, RatsClientBitTorrentIntegration) {
    librats::RatsClient client(58080);  // Use high port to avoid conflicts
    
    // BitTorrent should be disabled by default
    EXPECT_FALSE(client.is_bittorrent_enabled());
    EXPECT_EQ(client.get_active_torrents_count(), 0);
    
    // Start the client
    EXPECT_TRUE(client.start());
    
    // Enable BitTorrent
    EXPECT_TRUE(client.enable_bittorrent(58882));
    EXPECT_TRUE(client.is_bittorrent_enabled());
    
    // Get stats (should be zero)
    auto stats = client.get_bittorrent_stats();
    EXPECT_EQ(stats.first, 0);   // downloaded
    EXPECT_EQ(stats.second, 0);  // uploaded
    
    // Disable BitTorrent
    client.disable_bittorrent();
    EXPECT_FALSE(client.is_bittorrent_enabled());
    
    client.stop();
}

// Test PeerMessage creation and serialization
TEST_F(BitTorrentTest, PeerMessageCreation) {
    // Test simple messages
    auto choke_msg = librats::PeerMessage::create_choke();
    EXPECT_EQ(choke_msg.type, librats::MessageType::CHOKE);
    EXPECT_TRUE(choke_msg.payload.empty());
    
    auto unchoke_msg = librats::PeerMessage::create_unchoke();
    EXPECT_EQ(unchoke_msg.type, librats::MessageType::UNCHOKE);
    EXPECT_TRUE(unchoke_msg.payload.empty());
    
    // Test have message
    auto have_msg = librats::PeerMessage::create_have(42);
    EXPECT_EQ(have_msg.type, librats::MessageType::HAVE);
    EXPECT_EQ(have_msg.payload.size(), 4);
    
    // Test serialization
    auto serialized = choke_msg.serialize();
    EXPECT_EQ(serialized.size(), 5);  // 4 bytes length + 1 byte message type
}

// Test utility functions
TEST_F(BitTorrentTest, UtilityFunctions) {
    // Test peer ID generation
    auto peer_id = librats::generate_peer_id();
    EXPECT_EQ(peer_id.size(), 20);
    
    // Should start with our client identifier
    std::string prefix(peer_id.begin(), peer_id.begin() + 8);
    EXPECT_EQ(prefix, "-LR0001-");
    
    // Test info hash conversion
    librats::InfoHash test_hash;
    test_hash.fill(0xAB);  // Fill with test pattern
    
    std::string hex = librats::info_hash_to_hex(test_hash);
    EXPECT_EQ(hex.length(), 40);  // 20 bytes * 2 hex chars
    
    auto converted_back = librats::hex_to_info_hash(hex);
    EXPECT_EQ(test_hash, converted_back);
}

// Test handshake message creation and parsing
TEST_F(BitTorrentTest, HandshakeMessages) {
    librats::InfoHash info_hash;
    info_hash.fill(0x12);  // Test pattern
    
    librats::PeerID peer_id = librats::generate_peer_id();
    
    // Create handshake
    auto handshake = librats::create_handshake_message(info_hash, peer_id);
    EXPECT_EQ(handshake.size(), 68);  // Fixed handshake size
    
    // Parse handshake
    librats::InfoHash parsed_hash;
    librats::PeerID parsed_peer_id;
    
    EXPECT_TRUE(librats::parse_handshake_message(handshake, parsed_hash, parsed_peer_id));
    EXPECT_EQ(info_hash, parsed_hash);
    EXPECT_EQ(peer_id, parsed_peer_id);
}

// Test multiple BitTorrent clients (no conflicts)
TEST_F(BitTorrentTest, MultipleBitTorrentClients) {
    auto client1 = std::make_unique<librats::BitTorrentClient>();
    auto client2 = std::make_unique<librats::BitTorrentClient>();
    
    // Start on different ports
    EXPECT_TRUE(client1->start(58883));
    EXPECT_TRUE(client2->start(58884));
    
    EXPECT_TRUE(client1->is_running());
    EXPECT_TRUE(client2->is_running());
    
    // Stop them
    client1->stop();
    client2->stop();
    
    EXPECT_FALSE(client1->is_running());
    EXPECT_FALSE(client2->is_running());
}

// Test RatsClient with BitTorrent disabled operations
TEST_F(BitTorrentTest, BitTorrentDisabledOperations) {
    librats::RatsClient client(58085);
    
    EXPECT_TRUE(client.start());
    
    // All BitTorrent operations should fail gracefully when disabled
    EXPECT_FALSE(client.is_bittorrent_enabled());
    
    // These should return empty/null results
    auto torrents = client.get_all_torrents();
    EXPECT_TRUE(torrents.empty());
    
    auto stats = client.get_bittorrent_stats();
    EXPECT_EQ(stats.first, 0);
    EXPECT_EQ(stats.second, 0);
    
    EXPECT_EQ(client.get_active_torrents_count(), 0);
    
    // These should return null/false
    librats::InfoHash dummy_hash;
    dummy_hash.fill(0);
    
    auto torrent = client.get_torrent(dummy_hash);
    EXPECT_EQ(torrent, nullptr);
    
    EXPECT_FALSE(client.remove_torrent(dummy_hash));
    
    client.stop();
}

// Test TorrentInfo parsing from bencode
TEST_F(BitTorrentTest, TorrentInfoParsing) {
    auto torrent_bencode = create_test_torrent_bencode("test_file.txt", 1048576, 262144);
    
    librats::TorrentInfo torrent_info;
    EXPECT_TRUE(torrent_info.load_from_bencode(torrent_bencode));
    
    EXPECT_TRUE(torrent_info.is_valid());
    EXPECT_EQ(torrent_info.get_name(), "test_file.txt");
    EXPECT_EQ(torrent_info.get_total_length(), 1048576);
    EXPECT_EQ(torrent_info.get_piece_length(), 262144);
    EXPECT_EQ(torrent_info.get_num_pieces(), 4); // 1MB / 256KB = 4 pieces
    EXPECT_TRUE(torrent_info.is_single_file());
}

// Test TorrentInfo multi-file torrent
TEST_F(BitTorrentTest, TorrentInfoMultiFile) {
    using namespace librats;
    
    // Create multi-file torrent
    BencodeDict info_dict;
    info_dict["name"] = BencodeValue(std::string("test_folder"));
    info_dict["piece length"] = BencodeValue(static_cast<int64_t>(262144));
    
    // Add multiple files
    BencodeList files_list;
    
    BencodeDict file1;
    file1["length"] = BencodeValue(static_cast<int64_t>(524288));
    BencodeList path1;
    path1.push_back(BencodeValue(std::string("file1.txt")));
    file1["path"] = BencodeValue(path1);
    files_list.push_back(BencodeValue(file1));
    
    BencodeDict file2;
    file2["length"] = BencodeValue(static_cast<int64_t>(524288));
    BencodeList path2;
    path2.push_back(BencodeValue(std::string("subfolder")));
    path2.push_back(BencodeValue(std::string("file2.txt")));
    file2["path"] = BencodeValue(path2);
    files_list.push_back(BencodeValue(file2));
    
    info_dict["files"] = BencodeValue(files_list);
    
    // Generate piece hashes (4 pieces for 1MB total)
    std::string pieces_data;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 20; ++j) {
            pieces_data += static_cast<char>((i + j) % 256);
        }
    }
    info_dict["pieces"] = BencodeValue(pieces_data);
    
    BencodeDict torrent_dict;
    torrent_dict["info"] = BencodeValue(info_dict);
    torrent_dict["announce"] = BencodeValue(std::string("http://tracker.example.com:6969/announce"));
    
    TorrentInfo torrent_info;
    EXPECT_TRUE(torrent_info.load_from_bencode(BencodeValue(torrent_dict)));
    
    EXPECT_TRUE(torrent_info.is_valid());
    EXPECT_EQ(torrent_info.get_name(), "test_folder");
    EXPECT_EQ(torrent_info.get_total_length(), 1048576); // 512KB * 2
    EXPECT_FALSE(torrent_info.is_single_file());
    EXPECT_EQ(torrent_info.get_files().size(), 2);
}

// Test PieceInfo functionality
TEST_F(BitTorrentTest, PieceInfoTracking) {
    std::array<uint8_t, 20> test_hash;
    test_hash.fill(0xAB);
    
    librats::PieceInfo piece(0, test_hash, 262144);
    
    EXPECT_EQ(piece.index, 0);
    EXPECT_EQ(piece.length, 262144);
    EXPECT_FALSE(piece.verified);
    EXPECT_FALSE(piece.is_complete());
    
    // Calculate expected number of blocks
    uint32_t expected_blocks = (262144 + librats::BLOCK_SIZE - 1) / librats::BLOCK_SIZE;
    EXPECT_EQ(piece.get_num_blocks(), expected_blocks);
    
    // Mark all blocks as downloaded
    for (size_t i = 0; i < piece.blocks_downloaded.size(); ++i) {
        piece.blocks_downloaded[i] = true;
    }
    
    EXPECT_TRUE(piece.is_complete());
}

// Test PeerMessage bitfield encoding/decoding
TEST_F(BitTorrentTest, PeerMessageBitfield) {
    std::vector<bool> bitfield = {true, false, true, true, false, false, true, false,
                                   true, true, false, false, true, false, false, true};
    
    auto msg = librats::PeerMessage::create_bitfield(bitfield);
    EXPECT_EQ(msg.type, librats::MessageType::BITFIELD);
    EXPECT_EQ(msg.payload.size(), 2); // 16 bits = 2 bytes
    
    // Verify encoding
    // First byte: 10110010 = 0xB2
    // Second byte: 11001001 = 0xC9
    EXPECT_EQ(msg.payload[0], 0xB2);
    EXPECT_EQ(msg.payload[1], 0xC9);
}

// Test PeerMessage request encoding
TEST_F(BitTorrentTest, PeerMessageRequest) {
    auto msg = librats::PeerMessage::create_request(42, 16384, 16384);
    
    EXPECT_EQ(msg.type, librats::MessageType::REQUEST);
    EXPECT_EQ(msg.payload.size(), 12);
    
    // Verify piece index (42)
    uint32_t piece_index = (msg.payload[0] << 24) | (msg.payload[1] << 16) | 
                          (msg.payload[2] << 8) | msg.payload[3];
    EXPECT_EQ(piece_index, 42);
    
    // Verify offset (16384)
    uint32_t offset = (msg.payload[4] << 24) | (msg.payload[5] << 16) | 
                     (msg.payload[6] << 8) | msg.payload[7];
    EXPECT_EQ(offset, 16384);
    
    // Verify length (16384)
    uint32_t length = (msg.payload[8] << 24) | (msg.payload[9] << 16) | 
                     (msg.payload[10] << 8) | msg.payload[11];
    EXPECT_EQ(length, 16384);
}

// Test TorrentInfo piece length calculation
TEST_F(BitTorrentTest, TorrentInfoPieceLength) {
    auto torrent_bencode = create_test_torrent_bencode("test.bin", 1000000, 262144);
    
    librats::TorrentInfo torrent_info;
    EXPECT_TRUE(torrent_info.load_from_bencode(torrent_bencode));
    
    // First 3 pieces should be full size
    EXPECT_EQ(torrent_info.get_piece_length(0), 262144);
    EXPECT_EQ(torrent_info.get_piece_length(1), 262144);
    EXPECT_EQ(torrent_info.get_piece_length(2), 262144);
    
    // Last piece should be smaller (1000000 % 262144 = 213568)
    EXPECT_EQ(torrent_info.get_piece_length(3), 213568);
    
    // Invalid piece index
    EXPECT_EQ(torrent_info.get_piece_length(999), 0);
}

// Test info hash calculation consistency
TEST_F(BitTorrentTest, InfoHashConsistency) {
    auto torrent_bencode = create_test_torrent_bencode("test.bin", 1048576, 262144);
    
    librats::TorrentInfo torrent_info1;
    librats::TorrentInfo torrent_info2;
    
    EXPECT_TRUE(torrent_info1.load_from_bencode(torrent_bencode));
    EXPECT_TRUE(torrent_info2.load_from_bencode(torrent_bencode));
    
    // Same torrent should produce same info hash
    EXPECT_EQ(torrent_info1.get_info_hash(), torrent_info2.get_info_hash());
    
    // Info hash should be 20 bytes
    auto info_hash_hex = librats::info_hash_to_hex(torrent_info1.get_info_hash());
    EXPECT_EQ(info_hash_hex.length(), 40); // 20 bytes * 2 hex chars
}

// Test hex to info hash conversion
TEST_F(BitTorrentTest, InfoHashConversion) {
    std::string test_hex = "0123456789abcdef0123456789abcdef01234567";
    
    auto info_hash = librats::hex_to_info_hash(test_hex);
    auto converted_back = librats::info_hash_to_hex(info_hash);
    
    EXPECT_EQ(test_hex, converted_back);
    
    // Test invalid hex string
    auto invalid_hash = librats::hex_to_info_hash("invalid");
    librats::InfoHash zero_hash;
    zero_hash.fill(0);
    EXPECT_EQ(invalid_hash, zero_hash);
}

// Test BitTorrent constants
TEST_F(BitTorrentTest, BitTorrentConstants) {
    EXPECT_EQ(librats::BLOCK_SIZE, 16384);
    EXPECT_EQ(librats::MAX_PIECE_SIZE, 2 * 1024 * 1024);
    EXPECT_GT(librats::HANDSHAKE_TIMEOUT_MS, 0);
    EXPECT_GT(librats::REQUEST_TIMEOUT_MS, 0);
    EXPECT_GT(librats::MAX_REQUESTS_PER_PEER, 0);
    EXPECT_GT(librats::MAX_PEERS_PER_TORRENT, 0);
}

// Test TorrentInfo error handling - missing required fields
TEST_F(BitTorrentTest, TorrentInfoInvalidData) {
    using namespace librats;
    
    // Missing 'info' dictionary
    BencodeDict torrent_dict;
    torrent_dict["announce"] = BencodeValue(std::string("http://tracker.example.com:6969/announce"));
    
    TorrentInfo torrent_info;
    EXPECT_FALSE(torrent_info.load_from_bencode(BencodeValue(torrent_dict)));
    EXPECT_FALSE(torrent_info.is_valid());
}

// Test TorrentInfo error handling - invalid pieces
TEST_F(BitTorrentTest, TorrentInfoInvalidPieces) {
    using namespace librats;
    
    BencodeDict info_dict;
    info_dict["name"] = BencodeValue(std::string("test.bin"));
    info_dict["length"] = BencodeValue(static_cast<int64_t>(1048576));
    info_dict["piece length"] = BencodeValue(static_cast<int64_t>(262144));
    // Invalid pieces length (not multiple of 20)
    info_dict["pieces"] = BencodeValue(std::string("invalid"));
    
    BencodeDict torrent_dict;
    torrent_dict["info"] = BencodeValue(info_dict);
    torrent_dict["announce"] = BencodeValue(std::string("http://tracker.example.com:6969/announce"));
    
    TorrentInfo torrent_info;
    EXPECT_FALSE(torrent_info.load_from_bencode(BencodeValue(torrent_dict)));
}

// Test file system integration - file creation with size
TEST_F(BitTorrentTest, FileSystemIntegration) {
    std::string test_file = test_dir_ + "/test_file.bin";
    
    // Create a file with specific size
    uint64_t file_size = 1048576; // 1MB
    EXPECT_TRUE(librats::create_file_with_size(test_file.c_str(), file_size));
    
    // Verify file exists and has correct size
    EXPECT_TRUE(librats::file_exists(test_file.c_str()));
    EXPECT_EQ(librats::get_file_size(test_file.c_str()), static_cast<int64_t>(file_size));
    
    // Test chunk writing
    std::vector<uint8_t> test_data(16384, 0xAB);
    EXPECT_TRUE(librats::write_file_chunk(test_file.c_str(), 0, test_data.data(), test_data.size()));
    
    // Test chunk reading
    std::vector<uint8_t> read_data(16384);
    EXPECT_TRUE(librats::read_file_chunk(test_file.c_str(), 0, read_data.data(), read_data.size()));
    EXPECT_EQ(test_data, read_data);
}

// Test BitTorrent client configuration
TEST_F(BitTorrentTest, BitTorrentClientConfiguration) {
    auto client = std::make_unique<librats::BitTorrentClient>();
    
    client->set_max_connections_per_torrent(30);
    client->set_download_rate_limit(1024 * 1024); // 1 MB/s
    client->set_upload_rate_limit(512 * 1024);     // 512 KB/s
    
    EXPECT_TRUE(client->start(58890));
    EXPECT_TRUE(client->is_running());
    
    client->stop();
    EXPECT_FALSE(client->is_running());
}

// Test PeerMessage piece encoding/decoding
TEST_F(BitTorrentTest, PeerMessagePiece) {
    std::vector<uint8_t> test_data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    auto msg = librats::PeerMessage::create_piece(10, 32768, test_data);
    
    EXPECT_EQ(msg.type, librats::MessageType::PIECE);
    EXPECT_EQ(msg.payload.size(), 8 + test_data.size());
    
    // Verify piece index (10)
    uint32_t piece_index = (msg.payload[0] << 24) | (msg.payload[1] << 16) | 
                          (msg.payload[2] << 8) | msg.payload[3];
    EXPECT_EQ(piece_index, 10);
    
    // Verify offset (32768)
    uint32_t offset = (msg.payload[4] << 24) | (msg.payload[5] << 16) | 
                     (msg.payload[6] << 8) | msg.payload[7];
    EXPECT_EQ(offset, 32768);
    
    // Verify data
    std::vector<uint8_t> extracted_data(msg.payload.begin() + 8, msg.payload.end());
    EXPECT_EQ(extracted_data, test_data);
}

// Test TorrentInfo with announce-list
TEST_F(BitTorrentTest, TorrentInfoAnnounceList) {
    using namespace librats;
    
    auto torrent_bencode = create_test_torrent_bencode("test.bin", 1048576, 262144);
    
    // Add announce-list
    BencodeDict& torrent_dict = const_cast<BencodeDict&>(torrent_bencode.as_dict());
    
    BencodeList announce_list;
    BencodeList tier1;
    tier1.push_back(BencodeValue(std::string("http://tracker1.example.com:6969/announce")));
    announce_list.push_back(BencodeValue(tier1));
    
    BencodeList tier2;
    tier2.push_back(BencodeValue(std::string("http://tracker2.example.com:6969/announce")));
    announce_list.push_back(BencodeValue(tier2));
    
    torrent_dict["announce-list"] = BencodeValue(announce_list);
    
    TorrentInfo torrent_info;
    EXPECT_TRUE(torrent_info.load_from_bencode(torrent_bencode));
    
    EXPECT_FALSE(torrent_info.get_announce_list().empty());
    EXPECT_EQ(torrent_info.get_announce_list().size(), 2);
}

// Test PeerMessage cancel encoding
TEST_F(BitTorrentTest, PeerMessageCancel) {
    auto msg = librats::PeerMessage::create_cancel(5, 8192, 16384);
    
    EXPECT_EQ(msg.type, librats::MessageType::CANCEL);
    EXPECT_EQ(msg.payload.size(), 12);
    
    // Verify all fields
    uint32_t piece_index = (msg.payload[0] << 24) | (msg.payload[1] << 16) | 
                          (msg.payload[2] << 8) | msg.payload[3];
    EXPECT_EQ(piece_index, 5);
    
    uint32_t offset = (msg.payload[4] << 24) | (msg.payload[5] << 16) | 
                     (msg.payload[6] << 8) | msg.payload[7];
    EXPECT_EQ(offset, 8192);
    
    uint32_t length = (msg.payload[8] << 24) | (msg.payload[9] << 16) | 
                     (msg.payload[10] << 8) | msg.payload[11];
    EXPECT_EQ(length, 16384);
}

// Test PeerMessage port encoding
TEST_F(BitTorrentTest, PeerMessagePort) {
    auto msg = librats::PeerMessage::create_port(6881);
    
    EXPECT_EQ(msg.type, librats::MessageType::PORT);
    EXPECT_EQ(msg.payload.size(), 2);
    
    uint16_t port = (msg.payload[0] << 8) | msg.payload[1];
    EXPECT_EQ(port, 6881);
}

// Test TorrentInfo private flag
TEST_F(BitTorrentTest, TorrentInfoPrivateFlag) {
    using namespace librats;
    
    auto torrent_bencode = create_test_torrent_bencode("test.bin", 1048576, 262144);
    
    // Add private flag
    BencodeDict& torrent_dict = const_cast<BencodeDict&>(torrent_bencode.as_dict());
    BencodeDict& info_dict = const_cast<BencodeDict&>(torrent_dict["info"].as_dict());
    info_dict["private"] = BencodeValue(static_cast<int64_t>(1));
    
    TorrentInfo torrent_info;
    EXPECT_TRUE(torrent_info.load_from_bencode(torrent_bencode));
    EXPECT_TRUE(torrent_info.is_private());
}

// Test empty bitfield
TEST_F(BitTorrentTest, PeerMessageEmptyBitfield) {
    std::vector<bool> empty_bitfield;
    auto msg = librats::PeerMessage::create_bitfield(empty_bitfield);
    
    EXPECT_EQ(msg.type, librats::MessageType::BITFIELD);
    EXPECT_EQ(msg.payload.size(), 0);
}

// Test file path normalization in multi-file torrents
TEST_F(BitTorrentTest, TorrentInfoFilePathNormalization) {
    using namespace librats;
    
    BencodeDict info_dict;
    info_dict["name"] = BencodeValue(std::string("root"));
    info_dict["piece length"] = BencodeValue(static_cast<int64_t>(262144));
    
    BencodeList files_list;
    BencodeDict file;
    file["length"] = BencodeValue(static_cast<int64_t>(1024));
    
    BencodeList path;
    path.push_back(BencodeValue(std::string("folder")));
    path.push_back(BencodeValue(std::string("subfolder")));
    path.push_back(BencodeValue(std::string("file.txt")));
    file["path"] = BencodeValue(path);
    
    files_list.push_back(BencodeValue(file));
    info_dict["files"] = BencodeValue(files_list);
    
    // Generate piece hashes
    std::string pieces_data(20, 0);
    info_dict["pieces"] = BencodeValue(pieces_data);
    
    BencodeDict torrent_dict;
    torrent_dict["info"] = BencodeValue(info_dict);
    torrent_dict["announce"] = BencodeValue(std::string("http://tracker.example.com:6969/announce"));
    
    TorrentInfo torrent_info;
    EXPECT_TRUE(torrent_info.load_from_bencode(BencodeValue(torrent_dict)));
    
    const auto& files = torrent_info.get_files();
    EXPECT_EQ(files.size(), 1);
    EXPECT_EQ(files[0].path, "folder/subfolder/file.txt");
}

// Test directory structure creation
TEST_F(BitTorrentTest, DirectoryStructureCreation) {
    std::string nested_dir = test_dir_ + "/level1/level2/level3";
    
    EXPECT_TRUE(librats::create_directories(nested_dir.c_str()));
    EXPECT_TRUE(librats::directory_exists(nested_dir.c_str()));
    
    // Verify intermediate directories were created
    EXPECT_TRUE(librats::directory_exists((test_dir_ + "/level1").c_str()));
    EXPECT_TRUE(librats::directory_exists((test_dir_ + "/level1/level2").c_str()));
}

// Test file metadata operations
TEST_F(BitTorrentTest, FileMetadataOperations) {
    std::string test_file = test_dir_ + "/metadata_test.txt";
    
    std::string content = "Test content";
    EXPECT_TRUE(librats::create_file(test_file.c_str(), content.c_str()));
    
    // Test file size
    EXPECT_EQ(librats::get_file_size(test_file.c_str()), static_cast<int64_t>(content.length()));
    
    // Test is_file
    EXPECT_TRUE(librats::is_file(test_file.c_str()));
    EXPECT_FALSE(librats::is_directory(test_file.c_str()));
    
    // Test get_filename_from_path
    EXPECT_EQ(librats::get_filename_from_path(test_file.c_str()), "metadata_test.txt");
    
    // Test get_file_extension
    EXPECT_EQ(librats::get_file_extension(test_file.c_str()), ".txt");
    
    // Test get_parent_directory
    std::string parent = librats::get_parent_directory(test_file.c_str());
    EXPECT_TRUE(parent.find(test_dir_) != std::string::npos);
}

// Test zero-length piece handling
TEST_F(BitTorrentTest, ZeroLengthEdgeCases) {
    librats::PieceInfo piece(0, std::array<uint8_t, 20>{}, 0);
    EXPECT_EQ(piece.get_num_blocks(), 0);
    EXPECT_TRUE(piece.is_complete()); // Zero-length piece is complete by default
} 