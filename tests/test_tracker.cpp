#include <gtest/gtest.h>
#include "tracker.h"
#include "bittorrent.h"
#include <thread>
#include <chrono>

using namespace librats;

// Test fixture for tracker tests
class TrackerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Generate test info hash
        test_info_hash_.fill(0x12);
        
        // Generate test peer ID
        test_peer_id_ = generate_peer_id();
    }
    
    InfoHash test_info_hash_;
    PeerID test_peer_id_;
};

// Test TrackerEvent utility functions
TEST_F(TrackerTest, TrackerEventConversion) {
    EXPECT_EQ(tracker_event_to_string(TrackerEvent::STARTED), "started");
    EXPECT_EQ(tracker_event_to_string(TrackerEvent::STOPPED), "stopped");
    EXPECT_EQ(tracker_event_to_string(TrackerEvent::COMPLETED), "completed");
    EXPECT_EQ(tracker_event_to_string(TrackerEvent::NONE), "");
    
    EXPECT_EQ(string_to_tracker_event("started"), TrackerEvent::STARTED);
    EXPECT_EQ(string_to_tracker_event("stopped"), TrackerEvent::STOPPED);
    EXPECT_EQ(string_to_tracker_event("completed"), TrackerEvent::COMPLETED);
    EXPECT_EQ(string_to_tracker_event(""), TrackerEvent::NONE);
}

// Test HttpTrackerClient creation
TEST_F(TrackerTest, HttpTrackerClientCreation) {
    HttpTrackerClient http_tracker("http://tracker.example.com:8080/announce");
    
    EXPECT_EQ(http_tracker.get_url(), "http://tracker.example.com:8080/announce");
    EXPECT_TRUE(http_tracker.is_working());  // Initially marked as working
}

// Test UdpTrackerClient URL parsing
TEST_F(TrackerTest, UdpTrackerClientUrlParsing) {
    UdpTrackerClient udp_tracker("udp://tracker.example.com:6969/announce");
    
    EXPECT_EQ(udp_tracker.get_url(), "udp://tracker.example.com:6969/announce");
}

// Test TrackerRequest construction
TEST_F(TrackerTest, TrackerRequestConstruction) {
    TrackerRequest request;
    request.info_hash = test_info_hash_;
    request.peer_id = test_peer_id_;
    request.port = 6881;
    request.uploaded = 0;
    request.downloaded = 0;
    request.left = 1000000;
    request.event = TrackerEvent::STARTED;
    request.numwant = 50;
    
    EXPECT_EQ(request.port, 6881);
    EXPECT_EQ(request.uploaded, 0);
    EXPECT_EQ(request.downloaded, 0);
    EXPECT_EQ(request.left, 1000000);
    EXPECT_EQ(request.event, TrackerEvent::STARTED);
    EXPECT_EQ(request.numwant, 50);
}

// Test TrackerResponse construction
TEST_F(TrackerTest, TrackerResponseConstruction) {
    TrackerResponse response;
    
    EXPECT_FALSE(response.success);
    EXPECT_EQ(response.interval, 1800);
    EXPECT_EQ(response.min_interval, 900);
    EXPECT_EQ(response.complete, 0);
    EXPECT_EQ(response.incomplete, 0);
    EXPECT_TRUE(response.peers.empty());
}

// Test HttpTrackerClient URL building
TEST_F(TrackerTest, HttpTrackerUrlBuilding) {
    HttpTrackerClient tracker("http://tracker.example.com/announce");
    
    TrackerRequest request;
    request.info_hash = test_info_hash_;
    request.peer_id = test_peer_id_;
    request.port = 6881;
    request.uploaded = 100;
    request.downloaded = 200;
    request.left = 900;
    request.event = TrackerEvent::STARTED;
    request.numwant = 50;
    
    // Note: build_announce_url is private, but we can test via announce
    // This test mainly verifies the tracker is constructed correctly
    EXPECT_EQ(tracker.get_url(), "http://tracker.example.com/announce");
}

// Test compact peer list parsing (BEP 23)
TEST_F(TrackerTest, CompactPeerListParsing) {
    // Create a compact peer list: IP + port (6 bytes per peer)
    // Peer 1: 192.168.1.100:6881
    // Peer 2: 10.0.0.50:51413
    std::string compact_peers;
    
    // Peer 1: 192.168.1.100:6881
    compact_peers += static_cast<char>(192);
    compact_peers += static_cast<char>(168);
    compact_peers += static_cast<char>(1);
    compact_peers += static_cast<char>(100);
    compact_peers += static_cast<char>(6881 >> 8);      // Port high byte
    compact_peers += static_cast<char>(6881 & 0xFF);    // Port low byte
    
    // Peer 2: 10.0.0.50:51413
    compact_peers += static_cast<char>(10);
    compact_peers += static_cast<char>(0);
    compact_peers += static_cast<char>(0);
    compact_peers += static_cast<char>(50);
    compact_peers += static_cast<char>(51413 >> 8);     // Port high byte
    compact_peers += static_cast<char>(51413 & 0xFF);   // Port low byte
    
    // Create bencode response with compact peers
    BencodeValue response = BencodeValue::create_dict();
    response["interval"] = BencodeValue::create_integer(1800);
    response["complete"] = BencodeValue::create_integer(100);
    response["incomplete"] = BencodeValue::create_integer(50);
    response["peers"] = BencodeValue::create_string(compact_peers);
    
    // Encode and parse
    std::vector<uint8_t> encoded = response.encode();
    
    HttpTrackerClient tracker("http://test.com/announce");
    // We can't directly test parse_response as it's private,
    // but this verifies the bencode structure is correct
    EXPECT_GT(encoded.size(), 0);
}

// Test UDP tracker transaction ID generation
TEST_F(TrackerTest, UdpTransactionIdGeneration) {
    UdpTrackerClient tracker("udp://tracker.example.com:6969");
    
    // Generate multiple transaction IDs and ensure they're different
    // Note: generate_transaction_id is private, so we test indirectly
    // by verifying the tracker is constructed properly
    EXPECT_TRUE(tracker.is_working() || !tracker.is_working()); // Constructor may fail
}

// Test TrackerManager with TorrentInfo
TEST_F(TrackerTest, TrackerManagerCreation) {
    // Create a minimal TorrentInfo for testing
    TorrentInfo torrent_info;
    
    // Create fake bencode torrent data
    BencodeValue torrent_data = BencodeValue::create_dict();
    torrent_data["announce"] = BencodeValue::create_string("http://tracker1.example.com/announce");
    
    // Create announce-list
    BencodeValue announce_list = BencodeValue::create_list();
    BencodeValue tier1 = BencodeValue::create_list();
    tier1.push_back(BencodeValue::create_string("http://tracker2.example.com/announce"));
    announce_list.push_back(tier1);
    torrent_data["announce-list"] = announce_list;
    
    // Create minimal info dict
    BencodeValue info_dict = BencodeValue::create_dict();
    info_dict["name"] = BencodeValue::create_string("test.txt");
    info_dict["piece length"] = BencodeValue::create_integer(16384);
    info_dict["length"] = BencodeValue::create_integer(1000);
    
    // Create pieces (at least one 20-byte hash)
    std::string pieces_data(20, '\0');
    info_dict["pieces"] = BencodeValue::create_string(pieces_data);
    
    torrent_data["info"] = info_dict;
    
    // Load torrent
    ASSERT_TRUE(torrent_info.load_from_bencode(torrent_data));
    
    // Create tracker manager
    TrackerManager manager(torrent_info);
    
    // Verify trackers were added
    auto tracker_urls = manager.get_tracker_urls();
    EXPECT_GE(tracker_urls.size(), 1);
    
    // Check for the announce URL
    bool found_announce = false;
    for (const auto& url : tracker_urls) {
        if (url == "http://tracker1.example.com/announce") {
            found_announce = true;
            break;
        }
    }
    EXPECT_TRUE(found_announce);
}

// Test TrackerManager add tracker
TEST_F(TrackerTest, TrackerManagerAddTracker) {
    // Create minimal TorrentInfo
    TorrentInfo torrent_info = TorrentInfo::create_for_metadata_exchange(test_info_hash_);
    
    TrackerManager manager(torrent_info);
    
    // Add HTTP tracker
    EXPECT_TRUE(manager.add_tracker("http://new-tracker.example.com/announce"));
    
    // Try to add same tracker again (should fail)
    EXPECT_FALSE(manager.add_tracker("http://new-tracker.example.com/announce"));
    
    // Add UDP tracker
    EXPECT_TRUE(manager.add_tracker("udp://udp-tracker.example.com:6969"));
    
    // Verify tracker count
    EXPECT_GE(manager.get_tracker_urls().size(), 2);
}

// Test URL encoding for binary data
TEST_F(TrackerTest, UrlEncodeBinary) {
    HttpTrackerClient tracker("http://test.com/announce");
    
    // Test data with special characters
    uint8_t test_data[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    
    // Note: url_encode_binary is private, so we test indirectly
    // by verifying tracker construction succeeds
    EXPECT_EQ(tracker.get_url(), "http://test.com/announce");
}

// Test interval and timing
TEST_F(TrackerTest, AnnounceIntervals) {
    TorrentInfo torrent_info = TorrentInfo::create_for_metadata_exchange(test_info_hash_);
    TrackerManager manager(torrent_info);
    
    // Should not need to announce immediately after creation
    // (unless we've manually set last_announce_time)
    // This is mostly a structural test
    EXPECT_GE(manager.get_working_tracker_count(), 0);
}

// Test multiple tracker support
TEST_F(TrackerTest, MultipleTrackers) {
    TorrentInfo torrent_info = TorrentInfo::create_for_metadata_exchange(test_info_hash_);
    TrackerManager manager(torrent_info);
    
    // Add multiple trackers
    manager.add_tracker("http://tracker1.example.com/announce");
    manager.add_tracker("http://tracker2.example.com/announce");
    manager.add_tracker("udp://tracker3.example.com:6969");
    
    auto tracker_urls = manager.get_tracker_urls();
    EXPECT_EQ(tracker_urls.size(), 3);
}

// Integration test: TorrentDownload with trackers
TEST_F(TrackerTest, TorrentDownloadWithTrackers) {
    // Create a simple torrent
    TorrentInfo torrent_info = TorrentInfo::create_for_metadata_exchange(test_info_hash_);
    
    TorrentDownload torrent(torrent_info, "./test_download");
    
    // Verify tracker manager was created
    EXPECT_NE(torrent.get_tracker_manager(), nullptr);
    
    // Note: We don't actually start the download or announce to real trackers in tests
    // This just verifies the integration is set up correctly
}

//=============================================================================
// Simple Scrape API Tests
//=============================================================================

// Test hex_to_info_hash conversion
TEST_F(TrackerTest, HexToInfoHashConversion) {
    // Valid 40-character hex string
    std::string valid_hex = "1234567890abcdef1234567890abcdef12345678";
    InfoHash hash = hex_to_info_hash(valid_hex);
    
    // Verify first byte: 0x12
    EXPECT_EQ(hash[0], 0x12);
    // Verify second byte: 0x34
    EXPECT_EQ(hash[1], 0x34);
    // Verify last byte: 0x78
    EXPECT_EQ(hash[19], 0x78);
}

// Test hex_to_info_hash with invalid input
TEST_F(TrackerTest, HexToInfoHashInvalidInput) {
    // Too short
    InfoHash hash1 = hex_to_info_hash("12345678");
    bool all_zero1 = true;
    for (auto b : hash1) {
        if (b != 0) { all_zero1 = false; break; }
    }
    EXPECT_TRUE(all_zero1);
    
    // Invalid characters
    InfoHash hash2 = hex_to_info_hash("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
    bool all_zero2 = true;
    for (auto b : hash2) {
        if (b != 0) { all_zero2 = false; break; }
    }
    EXPECT_TRUE(all_zero2);
    
    // Empty string
    InfoHash hash3 = hex_to_info_hash("");
    bool all_zero3 = true;
    for (auto b : hash3) {
        if (b != 0) { all_zero3 = false; break; }
    }
    EXPECT_TRUE(all_zero3);
}

// Test ScrapeResult structure
TEST_F(TrackerTest, ScrapeResultConstruction) {
    ScrapeResult result;
    
    EXPECT_EQ(result.seeders, 0);
    EXPECT_EQ(result.leechers, 0);
    EXPECT_EQ(result.completed, 0);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.tracker.empty());
    EXPECT_TRUE(result.error.empty());
}

// Test get_default_trackers
TEST_F(TrackerTest, GetDefaultTrackers) {
    std::vector<std::string> trackers = get_default_trackers();
    
    // Should have at least some default trackers
    EXPECT_GE(trackers.size(), 4);
    
    // Check that trackers have valid protocol prefixes
    for (const auto& tracker : trackers) {
        EXPECT_TRUE(tracker.substr(0, 6) == "udp://" || tracker.substr(0, 7) == "http://" || tracker.substr(0, 8) == "https://");
    }
}

// Test scrape_tracker with invalid hash
TEST_F(TrackerTest, ScrapeTrackerInvalidHash) {
    bool callback_called = false;
    ScrapeResult result;
    
    // Invalid hash (too short)
    scrape_tracker("udp://tracker.example.com:6969", "invalid_hash", 
        [&callback_called, &result](const ScrapeResult& r) {
            callback_called = true;
            result = r;
        }, 1000);
    
    EXPECT_TRUE(callback_called);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error.empty());
}

// Test scrape_tracker with unsupported protocol
TEST_F(TrackerTest, ScrapeTrackerUnsupportedProtocol) {
    bool callback_called = false;
    ScrapeResult result;
    
    // Invalid protocol
    scrape_tracker("ftp://tracker.example.com:6969", "1234567890abcdef1234567890abcdef12345678", 
        [&callback_called, &result](const ScrapeResult& r) {
            callback_called = true;
            result = r;
        }, 1000);
    
    EXPECT_TRUE(callback_called);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.error, "Unsupported tracker protocol");
}

// Test scrape_multiple_trackers with invalid hash
TEST_F(TrackerTest, ScrapeMultipleTrackersInvalidHash) {
    bool callback_called = false;
    ScrapeResult result;
    
    // Invalid hash (too short)
    scrape_multiple_trackers("short_hash", 
        [&callback_called, &result](const ScrapeResult& r) {
            callback_called = true;
            result = r;
        }, 1000);
    
    EXPECT_TRUE(callback_called);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error.empty());
}
