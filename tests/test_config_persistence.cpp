#include "../src/librats.h"
#include "../src/fs.h"
#include "../src/json.hpp"
#include <gtest/gtest.h>
#include <thread>
#include <chrono>

using namespace librats;

class ConfigPersistenceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Clean up any existing config files before each test
        if (file_exists("config.json")) {
            delete_file("config.json");
        }
        if (file_exists("peers.rats")) {
            delete_file("peers.rats");
        }
    }
    
    void TearDown() override {
        // Clean up after each test
        if (file_exists("config.json")) {
            delete_file("config.json");
        }
        if (file_exists("peers.rats")) {
            delete_file("peers.rats");
        }
    }
};

TEST_F(ConfigPersistenceTest, PeerIdGenerationAndPersistence) {
    // Create first client instance
    std::string first_peer_id;
    {
        RatsClient client1(8888, 5);
        first_peer_id = client1.get_our_peer_id();
        EXPECT_FALSE(first_peer_id.empty());
        EXPECT_EQ(first_peer_id.length(), 40); // SHA1 hash length
    }
    
    // Create second client instance - should load the same peer ID
    {
        RatsClient client2(8888, 5);
        std::string second_peer_id = client2.get_our_peer_id();
        EXPECT_EQ(second_peer_id, first_peer_id);
    }
    
    // Verify config file was created
    EXPECT_TRUE(file_exists("config.json"));
    
    // Parse and verify config file content
    std::string config_data = read_file_text_cpp("config.json");
    EXPECT_FALSE(config_data.empty());
    
    nlohmann::json config = nlohmann::json::parse(config_data);
    EXPECT_TRUE(config.contains("peer_id"));
    EXPECT_EQ(config["peer_id"], first_peer_id);
    EXPECT_TRUE(config.contains("version"));
    EXPECT_TRUE(config.contains("listen_port"));
    EXPECT_EQ(config["listen_port"], 8888);
}

/*
TEST_F(ConfigPersistenceTest, PeerSerialization) {
    // Create two clients on different ports
    RatsClient client1(8889, 5);
    RatsClient client2(8890, 5);
    
    // Start both clients
    ASSERT_TRUE(client1.start());
    ASSERT_TRUE(client2.start());
    
    // Give them time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Connect client1 to client2
    bool connected = client1.connect_to_peer("127.0.0.1", 8890);
    EXPECT_TRUE(connected);
    
    // Give time for handshake to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // Check that they are connected
    EXPECT_GE(client1.get_peer_count(), 1);
    EXPECT_GE(client2.get_peer_count(), 1);
    
    // Stop the clients (this should save peers)
    client1.stop();
    client2.stop();
    
    // Give time for cleanup
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Verify peers.rats file was created
    EXPECT_TRUE(file_exists("peers.rats"));
    
    // Parse and verify peers file content
    std::string peers_data = read_file_text_cpp("peers.rats");
    EXPECT_FALSE(peers_data.empty());
    
    nlohmann::json peers = nlohmann::json::parse(peers_data);
    EXPECT_TRUE(peers.is_array());
    
    if (peers.size() > 0) {
        // Check first peer has required fields
        const auto& peer = peers[0];
        EXPECT_TRUE(peer.contains("ip"));
        EXPECT_TRUE(peer.contains("port"));
        EXPECT_TRUE(peer.contains("peer_id"));
        EXPECT_TRUE(peer.contains("normalized_address"));
        EXPECT_TRUE(peer.contains("last_seen"));
    }
}
*/

TEST_F(ConfigPersistenceTest, PeerReconnectionAttempt) {
    // Create a mock peers.rats file with a test peer
    nlohmann::json peers = nlohmann::json::array();
    nlohmann::json test_peer;
    test_peer["ip"] = "127.0.0.1";
    test_peer["port"] = 8891;
    test_peer["peer_id"] = "test_peer_id_for_reconnection_test";
    test_peer["normalized_address"] = "127.0.0.1:8891";
    test_peer["is_outgoing"] = true;
    test_peer["version"] = "1.0";
    
    auto now = std::chrono::high_resolution_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    test_peer["last_seen"] = timestamp;
    
    peers.push_back(test_peer);
    
    std::string peers_data = peers.dump(4);
    ASSERT_TRUE(create_file("peers.rats", peers_data));
    
    // Create a client that should attempt to reconnect
    RatsClient client(8892, 5);
    ASSERT_TRUE(client.start());
    
    // Give time for reconnection attempts
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    client.stop();
    
    // Test passes if no crashes occur (reconnection will fail since no server on 8891, but that's expected)
    SUCCEED();
} 