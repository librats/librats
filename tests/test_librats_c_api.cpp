#include <gtest/gtest.h>
#include "librats_c.h"
#include <thread>
#include <chrono>
#include <cstring>
#include <cstdlib>

class RatsCApiTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Disable verbose logging for tests
        rats_set_logging_enabled(1);
        rats_set_log_level("WARN");
    }
    
    void TearDown() override {
        // Cleanup any remaining clients
        if (client1) {
            rats_destroy(client1);
            client1 = nullptr;
        }
        if (client2) {
            rats_destroy(client2);
            client2 = nullptr;
        }
    }
    
    rats_client_t client1 = nullptr;
    rats_client_t client2 = nullptr;
};

// Basic C API creation and destruction tests
TEST_F(RatsCApiTest, BasicCreationAndDestruction) {
    // Test creating client with default port
    client1 = rats_create(0);
    ASSERT_NE(client1, nullptr);
    
    // Test that client starts successfully
    EXPECT_EQ(rats_start(client1), RATS_SUCCESS);
    
    // Test get peer ID
    char* peer_id = rats_get_our_peer_id(client1);
    ASSERT_NE(peer_id, nullptr);
    EXPECT_GT(strlen(peer_id), 0);
    rats_string_free(peer_id);
    
    // Test get peer count
    EXPECT_GE(rats_get_peer_count(client1), 0);
    
    // Test stopping and destroy
    rats_stop(client1);
    rats_destroy(client1);
    client1 = nullptr;
}

TEST_F(RatsCApiTest, ErrorHandling) {
    // Test null handle operations
    EXPECT_EQ(rats_start(nullptr), RATS_ERROR_INVALID_HANDLE);
    EXPECT_EQ(rats_get_peer_count(nullptr), 0);
    EXPECT_EQ(rats_get_our_peer_id(nullptr), nullptr);
    
    // Test operations on stopped client
    client1 = rats_create(0);
    ASSERT_NE(client1, nullptr);
    
    // Test invalid parameters
    EXPECT_EQ(rats_connect_with_strategy(nullptr, "127.0.0.1", 8080, RATS_STRATEGY_DIRECT_ONLY), RATS_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rats_connect_with_strategy(client1, nullptr, 8080, RATS_STRATEGY_DIRECT_ONLY), RATS_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rats_send_string(nullptr, "peer", "message"), RATS_ERROR_INVALID_HANDLE);
    EXPECT_EQ(rats_send_string(client1, nullptr, "message"), RATS_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rats_send_string(client1, "peer", nullptr), RATS_ERROR_INVALID_PARAMETER);
    
    rats_destroy(client1);
    client1 = nullptr;
}

TEST_F(RatsCApiTest, ConnectionStrategies) {
    client1 = rats_create(60000);
    ASSERT_NE(client1, nullptr);
    EXPECT_EQ(rats_start(client1), RATS_SUCCESS);
    
    client2 = rats_create(60001);
    ASSERT_NE(client2, nullptr);
    EXPECT_EQ(rats_start(client2), RATS_SUCCESS);
    
    // Test different connection strategies
    EXPECT_EQ(rats_connect_with_strategy(client2, "127.0.0.1", 60000, RATS_STRATEGY_DIRECT_ONLY), RATS_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    EXPECT_EQ(rats_connect_with_strategy(client2, "127.0.0.1", 60000, RATS_STRATEGY_STUN_ASSISTED), RATS_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    EXPECT_EQ(rats_connect_with_strategy(client2, "127.0.0.1", 60000, RATS_STRATEGY_ICE_FULL), RATS_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    EXPECT_EQ(rats_connect_with_strategy(client2, "127.0.0.1", 60000, RATS_STRATEGY_AUTO_ADAPTIVE), RATS_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // TURN relay might fail if no TURN server is configured
    rats_connect_with_strategy(client2, "127.0.0.1", 60000, RATS_STRATEGY_TURN_RELAY); // Don't check result
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    rats_stop(client1);
    rats_stop(client2);
}

// Test binary data APIs (these should compile and not crash)
TEST_F(RatsCApiTest, BinaryDataAPIs) {
    client1 = rats_create(60000);
    ASSERT_NE(client1, nullptr);
    
    // Test binary send functions exist and handle errors properly
    std::vector<uint8_t> test_data = {0x01, 0x02, 0x03, 0x04};
    
    // Test with null parameters
    EXPECT_EQ(rats_send_binary(nullptr, "peer", test_data.data(), test_data.size()), RATS_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rats_send_binary(client1, nullptr, test_data.data(), test_data.size()), RATS_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rats_send_binary(client1, "peer", nullptr, test_data.size()), RATS_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rats_send_binary(client1, "peer", test_data.data(), 0), RATS_ERROR_INVALID_PARAMETER);
    
    // Test broadcast functions
    EXPECT_EQ(rats_broadcast_binary(nullptr, test_data.data(), test_data.size()), 0);
    EXPECT_EQ(rats_broadcast_binary(client1, nullptr, test_data.size()), 0);
    EXPECT_EQ(rats_broadcast_binary(client1, test_data.data(), 0), 0);
    
    rats_destroy(client1);
    client1 = nullptr;
}

// Test JSON APIs
TEST_F(RatsCApiTest, JsonAPIs) {
    client1 = rats_create(60000);
    ASSERT_NE(client1, nullptr);
    
    const char* json_str = "{\"test\": \"value\"}";
    
    // Test with null parameters
    EXPECT_EQ(rats_send_json(nullptr, "peer", json_str), RATS_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rats_send_json(client1, nullptr, json_str), RATS_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rats_send_json(client1, "peer", nullptr), RATS_ERROR_INVALID_PARAMETER);
    
    // Test broadcast functions
    EXPECT_EQ(rats_broadcast_json(nullptr, json_str), 0);
    EXPECT_EQ(rats_broadcast_json(client1, nullptr), 0);
    
    rats_destroy(client1);
    client1 = nullptr;
}

// Test configuration and utility APIs
TEST_F(RatsCApiTest, ConfigurationAPIs) {
    // Test global configuration
    rats_set_logging_enabled(1);
    rats_set_log_level("DEBUG");
    rats_set_log_level("INFO");
    rats_set_log_level("WARN");
    rats_set_log_level("ERROR");
    
    client1 = rats_create(60000);
    ASSERT_NE(client1, nullptr);
    
    // Test encryption settings
    EXPECT_EQ(rats_set_encryption_enabled(client1, 1), RATS_SUCCESS);
    EXPECT_EQ(rats_set_encryption_enabled(client1, 0), RATS_SUCCESS);
    EXPECT_EQ(rats_set_encryption_enabled(nullptr, 1), RATS_ERROR_INVALID_HANDLE);
    
    // Test DHT operations
    EXPECT_EQ(rats_start_dht_discovery(client1, 6881), RATS_SUCCESS);
    rats_stop_dht_discovery(client1);
    EXPECT_EQ(rats_start_dht_discovery(nullptr, 6881), RATS_ERROR_INVALID_HANDLE);
    
    // Test mDNS operations - need to start client first
    EXPECT_EQ(rats_start(client1), RATS_SUCCESS);
    EXPECT_EQ(rats_start_mdns_discovery(client1, "test_service"), RATS_SUCCESS);
    rats_stop_mdns_discovery(client1);
    rats_stop(client1);
    EXPECT_EQ(rats_start_mdns_discovery(nullptr, "test_service"), RATS_ERROR_INVALID_HANDLE);
    
    rats_destroy(client1);
    client1 = nullptr;
}

// Test file transfer APIs
TEST_F(RatsCApiTest, FileTransferAPIs) {
    client1 = rats_create(60000);
    ASSERT_NE(client1, nullptr);
    
    // Test file operations with null parameters - these should return nullptr
    EXPECT_EQ(rats_send_file(nullptr, "peer", "/path/to/file", "remote.txt"), nullptr);
    EXPECT_EQ(rats_send_file(client1, nullptr, "/path/to/file", "remote.txt"), nullptr);
    EXPECT_EQ(rats_send_file(client1, "peer", nullptr, "remote.txt"), nullptr);
    EXPECT_EQ(rats_send_file(client1, "peer", "/path/to/file", nullptr), nullptr);
    
    // These should return nullptr since files don't exist and peer doesn't exist
    EXPECT_EQ(rats_send_file(client1, "nonexistent_peer", "/nonexistent/file", "remote.txt"), nullptr);
    
    rats_destroy(client1);
    client1 = nullptr;
}

// Test message exchange APIs
TEST_F(RatsCApiTest, MessageExchangeAPIs) {
    client1 = rats_create(60000);
    ASSERT_NE(client1, nullptr);
    
    // Test message registration with null parameters
    EXPECT_EQ(rats_on_message(nullptr, "test", nullptr, nullptr), RATS_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rats_on_message(client1, nullptr, nullptr, nullptr), RATS_ERROR_INVALID_PARAMETER);
    
    // Test message sending
    EXPECT_EQ(rats_send_message(nullptr, "peer", "type", "data"), RATS_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rats_send_message(client1, nullptr, "type", "data"), RATS_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rats_send_message(client1, "peer", nullptr, "data"), RATS_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rats_send_message(client1, "peer", "type", nullptr), RATS_ERROR_INVALID_PARAMETER);
    
    rats_destroy(client1);
    client1 = nullptr;
}

// Test callback setting (should not crash)
TEST_F(RatsCApiTest, CallbackAPIs) {
    client1 = rats_create(60000);
    ASSERT_NE(client1, nullptr);
    
    // These should not crash when setting to nullptr
    rats_set_connection_callback(client1, nullptr, nullptr);
    rats_set_string_callback(client1, nullptr, nullptr);
    rats_set_binary_callback(client1, nullptr, nullptr);
    rats_set_json_callback(client1, nullptr, nullptr);
    rats_set_disconnect_callback(client1, nullptr, nullptr);
    rats_set_peer_discovered_callback(client1, nullptr, nullptr);
    rats_set_file_progress_callback(client1, nullptr, nullptr);
    
    // Test with null handle - should not crash
    rats_set_connection_callback(nullptr, nullptr, nullptr);
    rats_set_string_callback(nullptr, nullptr, nullptr);
    
    rats_destroy(client1);
    client1 = nullptr;
}

// Test basic connectivity between two clients
TEST_F(RatsCApiTest, BasicConnectivityTest) {
    const int server_port = 55000;
    const int client_port = 55001;
    
    client1 = rats_create(server_port);
    client2 = rats_create(client_port);
    ASSERT_NE(client1, nullptr);
    ASSERT_NE(client2, nullptr);
    
    // Start both clients
    EXPECT_EQ(rats_start(client1), RATS_SUCCESS);
    EXPECT_EQ(rats_start(client2), RATS_SUCCESS);
    
    // Allow time for startup
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Initial state - no peers
    EXPECT_EQ(rats_get_peer_count(client1), 0);
    EXPECT_EQ(rats_get_peer_count(client2), 0);
    
    // Connect client2 to client1
    EXPECT_EQ(rats_connect_with_strategy(client2, "127.0.0.1", server_port, RATS_STRATEGY_DIRECT_ONLY), RATS_SUCCESS);
    
    // Wait for connection to establish
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Check that both clients now have 1 peer
    EXPECT_EQ(rats_get_peer_count(client1), 1);
    EXPECT_EQ(rats_get_peer_count(client2), 1);
    
    rats_stop(client1);
    rats_stop(client2);
}

// Test connectivity with callbacks
TEST_F(RatsCApiTest, ConnectivityWithCallbacksTest) {
    const int server_port = 55002;
    const int client_port = 55003;
    
    client1 = rats_create(server_port); // Server
    client2 = rats_create(client_port); // Client
    ASSERT_NE(client1, nullptr);
    ASSERT_NE(client2, nullptr);
    
    // Track connection events
    bool server_connection_received = false;
    bool client_connection_made = false;
    static char server_peer_id[256] = {0};
    static char client_peer_id[256] = {0};
    
    // Set up connection callbacks
    rats_set_connection_callback(client1, [](void* user_data, const char* peer_id) {
        bool* received = static_cast<bool*>(user_data);
        *received = true;
        strncpy(server_peer_id, peer_id, 255);
        server_peer_id[255] = '\0';
    }, &server_connection_received);
    
    rats_set_connection_callback(client2, [](void* user_data, const char* peer_id) {
        bool* made = static_cast<bool*>(user_data);
        *made = true;
        strncpy(client_peer_id, peer_id, 255);
        client_peer_id[255] = '\0';
    }, &client_connection_made);
    
    // Start both clients
    EXPECT_EQ(rats_start(client1), RATS_SUCCESS);
    EXPECT_EQ(rats_start(client2), RATS_SUCCESS);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Connect
    EXPECT_EQ(rats_connect_with_strategy(client2, "127.0.0.1", server_port, RATS_STRATEGY_DIRECT_ONLY), RATS_SUCCESS);
    
    // Wait for connection and callbacks
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // Verify callbacks were called
    EXPECT_TRUE(server_connection_received);
    EXPECT_TRUE(client_connection_made);
    EXPECT_GT(strlen(server_peer_id), 0);
    EXPECT_GT(strlen(client_peer_id), 0);
    
    // Verify peer counts
    EXPECT_EQ(rats_get_peer_count(client1), 1);
    EXPECT_EQ(rats_get_peer_count(client2), 1);
    
    rats_stop(client1);
    rats_stop(client2);
}

// Test string message communication
TEST_F(RatsCApiTest, StringCommunicationTest) {
    const int server_port = 55004;
    const int client_port = 55005;
    
    client1 = rats_create(server_port);
    client2 = rats_create(client_port);
    ASSERT_NE(client1, nullptr);
    ASSERT_NE(client2, nullptr);
    
    // Track messages
    bool server_received_message = false;
    bool client_received_message = false;
    static char server_received_text[256] = {0};
    static char client_received_text[256] = {0};
    static char server_sender_peer_id[256] = {0};
    static char client_sender_peer_id[256] = {0};
    
    // Set up string message callbacks
    rats_set_string_callback(client1, [](void* user_data, const char* peer_id, const char* message) {
        bool* received = static_cast<bool*>(user_data);
        *received = true;
        strncpy(server_received_text, message, 255);
        server_received_text[255] = '\0';
        strncpy(server_sender_peer_id, peer_id, 255);
        server_sender_peer_id[255] = '\0';
    }, &server_received_message);
    
    rats_set_string_callback(client2, [](void* user_data, const char* peer_id, const char* message) {
        bool* received = static_cast<bool*>(user_data);
        *received = true;
        strncpy(client_received_text, message, 255);
        client_received_text[255] = '\0';
        strncpy(client_sender_peer_id, peer_id, 255);
        client_sender_peer_id[255] = '\0';
    }, &client_received_message);
    
    // Start and connect
    EXPECT_EQ(rats_start(client1), RATS_SUCCESS);
    EXPECT_EQ(rats_start(client2), RATS_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    EXPECT_EQ(rats_connect_with_strategy(client2, "127.0.0.1", server_port, RATS_STRATEGY_DIRECT_ONLY), RATS_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Get peer IDs for sending messages
    char** client1_peers = nullptr;
    char** client2_peers = nullptr;
    int client1_peer_count = 0;
    int client2_peer_count = 0;
    
    client1_peers = rats_get_peer_ids(client1, &client1_peer_count);
    client2_peers = rats_get_peer_ids(client2, &client2_peer_count);
    
    EXPECT_EQ(client1_peer_count, 1);
    EXPECT_EQ(client2_peer_count, 1);
    
    if (client1_peer_count > 0 && client2_peer_count > 0) {
        // Send message from client2 to client1
        EXPECT_EQ(rats_send_string(client2, client2_peers[0], "Hello from client!"), RATS_SUCCESS);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        
        // Send message from client1 to client2  
        EXPECT_EQ(rats_send_string(client1, client1_peers[0], "Hello from server!"), RATS_SUCCESS);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        
        // Verify messages were received
        EXPECT_TRUE(server_received_message);
        EXPECT_TRUE(client_received_message);
        EXPECT_STREQ(server_received_text, "Hello from client!");
        EXPECT_STREQ(client_received_text, "Hello from server!");
        EXPECT_GT(strlen(server_sender_peer_id), 0);
        EXPECT_GT(strlen(client_sender_peer_id), 0);
    }
    
    // Cleanup peer ID arrays
    if (client1_peers) {
        for (int i = 0; i < client1_peer_count; i++) {
            rats_string_free(client1_peers[i]);
        }
        free(client1_peers);
    }
    if (client2_peers) {
        for (int i = 0; i < client2_peer_count; i++) {
            rats_string_free(client2_peers[i]);
        }
        free(client2_peers);
    }
    
    rats_stop(client1);
    rats_stop(client2);
}

// Test binary data communication  
TEST_F(RatsCApiTest, BinaryCommunicationTest) {
    const int server_port = 55006;
    const int client_port = 55007;
    
    client1 = rats_create(server_port);
    client2 = rats_create(client_port);
    ASSERT_NE(client1, nullptr);
    ASSERT_NE(client2, nullptr);
    
    // Test binary data with null bytes and various patterns
    uint8_t test_data[] = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x7F, 0x80};
    size_t test_data_size = sizeof(test_data);
    
    // Track binary messages
    bool server_received_binary = false;
    static uint8_t server_received_data[256] = {0};
    static size_t server_received_size = 0;
    
    // Set up binary message callback
    rats_set_binary_callback(client1, [](void* user_data, const char* peer_id, const void* data, size_t size) {
        bool* received = static_cast<bool*>(user_data);
        *received = true;
        server_received_size = size;
        if (size <= 256) {
            memcpy(server_received_data, data, size);
        }
    }, &server_received_binary);
    
    // Start and connect
    EXPECT_EQ(rats_start(client1), RATS_SUCCESS);
    EXPECT_EQ(rats_start(client2), RATS_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    EXPECT_EQ(rats_connect_with_strategy(client2, "127.0.0.1", server_port, RATS_STRATEGY_DIRECT_ONLY), RATS_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Get peer ID and send binary data
    char** peers = nullptr;
    int peer_count = 0;
    peers = rats_get_peer_ids(client2, &peer_count);
    
    EXPECT_EQ(peer_count, 1);
    
    if (peer_count > 0) {
        EXPECT_EQ(rats_send_binary(client2, peers[0], test_data, test_data_size), RATS_SUCCESS);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        
        // Verify binary data was received correctly
        EXPECT_TRUE(server_received_binary);
        EXPECT_EQ(server_received_size, test_data_size);
        EXPECT_EQ(memcmp(server_received_data, test_data, test_data_size), 0);
    }
    
    // Cleanup
    if (peers) {
        for (int i = 0; i < peer_count; i++) {
            rats_string_free(peers[i]);
        }
        free(peers);
    }
    
    rats_stop(client1);
    rats_stop(client2);
}

// Test version and utility APIs  
TEST_F(RatsCApiTest, VersionAPIs) {
    // Test version functions
    const char* version = rats_get_version_string();
    ASSERT_NE(version, nullptr);
    EXPECT_GT(strlen(version), 0);
    
    int major, minor, patch, build;
    rats_get_version(&major, &minor, &patch, &build);
    EXPECT_GE(major, 0);
    EXPECT_GE(minor, 0);
    EXPECT_GE(patch, 0);
    
    const char* git_desc = rats_get_git_describe();
    ASSERT_NE(git_desc, nullptr);
    
    uint32_t abi = rats_get_abi();
    EXPECT_GT(abi, 0);
}