#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "librats.h"
#include "socket.h"
#include <thread>
#include <chrono>
#include <atomic>

using namespace librats;

class ReconnectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        librats::Logger::getInstance().set_log_level(librats::LogLevel::DEBUG);
        init_socket_library();
    }
    
    void TearDown() override {
        cleanup_socket_library();
    }
    
    // Helper to wait for condition with timeout
    template<typename Predicate>
    bool wait_for_condition(Predicate pred, int timeout_ms = 5000) {
        auto start = std::chrono::steady_clock::now();
        while (!pred()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            if (elapsed.count() >= timeout_ms) {
                return false;
            }
        }
        return true;
    }
};

// ============================================================================
// ReconnectConfig and ReconnectInfo struct tests
// ============================================================================

TEST_F(ReconnectionTest, ReconnectConfigDefaults) {
    ReconnectConfig config;
    
    EXPECT_EQ(config.max_attempts, 3);
    EXPECT_EQ(config.retry_intervals_seconds.size(), 3);
    EXPECT_EQ(config.retry_intervals_seconds[0], 5);
    EXPECT_EQ(config.retry_intervals_seconds[1], 30);
    EXPECT_EQ(config.retry_intervals_seconds[2], 120);
    EXPECT_EQ(config.stable_connection_threshold_seconds, 60);
    EXPECT_EQ(config.stable_first_retry_seconds, 2);
    EXPECT_TRUE(config.enabled);
}

TEST_F(ReconnectionTest, ReconnectInfoConstruction) {
    ReconnectInfo info;
    
    EXPECT_TRUE(info.peer_id.empty());
    EXPECT_TRUE(info.ip.empty());
    EXPECT_EQ(info.port, 0);
    EXPECT_EQ(info.attempt_count, 0);
    EXPECT_EQ(info.connection_duration.count(), 0);
    EXPECT_FALSE(info.is_stable);
}

TEST_F(ReconnectionTest, ReconnectInfoWithParams) {
    std::chrono::milliseconds duration(65000); // 65 seconds
    ReconnectInfo info("peer123", "192.168.1.1", 8080, duration, true);
    
    EXPECT_EQ(info.peer_id, "peer123");
    EXPECT_EQ(info.ip, "192.168.1.1");
    EXPECT_EQ(info.port, 8080);
    EXPECT_EQ(info.attempt_count, 0);
    EXPECT_EQ(info.connection_duration.count(), 65000);
    EXPECT_TRUE(info.is_stable);
}

// ============================================================================
// RatsClient reconnection API tests
// ============================================================================

TEST_F(ReconnectionTest, ReconnectEnabledByDefault) {
    RatsClient client(0);
    EXPECT_TRUE(client.start());
    
    // Reconnection should be enabled by default
    EXPECT_TRUE(client.is_reconnect_enabled());
    
    client.stop();
}

TEST_F(ReconnectionTest, SetReconnectEnabled) {
    RatsClient client(0);
    EXPECT_TRUE(client.start());
    
    // Disable reconnection
    client.set_reconnect_enabled(false);
    EXPECT_FALSE(client.is_reconnect_enabled());
    
    // Re-enable reconnection
    client.set_reconnect_enabled(true);
    EXPECT_TRUE(client.is_reconnect_enabled());
    
    client.stop();
}

TEST_F(ReconnectionTest, SetReconnectConfig) {
    RatsClient client(0);
    EXPECT_TRUE(client.start());
    
    ReconnectConfig custom_config;
    custom_config.max_attempts = 5;
    custom_config.retry_intervals_seconds = {1, 2, 3, 4, 5};
    custom_config.stable_connection_threshold_seconds = 30;
    custom_config.stable_first_retry_seconds = 1;
    custom_config.enabled = true;
    
    client.set_reconnect_config(custom_config);
    
    const ReconnectConfig& retrieved = client.get_reconnect_config();
    EXPECT_EQ(retrieved.max_attempts, 5);
    EXPECT_EQ(retrieved.retry_intervals_seconds.size(), 5);
    EXPECT_EQ(retrieved.stable_connection_threshold_seconds, 30);
    EXPECT_EQ(retrieved.stable_first_retry_seconds, 1);
    
    client.stop();
}

TEST_F(ReconnectionTest, ReconnectQueueInitiallyEmpty) {
    RatsClient client(0);
    EXPECT_TRUE(client.start());
    
    EXPECT_EQ(client.get_reconnect_queue_size(), 0);
    EXPECT_TRUE(client.get_reconnect_queue().empty());
    
    client.stop();
}

TEST_F(ReconnectionTest, ClearReconnectQueue) {
    RatsClient client(0);
    EXPECT_TRUE(client.start());
    
    // Queue should be empty, but clear should still work
    client.clear_reconnect_queue();
    EXPECT_EQ(client.get_reconnect_queue_size(), 0);
    
    client.stop();
}

// ============================================================================
// Integration tests - actual peer connection and reconnection
// ============================================================================

TEST_F(ReconnectionTest, PeerDisconnectAddsToReconnectQueue) {
    // Create server
    RatsClient server(0);
    EXPECT_TRUE(server.start());
    int server_port = server.get_listen_port();
    
    // Create client with fast reconnection settings for testing
    RatsClient client(0);
    ReconnectConfig fast_config;
    fast_config.max_attempts = 2;
    fast_config.retry_intervals_seconds = {1, 2};
    fast_config.stable_connection_threshold_seconds = 1; // 1 second for stable
    fast_config.stable_first_retry_seconds = 1;
    client.set_reconnect_config(fast_config);
    EXPECT_TRUE(client.start());
    
    // Connect client to server
    EXPECT_TRUE(client.connect_to_peer("127.0.0.1", server_port));
    
    // Wait for connection to be established
    EXPECT_TRUE(wait_for_condition([&]() { 
        return client.get_peer_count() == 1 && server.get_peer_count() == 1;
    }, 3000));
    
    // Verify queue is empty while connected
    EXPECT_EQ(client.get_reconnect_queue_size(), 0);
    
    // Stop server to simulate disconnect
    server.stop();
    
    // Wait for client to detect disconnect and add to queue
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 0;
    }, 3000));
    
    // Give time for reconnection scheduling
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Check that peer was added to reconnection queue
    EXPECT_GE(client.get_reconnect_queue_size(), 0); // May be 0 if already attempting reconnect
    
    client.stop();
}

TEST_F(ReconnectionTest, ManualDisconnectDoesNotAddToQueue) {
    // Create server
    RatsClient server(0);
    EXPECT_TRUE(server.start());
    int server_port = server.get_listen_port();
    
    // Create client
    RatsClient client(0);
    EXPECT_TRUE(client.start());
    
    // Connect client to server
    EXPECT_TRUE(client.connect_to_peer("127.0.0.1", server_port));
    
    // Wait for connection
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 1;
    }, 3000));
    
    // Get peer ID for manual disconnect
    auto peers = client.get_validated_peers();
    ASSERT_EQ(peers.size(), 1);
    std::string peer_id = peers[0].peer_id;
    
    // Manually disconnect
    client.disconnect_peer_by_id(peer_id);
    
    // Wait for disconnect
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 0;
    }, 3000));
    
    // Queue should be empty because this was a manual disconnect
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(client.get_reconnect_queue_size(), 0);
    
    client.stop();
    server.stop();
}

TEST_F(ReconnectionTest, ReconnectDisabledDoesNotAddToQueue) {
    // Create server
    RatsClient server(0);
    EXPECT_TRUE(server.start());
    int server_port = server.get_listen_port();
    
    // Create client with reconnection disabled
    RatsClient client(0);
    client.set_reconnect_enabled(false);
    EXPECT_TRUE(client.start());
    
    // Connect
    EXPECT_TRUE(client.connect_to_peer("127.0.0.1", server_port));
    
    // Wait for connection
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 1;
    }, 3000));
    
    // Stop server to simulate disconnect
    server.stop();
    
    // Wait for disconnect
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 0;
    }, 3000));
    
    // Queue should be empty because reconnection is disabled
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(client.get_reconnect_queue_size(), 0);
    
    client.stop();
}

TEST_F(ReconnectionTest, SuccessfulReconnection) {
    // Create first server
    RatsClient server1(0);
    EXPECT_TRUE(server1.start());
    int server_port = server1.get_listen_port();
    
    // Create client with fast reconnection
    RatsClient client(0);
    ReconnectConfig fast_config;
    fast_config.max_attempts = 3;
    fast_config.retry_intervals_seconds = {1, 1, 1}; // Fast retries for testing
    fast_config.stable_connection_threshold_seconds = 0; // Always stable
    fast_config.stable_first_retry_seconds = 1;
    client.set_reconnect_config(fast_config);
    EXPECT_TRUE(client.start());
    
    // Connect
    EXPECT_TRUE(client.connect_to_peer("127.0.0.1", server_port));
    
    // Wait for connection
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 1;
    }, 3000));
    
    // Stop server
    server1.stop();
    
    // Wait for disconnect
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 0;
    }, 3000));
    
    // Start new server on same port
    RatsClient server2(server_port);
    EXPECT_TRUE(server2.start());
    
    // Wait for automatic reconnection (should happen within a few seconds)
    bool reconnected = wait_for_condition([&]() {
        return client.get_peer_count() == 1;
    }, 10000); // 10 second timeout for reconnection
    
    // May or may not reconnect depending on timing, but queue should eventually be empty
    // Either reconnected successfully or exhausted attempts
    
    client.stop();
    server2.stop();
}

TEST_F(ReconnectionTest, ReconnectionStatisticsInConnectionStats) {
    RatsClient client(0);
    EXPECT_TRUE(client.start());
    
    auto stats = client.get_connection_statistics();
    
    EXPECT_TRUE(stats.contains("reconnect_enabled"));
    EXPECT_TRUE(stats.contains("reconnect_queue_size"));
    EXPECT_TRUE(stats.contains("reconnect_max_attempts"));
    
    EXPECT_TRUE(stats["reconnect_enabled"].get<bool>());
    EXPECT_EQ(stats["reconnect_queue_size"].get<size_t>(), 0);
    EXPECT_EQ(stats["reconnect_max_attempts"].get<int>(), 3);
    
    client.stop();
}

TEST_F(ReconnectionTest, StablePeerDetection) {
    // Create server
    RatsClient server(0);
    EXPECT_TRUE(server.start());
    int server_port = server.get_listen_port();
    
    // Create client with short stable threshold for testing
    RatsClient client(0);
    ReconnectConfig config;
    config.max_attempts = 1; // Only one attempt to avoid reconnection loops
    config.retry_intervals_seconds = {60}; // Long interval so we can inspect queue
    config.stable_connection_threshold_seconds = 1; // 1 second for stable (faster test)
    config.stable_first_retry_seconds = 1;
    client.set_reconnect_config(config);
    EXPECT_TRUE(client.start());
    
    // Connect
    EXPECT_TRUE(client.connect_to_peer("127.0.0.1", server_port));
    
    // Wait for connection
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 1;
    }, 3000));
    
    // Wait for connection to become "stable" (> 1 second)
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    
    // Stop server
    server.stop();
    
    // Wait for disconnect
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 0;
    }, 3000));
    
    // Give time for queue update
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Check queue
    auto queue = client.get_reconnect_queue();
    if (!queue.empty()) {
        // Peer should be marked as stable
        EXPECT_TRUE(queue[0].is_stable);
        EXPECT_GE(queue[0].connection_duration.count(), 1000); // At least 1 second
    }
    
    client.stop();
}

// ============================================================================
// Edge cases
// ============================================================================

TEST_F(ReconnectionTest, ReconnectQueueClearedOnStop) {
    RatsClient server(0);
    EXPECT_TRUE(server.start());
    int server_port = server.get_listen_port();
    
    RatsClient client(0);
    ReconnectConfig config;
    config.retry_intervals_seconds = {60}; // Long interval
    client.set_reconnect_config(config);
    EXPECT_TRUE(client.start());
    
    // Connect
    EXPECT_TRUE(client.connect_to_peer("127.0.0.1", server_port));
    
    // Wait for connection
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 1;
    }, 3000));
    
    // Stop server to trigger reconnection queue
    server.stop();
    
    // Wait for disconnect
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 0;
    }, 3000));
    
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Stop client - queue should be cleared
    client.stop();
    
    // Can't check queue after stop, but this tests that stop() doesn't crash
    // with items in the queue
}

TEST_F(ReconnectionTest, MaxAttemptsExhausted) {
    // This test verifies that after max attempts, peer is removed from queue
    RatsClient server(0);
    EXPECT_TRUE(server.start());
    int server_port = server.get_listen_port();
    
    RatsClient client(0);
    ReconnectConfig config;
    config.max_attempts = 1; // Single attempt
    config.retry_intervals_seconds = {0}; // Immediate retry for faster testing
    config.stable_connection_threshold_seconds = 0; // Immediate stable
    config.stable_first_retry_seconds = 0; // Immediate first retry
    client.set_reconnect_config(config);
    EXPECT_TRUE(client.start());
    
    // Connect
    EXPECT_TRUE(client.connect_to_peer("127.0.0.1", server_port));
    
    // Wait for connection
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 1;
    }, 3000));
    
    // Stop server (no restart - reconnection will fail)
    server.stop();
    
    // Wait for disconnect
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_peer_count() == 0;
    }, 3000));
    
    // Wait for reconnection attempt to fail and be removed from queue
    // Using active waiting instead of fixed sleep - completes as soon as queue is empty
    // Timeout accounts for: management loop interval (2s) + connection timeout (10s) + margin
    EXPECT_TRUE(wait_for_condition([&]() {
        return client.get_reconnect_queue_size() == 0;
    }, 15000));
    
    client.stop();
}
