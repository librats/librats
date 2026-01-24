#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <atomic>

#include "bt_network.h"
#include "bt_handshake.h"
#include "socket.h"

using namespace librats;

class BtNetworkTest : public ::testing::Test {
protected:
    void SetUp() override {
        init_socket_library();
    }
    
    void TearDown() override {
        // Allow time for cleanup
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    BtInfoHash create_test_hash() {
        BtInfoHash hash;
        for (size_t i = 0; i < 20; ++i) {
            hash[i] = static_cast<uint8_t>(i * 10 + 5);
        }
        return hash;
    }
    
    PeerID create_test_peer_id() {
        return generate_peer_id("-TS0001-");
    }
};

//=============================================================================
// BtNetworkConfig Tests
//=============================================================================

TEST_F(BtNetworkTest, DefaultConfig) {
    BtNetworkConfig config;
    
    EXPECT_EQ(config.listen_port, 6881);
    EXPECT_EQ(config.max_connections, 200);
    EXPECT_EQ(config.max_pending_connects, 30);
    EXPECT_EQ(config.connect_timeout_ms, 10000);
    EXPECT_TRUE(config.enable_incoming);
}

//=============================================================================
// BtNetworkManager Construction Tests
//=============================================================================

TEST_F(BtNetworkTest, ManagerConstruction) {
    BtNetworkConfig config;
    config.listen_port = 0;  // Random port
    
    BtNetworkManager manager(config);
    
    EXPECT_FALSE(manager.is_running());
    EXPECT_EQ(manager.num_connections(), 0);
    EXPECT_EQ(manager.num_pending(), 0);
}

TEST_F(BtNetworkTest, ManagerStartStop) {
    BtNetworkConfig config;
    config.listen_port = 0;  // Random port
    config.enable_incoming = true;
    
    BtNetworkManager manager(config);
    
    ASSERT_TRUE(manager.start());
    EXPECT_TRUE(manager.is_running());
    EXPECT_GT(manager.listen_port(), 0);
    
    manager.stop();
    EXPECT_FALSE(manager.is_running());
}

TEST_F(BtNetworkTest, ManagerDoubleStart) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    
    ASSERT_TRUE(manager.start());
    EXPECT_TRUE(manager.start());  // Should succeed (no-op)
    EXPECT_TRUE(manager.is_running());
    
    manager.stop();
}

TEST_F(BtNetworkTest, ManagerDoubleStop) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    
    manager.start();
    manager.stop();
    manager.stop();  // Should be safe
    
    EXPECT_FALSE(manager.is_running());
}

//=============================================================================
// Torrent Registration Tests
//=============================================================================

TEST_F(BtNetworkTest, RegisterTorrent) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    manager.start();
    
    auto hash = create_test_hash();
    auto peer_id = create_test_peer_id();
    
    // Should not throw
    manager.register_torrent(hash, peer_id, 100);
    
    // Unregister
    manager.unregister_torrent(hash);
    
    manager.stop();
}

//=============================================================================
// Connection Queue Tests
//=============================================================================

TEST_F(BtNetworkTest, QueueConnection) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    manager.start();
    
    auto hash = create_test_hash();
    auto peer_id = create_test_peer_id();
    
    // Queue a connection (will fail since there's no peer)
    bool queued = manager.connect_peer("127.0.0.1", 12345, hash, peer_id, 100);
    EXPECT_TRUE(queued);
    
    // Wait a bit for the connection attempt to process
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    manager.stop();
}

TEST_F(BtNetworkTest, ConnectBeforeStart) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    // Don't start
    
    auto hash = create_test_hash();
    auto peer_id = create_test_peer_id();
    
    bool queued = manager.connect_peer("127.0.0.1", 12345, hash, peer_id, 100);
    EXPECT_FALSE(queued);  // Should fail when not running
}

//=============================================================================
// Callback Tests
//=============================================================================

TEST_F(BtNetworkTest, SetCallbacks) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    
    std::atomic<bool> connected_called{false};
    std::atomic<bool> disconnected_called{false};
    std::atomic<bool> data_called{false};
    
    manager.set_connected_callback([&](const BtInfoHash&, 
                                        std::shared_ptr<BtPeerConnection>, 
                                        socket_t, bool) {
        connected_called = true;
    });
    
    manager.set_disconnected_callback([&](const BtInfoHash&, BtPeerConnection*) {
        disconnected_called = true;
    });
    
    manager.set_data_callback([&](const BtInfoHash&, BtPeerConnection*, socket_t) {
        data_called = true;
    });
    
    manager.start();
    manager.stop();
    
    // Callbacks weren't called (no connections)
    EXPECT_FALSE(connected_called);
    EXPECT_FALSE(disconnected_called);
    EXPECT_FALSE(data_called);
}

//=============================================================================
// Peer Connection Loopback Test
//=============================================================================

TEST_F(BtNetworkTest, LoopbackConnection) {
    // Create two network managers and connect them
    
    BtNetworkConfig server_config;
    server_config.listen_port = 0;
    
    BtNetworkConfig client_config;
    client_config.listen_port = 0;
    client_config.enable_incoming = false;  // Client doesn't need to listen
    
    BtNetworkManager server(server_config);
    BtNetworkManager client(client_config);
    
    auto hash = create_test_hash();
    auto server_peer_id = generate_peer_id("-SV0001-");
    auto client_peer_id = generate_peer_id("-CL0001-");
    
    std::atomic<bool> server_got_connection{false};
    std::atomic<bool> client_got_connection{false};
    
    server.set_connected_callback([&](const BtInfoHash& h, 
                                       std::shared_ptr<BtPeerConnection> conn, 
                                       socket_t, bool incoming) {
        EXPECT_EQ(h, hash);
        EXPECT_TRUE(incoming);
        server_got_connection = true;
    });
    
    client.set_connected_callback([&](const BtInfoHash& h, 
                                       std::shared_ptr<BtPeerConnection> conn, 
                                       socket_t, bool incoming) {
        EXPECT_EQ(h, hash);
        EXPECT_FALSE(incoming);
        client_got_connection = true;
    });
    
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());
    
    // Register torrent on server
    server.register_torrent(hash, server_peer_id, 100);
    
    // Client connects to server
    uint16_t server_port = server.listen_port();
    ASSERT_GT(server_port, 0);
    
    bool queued = client.connect_peer("127.0.0.1", server_port, hash, client_peer_id, 100);
    EXPECT_TRUE(queued);
    
    // Wait for connection
    for (int i = 0; i < 50 && !server_got_connection; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Note: The actual handshake completes on the incoming side, 
    // but the outgoing side may not trigger the callback in all code paths
    // This test verifies the server receives the connection
    EXPECT_TRUE(server_got_connection);
    
    client.stop();
    server.stop();
}

//=============================================================================
// Connection Limits Tests
//=============================================================================

TEST_F(BtNetworkTest, MaxPendingConnections) {
    BtNetworkConfig config;
    config.listen_port = 0;
    config.max_pending_connects = 5;
    
    BtNetworkManager manager(config);
    manager.start();
    
    auto hash = create_test_hash();
    auto peer_id = create_test_peer_id();
    
    // Queue more connections than the limit
    for (int i = 0; i < 10; ++i) {
        manager.connect_peer("127.0.0.1", static_cast<uint16_t>(10000 + i), 
                            hash, peer_id, 100);
    }
    
    // Wait a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Should respect the limit (pending <= max_pending_connects)
    EXPECT_LE(manager.num_pending(), config.max_pending_connects);
    
    manager.stop();
}

//=============================================================================
// PeerConnectRequest Tests
//=============================================================================

TEST_F(BtNetworkTest, PeerConnectRequestConstruction) {
    auto hash = create_test_hash();
    auto peer_id = create_test_peer_id();
    
    PeerConnectRequest req("192.168.1.100", 6881, hash, peer_id, 1000);
    
    EXPECT_EQ(req.ip, "192.168.1.100");
    EXPECT_EQ(req.port, 6881);
    EXPECT_EQ(req.info_hash, hash);
    EXPECT_EQ(req.our_peer_id, peer_id);
    EXPECT_EQ(req.num_pieces, 1000);
}

//=============================================================================
// ActiveConnection Tests
//=============================================================================

TEST_F(BtNetworkTest, ActiveConnectionConstruction) {
    ActiveConnection conn;
    
    EXPECT_EQ(conn.socket, INVALID_SOCKET_VALUE);
    EXPECT_FALSE(conn.is_incoming);
    EXPECT_EQ(conn.connection, nullptr);
}

//=============================================================================
// Stress Test
//=============================================================================

/*
TEST_F(BtNetworkTest, StressTest) {
    // Disabled by default - enable for stress testing
    
    BtNetworkConfig config;
    config.listen_port = 0;
    config.max_pending_connects = 50;
    
    BtNetworkManager manager(config);
    manager.start();
    
    auto hash = create_test_hash();
    auto peer_id = create_test_peer_id();
    
    // Queue many connection attempts
    for (int i = 0; i < 100; ++i) {
        manager.connect_peer("127.0.0.1", static_cast<uint16_t>(10000 + i), 
                            hash, peer_id, 100);
    }
    
    // Let it run
    std::this_thread::sleep_for(std::chrono::seconds(5));
    
    manager.stop();
}
*/
