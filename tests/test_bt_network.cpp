#include <gtest/gtest.h>
#include "bt_network.h"

namespace librats {
namespace {

//=============================================================================
// SendChunk Tests
//=============================================================================

TEST(SendChunkTest, DefaultConstruction) {
    SendChunk chunk;
    
    EXPECT_TRUE(chunk.data.empty());
    EXPECT_EQ(chunk.offset, 0);
    EXPECT_EQ(chunk.remaining(), 0);
}

TEST(SendChunkTest, ConstructWithData) {
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    SendChunk chunk(data);
    
    EXPECT_EQ(chunk.data.size(), 5);
    EXPECT_EQ(chunk.offset, 0);
    EXPECT_EQ(chunk.remaining(), 5);
    EXPECT_EQ(chunk.current()[0], 1);
}

TEST(SendChunkTest, PartialConsume) {
    std::vector<uint8_t> data = {10, 20, 30, 40, 50};
    SendChunk chunk(data);
    
    chunk.offset = 2;
    
    EXPECT_EQ(chunk.remaining(), 3);
    EXPECT_EQ(chunk.current()[0], 30);
}

//=============================================================================
// ChainedSendBuffer Tests
//=============================================================================

TEST(ChainedSendBufferTest, EmptyBuffer) {
    ChainedSendBuffer buffer;
    
    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.size(), 0);
    EXPECT_EQ(buffer.chunk_count(), 0);
}

TEST(ChainedSendBufferTest, AppendVector) {
    ChainedSendBuffer buffer;
    
    std::vector<uint8_t> data1 = {1, 2, 3, 4, 5};
    std::vector<uint8_t> data2 = {6, 7, 8};
    
    buffer.append(data1);
    EXPECT_EQ(buffer.size(), 5);
    EXPECT_EQ(buffer.chunk_count(), 1);
    
    buffer.append(data2);
    EXPECT_EQ(buffer.size(), 8);
    EXPECT_EQ(buffer.chunk_count(), 2);
}

TEST(ChainedSendBufferTest, AppendPointer) {
    ChainedSendBuffer buffer;
    
    uint8_t data[] = {1, 2, 3, 4, 5};
    buffer.append(data, sizeof(data));
    
    EXPECT_EQ(buffer.size(), 5);
    EXPECT_EQ(buffer.chunk_count(), 1);
    
    std::vector<uint8_t> output(5);
    buffer.copy_to(output.data(), output.size());
    
    EXPECT_EQ(output[0], 1);
    EXPECT_EQ(output[4], 5);
}

TEST(ChainedSendBufferTest, AppendEmpty) {
    ChainedSendBuffer buffer;
    
    // Append empty vector - should be no-op
    buffer.append(std::vector<uint8_t>{});
    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.chunk_count(), 0);
    
    // Append empty pointer - should be no-op
    uint8_t dummy;
    buffer.append(&dummy, 0);
    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.chunk_count(), 0);
}

TEST(ChainedSendBufferTest, CopyTo) {
    ChainedSendBuffer buffer;
    
    std::vector<uint8_t> data1 = {1, 2, 3};
    std::vector<uint8_t> data2 = {4, 5, 6};
    
    buffer.append(data1);
    buffer.append(data2);
    
    std::vector<uint8_t> output(10);
    size_t copied = buffer.copy_to(output.data(), output.size());
    
    EXPECT_EQ(copied, 6);
    EXPECT_EQ(output[0], 1);
    EXPECT_EQ(output[5], 6);
}

TEST(ChainedSendBufferTest, CopyToPartial) {
    ChainedSendBuffer buffer;
    
    std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8};
    buffer.append(data);
    
    std::vector<uint8_t> output(4);
    size_t copied = buffer.copy_to(output.data(), output.size());
    
    EXPECT_EQ(copied, 4);
    EXPECT_EQ(output[0], 1);
    EXPECT_EQ(output[3], 4);
}

TEST(ChainedSendBufferTest, CopyToSpanningChunks) {
    ChainedSendBuffer buffer;
    
    // Create 3 chunks
    buffer.append(std::vector<uint8_t>{1, 2});
    buffer.append(std::vector<uint8_t>{3, 4});
    buffer.append(std::vector<uint8_t>{5, 6});
    
    EXPECT_EQ(buffer.chunk_count(), 3);
    
    // Copy 5 bytes, spanning first two chunks and part of third
    std::vector<uint8_t> output(5);
    size_t copied = buffer.copy_to(output.data(), output.size());
    
    EXPECT_EQ(copied, 5);
    EXPECT_EQ(output[0], 1);
    EXPECT_EQ(output[1], 2);
    EXPECT_EQ(output[2], 3);
    EXPECT_EQ(output[3], 4);
    EXPECT_EQ(output[4], 5);
}

TEST(ChainedSendBufferTest, CopyToEmptyBuffer) {
    ChainedSendBuffer buffer;
    
    std::vector<uint8_t> output(10);
    size_t copied = buffer.copy_to(output.data(), output.size());
    
    EXPECT_EQ(copied, 0);
}

TEST(ChainedSendBufferTest, PopFront) {
    ChainedSendBuffer buffer;
    
    std::vector<uint8_t> data1 = {1, 2, 3};
    std::vector<uint8_t> data2 = {4, 5, 6};
    
    buffer.append(data1);
    buffer.append(data2);
    
    buffer.pop_front(2);
    EXPECT_EQ(buffer.size(), 4);
    
    std::vector<uint8_t> output(4);
    buffer.copy_to(output.data(), output.size());
    EXPECT_EQ(output[0], 3);  // After popping 1,2
    EXPECT_EQ(output[1], 4);
}

TEST(ChainedSendBufferTest, PopFrontCrossChunk) {
    ChainedSendBuffer buffer;
    
    std::vector<uint8_t> data1 = {1, 2};
    std::vector<uint8_t> data2 = {3, 4};
    
    buffer.append(data1);
    buffer.append(data2);
    EXPECT_EQ(buffer.chunk_count(), 2);
    
    // Pop 3 bytes, crossing chunk boundary
    buffer.pop_front(3);
    EXPECT_EQ(buffer.size(), 1);
    EXPECT_EQ(buffer.chunk_count(), 1);
    
    std::vector<uint8_t> output(1);
    buffer.copy_to(output.data(), output.size());
    EXPECT_EQ(output[0], 4);
}

TEST(ChainedSendBufferTest, PopFrontEntireBuffer) {
    ChainedSendBuffer buffer;
    
    buffer.append(std::vector<uint8_t>{1, 2, 3});
    buffer.append(std::vector<uint8_t>{4, 5});
    
    buffer.pop_front(5);
    
    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.size(), 0);
    EXPECT_EQ(buffer.chunk_count(), 0);
}

TEST(ChainedSendBufferTest, PopFrontExactChunkBoundary) {
    ChainedSendBuffer buffer;
    
    buffer.append(std::vector<uint8_t>{1, 2, 3});
    buffer.append(std::vector<uint8_t>{4, 5, 6});
    
    // Pop exactly one chunk
    buffer.pop_front(3);
    
    EXPECT_EQ(buffer.size(), 3);
    EXPECT_EQ(buffer.chunk_count(), 1);
    
    std::vector<uint8_t> output(3);
    buffer.copy_to(output.data(), output.size());
    EXPECT_EQ(output[0], 4);
}

TEST(ChainedSendBufferTest, Clear) {
    ChainedSendBuffer buffer;
    
    buffer.append(std::vector<uint8_t>{1, 2, 3});
    buffer.append(std::vector<uint8_t>{4, 5, 6});
    
    EXPECT_FALSE(buffer.empty());
    
    buffer.clear();
    
    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.size(), 0);
    EXPECT_EQ(buffer.chunk_count(), 0);
}

TEST(ChainedSendBufferTest, AppendAfterClear) {
    ChainedSendBuffer buffer;
    
    buffer.append(std::vector<uint8_t>{1, 2, 3});
    buffer.clear();
    buffer.append(std::vector<uint8_t>{4, 5, 6});
    
    EXPECT_EQ(buffer.size(), 3);
    EXPECT_EQ(buffer.chunk_count(), 1);
    
    std::vector<uint8_t> output(3);
    buffer.copy_to(output.data(), output.size());
    EXPECT_EQ(output[0], 4);
}

TEST(ChainedSendBufferTest, LargeBuffer) {
    ChainedSendBuffer buffer;
    
    // Create a larger buffer with many chunks
    for (int i = 0; i < 100; ++i) {
        buffer.append(std::vector<uint8_t>(100, static_cast<uint8_t>(i)));
    }
    
    EXPECT_EQ(buffer.size(), 10000);
    EXPECT_EQ(buffer.chunk_count(), 100);
    
    // Pop half
    buffer.pop_front(5000);
    EXPECT_EQ(buffer.size(), 5000);
    
    // Verify first remaining byte
    std::vector<uint8_t> output(1);
    buffer.copy_to(output.data(), output.size());
    EXPECT_EQ(output[0], 50);  // 50th chunk starts at index 50
}

//=============================================================================
// BtNetworkConfig Tests
//=============================================================================

TEST(BtNetworkConfigTest, DefaultValues) {
    BtNetworkConfig config;
    
    EXPECT_EQ(config.listen_port, 6881);
    EXPECT_EQ(config.max_connections, 200);
    EXPECT_TRUE(config.enable_incoming);
    EXPECT_EQ(config.connect_timeout_ms, 30000);
    EXPECT_EQ(config.select_timeout_ms, 15);
    EXPECT_EQ(config.send_buffer_high_water, 1024 * 1024);
}

TEST(BtNetworkConfigTest, CustomValues) {
    BtNetworkConfig config;
    config.listen_port = 51413;
    config.max_connections = 50;
    config.enable_incoming = false;
    config.connect_timeout_ms = 10000;
    config.select_timeout_ms = 100;
    config.send_buffer_high_water = 512 * 1024;
    
    EXPECT_EQ(config.listen_port, 51413);
    EXPECT_EQ(config.max_connections, 50);
    EXPECT_FALSE(config.enable_incoming);
    EXPECT_EQ(config.connect_timeout_ms, 10000);
    EXPECT_EQ(config.select_timeout_ms, 100);
    EXPECT_EQ(config.send_buffer_high_water, 512 * 1024);
}

//=============================================================================
// SocketContext Tests
//=============================================================================

TEST(SocketContextTest, DefaultValues) {
    SocketContext ctx;
    
    EXPECT_EQ(ctx.socket, INVALID_SOCKET_VALUE);
    EXPECT_EQ(ctx.state, NetConnectionState::Connecting);
    EXPECT_FALSE(ctx.incoming);
    EXPECT_EQ(ctx.connection, nullptr);
}

//=============================================================================
// PendingConnect Tests
//=============================================================================

TEST(PendingConnectTest, DefaultValues) {
    PendingConnect pending;
    
    EXPECT_TRUE(pending.ip.empty());
    EXPECT_EQ(pending.port, 0);
    EXPECT_EQ(pending.num_pieces, 0);
    EXPECT_EQ(pending.socket, INVALID_SOCKET_VALUE);
}

//=============================================================================
// TorrentRegistration Tests
//=============================================================================

TEST(TorrentRegistrationTest, DefaultValues) {
    TorrentRegistration reg;
    
    EXPECT_EQ(reg.num_pieces, 0);
}

//=============================================================================
// NetConnectionState Tests
//=============================================================================

TEST(NetConnectionStateTest, EnumValues) {
    // Ensure enum values are distinct and correctly ordered
    EXPECT_NE(static_cast<int>(NetConnectionState::Connecting),
              static_cast<int>(NetConnectionState::Handshaking));
    EXPECT_NE(static_cast<int>(NetConnectionState::Handshaking),
              static_cast<int>(NetConnectionState::Connected));
    EXPECT_NE(static_cast<int>(NetConnectionState::Connected),
              static_cast<int>(NetConnectionState::Closing));
}

//=============================================================================
// BtNetworkManager Tests
//=============================================================================

TEST(BtNetworkManagerTest, ConstructDestruct) {
    BtNetworkConfig config;
    config.listen_port = 0;  // Use ephemeral port
    
    BtNetworkManager manager(config);
    
    EXPECT_FALSE(manager.is_running());
    EXPECT_EQ(manager.listen_port(), 0);
}

TEST(BtNetworkManagerTest, StartStop) {
    BtNetworkConfig config;
    config.listen_port = 0;  // Use ephemeral port
    
    BtNetworkManager manager(config);
    
    // Note: start() may fail in restricted environments (CI, no network, etc.)
    // We test the basic lifecycle, accepting that socket creation might fail
    bool started = manager.start();
    
    if (started) {
        EXPECT_TRUE(manager.is_running());
        EXPECT_NE(manager.listen_port(), 0);
        
        manager.stop();
        EXPECT_FALSE(manager.is_running());
    } else {
        // In restricted environments, just verify we can call stop safely
        EXPECT_FALSE(manager.is_running());
        manager.stop();  // Should be safe to call even if not started
        EXPECT_FALSE(manager.is_running());
    }
}

TEST(BtNetworkManagerTest, StartWithIncomingDisabled) {
    BtNetworkConfig config;
    config.listen_port = 0;
    config.enable_incoming = false;
    
    BtNetworkManager manager(config);
    
    bool started = manager.start();
    
    if (started) {
        EXPECT_TRUE(manager.is_running());
        // When incoming disabled, listen_port should stay 0
        EXPECT_EQ(manager.listen_port(), 0);
        manager.stop();
    }
}

TEST(BtNetworkManagerTest, DoubleStart) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    
    bool started1 = manager.start();
    bool started2 = manager.start();  // Should return true (already running)
    
    if (started1) {
        EXPECT_TRUE(started2);
        manager.stop();
    }
}

TEST(BtNetworkManagerTest, DoubleStop) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    
    manager.start();
    manager.stop();
    manager.stop();  // Should be safe to call twice
    
    EXPECT_FALSE(manager.is_running());
}

TEST(BtNetworkManagerTest, RegisterTorrent) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    manager.start();
    
    BtInfoHash hash = {};
    hash[0] = 0xAB;
    hash[1] = 0xCD;
    
    PeerID peer_id = generate_peer_id();
    
    manager.register_torrent(hash, peer_id, 100);
    
    // Unregister
    manager.unregister_torrent(hash);
    
    manager.stop();
}

TEST(BtNetworkManagerTest, RegisterMultipleTorrents) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    manager.start();
    
    PeerID peer_id = generate_peer_id();
    
    // Register 3 torrents
    for (int i = 0; i < 3; ++i) {
        BtInfoHash hash = {};
        hash[0] = static_cast<uint8_t>(i);
        manager.register_torrent(hash, peer_id, 100 + i);
    }
    
    // Unregister all
    for (int i = 0; i < 3; ++i) {
        BtInfoHash hash = {};
        hash[0] = static_cast<uint8_t>(i);
        manager.unregister_torrent(hash);
    }
    
    manager.stop();
}

TEST(BtNetworkManagerTest, ConnectionCounts) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    manager.start();
    
    EXPECT_EQ(manager.connection_count(), 0);
    EXPECT_EQ(manager.pending_connect_count(), 0);
    
    manager.stop();
}

TEST(BtNetworkManagerTest, ConnectPeerQueued) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    
    bool started = manager.start();
    if (!started) {
        GTEST_SKIP() << "Network not available";
    }
    
    BtInfoHash hash = {};
    hash[0] = 0x12;
    
    PeerID peer_id = generate_peer_id();
    
    // Queue a connection to a non-existent peer
    bool queued = manager.connect_peer("127.0.0.1", 12345, hash, peer_id, 100);
    EXPECT_TRUE(queued);
    
    // Give IO loop time to process
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Should be in pending or connection count
    // (connection may fail quickly if port is closed)
    
    manager.stop();
}

TEST(BtNetworkManagerTest, ConnectPeerDuplicate) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    
    bool started = manager.start();
    if (!started) {
        GTEST_SKIP() << "Network not available";
    }
    
    BtInfoHash hash = {};
    PeerID peer_id = generate_peer_id();
    
    // Queue first connection
    bool queued1 = manager.connect_peer("127.0.0.1", 54321, hash, peer_id, 100);
    EXPECT_TRUE(queued1);
    
    // Try to queue duplicate - should be rejected
    bool queued2 = manager.connect_peer("127.0.0.1", 54321, hash, peer_id, 100);
    EXPECT_FALSE(queued2);
    
    manager.stop();
}

TEST(BtNetworkManagerTest, ConnectPeerConnectionLimit) {
    BtNetworkConfig config;
    config.listen_port = 0;
    config.max_connections = 2;  // Very low limit for testing
    
    BtNetworkManager manager(config);
    
    bool started = manager.start();
    if (!started) {
        GTEST_SKIP() << "Network not available";
    }
    
    BtInfoHash hash = {};
    PeerID peer_id = generate_peer_id();
    
    // Queue connections up to limit
    for (int i = 0; i < 3; ++i) {
        manager.connect_peer("127.0.0.1", static_cast<uint16_t>(50000 + i), 
                            hash, peer_id, 100);
    }
    
    // Give IO loop time to process
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Total pending + connected should not exceed max
    EXPECT_LE(manager.connection_count() + manager.pending_connect_count(), 
              config.max_connections);
    
    manager.stop();
}

TEST(BtNetworkManagerTest, SendToPeerUnknownSocket) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    manager.start();
    
    // Try to send to a socket that doesn't exist
    std::vector<uint8_t> data = {1, 2, 3, 4};
    bool sent = manager.send_to_peer(999999, data);
    
    EXPECT_FALSE(sent);
    
    manager.stop();
}

TEST(BtNetworkManagerTest, CloseUnknownConnection) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    manager.start();
    
    // Should not crash when closing non-existent socket
    manager.close_connection(999999);
    
    manager.stop();
}

TEST(BtNetworkManagerTest, SetCallbacks) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    
    bool connected_called = false;
    bool disconnected_called = false;
    bool data_called = false;
    
    manager.set_connected_callback(
        [&](const BtInfoHash&, std::shared_ptr<BtPeerConnection>, socket_t, bool) {
            connected_called = true;
        });
    
    manager.set_disconnected_callback(
        [&](const BtInfoHash&, BtPeerConnection*) {
            disconnected_called = true;
        });
    
    manager.set_data_callback(
        [&](const BtInfoHash&, BtPeerConnection*, socket_t) {
            data_called = true;
        });
    
    // Just verify callbacks were set without crash
    manager.start();
    manager.stop();
}

TEST(BtNetworkManagerTest, CountsThreadSafety) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    
    bool started = manager.start();
    if (!started) {
        GTEST_SKIP() << "Network not available";
    }
    
    // Call count methods from multiple threads simultaneously
    std::atomic<bool> done{false};
    std::thread counter([&]() {
        while (!done) {
            (void)manager.connection_count();
            (void)manager.pending_connect_count();
        }
    });
    
    // Give some time for concurrent access
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    done = true;
    counter.join();
    
    manager.stop();
}

} // namespace
} // namespace librats
