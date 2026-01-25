#include <gtest/gtest.h>
#include "bt_network.h"

namespace librats {
namespace {

//=============================================================================
// ChainedSendBuffer Tests
//=============================================================================

TEST(ChainedSendBufferTest, EmptyBuffer) {
    ChainedSendBuffer buffer;
    
    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.size(), 0);
    EXPECT_EQ(buffer.chunk_count(), 0);
}

TEST(ChainedSendBufferTest, AppendAndSize) {
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

//=============================================================================
// BtNetworkConfig Tests
//=============================================================================

TEST(BtNetworkConfigTest, DefaultValues) {
    BtNetworkConfig config;
    
    EXPECT_EQ(config.listen_port, 6881);
    EXPECT_EQ(config.max_connections, 200);
    EXPECT_TRUE(config.enable_incoming);
    EXPECT_GT(config.connect_timeout_ms, 0);
    EXPECT_GT(config.recv_buffer_size, 0);
}

//=============================================================================
// BtNetworkManager Tests
//=============================================================================

TEST(BtNetworkManagerTest, ConstructDestruct) {
    BtNetworkConfig config;
    config.listen_port = 0;  // Use ephemeral port
    
    BtNetworkManager manager(config);
    
    EXPECT_FALSE(manager.is_running());
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

TEST(BtNetworkManagerTest, ConnectionCounts) {
    BtNetworkConfig config;
    config.listen_port = 0;
    
    BtNetworkManager manager(config);
    manager.start();
    
    EXPECT_EQ(manager.connection_count(), 0);
    EXPECT_EQ(manager.pending_connect_count(), 0);
    
    manager.stop();
}

} // namespace
} // namespace librats
