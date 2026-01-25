#include <gtest/gtest.h>
#include "chained_send_buffer.h"
#include <cstring>
#include <vector>
#include <algorithm>

using namespace librats;

TEST(ChainedSendBufferTest, Construction) {
    ChainedSendBuffer buf;
    
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0);
    EXPECT_EQ(buf.chunk_count(), 0);
    EXPECT_EQ(buf.front_data(), nullptr);
    EXPECT_EQ(buf.front_size(), 0);
}

TEST(ChainedSendBufferTest, AppendMove) {
    ChainedSendBuffer buf;
    
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    buf.append(std::move(data));
    
    EXPECT_FALSE(buf.empty());
    EXPECT_EQ(buf.size(), 5);
    EXPECT_EQ(buf.chunk_count(), 1);
    EXPECT_NE(buf.front_data(), nullptr);
    EXPECT_EQ(buf.front_size(), 5);
    EXPECT_EQ(buf.front_data()[0], 1);
    EXPECT_EQ(buf.front_data()[4], 5);
}

TEST(ChainedSendBufferTest, AppendCopy) {
    ChainedSendBuffer buf;
    
    std::vector<uint8_t> data = {10, 20, 30};
    buf.append(data.data(), data.size());
    
    EXPECT_EQ(buf.size(), 3);
    EXPECT_EQ(buf.front_data()[0], 10);
}

TEST(ChainedSendBufferTest, AppendEmpty) {
    ChainedSendBuffer buf;
    
    std::vector<uint8_t> empty;
    buf.append(std::move(empty));
    buf.append(nullptr, 0);
    
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.chunk_count(), 0);
}

TEST(ChainedSendBufferTest, MultipleChunks) {
    ChainedSendBuffer buf;
    
    buf.append(std::vector<uint8_t>{1, 2, 3});
    buf.append(std::vector<uint8_t>{4, 5});
    buf.append(std::vector<uint8_t>{6, 7, 8, 9});
    
    EXPECT_EQ(buf.size(), 9);
    EXPECT_EQ(buf.chunk_count(), 3);
    
    // Front is first chunk
    EXPECT_EQ(buf.front_size(), 3);
    EXPECT_EQ(buf.front_data()[0], 1);
}

TEST(ChainedSendBufferTest, PopFrontPartial) {
    ChainedSendBuffer buf;
    
    buf.append(std::vector<uint8_t>{1, 2, 3, 4, 5});
    
    // Pop partial
    buf.pop_front(2);
    
    EXPECT_EQ(buf.size(), 3);
    EXPECT_EQ(buf.chunk_count(), 1);  // Still one chunk
    EXPECT_EQ(buf.front_size(), 3);
    EXPECT_EQ(buf.front_data()[0], 3);  // Data shifted
}

TEST(ChainedSendBufferTest, PopFrontEntireChunk) {
    ChainedSendBuffer buf;
    
    buf.append(std::vector<uint8_t>{1, 2, 3});
    buf.append(std::vector<uint8_t>{4, 5, 6});
    
    // Pop entire first chunk
    buf.pop_front(3);
    
    EXPECT_EQ(buf.size(), 3);
    EXPECT_EQ(buf.chunk_count(), 1);
    EXPECT_EQ(buf.front_data()[0], 4);
}

TEST(ChainedSendBufferTest, PopFrontAcrossChunks) {
    ChainedSendBuffer buf;
    
    buf.append(std::vector<uint8_t>{1, 2});
    buf.append(std::vector<uint8_t>{3, 4});
    buf.append(std::vector<uint8_t>{5, 6});
    
    // Pop across chunk boundaries
    buf.pop_front(5);
    
    EXPECT_EQ(buf.size(), 1);
    EXPECT_EQ(buf.chunk_count(), 1);
    EXPECT_EQ(buf.front_data()[0], 6);
}

TEST(ChainedSendBufferTest, PopFrontAll) {
    ChainedSendBuffer buf;
    
    buf.append(std::vector<uint8_t>{1, 2, 3});
    buf.pop_front(3);
    
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0);
    EXPECT_EQ(buf.chunk_count(), 0);
}

TEST(ChainedSendBufferTest, CopyTo) {
    ChainedSendBuffer buf;
    
    buf.append(std::vector<uint8_t>{1, 2, 3});
    buf.append(std::vector<uint8_t>{4, 5, 6, 7});
    
    std::vector<uint8_t> dest(10);
    size_t copied = buf.copy_to(dest.data(), dest.size());
    
    EXPECT_EQ(copied, 7);
    EXPECT_EQ(dest[0], 1);
    EXPECT_EQ(dest[3], 4);
    EXPECT_EQ(dest[6], 7);
}

TEST(ChainedSendBufferTest, CopyToPartial) {
    ChainedSendBuffer buf;
    
    buf.append(std::vector<uint8_t>{1, 2, 3, 4, 5});
    
    std::vector<uint8_t> dest(3);
    size_t copied = buf.copy_to(dest.data(), dest.size());
    
    EXPECT_EQ(copied, 3);
    EXPECT_EQ(dest[0], 1);
    EXPECT_EQ(dest[2], 3);
    
    // Buffer unchanged
    EXPECT_EQ(buf.size(), 5);
}

TEST(ChainedSendBufferTest, Clear) {
    ChainedSendBuffer buf;
    
    buf.append(std::vector<uint8_t>{1, 2, 3});
    buf.append(std::vector<uint8_t>{4, 5, 6});
    
    buf.clear();
    
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0);
    EXPECT_EQ(buf.chunk_count(), 0);
}

TEST(ChainedSendBufferTest, LargeData) {
    ChainedSendBuffer buf;
    
    // Simulate piece data (16KB blocks)
    std::vector<uint8_t> piece(16384, 0xAB);
    buf.append(std::move(piece));
    
    EXPECT_EQ(buf.size(), 16384);
    EXPECT_EQ(buf.front_size(), 16384);
    
    // Partial send simulation
    buf.pop_front(8000);
    EXPECT_EQ(buf.size(), 8384);
    EXPECT_EQ(buf.front_size(), 8384);
    
    buf.pop_front(8384);
    EXPECT_TRUE(buf.empty());
}

TEST(ChainedSendBufferTest, SimulateSendLoop) {
    ChainedSendBuffer buf;
    
    // Queue multiple messages
    buf.append(std::vector<uint8_t>(5, 0x01));   // interested
    buf.append(std::vector<uint8_t>(9, 0x02));   // have
    buf.append(std::vector<uint8_t>(1000, 0x03)); // piece
    
    EXPECT_EQ(buf.size(), 1014);
    
    // Simulate send loop
    size_t total_sent = 0;
    while (!buf.empty()) {
        // "Send" up to 100 bytes at a time
        size_t to_send = std::min(buf.front_size(), size_t(100));
        buf.pop_front(to_send);
        total_sent += to_send;
    }
    
    EXPECT_EQ(total_sent, 1014);
    EXPECT_TRUE(buf.empty());
}
