#include <gtest/gtest.h>
#include "receive_buffer.h"
#include <cstring>
#include <vector>

using namespace librats;

TEST(ReceiveBufferTest, Construction) {
    ReceiveBuffer buf(1024);
    
    EXPECT_EQ(buf.capacity(), 1024);
    EXPECT_EQ(buf.size(), 0);
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.front_waste(), 0);
    EXPECT_EQ(buf.write_space(), 1024);
}

TEST(ReceiveBufferTest, DefaultConstruction) {
    ReceiveBuffer buf;
    
    EXPECT_EQ(buf.capacity(), 4096);  // Default capacity
    EXPECT_TRUE(buf.empty());
}

TEST(ReceiveBufferTest, WriteAndRead) {
    ReceiveBuffer buf(1024);
    
    // Simulate receiving data
    const char* test_data = "Hello, World!";
    size_t len = strlen(test_data);
    
    buf.ensure_space(len);
    std::memcpy(buf.write_ptr(), test_data, len);
    buf.received(len);
    
    EXPECT_EQ(buf.size(), len);
    EXPECT_FALSE(buf.empty());
    EXPECT_EQ(std::memcmp(buf.data(), test_data, len), 0);
}

TEST(ReceiveBufferTest, ConsumeO1) {
    ReceiveBuffer buf(1024);
    
    // Write some data
    std::vector<uint8_t> data(100, 0xAB);
    buf.ensure_space(data.size());
    std::memcpy(buf.write_ptr(), data.data(), data.size());
    buf.received(data.size());
    
    EXPECT_EQ(buf.size(), 100);
    
    // Consume half - should be O(1)
    buf.consume(50);
    
    EXPECT_EQ(buf.size(), 50);
    EXPECT_EQ(buf.front_waste(), 50);  // 50 bytes wasted at front
    
    // Verify remaining data
    EXPECT_EQ(buf.data()[0], 0xAB);
}

TEST(ReceiveBufferTest, ConsumeAll) {
    ReceiveBuffer buf(1024);
    
    // Write and consume all
    std::vector<uint8_t> data(100, 0xCD);
    buf.ensure_space(data.size());
    std::memcpy(buf.write_ptr(), data.data(), data.size());
    buf.received(data.size());
    
    buf.consume(100);
    
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0);
    EXPECT_EQ(buf.front_waste(), 0);  // Reset when empty
}

TEST(ReceiveBufferTest, Normalize) {
    ReceiveBuffer buf(1024);
    
    // Fill with data
    std::vector<uint8_t> data(500, 0xEF);
    buf.ensure_space(data.size());
    std::memcpy(buf.write_ptr(), data.data(), data.size());
    buf.received(data.size());
    
    // Consume to create waste
    buf.consume(400);
    EXPECT_EQ(buf.front_waste(), 400);
    EXPECT_EQ(buf.size(), 100);
    
    // Normalize to reclaim space
    buf.normalize();
    
    EXPECT_EQ(buf.front_waste(), 0);
    EXPECT_EQ(buf.size(), 100);
    EXPECT_EQ(buf.data()[0], 0xEF);  // Data preserved
}

TEST(ReceiveBufferTest, EnsureSpaceGrows) {
    ReceiveBuffer buf(100);
    
    // Request more space than capacity
    buf.ensure_space(200);
    
    EXPECT_GE(buf.capacity(), 200);
    EXPECT_GE(buf.write_space(), 200);
}

TEST(ReceiveBufferTest, EnsureSpaceNormalizesFirst) {
    ReceiveBuffer buf(200);
    
    // Fill buffer
    std::vector<uint8_t> data(150, 0x11);
    buf.ensure_space(data.size());
    std::memcpy(buf.write_ptr(), data.data(), data.size());
    buf.received(data.size());
    
    // Consume most of it
    buf.consume(140);
    EXPECT_EQ(buf.size(), 10);
    EXPECT_EQ(buf.front_waste(), 140);
    
    // Need 100 bytes - should normalize instead of growing
    buf.ensure_space(100);
    
    EXPECT_EQ(buf.capacity(), 200);  // No growth
    EXPECT_GE(buf.write_space(), 100);
    EXPECT_EQ(buf.front_waste(), 0);  // Normalized
}

TEST(ReceiveBufferTest, Clear) {
    ReceiveBuffer buf(1024);
    
    // Add data
    std::vector<uint8_t> data(100, 0x22);
    buf.ensure_space(data.size());
    std::memcpy(buf.write_ptr(), data.data(), data.size());
    buf.received(data.size());
    
    buf.consume(50);
    
    // Clear
    buf.clear();
    
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0);
    EXPECT_EQ(buf.front_waste(), 0);
}

TEST(ReceiveBufferTest, MultipleWriteRead) {
    ReceiveBuffer buf(1024);
    
    // Write in chunks, read in different sizes
    for (int i = 0; i < 10; ++i) {
        std::vector<uint8_t> data(50, static_cast<uint8_t>(i));
        buf.ensure_space(data.size());
        std::memcpy(buf.write_ptr(), data.data(), data.size());
        buf.received(data.size());
    }
    
    EXPECT_EQ(buf.size(), 500);
    
    // Consume in different sized chunks
    buf.consume(75);
    EXPECT_EQ(buf.size(), 425);
    
    buf.consume(200);
    EXPECT_EQ(buf.size(), 225);
    
    buf.normalize();
    EXPECT_EQ(buf.size(), 225);
    EXPECT_EQ(buf.front_waste(), 0);
}
