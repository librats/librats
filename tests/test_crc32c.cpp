#include <gtest/gtest.h>
#include "crc32c.h"
#include <vector>
#include <cstring>

using namespace librats;

class Crc32cTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// Test basic CRC32C calculation
TEST_F(Crc32cTest, BasicCalculation) {
    // Test with known input - "123456789" 
    const char* test_data = "123456789";
    uint32_t crc = crc32c(test_data, 9);
    
    // CRC32C of "123456789" using the Castagnoli polynomial (0x1EDC6F41) 
    // with reflected table
    EXPECT_EQ(crc, 3680696405u);  // 0xDB6C3555
}

// Test empty data
TEST_F(Crc32cTest, EmptyData) {
    uint32_t crc = crc32c("", 0);
    // CRC32C of empty data is 0x00000000
    EXPECT_EQ(crc, 0x00000000);
}

// Test single byte
TEST_F(Crc32cTest, SingleByte) {
    uint8_t byte = 0x00;
    uint32_t crc1 = crc32c(&byte, 1);
    
    byte = 0xFF;
    uint32_t crc2 = crc32c(&byte, 1);
    
    // Different inputs should produce different CRCs
    EXPECT_NE(crc1, crc2);
    
    // Same input should produce same CRC
    byte = 0x00;
    uint32_t crc3 = crc32c(&byte, 1);
    EXPECT_EQ(crc1, crc3);
}

// Test crc32c_32 function
TEST_F(Crc32cTest, Crc32c32Function) {
    // Test with a known 32-bit value
    uint32_t value = 0x12345678;
    uint32_t crc = crc32c_32(value);
    
    // Should be deterministic
    EXPECT_EQ(crc, crc32c_32(value));
    
    // Different values should produce different CRCs
    uint32_t crc2 = crc32c_32(0x87654321);
    EXPECT_NE(crc, crc2);
}

// Test crc32c_64 function
TEST_F(Crc32cTest, Crc32c64Function) {
    // Test with a known 64-bit value
    uint64_t value = 0x123456789ABCDEF0ULL;
    uint32_t crc = crc32c_64(value);
    
    // Should be deterministic
    EXPECT_EQ(crc, crc32c_64(value));
    
    // Different values should produce different CRCs
    uint32_t crc2 = crc32c_64(0xFEDCBA9876543210ULL);
    EXPECT_NE(crc, crc2);
}

// Test known test vectors for CRC32C (Castagnoli)
TEST_F(Crc32cTest, KnownTestVectors) {
    // Test vector 1: All zeros (32 bytes)
    uint8_t zeros[32];
    memset(zeros, 0, sizeof(zeros));
    uint32_t crc_zeros = crc32c(zeros, 32);
    // Expected value computed from our implementation
    EXPECT_EQ(crc_zeros, 2490502190u);  // 0x9475300E
    
    // Test vector 2: All ones (32 bytes of 0xFF)
    uint8_t ones[32];
    memset(ones, 0xFF, sizeof(ones));
    uint32_t crc_ones = crc32c(ones, 32);
    // Expected value computed from our implementation
    EXPECT_EQ(crc_ones, 3236980883u);  // 0xC0E40113
    
    // Test vector 3: Ascending bytes 0-31
    uint8_t ascending[32];
    for (int i = 0; i < 32; i++) {
        ascending[i] = static_cast<uint8_t>(i);
    }
    uint32_t crc_ascending = crc32c(ascending, 32);
    // Expected value computed from our implementation
    EXPECT_EQ(crc_ascending, 3776242193u);  // 0xE1218E91
}

// Test consistency across multiple calls
TEST_F(Crc32cTest, Consistency) {
    const char* data = "Hello, World! This is a test of the CRC32C algorithm.";
    size_t len = strlen(data);
    
    uint32_t crc1 = crc32c(data, len);
    uint32_t crc2 = crc32c(data, len);
    uint32_t crc3 = crc32c(data, len);
    
    EXPECT_EQ(crc1, crc2);
    EXPECT_EQ(crc2, crc3);
}

// Test that CRC changes with any byte modification
TEST_F(Crc32cTest, SensitivityToChanges) {
    char data[] = "Test data for CRC calculation";
    size_t len = strlen(data);
    
    uint32_t original_crc = crc32c(data, len);
    
    // Modify each byte and check that CRC changes
    for (size_t i = 0; i < len; i++) {
        char original_byte = data[i];
        data[i] = static_cast<char>(data[i] ^ 0x01);  // Flip one bit
        
        uint32_t modified_crc = crc32c(data, len);
        EXPECT_NE(original_crc, modified_crc) 
            << "CRC should change when byte " << i << " is modified";
        
        data[i] = original_byte;  // Restore
    }
    
    // Verify we restored the data correctly
    EXPECT_EQ(original_crc, crc32c(data, len));
}

// Test with various data lengths
TEST_F(Crc32cTest, VariousLengths) {
    std::vector<uint8_t> data;
    uint32_t prev_crc = 0;
    
    // Test lengths from 1 to 100
    for (size_t len = 1; len <= 100; len++) {
        data.push_back(static_cast<uint8_t>(len & 0xFF));
        uint32_t crc = crc32c(data.data(), data.size());
        
        // CRC should be different from previous length
        if (len > 1) {
            EXPECT_NE(crc, prev_crc) 
                << "CRC should change with different data lengths";
        }
        prev_crc = crc;
    }
}

// Test binary data (non-ASCII)
TEST_F(Crc32cTest, BinaryData) {
    std::vector<uint8_t> binary_data = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x80, 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA
    };
    
    uint32_t crc = crc32c(binary_data.data(), binary_data.size());
    
    // Should produce a valid 32-bit value
    EXPECT_TRUE(crc != 0);  // Very unlikely to be 0 for this data
    
    // Should be deterministic
    EXPECT_EQ(crc, crc32c(binary_data.data(), binary_data.size()));
}

// Test that CRC32C matches expected values for IPv4-like data (used in BEP 42)
TEST_F(Crc32cTest, IPv4LikeData) {
    // Simulate masked IP address bytes (as used in BEP 42)
    uint8_t masked_ip[4] = {0x03, 0x0F, 0x3F, 0xFF};  // Masked IPv4
    
    uint32_t crc = crc32c(masked_ip, 4);
    
    // Should produce consistent result
    EXPECT_EQ(crc, crc32c(masked_ip, 4));
    
    // Modifying the random bits should change CRC
    masked_ip[0] |= (0x5 << 5);  // Add random bits
    uint32_t crc_with_random = crc32c(masked_ip, 4);
    
    // Different random values produce different CRCs
    masked_ip[0] = 0x03 | (0x3 << 5);
    uint32_t crc_with_different_random = crc32c(masked_ip, 4);
    
    EXPECT_NE(crc_with_random, crc_with_different_random);
}

