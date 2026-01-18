/**
 * @file test_crypto_blake2.cpp
 * @brief Unit tests for BLAKE2s and BLAKE2b implementations
 */

#include <gtest/gtest.h>
#include <cstring>
#include "blake2s.h"
#include "blake2b.h"

class BLAKE2sTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
    
    std::string toHex(const uint8_t* data, size_t len) {
        std::string result;
        result.reserve(len * 2);
        const char* hex = "0123456789abcdef";
        for (size_t i = 0; i < len; i++) {
            result += hex[(data[i] >> 4) & 0xF];
            result += hex[data[i] & 0xF];
        }
        return result;
    }
};

class BLAKE2bTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
    
    std::string toHex(const uint8_t* data, size_t len) {
        std::string result;
        result.reserve(len * 2);
        const char* hex = "0123456789abcdef";
        for (size_t i = 0; i < len; i++) {
            result += hex[(data[i] >> 4) & 0xF];
            result += hex[data[i] & 0xF];
        }
        return result;
    }
};

// BLAKE2s test vectors from RFC 7693

TEST_F(BLAKE2sTest, EmptyString) {
    uint8_t hash[32];
    BLAKE2s_context_t ctx;
    
    BLAKE2s_reset(&ctx);
    BLAKE2s_update(&ctx, "", 0);
    BLAKE2s_finish(&ctx, hash);
    
    // BLAKE2s-256 of empty string
    std::string expected = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9";
    EXPECT_EQ(toHex(hash, 32), expected);
}

TEST_F(BLAKE2sTest, ABC) {
    uint8_t hash[32];
    BLAKE2s_context_t ctx;
    
    BLAKE2s_reset(&ctx);
    BLAKE2s_update(&ctx, "abc", 3);
    BLAKE2s_finish(&ctx, hash);
    
    // BLAKE2s-256 of "abc"
    std::string expected = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
    EXPECT_EQ(toHex(hash, 32), expected);
}

TEST_F(BLAKE2sTest, IncrementalUpdate) {
    const char* part1 = "Hello, ";
    const char* part2 = "World!";
    
    // Compute hash in one go
    uint8_t hash1[32];
    BLAKE2s_context_t ctx1;
    std::string full = std::string(part1) + part2;
    BLAKE2s_reset(&ctx1);
    BLAKE2s_update(&ctx1, full.c_str(), full.length());
    BLAKE2s_finish(&ctx1, hash1);
    
    // Compute hash incrementally
    uint8_t hash2[32];
    BLAKE2s_context_t ctx2;
    BLAKE2s_reset(&ctx2);
    BLAKE2s_update(&ctx2, part1, strlen(part1));
    BLAKE2s_update(&ctx2, part2, strlen(part2));
    BLAKE2s_finish(&ctx2, hash2);
    
    EXPECT_EQ(memcmp(hash1, hash2, 32), 0);
}

TEST_F(BLAKE2sTest, LongMessage) {
    // Test with data longer than block size (64 bytes)
    std::string input(256, 'a');
    
    uint8_t hash[32];
    BLAKE2s_context_t ctx;
    BLAKE2s_reset(&ctx);
    BLAKE2s_update(&ctx, input.c_str(), input.length());
    BLAKE2s_finish(&ctx, hash);
    
    // Just verify it produces a hash (deterministic test)
    uint8_t hash2[32];
    BLAKE2s_context_t ctx2;
    BLAKE2s_reset(&ctx2);
    BLAKE2s_update(&ctx2, input.c_str(), input.length());
    BLAKE2s_finish(&ctx2, hash2);
    
    EXPECT_EQ(memcmp(hash, hash2, 32), 0);
}

TEST_F(BLAKE2sTest, DifferentInputsDifferentHashes) {
    uint8_t hash1[32], hash2[32];
    BLAKE2s_context_t ctx;
    
    BLAKE2s_reset(&ctx);
    BLAKE2s_update(&ctx, "message1", 8);
    BLAKE2s_finish(&ctx, hash1);
    
    BLAKE2s_reset(&ctx);
    BLAKE2s_update(&ctx, "message2", 8);
    BLAKE2s_finish(&ctx, hash2);
    
    EXPECT_NE(memcmp(hash1, hash2, 32), 0);
}

// BLAKE2b test vectors from RFC 7693

TEST_F(BLAKE2bTest, EmptyString) {
    uint8_t hash[64];
    BLAKE2b_context_t ctx;
    
    BLAKE2b_reset(&ctx);
    BLAKE2b_update(&ctx, "", 0);
    BLAKE2b_finish(&ctx, hash);
    
    // BLAKE2b-512 of empty string
    std::string expected = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
                           "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce";
    EXPECT_EQ(toHex(hash, 64), expected);
}

TEST_F(BLAKE2bTest, ABC) {
    uint8_t hash[64];
    BLAKE2b_context_t ctx;
    
    BLAKE2b_reset(&ctx);
    BLAKE2b_update(&ctx, "abc", 3);
    BLAKE2b_finish(&ctx, hash);
    
    // BLAKE2b-512 of "abc"
    std::string expected = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                           "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";
    EXPECT_EQ(toHex(hash, 64), expected);
}

TEST_F(BLAKE2bTest, IncrementalUpdate) {
    const char* part1 = "Hello, ";
    const char* part2 = "World!";
    
    // Compute hash in one go
    uint8_t hash1[64];
    BLAKE2b_context_t ctx1;
    std::string full = std::string(part1) + part2;
    BLAKE2b_reset(&ctx1);
    BLAKE2b_update(&ctx1, full.c_str(), full.length());
    BLAKE2b_finish(&ctx1, hash1);
    
    // Compute hash incrementally
    uint8_t hash2[64];
    BLAKE2b_context_t ctx2;
    BLAKE2b_reset(&ctx2);
    BLAKE2b_update(&ctx2, part1, strlen(part1));
    BLAKE2b_update(&ctx2, part2, strlen(part2));
    BLAKE2b_finish(&ctx2, hash2);
    
    EXPECT_EQ(memcmp(hash1, hash2, 64), 0);
}

TEST_F(BLAKE2bTest, LongMessage) {
    // Test with data longer than block size (128 bytes)
    std::string input(512, 'a');
    
    uint8_t hash[64];
    BLAKE2b_context_t ctx;
    BLAKE2b_reset(&ctx);
    BLAKE2b_update(&ctx, input.c_str(), input.length());
    BLAKE2b_finish(&ctx, hash);
    
    // Just verify it produces a hash (deterministic test)
    uint8_t hash2[64];
    BLAKE2b_context_t ctx2;
    BLAKE2b_reset(&ctx2);
    BLAKE2b_update(&ctx2, input.c_str(), input.length());
    BLAKE2b_finish(&ctx2, hash2);
    
    EXPECT_EQ(memcmp(hash, hash2, 64), 0);
}

TEST_F(BLAKE2bTest, DifferentInputsDifferentHashes) {
    uint8_t hash1[64], hash2[64];
    BLAKE2b_context_t ctx;
    
    BLAKE2b_reset(&ctx);
    BLAKE2b_update(&ctx, "message1", 8);
    BLAKE2b_finish(&ctx, hash1);
    
    BLAKE2b_reset(&ctx);
    BLAKE2b_update(&ctx, "message2", 8);
    BLAKE2b_finish(&ctx, hash2);
    
    EXPECT_NE(memcmp(hash1, hash2, 64), 0);
}

TEST_F(BLAKE2bTest, ByteByByteUpdate) {
    const char* message = "test";
    size_t len = strlen(message);
    
    // Hash all at once
    uint8_t hash1[64];
    BLAKE2b_context_t ctx1;
    BLAKE2b_reset(&ctx1);
    BLAKE2b_update(&ctx1, message, len);
    BLAKE2b_finish(&ctx1, hash1);
    
    // Hash byte by byte
    uint8_t hash2[64];
    BLAKE2b_context_t ctx2;
    BLAKE2b_reset(&ctx2);
    for (size_t i = 0; i < len; i++) {
        BLAKE2b_update(&ctx2, message + i, 1);
    }
    BLAKE2b_finish(&ctx2, hash2);
    
    EXPECT_EQ(memcmp(hash1, hash2, 64), 0);
}
