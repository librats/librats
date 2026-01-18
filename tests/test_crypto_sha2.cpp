/**
 * @file test_crypto_sha2.cpp
 * @brief Unit tests for SHA-256 and SHA-512 implementations
 */

#include <gtest/gtest.h>
#include <cstring>
#include "sha256.h"
#include "sha512.h"

class SHA256Test : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
    
    // Helper to convert hash to hex string
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

class SHA512Test : public ::testing::Test {
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

// SHA-256 test vectors from NIST FIPS 180-4

TEST_F(SHA256Test, EmptyString) {
    uint8_t hash[32];
    sha256_hash(hash, "", 0);
    
    std::string expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    EXPECT_EQ(toHex(hash, 32), expected);
}

TEST_F(SHA256Test, ABC) {
    const char* input = "abc";
    uint8_t hash[32];
    sha256_hash(hash, input, strlen(input));
    
    std::string expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    EXPECT_EQ(toHex(hash, 32), expected);
}

TEST_F(SHA256Test, TwoBlocks) {
    const char* input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t hash[32];
    sha256_hash(hash, input, strlen(input));
    
    std::string expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    EXPECT_EQ(toHex(hash, 32), expected);
}

TEST_F(SHA256Test, IncrementalUpdate) {
    const char* part1 = "Hello, ";
    const char* part2 = "World!";
    
    // Compute hash in one go
    uint8_t hash1[32];
    std::string full = std::string(part1) + part2;
    sha256_hash(hash1, full.c_str(), full.length());
    
    // Compute hash incrementally
    uint8_t hash2[32];
    sha256_context_t ctx;
    sha256_reset(&ctx);
    sha256_update(&ctx, part1, strlen(part1));
    sha256_update(&ctx, part2, strlen(part2));
    sha256_finish(&ctx, hash2);
    
    EXPECT_EQ(memcmp(hash1, hash2, 32), 0);
}

TEST_F(SHA256Test, LongMessage) {
    // 1 million 'a' characters
    std::string input(1000000, 'a');
    uint8_t hash[32];
    sha256_hash(hash, input.c_str(), input.length());
    
    std::string expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    EXPECT_EQ(toHex(hash, 32), expected);
}

TEST_F(SHA256Test, DeterministicOutput) {
    const char* input = "test message";
    uint8_t hash1[32], hash2[32];
    
    sha256_hash(hash1, input, strlen(input));
    sha256_hash(hash2, input, strlen(input));
    
    EXPECT_EQ(memcmp(hash1, hash2, 32), 0);
}

// SHA-512 test vectors from NIST FIPS 180-4

TEST_F(SHA512Test, EmptyString) {
    uint8_t hash[64];
    sha512_hash(hash, "", 0);
    
    std::string expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                           "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    EXPECT_EQ(toHex(hash, 64), expected);
}

TEST_F(SHA512Test, ABC) {
    const char* input = "abc";
    uint8_t hash[64];
    sha512_hash(hash, input, strlen(input));
    
    std::string expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                           "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    EXPECT_EQ(toHex(hash, 64), expected);
}

TEST_F(SHA512Test, TwoBlocks) {
    const char* input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t hash[64];
    sha512_hash(hash, input, strlen(input));
    
    std::string expected = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                           "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";
    EXPECT_EQ(toHex(hash, 64), expected);
}

TEST_F(SHA512Test, IncrementalUpdate) {
    const char* part1 = "Hello, ";
    const char* part2 = "World!";
    
    // Compute hash in one go
    uint8_t hash1[64];
    std::string full = std::string(part1) + part2;
    sha512_hash(hash1, full.c_str(), full.length());
    
    // Compute hash incrementally
    uint8_t hash2[64];
    sha512_context_t ctx;
    sha512_reset(&ctx);
    sha512_update(&ctx, part1, strlen(part1));
    sha512_update(&ctx, part2, strlen(part2));
    sha512_finish(&ctx, hash2);
    
    EXPECT_EQ(memcmp(hash1, hash2, 64), 0);
}

TEST_F(SHA512Test, DeterministicOutput) {
    const char* input = "test message";
    uint8_t hash1[64], hash2[64];
    
    sha512_hash(hash1, input, strlen(input));
    sha512_hash(hash2, input, strlen(input));
    
    EXPECT_EQ(memcmp(hash1, hash2, 64), 0);
}

TEST_F(SHA512Test, DifferentInputsDifferentHashes) {
    const char* input1 = "message1";
    const char* input2 = "message2";
    uint8_t hash1[64], hash2[64];
    
    sha512_hash(hash1, input1, strlen(input1));
    sha512_hash(hash2, input2, strlen(input2));
    
    EXPECT_NE(memcmp(hash1, hash2, 64), 0);
}
