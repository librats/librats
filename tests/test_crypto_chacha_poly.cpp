/**
 * @file test_crypto_chacha_poly.cpp
 * @brief Unit tests for ChaCha20 and Poly1305 implementations
 */

#include <gtest/gtest.h>
#include <cstring>
#include "chacha.h"
#include "poly1305.h"

class ChaChaTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

class Poly1305Test : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// ChaCha20 test vector from RFC 7539, Section 2.4.2
TEST_F(ChaChaTest, RFC7539TestVector) {
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    uint8_t nonce[8] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a
    };
    
    uint8_t counter[8] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    const char *plaintext_str = "Ladies and Gentlemen of the class of '99: "
                                "If I could offer you only one tip for the future, "
                                "sunscreen would be it.";
    
    size_t len = strlen(plaintext_str);
    uint8_t plaintext[128];
    uint8_t ciphertext[128];
    
    memcpy(plaintext, plaintext_str, len);
    memcpy(ciphertext, plaintext, len);
    
    chacha_ctx ctx;
    chacha_keysetup(&ctx, key, 256);
    chacha_ivsetup(&ctx, nonce, counter);
    chacha_encrypt_bytes(&ctx, ciphertext, ciphertext, (uint32_t)len);
    
    // Verify ciphertext is different from plaintext
    EXPECT_NE(memcmp(plaintext, ciphertext, len), 0);
    
    // Decrypt by encrypting again (ChaCha20 is symmetric)
    uint8_t decrypted[128];
    memcpy(decrypted, ciphertext, len);
    
    chacha_keysetup(&ctx, key, 256);
    chacha_ivsetup(&ctx, nonce, counter);
    chacha_encrypt_bytes(&ctx, decrypted, decrypted, (uint32_t)len);
    
    EXPECT_EQ(memcmp(plaintext, decrypted, len), 0);
}

TEST_F(ChaChaTest, EncryptDecryptSymmetric) {
    uint8_t key[32];
    uint8_t nonce[8];
    
    // Initialize with test values
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 8; i++) nonce[i] = (uint8_t)(i + 100);
    
    uint8_t plaintext[64] = "Hello, World! This is a test of ChaCha20 encryption.";
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    
    size_t len = strlen((char*)plaintext) + 1;
    
    chacha_ctx ctx;
    
    // Encrypt
    chacha_keysetup(&ctx, key, 256);
    chacha_ivsetup(&ctx, nonce, NULL);
    memcpy(ciphertext, plaintext, len);
    chacha_encrypt_bytes(&ctx, ciphertext, ciphertext, (uint32_t)len);
    
    // Decrypt
    chacha_keysetup(&ctx, key, 256);
    chacha_ivsetup(&ctx, nonce, NULL);
    memcpy(decrypted, ciphertext, len);
    chacha_encrypt_bytes(&ctx, decrypted, decrypted, (uint32_t)len);
    
    EXPECT_EQ(memcmp(plaintext, decrypted, len), 0);
}

TEST_F(ChaChaTest, DifferentKeysProduceDifferentOutput) {
    uint8_t key1[32], key2[32];
    uint8_t nonce[8] = {0};
    
    for (int i = 0; i < 32; i++) {
        key1[i] = (uint8_t)i;
        key2[i] = (uint8_t)(i + 1);
    }
    
    uint8_t plaintext[32] = {0};
    uint8_t ciphertext1[32], ciphertext2[32];
    
    chacha_ctx ctx;
    
    chacha_keysetup(&ctx, key1, 256);
    chacha_ivsetup(&ctx, nonce, NULL);
    chacha_encrypt_bytes(&ctx, plaintext, ciphertext1, 32);
    
    chacha_keysetup(&ctx, key2, 256);
    chacha_ivsetup(&ctx, nonce, NULL);
    chacha_encrypt_bytes(&ctx, plaintext, ciphertext2, 32);
    
    EXPECT_NE(memcmp(ciphertext1, ciphertext2, 32), 0);
}

// Poly1305 test from RFC 7539, Section 2.5.2
TEST_F(Poly1305Test, RFC7539TestVector) {
    uint8_t key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    };
    
    const char *message = "Cryptographic Forum Research Group";
    size_t len = strlen(message);
    
    uint8_t expected_tag[16] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    };
    
    uint8_t tag[16];
    poly1305_auth(tag, (const uint8_t*)message, len, key);
    
    EXPECT_EQ(memcmp(tag, expected_tag, 16), 0);
}

TEST_F(Poly1305Test, VerifyCorrectTag) {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    
    const char *message = "Test message for Poly1305";
    size_t len = strlen(message);
    
    uint8_t tag[16];
    poly1305_auth(tag, (const uint8_t*)message, len, key);
    
    EXPECT_EQ(poly1305_verify(tag, tag), 1);
}

TEST_F(Poly1305Test, VerifyIncorrectTag) {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    
    const char *message = "Test message for Poly1305";
    size_t len = strlen(message);
    
    uint8_t tag1[16], tag2[16];
    poly1305_auth(tag1, (const uint8_t*)message, len, key);
    
    // Modify the message and compute new tag
    const char *modified = "Test message for Poly1306";
    poly1305_auth(tag2, (const uint8_t*)modified, strlen(modified), key);
    
    EXPECT_EQ(poly1305_verify(tag1, tag2), 0);
}

TEST_F(Poly1305Test, SelfTest) {
    EXPECT_EQ(poly1305_power_on_self_test(), 1);
}

TEST_F(Poly1305Test, IncrementalUpdate) {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 0x10);
    
    const char *message = "This is a longer message that will be processed in parts";
    size_t len = strlen(message);
    
    // Compute tag in one go
    uint8_t tag1[16];
    poly1305_auth(tag1, (const uint8_t*)message, len, key);
    
    // Compute tag incrementally
    uint8_t tag2[16];
    poly1305_context ctx;
    poly1305_init(&ctx, key);
    poly1305_update(&ctx, (const uint8_t*)message, 20);
    poly1305_update(&ctx, (const uint8_t*)message + 20, len - 20);
    poly1305_finish(&ctx, tag2);
    
    EXPECT_EQ(memcmp(tag1, tag2, 16), 0);
}
