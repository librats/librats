/**
 * @file test_noise.cpp
 * @brief Unit tests for Noise Protocol implementation
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include "noise.h"

extern "C" {
#include "chachapoly.h"
#include "hkdf.h"
}

using namespace rats;

// =============================================================================
// ChaCha20-Poly1305 AEAD Tests
// =============================================================================

class ChaChaPolyTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(ChaChaPolyTest, EncryptDecrypt) {
    uint8_t key[32];
    uint8_t nonce[12];
    
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i + 100);
    
    const char* plaintext = "Hello, Noise Protocol!";
    size_t pt_len = strlen(plaintext);
    
    std::vector<uint8_t> ciphertext(pt_len + CHACHAPOLY_TAG_SIZE);
    std::vector<uint8_t> decrypted(pt_len);
    
    // Encrypt
    size_t ct_len = chachapoly_encrypt(
        key, nonce,
        nullptr, 0,
        (const uint8_t*)plaintext, pt_len,
        ciphertext.data()
    );
    
    EXPECT_EQ(ct_len, pt_len + CHACHAPOLY_TAG_SIZE);
    
    // Decrypt
    size_t dec_len = chachapoly_decrypt(
        key, nonce,
        nullptr, 0,
        ciphertext.data(), ct_len,
        decrypted.data()
    );
    
    EXPECT_EQ(dec_len, pt_len);
    EXPECT_EQ(memcmp(plaintext, decrypted.data(), pt_len), 0);
}

TEST_F(ChaChaPolyTest, EncryptDecryptWithAD) {
    uint8_t key[32];
    uint8_t nonce[12];
    
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i + 50);
    
    const char* plaintext = "Secret message";
    const char* ad = "Associated data";
    size_t pt_len = strlen(plaintext);
    size_t ad_len = strlen(ad);
    
    std::vector<uint8_t> ciphertext(pt_len + CHACHAPOLY_TAG_SIZE);
    std::vector<uint8_t> decrypted(pt_len);
    
    // Encrypt
    size_t ct_len = chachapoly_encrypt(
        key, nonce,
        (const uint8_t*)ad, ad_len,
        (const uint8_t*)plaintext, pt_len,
        ciphertext.data()
    );
    
    EXPECT_EQ(ct_len, pt_len + CHACHAPOLY_TAG_SIZE);
    
    // Decrypt with correct AD
    size_t dec_len = chachapoly_decrypt(
        key, nonce,
        (const uint8_t*)ad, ad_len,
        ciphertext.data(), ct_len,
        decrypted.data()
    );
    
    EXPECT_EQ(dec_len, pt_len);
    EXPECT_EQ(memcmp(plaintext, decrypted.data(), pt_len), 0);
}

TEST_F(ChaChaPolyTest, DecryptWithWrongADFails) {
    uint8_t key[32];
    uint8_t nonce[12];
    
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 3);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i + 50);
    
    const char* plaintext = "Secret message";
    const char* ad = "Associated data";
    const char* wrong_ad = "Wrong associated data";
    size_t pt_len = strlen(plaintext);
    size_t ad_len = strlen(ad);
    
    std::vector<uint8_t> ciphertext(pt_len + CHACHAPOLY_TAG_SIZE);
    std::vector<uint8_t> decrypted(pt_len);
    
    // Encrypt
    chachapoly_encrypt(
        key, nonce,
        (const uint8_t*)ad, ad_len,
        (const uint8_t*)plaintext, pt_len,
        ciphertext.data()
    );
    
    // Decrypt with wrong AD should fail
    size_t dec_len = chachapoly_decrypt(
        key, nonce,
        (const uint8_t*)wrong_ad, strlen(wrong_ad),
        ciphertext.data(), pt_len + CHACHAPOLY_TAG_SIZE,
        decrypted.data()
    );
    
    EXPECT_EQ(dec_len, 0u);
}

TEST_F(ChaChaPolyTest, TamperedCiphertextFails) {
    uint8_t key[32];
    uint8_t nonce[12];
    
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i + 100);
    
    const char* plaintext = "Hello, Noise!";
    size_t pt_len = strlen(plaintext);
    
    std::vector<uint8_t> ciphertext(pt_len + CHACHAPOLY_TAG_SIZE);
    std::vector<uint8_t> decrypted(pt_len);
    
    // Encrypt
    size_t ct_len = chachapoly_encrypt(
        key, nonce,
        nullptr, 0,
        (const uint8_t*)plaintext, pt_len,
        ciphertext.data()
    );
    
    // Tamper with ciphertext
    ciphertext[0] ^= 0x01;
    
    // Decrypt should fail
    size_t dec_len = chachapoly_decrypt(
        key, nonce,
        nullptr, 0,
        ciphertext.data(), ct_len,
        decrypted.data()
    );
    
    EXPECT_EQ(dec_len, 0u);
}

// =============================================================================
// HKDF Tests
// =============================================================================

class HKDFTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(HKDFTest, HMACSHA256) {
    // Test vector from RFC 4231
    uint8_t key[20];
    memset(key, 0x0b, 20);
    
    const char* data = "Hi There";
    uint8_t output[32];
    
    hmac_sha256(key, 20, (const uint8_t*)data, strlen(data), output);
    
    // Expected output from RFC 4231
    uint8_t expected[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };
    
    EXPECT_EQ(memcmp(output, expected, 32), 0);
}

TEST_F(HKDFTest, NoiseHKDF2) {
    uint8_t ck[32];
    memset(ck, 0x00, 32);
    
    uint8_t input[32];
    for (int i = 0; i < 32; i++) input[i] = (uint8_t)i;
    
    uint8_t out1[32], out2[32];
    noise_hkdf_2(ck, input, 32, out1, out2);
    
    // Outputs should be different
    EXPECT_NE(memcmp(out1, out2, 32), 0);
    
    // Should be deterministic
    uint8_t out1_2[32], out2_2[32];
    noise_hkdf_2(ck, input, 32, out1_2, out2_2);
    
    EXPECT_EQ(memcmp(out1, out1_2, 32), 0);
    EXPECT_EQ(memcmp(out2, out2_2, 32), 0);
}

TEST_F(HKDFTest, NoiseHKDF3) {
    uint8_t ck[32];
    memset(ck, 0x00, 32);
    
    uint8_t input[32];
    for (int i = 0; i < 32; i++) input[i] = (uint8_t)(i + 100);
    
    uint8_t out1[32], out2[32], out3[32];
    noise_hkdf_3(ck, input, 32, out1, out2, out3);
    
    // All outputs should be different
    EXPECT_NE(memcmp(out1, out2, 32), 0);
    EXPECT_NE(memcmp(out2, out3, 32), 0);
    EXPECT_NE(memcmp(out1, out3, 32), 0);
}

// =============================================================================
// NoiseCipherState Tests
// =============================================================================

class NoiseCipherStateTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(NoiseCipherStateTest, EncryptDecrypt) {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    
    NoiseCipherState cipher1;
    NoiseCipherState cipher2;
    
    cipher1.initialize_key(key);
    cipher2.initialize_key(key);
    
    const char* message = "Hello, Noise CipherState!";
    size_t msg_len = strlen(message);
    
    std::vector<uint8_t> ciphertext(msg_len + NOISE_TAG_SIZE);
    std::vector<uint8_t> decrypted(msg_len);
    
    // Encrypt
    size_t ct_len = cipher1.encrypt_with_ad(
        nullptr, 0,
        (const uint8_t*)message, msg_len,
        ciphertext.data()
    );
    
    EXPECT_EQ(ct_len, msg_len + NOISE_TAG_SIZE);
    
    // Decrypt
    size_t pt_len = cipher2.decrypt_with_ad(
        nullptr, 0,
        ciphertext.data(), ct_len,
        decrypted.data()
    );
    
    EXPECT_EQ(pt_len, msg_len);
    EXPECT_EQ(memcmp(message, decrypted.data(), msg_len), 0);
}

TEST_F(NoiseCipherStateTest, NonceIncrement) {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    
    NoiseCipherState cipher;
    cipher.initialize_key(key);
    
    EXPECT_EQ(cipher.get_nonce(), 0u);
    
    uint8_t pt[16] = {0};
    uint8_t ct[32];
    
    cipher.encrypt_with_ad(nullptr, 0, pt, 16, ct);
    EXPECT_EQ(cipher.get_nonce(), 1u);
    
    cipher.encrypt_with_ad(nullptr, 0, pt, 16, ct);
    EXPECT_EQ(cipher.get_nonce(), 2u);
}

TEST_F(NoiseCipherStateTest, NoKeyPassthrough) {
    NoiseCipherState cipher;
    
    EXPECT_FALSE(cipher.has_key());
    
    const char* message = "No encryption";
    size_t msg_len = strlen(message);
    
    std::vector<uint8_t> output(msg_len);
    
    // Without key, should just copy data
    size_t out_len = cipher.encrypt_with_ad(
        nullptr, 0,
        (const uint8_t*)message, msg_len,
        output.data()
    );
    
    EXPECT_EQ(out_len, msg_len);
    EXPECT_EQ(memcmp(message, output.data(), msg_len), 0);
}

// =============================================================================
// NoiseSymmetricState Tests
// =============================================================================

class NoiseSymmetricStateTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(NoiseSymmetricStateTest, InitializeSymmetric) {
    NoiseSymmetricState ss;
    ss.initialize_symmetric(NOISE_PROTOCOL_NAME);
    
    // Hash should be non-zero after initialization
    const uint8_t* h = ss.get_handshake_hash();
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (h[i] != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero);
}

TEST_F(NoiseSymmetricStateTest, MixHash) {
    NoiseSymmetricState ss;
    ss.initialize_symmetric(NOISE_PROTOCOL_NAME);
    
    uint8_t h1[32];
    memcpy(h1, ss.get_handshake_hash(), 32);
    
    const char* data = "Some data to mix";
    ss.mix_hash((const uint8_t*)data, strlen(data));
    
    // Hash should change after mixing
    EXPECT_NE(memcmp(h1, ss.get_handshake_hash(), 32), 0);
}

TEST_F(NoiseSymmetricStateTest, Split) {
    NoiseSymmetricState ss;
    ss.initialize_symmetric(NOISE_PROTOCOL_NAME);
    
    // Mix in some key material
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    ss.mix_key(key, 32);
    
    NoiseCipherState c1, c2;
    ss.split(c1, c2);
    
    EXPECT_TRUE(c1.has_key());
    EXPECT_TRUE(c2.has_key());
}

// =============================================================================
// NoiseHandshakeState Tests
// =============================================================================

class NoiseHandshakeStateTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(NoiseHandshakeStateTest, Initialize) {
    NoiseHandshakeState hs;
    NoiseError err = hs.initialize(true); // initiator
    
    EXPECT_EQ(err, NoiseError::OK);
    EXPECT_FALSE(hs.is_handshake_complete());
}

TEST_F(NoiseHandshakeStateTest, XXPatternFullHandshake) {
    // Create initiator and responder
    NoiseHandshakeState initiator;
    NoiseHandshakeState responder;
    
    NoiseError err = initiator.initialize(true);
    EXPECT_EQ(err, NoiseError::OK);
    
    err = responder.initialize(false);
    EXPECT_EQ(err, NoiseError::OK);
    
    uint8_t message[256];
    uint8_t payload[256];
    size_t msg_len, payload_len;
    
    // Message 0: Initiator -> Responder (e)
    msg_len = sizeof(message);
    err = initiator.write_message(nullptr, 0, message, &msg_len);
    EXPECT_EQ(err, NoiseError::OK);
    EXPECT_GT(msg_len, 0u);
    
    payload_len = sizeof(payload);
    err = responder.read_message(message, msg_len, payload, &payload_len);
    EXPECT_EQ(err, NoiseError::OK);
    
    // Message 1: Responder -> Initiator (e, ee, s, es)
    msg_len = sizeof(message);
    err = responder.write_message(nullptr, 0, message, &msg_len);
    EXPECT_EQ(err, NoiseError::OK);
    EXPECT_GT(msg_len, 0u);
    
    payload_len = sizeof(payload);
    err = initiator.read_message(message, msg_len, payload, &payload_len);
    EXPECT_EQ(err, NoiseError::OK);
    
    // Message 2: Initiator -> Responder (s, se)
    msg_len = sizeof(message);
    err = initiator.write_message(nullptr, 0, message, &msg_len);
    EXPECT_EQ(err, NoiseError::OK);
    EXPECT_GT(msg_len, 0u);
    
    // Initiator should be done after sending message 2
    EXPECT_TRUE(initiator.is_handshake_complete());
    
    payload_len = sizeof(payload);
    err = responder.read_message(message, msg_len, payload, &payload_len);
    EXPECT_EQ(err, NoiseError::OK);
    
    // Responder should be done after receiving message 2
    EXPECT_TRUE(responder.is_handshake_complete());
    
    // Both should have each other's static keys
    EXPECT_TRUE(initiator.has_remote_static());
    EXPECT_TRUE(responder.has_remote_static());
    
    // Check that keys match
    EXPECT_EQ(memcmp(
        initiator.get_remote_static_public(),
        responder.get_local_static_public(),
        32
    ), 0);
    
    EXPECT_EQ(memcmp(
        responder.get_remote_static_public(),
        initiator.get_local_static_public(),
        32
    ), 0);
}

TEST_F(NoiseHandshakeStateTest, SplitAndTransport) {
    // Complete handshake
    NoiseHandshakeState initiator;
    NoiseHandshakeState responder;
    
    initiator.initialize(true);
    responder.initialize(false);
    
    uint8_t message[256];
    uint8_t payload[256];
    size_t msg_len, payload_len;
    
    // Message 0
    msg_len = sizeof(message);
    initiator.write_message(nullptr, 0, message, &msg_len);
    payload_len = sizeof(payload);
    responder.read_message(message, msg_len, payload, &payload_len);
    
    // Message 1
    msg_len = sizeof(message);
    responder.write_message(nullptr, 0, message, &msg_len);
    payload_len = sizeof(payload);
    initiator.read_message(message, msg_len, payload, &payload_len);
    
    // Message 2
    msg_len = sizeof(message);
    initiator.write_message(nullptr, 0, message, &msg_len);
    payload_len = sizeof(payload);
    responder.read_message(message, msg_len, payload, &payload_len);
    
    // Split into transport ciphers
    NoiseCipherState initiator_send, initiator_recv;
    NoiseCipherState responder_send, responder_recv;
    
    NoiseError err = initiator.split(initiator_send, initiator_recv);
    EXPECT_EQ(err, NoiseError::OK);
    
    err = responder.split(responder_send, responder_recv);
    EXPECT_EQ(err, NoiseError::OK);
    
    // Test transport encryption
    const char* test_message = "Hello from initiator!";
    size_t test_len = strlen(test_message);
    
    std::vector<uint8_t> ciphertext(test_len + NOISE_TAG_SIZE);
    std::vector<uint8_t> decrypted(test_len);
    
    // Initiator sends, responder receives
    size_t ct_len = initiator_send.encrypt_with_ad(
        nullptr, 0,
        (const uint8_t*)test_message, test_len,
        ciphertext.data()
    );
    
    size_t pt_len = responder_recv.decrypt_with_ad(
        nullptr, 0,
        ciphertext.data(), ct_len,
        decrypted.data()
    );
    
    EXPECT_EQ(pt_len, test_len);
    EXPECT_EQ(memcmp(test_message, decrypted.data(), test_len), 0);
    
    // Responder sends, initiator receives
    const char* reply = "Hello from responder!";
    size_t reply_len = strlen(reply);
    
    ciphertext.resize(reply_len + NOISE_TAG_SIZE);
    decrypted.resize(reply_len);
    
    ct_len = responder_send.encrypt_with_ad(
        nullptr, 0,
        (const uint8_t*)reply, reply_len,
        ciphertext.data()
    );
    
    pt_len = initiator_recv.decrypt_with_ad(
        nullptr, 0,
        ciphertext.data(), ct_len,
        decrypted.data()
    );
    
    EXPECT_EQ(pt_len, reply_len);
    EXPECT_EQ(memcmp(reply, decrypted.data(), reply_len), 0);
}

TEST_F(NoiseHandshakeStateTest, HandshakeWithPrologue) {
    NoiseHandshakeState initiator;
    NoiseHandshakeState responder;
    
    const char* prologue = "librats/1.0";
    
    NoiseError err = initiator.initialize(true, nullptr, 
                                           (const uint8_t*)prologue, strlen(prologue));
    EXPECT_EQ(err, NoiseError::OK);
    
    err = responder.initialize(false, nullptr,
                               (const uint8_t*)prologue, strlen(prologue));
    EXPECT_EQ(err, NoiseError::OK);
    
    // Complete handshake
    uint8_t message[256];
    uint8_t payload[256];
    size_t msg_len, payload_len;
    
    msg_len = sizeof(message);
    initiator.write_message(nullptr, 0, message, &msg_len);
    payload_len = sizeof(payload);
    responder.read_message(message, msg_len, payload, &payload_len);
    
    msg_len = sizeof(message);
    responder.write_message(nullptr, 0, message, &msg_len);
    payload_len = sizeof(payload);
    initiator.read_message(message, msg_len, payload, &payload_len);
    
    msg_len = sizeof(message);
    initiator.write_message(nullptr, 0, message, &msg_len);
    payload_len = sizeof(payload);
    responder.read_message(message, msg_len, payload, &payload_len);
    
    EXPECT_TRUE(initiator.is_handshake_complete());
    EXPECT_TRUE(responder.is_handshake_complete());
}

// =============================================================================
// NoiseSession Tests
// =============================================================================

class NoiseSessionTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(NoiseSessionTest, FullSession) {
    NoiseSession initiator;
    NoiseSession responder;
    
    NoiseError err = initiator.start(true);
    EXPECT_EQ(err, NoiseError::OK);
    
    err = responder.start(false);
    EXPECT_EQ(err, NoiseError::OK);
    
    EXPECT_FALSE(initiator.is_handshake_complete());
    EXPECT_FALSE(responder.is_handshake_complete());
}

// =============================================================================
// Utility Function Tests
// =============================================================================

class NoiseUtilTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(NoiseUtilTest, GenerateKeypair) {
    NoiseKeyPair kp1, kp2;
    
    noise_generate_keypair(kp1);
    noise_generate_keypair(kp2);
    
    EXPECT_TRUE(kp1.has_keys);
    EXPECT_TRUE(kp2.has_keys);
    
    // Private keys should be different
    EXPECT_NE(memcmp(kp1.private_key, kp2.private_key, 32), 0);
    
    // Public keys should be different
    EXPECT_NE(memcmp(kp1.public_key, kp2.public_key, 32), 0);
}

TEST_F(NoiseUtilTest, DerivePublicKey) {
    NoiseKeyPair kp;
    noise_generate_keypair(kp);
    
    uint8_t derived_public[32];
    noise_derive_public_key(kp.private_key, derived_public);
    
    EXPECT_EQ(memcmp(kp.public_key, derived_public, 32), 0);
}

TEST_F(NoiseUtilTest, KeypairClear) {
    NoiseKeyPair kp;
    noise_generate_keypair(kp);
    
    EXPECT_TRUE(kp.has_keys);
    
    kp.clear();
    
    EXPECT_FALSE(kp.has_keys);
    
    // Private key should be zeroed
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (kp.private_key[i] != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_TRUE(all_zero);
}
