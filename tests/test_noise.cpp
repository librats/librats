#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "noise.h"
#include "encrypted_socket.h"
#include <string>
#include <vector>

using namespace librats;

class NoiseTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup if needed
    }
    
    void TearDown() override {
        // Cleanup if needed
    }
};

// Test key generation
TEST_F(NoiseTest, KeyGenerationTest) {
    NoiseKey key1 = noise_utils::generate_static_keypair();
    NoiseKey key2 = noise_utils::generate_static_keypair();
    
    // Keys should not be all zeros
    bool key1_valid = false;
    bool key2_valid = false;
    
    for (uint8_t byte : key1) {
        if (byte != 0) {
            key1_valid = true;
            break;
        }
    }
    
    for (uint8_t byte : key2) {
        if (byte != 0) {
            key2_valid = true;
            break;
        }
    }
    
    EXPECT_TRUE(key1_valid);
    EXPECT_TRUE(key2_valid);
    
    // Keys should be different
    EXPECT_NE(key1, key2);
}

// Test key conversion
TEST_F(NoiseTest, KeyConversionTest) {
    NoiseKey original_key = noise_utils::generate_static_keypair();
    
    std::string key_hex = noise_utils::key_to_hex(original_key);
    EXPECT_EQ(key_hex.length(), NOISE_KEY_SIZE * 2); // 64 hex characters
    
    NoiseKey converted_key = noise_utils::hex_to_key(key_hex);
    EXPECT_EQ(original_key, converted_key);
}

// Test noise session initialization
TEST_F(NoiseTest, SessionInitializationTest) {
    NoiseKey initiator_key = noise_utils::generate_static_keypair();
    NoiseKey responder_key = noise_utils::generate_static_keypair();
    
    NoiseSession initiator_session;
    NoiseSession responder_session;
    
    EXPECT_TRUE(initiator_session.initialize_as_initiator(initiator_key));
    EXPECT_TRUE(responder_session.initialize_as_responder(responder_key));
    
    EXPECT_EQ(initiator_session.get_role(), NoiseRole::INITIATOR);
    EXPECT_EQ(responder_session.get_role(), NoiseRole::RESPONDER);
    
    EXPECT_FALSE(initiator_session.is_handshake_completed());
    EXPECT_FALSE(responder_session.is_handshake_completed());
    EXPECT_FALSE(initiator_session.has_handshake_failed());
    EXPECT_FALSE(responder_session.has_handshake_failed());
}

// Test noise handshake flow
TEST_F(NoiseTest, HandshakeFlowTest) {
    NoiseKey initiator_key = noise_utils::generate_static_keypair();
    NoiseKey responder_key = noise_utils::generate_static_keypair();
    
    NoiseSession initiator_session;
    NoiseSession responder_session;
    
    ASSERT_TRUE(initiator_session.initialize_as_initiator(initiator_key));
    ASSERT_TRUE(responder_session.initialize_as_responder(responder_key));
    
    // Message 1: Initiator -> Responder
    std::vector<uint8_t> msg1 = initiator_session.create_handshake_message();
    EXPECT_FALSE(msg1.empty());
    
    std::vector<uint8_t> payload1 = responder_session.process_handshake_message(msg1);
    EXPECT_FALSE(responder_session.has_handshake_failed());
    
    // Message 2: Responder -> Initiator
    std::vector<uint8_t> msg2 = responder_session.create_handshake_message();
    EXPECT_FALSE(msg2.empty());
    
    std::vector<uint8_t> payload2 = initiator_session.process_handshake_message(msg2);
    EXPECT_FALSE(initiator_session.has_handshake_failed());
    
    // Message 3: Initiator -> Responder
    std::vector<uint8_t> msg3 = initiator_session.create_handshake_message();
    EXPECT_FALSE(msg3.empty());
    
    std::vector<uint8_t> payload3 = responder_session.process_handshake_message(msg3);
    EXPECT_FALSE(responder_session.has_handshake_failed());
    
    // Both sessions should now be completed
    EXPECT_TRUE(initiator_session.is_handshake_completed());
    EXPECT_TRUE(responder_session.is_handshake_completed());
}

// Test encrypted communication after handshake
TEST_F(NoiseTest, EncryptedCommunicationTest) {
    NoiseKey initiator_key = noise_utils::generate_static_keypair();
    NoiseKey responder_key = noise_utils::generate_static_keypair();
    
    NoiseSession initiator_session;
    NoiseSession responder_session;
    
    ASSERT_TRUE(initiator_session.initialize_as_initiator(initiator_key));
    ASSERT_TRUE(responder_session.initialize_as_responder(responder_key));
    
    // Perform complete handshake
    auto msg1 = initiator_session.create_handshake_message();
    responder_session.process_handshake_message(msg1);
    
    auto msg2 = responder_session.create_handshake_message();
    initiator_session.process_handshake_message(msg2);
    
    auto msg3 = initiator_session.create_handshake_message();
    responder_session.process_handshake_message(msg3);
    
    ASSERT_TRUE(initiator_session.is_handshake_completed());
    ASSERT_TRUE(responder_session.is_handshake_completed());
    
    // Test encrypted communication
    std::string test_message = "Hello, encrypted world!";
    std::vector<uint8_t> plaintext(test_message.begin(), test_message.end());
    
    // Encrypt from initiator
    auto ciphertext = initiator_session.encrypt_transport_message(plaintext);
    EXPECT_FALSE(ciphertext.empty());
    EXPECT_NE(ciphertext.size(), plaintext.size()); // Should include authentication tag
    
    // Decrypt at responder
    auto decrypted = responder_session.decrypt_transport_message(ciphertext);
    EXPECT_FALSE(decrypted.empty());
    EXPECT_EQ(decrypted, plaintext);
    
    std::string decrypted_message(decrypted.begin(), decrypted.end());
    EXPECT_EQ(decrypted_message, test_message);
}

// Test encrypted socket utility functions
TEST_F(NoiseTest, EncryptedSocketUtilsTest) {
    NoiseKey key = EncryptedSocket::generate_static_key();
    
    // Test key validation
    bool key_valid = false;
    for (uint8_t byte : key) {
        if (byte != 0) {
            key_valid = true;
            break;
        }
    }
    EXPECT_TRUE(key_valid);
    
    // Test key string conversion
    std::string key_str = EncryptedSocket::key_to_string(key);
    EXPECT_EQ(key_str.length(), NOISE_KEY_SIZE * 2);
    
    NoiseKey converted_key = EncryptedSocket::string_to_key(key_str);
    EXPECT_EQ(key, converted_key);
}

// Test protocol name and utilities
TEST_F(NoiseTest, ProtocolUtilitiesTest) {
    std::string protocol_name = noise_utils::get_protocol_name();
    EXPECT_FALSE(protocol_name.empty());
    EXPECT_EQ(protocol_name, "Noise_XX_25519_ChaChaPoly_SHA256");
    
    EXPECT_TRUE(noise_utils::validate_message_size(1000));
    EXPECT_TRUE(noise_utils::validate_message_size(NOISE_MAX_MESSAGE_SIZE));
    EXPECT_FALSE(noise_utils::validate_message_size(NOISE_MAX_MESSAGE_SIZE + 1));
    
    // Test error strings
    EXPECT_EQ(noise_utils::noise_error_to_string(noise_utils::NoiseError::SUCCESS), "Success");
    EXPECT_EQ(noise_utils::noise_error_to_string(noise_utils::NoiseError::HANDSHAKE_FAILED), "Handshake failed");
} 