/*
 * Noise Protocol implementation for librats
 * Implements Noise_XX_25519_ChaChaPoly_SHA256
 * 
 * Based on the Noise Protocol Framework specification:
 * https://noiseprotocol.org/noise.html
 */

#ifndef RATS_NOISE_H
#define RATS_NOISE_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <memory>
#include <string>

namespace rats {

/* Constants */
constexpr size_t NOISE_KEY_SIZE = 32;
constexpr size_t NOISE_HASH_SIZE = 32;
constexpr size_t NOISE_DH_SIZE = 32;
constexpr size_t NOISE_TAG_SIZE = 16;
constexpr size_t NOISE_MAX_MESSAGE_SIZE = 65535;

/* Protocol name for Noise_XX_25519_ChaChaPoly_SHA256 */
constexpr const char* NOISE_PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_SHA256";

/**
 * Noise Protocol error codes
 */
enum class NoiseError {
    OK = 0,
    INVALID_STATE,
    DECRYPT_FAILED,
    MESSAGE_TOO_LARGE,
    HANDSHAKE_NOT_COMPLETE,
    HANDSHAKE_ALREADY_COMPLETE,
    INVALID_KEY,
    INTERNAL_ERROR
};

/**
 * CipherState - Manages transport-level encryption
 * 
 * Wraps ChaCha20-Poly1305 AEAD with automatic nonce management
 */
class NoiseCipherState {
public:
    NoiseCipherState();
    ~NoiseCipherState();
    
    /* Initialize with key */
    void initialize_key(const uint8_t key[NOISE_KEY_SIZE]);
    
    /* Check if key is set */
    bool has_key() const { return has_key_; }
    
    /* Get current nonce value */
    uint64_t get_nonce() const { return nonce_; }
    
    /* Set nonce (for testing/rekey) */
    void set_nonce(uint64_t n) { nonce_ = n; }
    
    /**
     * Encrypt with associated data
     * @param ad Associated data (not encrypted, but authenticated)
     * @param ad_len Length of associated data
     * @param plaintext Input plaintext
     * @param pt_len Length of plaintext
     * @param ciphertext Output buffer (must be pt_len + 16 bytes)
     * @return Length of ciphertext on success, 0 on failure
     */
    size_t encrypt_with_ad(
        const uint8_t* ad, size_t ad_len,
        const uint8_t* plaintext, size_t pt_len,
        uint8_t* ciphertext
    );
    
    /**
     * Decrypt with associated data
     * @param ad Associated data
     * @param ad_len Length of associated data
     * @param ciphertext Input ciphertext
     * @param ct_len Length of ciphertext
     * @param plaintext Output buffer (must be ct_len - 16 bytes)
     * @return Length of plaintext on success, 0 on failure
     */
    size_t decrypt_with_ad(
        const uint8_t* ad, size_t ad_len,
        const uint8_t* ciphertext, size_t ct_len,
        uint8_t* plaintext
    );
    
    /* Rekey the cipher state */
    void rekey();
    
    /* Clear sensitive data */
    void clear();

private:
    uint8_t key_[NOISE_KEY_SIZE];
    uint64_t nonce_;
    bool has_key_;
};

/**
 * SymmetricState - Manages handshake hash and chaining key
 */
class NoiseSymmetricState {
public:
    NoiseSymmetricState();
    ~NoiseSymmetricState();
    
    /**
     * Initialize with protocol name
     * Sets h and ck based on protocol name
     */
    void initialize_symmetric(const char* protocol_name);
    
    /**
     * Mix key material into chaining key and optionally cipher
     * Updates ck and optionally initializes cipher key
     */
    void mix_key(const uint8_t* input_key_material, size_t len);
    
    /**
     * Mix data into handshake hash
     */
    void mix_hash(const uint8_t* data, size_t len);
    
    /**
     * Encrypt plaintext and mix ciphertext into hash
     * @param plaintext Input plaintext
     * @param pt_len Length of plaintext
     * @param ciphertext Output buffer
     * @return Length of ciphertext on success, 0 on failure
     */
    size_t encrypt_and_hash(const uint8_t* plaintext, size_t pt_len, uint8_t* ciphertext);
    
    /**
     * Decrypt ciphertext and mix it into hash
     * @param ciphertext Input ciphertext
     * @param ct_len Length of ciphertext
     * @param plaintext Output buffer
     * @return Length of plaintext on success, 0 on failure
     */
    size_t decrypt_and_hash(const uint8_t* ciphertext, size_t ct_len, uint8_t* plaintext);
    
    /**
     * Split into two CipherState objects for transport phase
     * Returns (initiator_send_cipher, responder_send_cipher)
     */
    void split(NoiseCipherState& c1, NoiseCipherState& c2);
    
    /* Get current handshake hash (for channel binding) */
    const uint8_t* get_handshake_hash() const { return h_; }
    
    /* Clear sensitive data */
    void clear();
    
    /* Check if cipher has key (for handshake state) */
    bool cipher_has_key() const { return cipher_.has_key(); }

private:
    uint8_t ck_[NOISE_HASH_SIZE];  /* Chaining key */
    uint8_t h_[NOISE_HASH_SIZE];   /* Handshake hash */
    NoiseCipherState cipher_;
    
    friend class NoiseHandshakeState;
};

/**
 * NoiseKeyPair - Static or ephemeral DH key pair
 */
struct NoiseKeyPair {
    uint8_t private_key[NOISE_DH_SIZE];
    uint8_t public_key[NOISE_DH_SIZE];
    bool has_keys;
    
    NoiseKeyPair() : has_keys(false) {
        memset(private_key, 0, NOISE_DH_SIZE);
        memset(public_key, 0, NOISE_DH_SIZE);
    }
    
    void clear() {
        volatile uint8_t* p = private_key;
        for (size_t i = 0; i < NOISE_DH_SIZE; i++) p[i] = 0;
        memset(public_key, 0, NOISE_DH_SIZE);
        has_keys = false;
    }
    
    ~NoiseKeyPair() { clear(); }
};

/**
 * HandshakeState - Implements the XX handshake pattern
 * 
 * XX Pattern:
 *   -> e                           (initiator sends ephemeral public key)
 *   <- e, ee, s, es                (responder: ephemeral, DH, encrypted static)
 *   -> s, se                       (initiator: encrypted static, DH)
 */
class NoiseHandshakeState {
public:
    NoiseHandshakeState();
    ~NoiseHandshakeState();
    
    /**
     * Initialize as initiator or responder
     * @param is_initiator true if initiating the connection
     * @param static_keypair Pre-generated static key pair (optional, generates if null)
     * @param prologue Optional prologue data to mix into handshake
     * @param prologue_len Length of prologue
     */
    NoiseError initialize(
        bool is_initiator,
        const NoiseKeyPair* static_keypair = nullptr,
        const uint8_t* prologue = nullptr,
        size_t prologue_len = 0
    );
    
    /**
     * Write next handshake message
     * @param payload Optional payload to encrypt
     * @param payload_len Length of payload
     * @param message_out Output buffer for message
     * @param message_out_len Max size of output buffer, updated with actual size
     * @return NoiseError::OK on success
     */
    NoiseError write_message(
        const uint8_t* payload, size_t payload_len,
        uint8_t* message_out, size_t* message_out_len
    );
    
    /**
     * Read and process handshake message
     * @param message Input handshake message
     * @param message_len Length of message
     * @param payload_out Output buffer for decrypted payload
     * @param payload_out_len Max size of output buffer, updated with actual size
     * @return NoiseError::OK on success
     */
    NoiseError read_message(
        const uint8_t* message, size_t message_len,
        uint8_t* payload_out, size_t* payload_out_len
    );
    
    /**
     * Check if handshake is complete
     */
    bool is_handshake_complete() const { return handshake_complete_; }
    
    /**
     * Get transport ciphers after handshake completes
     * @param send_cipher Cipher for sending
     * @param recv_cipher Cipher for receiving
     * @return NoiseError::OK on success
     */
    NoiseError split(NoiseCipherState& send_cipher, NoiseCipherState& recv_cipher);
    
    /**
     * Get the remote peer's static public key (available after handshake)
     */
    const uint8_t* get_remote_static_public() const { return rs_.public_key; }
    bool has_remote_static() const { return rs_.has_keys; }
    
    /**
     * Get the local static public key
     */
    const uint8_t* get_local_static_public() const { return s_.public_key; }
    
    /**
     * Get handshake hash for channel binding
     */
    const uint8_t* get_handshake_hash() const { return symmetric_.get_handshake_hash(); }
    
    /**
     * Clear all sensitive data
     */
    void clear();

private:
    /* Generate ephemeral key pair */
    void generate_ephemeral();
    
    /* Perform DH and mix result into state */
    void mix_dh(const uint8_t* local_private, const uint8_t* remote_public);
    
    /* Write a public key to message */
    size_t write_e(uint8_t* out);
    size_t write_s(uint8_t* out);
    
    /* Read a public key from message */
    size_t read_e(const uint8_t* in, size_t len);
    size_t read_s(const uint8_t* in, size_t len);
    
    NoiseSymmetricState symmetric_;
    NoiseKeyPair s_;   /* Local static */
    NoiseKeyPair e_;   /* Local ephemeral */
    NoiseKeyPair rs_;  /* Remote static */
    NoiseKeyPair re_;  /* Remote ephemeral */
    
    bool is_initiator_;
    int message_index_;
    bool handshake_complete_;
    bool initialized_;
};

/**
 * NoiseSession - Complete encrypted session
 * 
 * Combines handshake and transport phases for easy use
 */
class NoiseSession {
public:
    NoiseSession();
    ~NoiseSession();
    
    /**
     * Start a new session
     * @param is_initiator true if initiating the connection
     * @param static_keypair Optional pre-generated static key pair
     */
    NoiseError start(bool is_initiator, const NoiseKeyPair* static_keypair = nullptr);
    
    /**
     * Process handshake - call repeatedly until is_handshake_complete()
     * @param received_message Received handshake message (nullptr for first initiator message)
     * @param received_len Length of received message
     * @param send_message Output buffer for message to send
     * @param send_len Max size of buffer, updated with actual size
     * @param need_to_send Set to true if there's a message to send
     * @return NoiseError::OK on success
     */
    NoiseError handshake_step(
        const uint8_t* received_message, size_t received_len,
        uint8_t* send_message, size_t* send_len,
        bool* need_to_send
    );
    
    /**
     * Check if handshake is complete
     */
    bool is_handshake_complete() const;
    
    /**
     * Encrypt a message for transport
     * @param plaintext Input data
     * @param pt_len Length of input
     * @param ciphertext Output buffer (must be pt_len + 16 bytes)
     * @return Length of ciphertext, 0 on error
     */
    size_t encrypt(const uint8_t* plaintext, size_t pt_len, uint8_t* ciphertext);
    
    /**
     * Decrypt a received message
     * @param ciphertext Input data
     * @param ct_len Length of input
     * @param plaintext Output buffer (must be ct_len - 16 bytes)
     * @return Length of plaintext, 0 on error
     */
    size_t decrypt(const uint8_t* ciphertext, size_t ct_len, uint8_t* plaintext);
    
    /**
     * Get remote peer's static public key
     */
    const uint8_t* get_remote_static_public() const;
    
    /**
     * Get handshake hash for channel binding
     */
    std::vector<uint8_t> get_handshake_hash() const;
    
    /**
     * Clear sensitive data
     */
    void clear();

private:
    NoiseHandshakeState handshake_;
    NoiseCipherState send_cipher_;
    NoiseCipherState recv_cipher_;
    bool transport_ready_;
};

/* Utility functions */

/**
 * Generate a new static key pair
 * @param keypair Output key pair
 */
void noise_generate_keypair(NoiseKeyPair& keypair);

/**
 * Derive public key from private key
 * @param private_key 32-byte private key
 * @param public_key Output 32-byte public key
 */
void noise_derive_public_key(const uint8_t private_key[NOISE_DH_SIZE], 
                             uint8_t public_key[NOISE_DH_SIZE]);

} /* namespace rats */

#endif /* RATS_NOISE_H */
