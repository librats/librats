/*
 * Noise Protocol implementation for librats
 * Implements Noise_XX_25519_ChaChaPoly_SHA256
 */

#include "noise.h"
#include "logger.h"
#include <cstring>
#include <random>
#include <iomanip>
#include <sstream>

extern "C" {
#include "crypto/chachapoly.h"
#include "crypto/hkdf.h"
#include "crypto/sha256.h"
#include "crypto/curve25519.h"
}

// Noise Protocol logging macros
#define LOG_NOISE_DEBUG(message) LOG_DEBUG("noise", message)
#define LOG_NOISE_INFO(message)  LOG_INFO("noise", message)
#define LOG_NOISE_WARN(message)  LOG_WARN("noise", message)
#define LOG_NOISE_ERROR(message) LOG_ERROR("noise", message)

namespace rats {

/* Helper to format public key prefix for logging (first 8 hex chars) */
static std::string format_key_prefix(const uint8_t* key) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 4; i++) {
        oss << std::setw(2) << static_cast<int>(key[i]);
    }
    return oss.str();
}

/* Secure memory zeroing */
static void secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

/* Generate random bytes using platform CSPRNG */
static void generate_random_bytes(uint8_t* output, size_t len) {
    std::random_device rd;
    for (size_t i = 0; i < len; i++) {
        output[i] = static_cast<uint8_t>(rd());
    }
}

/* Create 12-byte nonce from 64-bit counter */
static void make_nonce(uint8_t nonce[12], uint64_t n) {
    memset(nonce, 0, 4);
    nonce[4] = static_cast<uint8_t>(n);
    nonce[5] = static_cast<uint8_t>(n >> 8);
    nonce[6] = static_cast<uint8_t>(n >> 16);
    nonce[7] = static_cast<uint8_t>(n >> 24);
    nonce[8] = static_cast<uint8_t>(n >> 32);
    nonce[9] = static_cast<uint8_t>(n >> 40);
    nonce[10] = static_cast<uint8_t>(n >> 48);
    nonce[11] = static_cast<uint8_t>(n >> 56);
}

/* ========== NoiseCipherState Implementation ========== */

NoiseCipherState::NoiseCipherState() : nonce_(0), has_key_(false) {
    memset(key_, 0, NOISE_KEY_SIZE);
}

NoiseCipherState::~NoiseCipherState() {
    clear();
}

void NoiseCipherState::initialize_key(const uint8_t key[NOISE_KEY_SIZE]) {
    memcpy(key_, key, NOISE_KEY_SIZE);
    nonce_ = 0;
    has_key_ = true;
    LOG_NOISE_DEBUG("CipherState key initialized, nonce reset to 0");
}

size_t NoiseCipherState::encrypt_with_ad(
    const uint8_t* ad, size_t ad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext
) {
    if (!has_key_) {
        /* If no key, just copy plaintext (for initial handshake messages) */
        memcpy(ciphertext, plaintext, pt_len);
        LOG_NOISE_DEBUG("Encrypt passthrough (no key): " << pt_len << " bytes");
        return pt_len;
    }
    
    uint8_t nonce[12];
    make_nonce(nonce, nonce_);
    
    size_t result = chachapoly_encrypt(
        key_, nonce,
        ad, ad_len,
        plaintext, pt_len,
        ciphertext
    );
    
    if (result > 0) {
        nonce_++;
        LOG_NOISE_DEBUG("Encrypted " << pt_len << " bytes -> " << result << " bytes (nonce: " << nonce_ << ")");
    } else {
        LOG_NOISE_ERROR("Encryption failed for " << pt_len << " bytes");
    }
    
    return result;
}

size_t NoiseCipherState::decrypt_with_ad(
    const uint8_t* ad, size_t ad_len,
    const uint8_t* ciphertext, size_t ct_len,
    uint8_t* plaintext
) {
    if (!has_key_) {
        /* If no key, just copy ciphertext */
        memcpy(plaintext, ciphertext, ct_len);
        LOG_NOISE_DEBUG("Decrypt passthrough (no key): " << ct_len << " bytes");
        return ct_len;
    }
    
    if (ct_len < NOISE_TAG_SIZE) {
        LOG_NOISE_ERROR("Ciphertext too small: " << ct_len << " bytes (min: " << NOISE_TAG_SIZE << ")");
        return 0;
    }
    
    uint8_t nonce[12];
    make_nonce(nonce, nonce_);
    
    size_t result = chachapoly_decrypt(
        key_, nonce,
        ad, ad_len,
        ciphertext, ct_len,
        plaintext
    );
    
    if (result > 0) {
        nonce_++;
        LOG_NOISE_DEBUG("Decrypted " << ct_len << " bytes -> " << result << " bytes (nonce: " << nonce_ << ")");
    } else {
        LOG_NOISE_ERROR("Decryption failed for " << ct_len << " bytes - authentication failed");
    }
    
    return result;
}

void NoiseCipherState::rekey() {
    if (!has_key_) {
        LOG_NOISE_WARN("Rekey called but no key is set");
        return;
    }
    
    uint8_t zeros[NOISE_KEY_SIZE] = {0};
    uint8_t new_key[NOISE_KEY_SIZE + NOISE_TAG_SIZE];
    
    uint8_t nonce[12];
    /* Use max nonce value for rekey */
    memset(nonce, 0xFF, 12);
    
    chachapoly_encrypt(key_, nonce, nullptr, 0, zeros, NOISE_KEY_SIZE, new_key);
    
    memcpy(key_, new_key, NOISE_KEY_SIZE);
    secure_zero(new_key, sizeof(new_key));
    
    LOG_NOISE_INFO("CipherState rekeyed successfully");
}

void NoiseCipherState::clear() {
    secure_zero(key_, NOISE_KEY_SIZE);
    nonce_ = 0;
    has_key_ = false;
}

/* ========== NoiseSymmetricState Implementation ========== */

NoiseSymmetricState::NoiseSymmetricState() {
    memset(ck_, 0, NOISE_HASH_SIZE);
    memset(h_, 0, NOISE_HASH_SIZE);
}

NoiseSymmetricState::~NoiseSymmetricState() {
    clear();
}

void NoiseSymmetricState::initialize_symmetric(const char* protocol_name) {
    size_t name_len = strlen(protocol_name);
    
    if (name_len <= NOISE_HASH_SIZE) {
        /* If protocol name fits in hash size, pad with zeros */
        memset(h_, 0, NOISE_HASH_SIZE);
        memcpy(h_, protocol_name, name_len);
    } else {
        /* Otherwise, hash the protocol name */
        sha256_hash(h_, protocol_name, name_len);
    }
    
    /* ck = h */
    memcpy(ck_, h_, NOISE_HASH_SIZE);
    
    LOG_NOISE_INFO("SymmetricState initialized with protocol: " << protocol_name);
}

void NoiseSymmetricState::mix_key(const uint8_t* input_key_material, size_t len) {
    uint8_t temp_k[NOISE_KEY_SIZE];
    
    /* HKDF(ck, input_key_material) -> (new_ck, temp_k) */
    noise_hkdf_2(ck_, input_key_material, len, ck_, temp_k);
    
    /* Initialize cipher with temp_k */
    cipher_.initialize_key(temp_k);
    
    secure_zero(temp_k, NOISE_KEY_SIZE);
    
    LOG_NOISE_DEBUG("MixKey: derived new chaining key and cipher key from " << len << " bytes");
}

void NoiseSymmetricState::mix_hash(const uint8_t* data, size_t len) {
    /* h = SHA256(h || data) */
    sha256_context_t ctx;
    sha256_reset(&ctx);
    sha256_update(&ctx, h_, NOISE_HASH_SIZE);
    sha256_update(&ctx, data, len);
    sha256_finish(&ctx, h_);
    
    LOG_NOISE_DEBUG("MixHash: mixed " << len << " bytes into handshake hash");
}

size_t NoiseSymmetricState::encrypt_and_hash(const uint8_t* plaintext, size_t pt_len, uint8_t* ciphertext) {
    size_t ct_len;
    
    /* Encrypt with h as AD */
    ct_len = cipher_.encrypt_with_ad(h_, NOISE_HASH_SIZE, plaintext, pt_len, ciphertext);
    
    /* Mix ciphertext into hash */
    mix_hash(ciphertext, ct_len);
    
    return ct_len;
}

size_t NoiseSymmetricState::decrypt_and_hash(const uint8_t* ciphertext, size_t ct_len, uint8_t* plaintext) {
    /* Save ciphertext for mixing (before decryption modifies anything) */
    /* Mix ciphertext into hash first */
    uint8_t h_backup[NOISE_HASH_SIZE];
    memcpy(h_backup, h_, NOISE_HASH_SIZE);
    mix_hash(ciphertext, ct_len);
    
    /* Decrypt with old h as AD */
    size_t pt_len = cipher_.decrypt_with_ad(h_backup, NOISE_HASH_SIZE, ciphertext, ct_len, plaintext);
    
    secure_zero(h_backup, NOISE_HASH_SIZE);
    
    return pt_len;
}

void NoiseSymmetricState::split(NoiseCipherState& c1, NoiseCipherState& c2) {
    uint8_t temp_k1[NOISE_KEY_SIZE];
    uint8_t temp_k2[NOISE_KEY_SIZE];
    
    /* HKDF(ck, empty) -> (temp_k1, temp_k2) */
    noise_hkdf_2(ck_, nullptr, 0, temp_k1, temp_k2);
    
    c1.initialize_key(temp_k1);
    c2.initialize_key(temp_k2);
    
    secure_zero(temp_k1, NOISE_KEY_SIZE);
    secure_zero(temp_k2, NOISE_KEY_SIZE);
    
    LOG_NOISE_INFO("SymmetricState split into two transport CipherStates");
}

void NoiseSymmetricState::clear() {
    secure_zero(ck_, NOISE_HASH_SIZE);
    secure_zero(h_, NOISE_HASH_SIZE);
    cipher_.clear();
}

/* ========== NoiseHandshakeState Implementation ========== */

NoiseHandshakeState::NoiseHandshakeState()
    : is_initiator_(false)
    , message_index_(0)
    , handshake_complete_(false)
    , initialized_(false)
{
}

NoiseHandshakeState::~NoiseHandshakeState() {
    clear();
}

void NoiseHandshakeState::generate_ephemeral() {
    generate_random_bytes(e_.private_key, NOISE_DH_SIZE);
    
    /* Clamp private key for X25519 */
    e_.private_key[0] &= 248;
    e_.private_key[31] &= 127;
    e_.private_key[31] |= 64;
    
    /* Derive public key */
    curve25519_donna(e_.public_key, e_.private_key, curve25519_basepoint);
    e_.has_keys = true;
    
    LOG_NOISE_DEBUG("Generated ephemeral keypair (pub: " << format_key_prefix(e_.public_key) << "...)");
}

void NoiseHandshakeState::mix_dh(const uint8_t* local_private, const uint8_t* remote_public) {
    uint8_t dh_output[NOISE_DH_SIZE];
    
    curve25519_donna(dh_output, local_private, remote_public);
    symmetric_.mix_key(dh_output, NOISE_DH_SIZE);
    
    secure_zero(dh_output, NOISE_DH_SIZE);
    
    LOG_NOISE_DEBUG("DH exchange performed with remote key: " << format_key_prefix(remote_public) << "...");
}

size_t NoiseHandshakeState::write_e(uint8_t* out) {
    if (!e_.has_keys) {
        generate_ephemeral();
    }
    
    memcpy(out, e_.public_key, NOISE_DH_SIZE);
    symmetric_.mix_hash(e_.public_key, NOISE_DH_SIZE);
    
    LOG_NOISE_DEBUG("Wrote ephemeral public key: " << format_key_prefix(e_.public_key) << "...");
    return NOISE_DH_SIZE;
}

size_t NoiseHandshakeState::write_s(uint8_t* out) {
    /* Encrypt static public key */
    size_t len = symmetric_.encrypt_and_hash(s_.public_key, NOISE_DH_SIZE, out);
    LOG_NOISE_DEBUG("Wrote encrypted static public key: " << format_key_prefix(s_.public_key) << "... (" << len << " bytes)");
    return len;
}

size_t NoiseHandshakeState::read_e(const uint8_t* in, size_t len) {
    if (len < NOISE_DH_SIZE) {
        LOG_NOISE_ERROR("Read ephemeral failed: input too short (" << len << " < " << NOISE_DH_SIZE << ")");
        return 0;
    }
    
    memcpy(re_.public_key, in, NOISE_DH_SIZE);
    re_.has_keys = true;
    symmetric_.mix_hash(re_.public_key, NOISE_DH_SIZE);
    
    LOG_NOISE_DEBUG("Read remote ephemeral public key: " << format_key_prefix(re_.public_key) << "...");
    return NOISE_DH_SIZE;
}

size_t NoiseHandshakeState::read_s(const uint8_t* in, size_t len) {
    size_t expected_len = NOISE_DH_SIZE;
    
    /* If cipher has key, expect encrypted (with tag) */
    if (symmetric_.cipher_has_key()) {
        expected_len += NOISE_TAG_SIZE;
    }
    
    if (len < expected_len) {
        LOG_NOISE_ERROR("Read static failed: input too short (" << len << " < " << expected_len << ")");
        return 0;
    }
    
    size_t pt_len = symmetric_.decrypt_and_hash(in, expected_len, rs_.public_key);
    if (pt_len != NOISE_DH_SIZE) {
        LOG_NOISE_ERROR("Read static failed: decryption returned " << pt_len << " bytes (expected " << NOISE_DH_SIZE << ")");
        return 0;
    }
    
    rs_.has_keys = true;
    LOG_NOISE_DEBUG("Read remote static public key: " << format_key_prefix(rs_.public_key) << "...");
    return expected_len;
}

NoiseError NoiseHandshakeState::initialize(
    bool is_initiator,
    const NoiseKeyPair* static_keypair,
    const uint8_t* prologue,
    size_t prologue_len
) {
    is_initiator_ = is_initiator;
    message_index_ = 0;
    handshake_complete_ = false;
    
    LOG_NOISE_INFO("HandshakeState initializing as " << (is_initiator ? "initiator" : "responder"));
    
    /* Initialize symmetric state with protocol name */
    symmetric_.initialize_symmetric(NOISE_PROTOCOL_NAME);
    
    /* Mix in prologue if provided */
    if (prologue != nullptr && prologue_len > 0) {
        symmetric_.mix_hash(prologue, prologue_len);
        LOG_NOISE_DEBUG("Mixed prologue into handshake hash: " << prologue_len << " bytes");
    }
    
    /* Set up static key pair */
    if (static_keypair != nullptr && static_keypair->has_keys) {
        memcpy(s_.private_key, static_keypair->private_key, NOISE_DH_SIZE);
        memcpy(s_.public_key, static_keypair->public_key, NOISE_DH_SIZE);
        s_.has_keys = true;
        LOG_NOISE_DEBUG("Using provided static keypair (pub: " << format_key_prefix(s_.public_key) << "...)");
    } else {
        /* Generate new static key pair */
        noise_generate_keypair(s_);
        LOG_NOISE_DEBUG("Generated new static keypair (pub: " << format_key_prefix(s_.public_key) << "...)");
    }
    
    initialized_ = true;
    LOG_NOISE_INFO("HandshakeState initialized successfully");
    return NoiseError::OK;
}

NoiseError NoiseHandshakeState::write_message(
    const uint8_t* payload, size_t payload_len,
    uint8_t* message_out, size_t* message_out_len
) {
    if (!initialized_) {
        LOG_NOISE_ERROR("write_message called on uninitialized handshake state");
        return NoiseError::INVALID_STATE;
    }
    
    if (handshake_complete_) {
        LOG_NOISE_ERROR("write_message called but handshake already complete");
        return NoiseError::HANDSHAKE_ALREADY_COMPLETE;
    }
    
    LOG_NOISE_DEBUG("Writing handshake message " << message_index_ << " (" << (is_initiator_ ? "initiator" : "responder") << ")");
    
    size_t offset = 0;
    size_t max_len = *message_out_len;
    
    /*
     * XX Pattern:
     *   -> e                           (message 0, initiator)
     *   <- e, ee, s, es                (message 1, responder)
     *   -> s, se                       (message 2, initiator)
     */
    
    if (is_initiator_) {
        if (message_index_ == 0) {
            /* -> e */
            if (max_len < NOISE_DH_SIZE) {
                LOG_NOISE_ERROR("Buffer too small for message 0");
                return NoiseError::MESSAGE_TOO_LARGE;
            }
            LOG_NOISE_DEBUG("Message 0: -> e");
            offset += write_e(message_out + offset);
        }
        else if (message_index_ == 2) {
            /* -> s, se */
            size_t s_len = NOISE_DH_SIZE + NOISE_TAG_SIZE;  /* encrypted static */
            if (max_len < s_len) {
                LOG_NOISE_ERROR("Buffer too small for message 2");
                return NoiseError::MESSAGE_TOO_LARGE;
            }
            
            LOG_NOISE_DEBUG("Message 2: -> s, se");
            offset += write_s(message_out + offset);
            
            /* se: DH(s, re) */
            mix_dh(s_.private_key, re_.public_key);
            
            handshake_complete_ = true;
            LOG_NOISE_INFO("Handshake complete (initiator)");
        }
    } else {
        if (message_index_ == 1) {
            /* <- e, ee, s, es */
            size_t needed = NOISE_DH_SIZE + NOISE_DH_SIZE + NOISE_TAG_SIZE;
            if (max_len < needed) {
                LOG_NOISE_ERROR("Buffer too small for message 1");
                return NoiseError::MESSAGE_TOO_LARGE;
            }
            
            LOG_NOISE_DEBUG("Message 1: <- e, ee, s, es");
            
            /* e: send ephemeral */
            offset += write_e(message_out + offset);
            
            /* ee: DH(e, re) */
            mix_dh(e_.private_key, re_.public_key);
            
            /* s: send encrypted static */
            offset += write_s(message_out + offset);
            
            /* es: DH(e, rs) - but rs is not known yet for responder */
            /* Actually for XX, responder knows re from initiator's first message */
            /* es should be DH(local_static, remote_ephemeral) for responder */
            mix_dh(s_.private_key, re_.public_key);
        }
    }
    
    /* Add payload if provided */
    if (payload != nullptr && payload_len > 0) {
        if (offset + payload_len + (symmetric_.cipher_.has_key() ? NOISE_TAG_SIZE : 0) > max_len) {
            LOG_NOISE_ERROR("Buffer too small for payload");
            return NoiseError::MESSAGE_TOO_LARGE;
        }
        offset += symmetric_.encrypt_and_hash(payload, payload_len, message_out + offset);
        LOG_NOISE_DEBUG("Encrypted payload: " << payload_len << " bytes");
    }
    
    *message_out_len = offset;
    message_index_++;
    
    LOG_NOISE_DEBUG("Handshake message written: " << offset << " bytes");
    
    return NoiseError::OK;
}

NoiseError NoiseHandshakeState::read_message(
    const uint8_t* message, size_t message_len,
    uint8_t* payload_out, size_t* payload_out_len
) {
    if (!initialized_) {
        LOG_NOISE_ERROR("read_message called on uninitialized handshake state");
        return NoiseError::INVALID_STATE;
    }
    
    if (handshake_complete_) {
        LOG_NOISE_ERROR("read_message called but handshake already complete");
        return NoiseError::HANDSHAKE_ALREADY_COMPLETE;
    }
    
    LOG_NOISE_DEBUG("Reading handshake message " << message_index_ << " (" << (is_initiator_ ? "initiator" : "responder") << "): " << message_len << " bytes");
    
    size_t offset = 0;
    size_t consumed;
    
    if (is_initiator_) {
        if (message_index_ == 1) {
            /* Receive: <- e, ee, s, es */
            LOG_NOISE_DEBUG("Message 1: <- e, ee, s, es");
            
            /* e: read remote ephemeral */
            consumed = read_e(message + offset, message_len - offset);
            if (consumed == 0) {
                LOG_NOISE_ERROR("Failed to read remote ephemeral in message 1");
                return NoiseError::DECRYPT_FAILED;
            }
            offset += consumed;
            
            /* ee: DH(e, re) */
            mix_dh(e_.private_key, re_.public_key);
            
            /* s: read encrypted remote static */
            consumed = read_s(message + offset, message_len - offset);
            if (consumed == 0) {
                LOG_NOISE_ERROR("Failed to read remote static in message 1");
                return NoiseError::DECRYPT_FAILED;
            }
            offset += consumed;
            
            /* es: DH(e, rs) */
            mix_dh(e_.private_key, rs_.public_key);
        }
    } else {
        if (message_index_ == 0) {
            /* Receive: -> e */
            LOG_NOISE_DEBUG("Message 0: -> e");
            consumed = read_e(message + offset, message_len - offset);
            if (consumed == 0) {
                LOG_NOISE_ERROR("Failed to read remote ephemeral in message 0");
                return NoiseError::DECRYPT_FAILED;
            }
            offset += consumed;
        }
        else if (message_index_ == 2) {
            /* Receive: -> s, se */
            LOG_NOISE_DEBUG("Message 2: -> s, se");
            
            /* s: read encrypted remote static */
            consumed = read_s(message + offset, message_len - offset);
            if (consumed == 0) {
                LOG_NOISE_ERROR("Failed to read remote static in message 2");
                return NoiseError::DECRYPT_FAILED;
            }
            offset += consumed;
            
            /* se: DH(e, rs) */
            mix_dh(e_.private_key, rs_.public_key);
            
            handshake_complete_ = true;
            LOG_NOISE_INFO("Handshake complete (responder)");
        }
    }
    
    /* Decrypt payload if there's remaining data */
    if (offset < message_len) {
        size_t remaining = message_len - offset;
        size_t pt_len = symmetric_.decrypt_and_hash(message + offset, remaining, payload_out);
        if (pt_len == 0 && remaining > 0) {
            LOG_NOISE_ERROR("Failed to decrypt payload in handshake message");
            return NoiseError::DECRYPT_FAILED;
        }
        *payload_out_len = pt_len;
        LOG_NOISE_DEBUG("Decrypted payload: " << pt_len << " bytes");
    } else {
        *payload_out_len = 0;
    }
    
    message_index_++;
    LOG_NOISE_DEBUG("Handshake message processed successfully");
    
    return NoiseError::OK;
}

NoiseError NoiseHandshakeState::split(NoiseCipherState& send_cipher, NoiseCipherState& recv_cipher) {
    if (!handshake_complete_) {
        LOG_NOISE_ERROR("split() called but handshake not complete");
        return NoiseError::HANDSHAKE_NOT_COMPLETE;
    }
    
    NoiseCipherState c1, c2;
    symmetric_.split(c1, c2);
    
    if (is_initiator_) {
        /* Initiator: c1 is for sending, c2 is for receiving */
        send_cipher = std::move(c1);
        recv_cipher = std::move(c2);
        LOG_NOISE_INFO("HandshakeState split: initiator (c1=send, c2=recv)");
    } else {
        /* Responder: c2 is for sending, c1 is for receiving */
        send_cipher = std::move(c2);
        recv_cipher = std::move(c1);
        LOG_NOISE_INFO("HandshakeState split: responder (c2=send, c1=recv)");
    }
    
    return NoiseError::OK;
}

void NoiseHandshakeState::clear() {
    symmetric_.clear();
    s_.clear();
    e_.clear();
    rs_.clear();
    re_.clear();
    is_initiator_ = false;
    message_index_ = 0;
    handshake_complete_ = false;
    initialized_ = false;
}

/* ========== NoiseSession Implementation ========== */

NoiseSession::NoiseSession() : transport_ready_(false) {}

NoiseSession::~NoiseSession() {
    clear();
}

NoiseError NoiseSession::start(bool is_initiator, const NoiseKeyPair* static_keypair) {
    LOG_NOISE_INFO("Session starting as " << (is_initiator ? "initiator" : "responder"));
    transport_ready_ = false;
    NoiseError err = handshake_.initialize(is_initiator, static_keypair);
    if (err != NoiseError::OK) {
        LOG_NOISE_ERROR("Session start failed: " << static_cast<int>(err));
    }
    return err;
}

NoiseError NoiseSession::handshake_step(
    const uint8_t* received_message, size_t received_len,
    uint8_t* send_message, size_t* send_len,
    bool* need_to_send
) {
    if (transport_ready_) {
        LOG_NOISE_WARN("handshake_step called but transport already ready");
        return NoiseError::HANDSHAKE_ALREADY_COMPLETE;
    }
    
    LOG_NOISE_DEBUG("Session handshake step (received: " << received_len << " bytes)");
    
    NoiseError err;
    uint8_t payload_buf[256];
    size_t payload_len = sizeof(payload_buf);
    
    *need_to_send = false;
    
    /* If we received a message, process it */
    if (received_message != nullptr && received_len > 0) {
        err = handshake_.read_message(received_message, received_len, payload_buf, &payload_len);
        if (err != NoiseError::OK) {
            LOG_NOISE_ERROR("Session handshake step: read_message failed with error " << static_cast<int>(err));
            return err;
        }
    }
    
    /* If handshake is not complete and it's our turn, write a message */
    if (!handshake_.is_handshake_complete()) {
        bool is_initiator = (handshake_.get_local_static_public() != nullptr);
        (void)is_initiator; // Used for documentation purposes
        
        /* Determine if it's our turn to send:
         * Initiator sends on message_index 0, 2
         * Responder sends on message_index 1
         */
        err = handshake_.write_message(nullptr, 0, send_message, send_len);
        if (err == NoiseError::OK) {
            *need_to_send = true;
            LOG_NOISE_DEBUG("Session handshake step: message to send (" << *send_len << " bytes)");
        }
    }
    
    /* Check if handshake completed */
    if (handshake_.is_handshake_complete()) {
        err = handshake_.split(send_cipher_, recv_cipher_);
        if (err != NoiseError::OK) {
            LOG_NOISE_ERROR("Session handshake step: split failed with error " << static_cast<int>(err));
            return err;
        }
        transport_ready_ = true;
        LOG_NOISE_INFO("Session transport ready - handshake complete");
    }
    
    return NoiseError::OK;
}

bool NoiseSession::is_handshake_complete() const {
    return transport_ready_;
}

size_t NoiseSession::encrypt(const uint8_t* plaintext, size_t pt_len, uint8_t* ciphertext) {
    if (!transport_ready_) {
        LOG_NOISE_ERROR("Session encrypt called but transport not ready");
        return 0;
    }
    
    size_t result = send_cipher_.encrypt_with_ad(nullptr, 0, plaintext, pt_len, ciphertext);
    if (result > 0) {
        LOG_NOISE_DEBUG("Session encrypted " << pt_len << " bytes -> " << result << " bytes");
    }
    return result;
}

size_t NoiseSession::decrypt(const uint8_t* ciphertext, size_t ct_len, uint8_t* plaintext) {
    if (!transport_ready_) {
        LOG_NOISE_ERROR("Session decrypt called but transport not ready");
        return 0;
    }
    
    size_t result = recv_cipher_.decrypt_with_ad(nullptr, 0, ciphertext, ct_len, plaintext);
    if (result > 0) {
        LOG_NOISE_DEBUG("Session decrypted " << ct_len << " bytes -> " << result << " bytes");
    }
    return result;
}

const uint8_t* NoiseSession::get_remote_static_public() const {
    return handshake_.get_remote_static_public();
}

std::vector<uint8_t> NoiseSession::get_handshake_hash() const {
    const uint8_t* hash = handshake_.get_handshake_hash();
    return std::vector<uint8_t>(hash, hash + NOISE_HASH_SIZE);
}

void NoiseSession::clear() {
    handshake_.clear();
    send_cipher_.clear();
    recv_cipher_.clear();
    transport_ready_ = false;
}

/* ========== Utility Functions ========== */

void noise_generate_keypair(NoiseKeyPair& keypair) {
    generate_random_bytes(keypair.private_key, NOISE_DH_SIZE);
    
    /* Clamp for X25519 */
    keypair.private_key[0] &= 248;
    keypair.private_key[31] &= 127;
    keypair.private_key[31] |= 64;
    
    /* Derive public key */
    curve25519_donna(keypair.public_key, keypair.private_key, curve25519_basepoint);
    keypair.has_keys = true;
    
    LOG_NOISE_DEBUG("Generated static keypair (pub: " << format_key_prefix(keypair.public_key) << "...)");
}

void noise_derive_public_key(const uint8_t private_key[NOISE_DH_SIZE], 
                             uint8_t public_key[NOISE_DH_SIZE]) {
    uint8_t clamped[NOISE_DH_SIZE];
    memcpy(clamped, private_key, NOISE_DH_SIZE);
    
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    
    curve25519_donna(public_key, clamped, curve25519_basepoint);
    
    secure_zero(clamped, NOISE_DH_SIZE);
    
    LOG_NOISE_DEBUG("Derived public key from private key (pub: " << format_key_prefix(public_key) << "...)");
}

} /* namespace rats */
