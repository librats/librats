#include "librats.h"
#include "logger.h"

#define LOG_CLIENT_DEBUG(message) LOG_DEBUG("client", message)
#define LOG_CLIENT_INFO(message)  LOG_INFO("client", message)
#define LOG_CLIENT_WARN(message)  LOG_WARN("client", message)
#define LOG_CLIENT_ERROR(message) LOG_ERROR("client", message)

namespace librats {

// =========================================================================
// Encryption Functionality - Noise Protocol Implementation
// =========================================================================

void RatsClient::initialize_noise_keypair() {
    std::lock_guard<std::mutex> lock(encryption_mutex_);
    if (!noise_keypair_initialized_) {
        rats::noise_generate_keypair(noise_static_keypair_);
        noise_keypair_initialized_ = true;
        LOG_CLIENT_INFO("Noise Protocol static keypair generated");
    }
}

bool RatsClient::initialize_encryption(bool enable) {
    std::lock_guard<std::mutex> lock(encryption_mutex_);
    encryption_enabled_ = enable;
    
    if (enable && !noise_keypair_initialized_) {
        rats::noise_generate_keypair(noise_static_keypair_);
        noise_keypair_initialized_ = true;
        LOG_CLIENT_INFO("Noise Protocol initialized with new static keypair");
    }
    
    LOG_CLIENT_INFO("Encryption " << (enable ? "enabled" : "disabled"));
    return true;
}

void RatsClient::set_encryption_enabled(bool enabled) {
    std::lock_guard<std::mutex> lock(encryption_mutex_);
    encryption_enabled_ = enabled;
    
    if (enabled && !noise_keypair_initialized_) {
        rats::noise_generate_keypair(noise_static_keypair_);
        noise_keypair_initialized_ = true;
    }
    
    LOG_CLIENT_DEBUG("Encryption set to " << (enabled ? "enabled" : "disabled"));
}

bool RatsClient::is_encryption_enabled() const {
    std::lock_guard<std::mutex> lock(encryption_mutex_);
    return encryption_enabled_;
}

bool RatsClient::is_peer_encrypted(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = peers_.find(peer_id);
    if (it != peers_.end()) {
        return it->second.noise_handshake_completed && 
               it->second.send_cipher && 
               it->second.recv_cipher;
    }
    return false;
}

bool RatsClient::set_noise_static_keypair(const uint8_t private_key[32]) {
    std::lock_guard<std::mutex> lock(encryption_mutex_);
    
    memcpy(noise_static_keypair_.private_key, private_key, 32);
    rats::noise_derive_public_key(private_key, noise_static_keypair_.public_key);
    noise_static_keypair_.has_keys = true;
    noise_keypair_initialized_ = true;
    
    LOG_CLIENT_INFO("Noise Protocol static keypair set from provided private key");
    return true;
}

std::vector<uint8_t> RatsClient::get_noise_static_public_key() const {
    std::lock_guard<std::mutex> lock(encryption_mutex_);
    
    if (!noise_keypair_initialized_) {
        return std::vector<uint8_t>();
    }
    
    return std::vector<uint8_t>(noise_static_keypair_.public_key, 
                                 noise_static_keypair_.public_key + 32);
}

std::vector<uint8_t> RatsClient::get_peer_noise_public_key(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = peers_.find(peer_id);
    if (it != peers_.end() && it->second.noise_handshake_completed) {
        return it->second.remote_static_key;
    }
    return std::vector<uint8_t>();
}

std::vector<uint8_t> RatsClient::get_peer_handshake_hash(const std::string& peer_id) const {
    // Handshake hash is not stored after handshake for memory efficiency
    // This could be added to RatsPeer if needed for channel binding
    (void)peer_id;
    return std::vector<uint8_t>();
}

bool RatsClient::send_noise_message(socket_t socket, const uint8_t* data, size_t len) {
    // Send length-prefixed message for Noise handshake
    uint32_t network_len = htonl(static_cast<uint32_t>(len));
    
    // Send length
    int sent = ::send(socket, reinterpret_cast<const char*>(&network_len), 4, 0);
    if (sent != 4) {
        LOG_CLIENT_ERROR("Failed to send Noise message length");
        return false;
    }
    
    // Send data
    sent = ::send(socket, reinterpret_cast<const char*>(data), static_cast<int>(len), 0);
    if (sent != static_cast<int>(len)) {
        LOG_CLIENT_ERROR("Failed to send Noise message data");
        return false;
    }
    
    return true;
}

bool RatsClient::recv_noise_message(socket_t socket, std::vector<uint8_t>& out_data, int timeout_ms) {
    // Set socket timeout (platform-specific)
#ifdef _WIN32
    // Windows: SO_RCVTIMEO expects DWORD (milliseconds)
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    // Unix: SO_RCVTIMEO expects struct timeval
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif
    
    // Receive length
    uint32_t network_len;
    int received = recv(socket, reinterpret_cast<char*>(&network_len), 4, MSG_WAITALL);
    if (received != 4) {
        LOG_CLIENT_ERROR("Failed to receive Noise message length");
        return false;
    }
    
    uint32_t len = ntohl(network_len);
    if (len > rats::NOISE_MAX_MESSAGE_SIZE) {
        LOG_CLIENT_ERROR("Noise message too large: " << len);
        return false;
    }
    
    // Receive data
    out_data.resize(len);
    received = recv(socket, reinterpret_cast<char*>(out_data.data()), static_cast<int>(len), MSG_WAITALL);
    if (received != static_cast<int>(len)) {
        LOG_CLIENT_ERROR("Failed to receive Noise message data");
        return false;
    }
    
    return true;
}

bool RatsClient::perform_noise_handshake(socket_t socket, const std::string& peer_id, bool is_initiator) {
    LOG_CLIENT_INFO("Starting Noise handshake with " << peer_id << " (initiator: " << is_initiator << ")");
    
    // Get our static keypair
    rats::NoiseKeyPair static_keypair;
    {
        std::lock_guard<std::mutex> lock(encryption_mutex_);
        if (!noise_keypair_initialized_) {
            rats::noise_generate_keypair(noise_static_keypair_);
            noise_keypair_initialized_ = true;
        }
        memcpy(static_keypair.private_key, noise_static_keypair_.private_key, 32);
        memcpy(static_keypair.public_key, noise_static_keypair_.public_key, 32);
        static_keypair.has_keys = true;
    }
    
    // Initialize handshake state
    rats::NoiseHandshakeState handshake;
    rats::NoiseError err = handshake.initialize(is_initiator, &static_keypair);
    if (err != rats::NoiseError::OK) {
        LOG_CLIENT_ERROR("Failed to initialize Noise handshake: " << static_cast<int>(err));
        return false;
    }
    
    uint8_t message_buf[256];
    size_t message_len;
    std::vector<uint8_t> received_data;
    uint8_t payload_buf[256];
    size_t payload_len;
    
    /*
     * XX Pattern:
     *   -> e                           (message 0, initiator sends)
     *   <- e, ee, s, es                (message 1, responder sends)
     *   -> s, se                       (message 2, initiator sends)
     */
    
    if (is_initiator) {
        // Message 0: -> e
        message_len = sizeof(message_buf);
        err = handshake.write_message(nullptr, 0, message_buf, &message_len);
        if (err != rats::NoiseError::OK) {
            LOG_CLIENT_ERROR("Failed to write Noise message 0");
            return false;
        }
        
        if (!send_noise_message(socket, message_buf, message_len)) {
            return false;
        }
        LOG_CLIENT_DEBUG("Sent Noise message 0 (e) - " << message_len << " bytes");
        
        // Receive message 1: <- e, ee, s, es
        if (!recv_noise_message(socket, received_data)) {
            return false;
        }
        LOG_CLIENT_DEBUG("Received Noise message 1 - " << received_data.size() << " bytes");
        
        payload_len = sizeof(payload_buf);
        err = handshake.read_message(received_data.data(), received_data.size(), payload_buf, &payload_len);
        if (err != rats::NoiseError::OK) {
            LOG_CLIENT_ERROR("Failed to read Noise message 1: " << static_cast<int>(err));
            return false;
        }
        
        // Message 2: -> s, se
        message_len = sizeof(message_buf);
        err = handshake.write_message(nullptr, 0, message_buf, &message_len);
        if (err != rats::NoiseError::OK) {
            LOG_CLIENT_ERROR("Failed to write Noise message 2");
            return false;
        }
        
        if (!send_noise_message(socket, message_buf, message_len)) {
            return false;
        }
        LOG_CLIENT_DEBUG("Sent Noise message 2 (s, se) - " << message_len << " bytes");
        
    } else {
        // Responder
        
        // Receive message 0: -> e
        if (!recv_noise_message(socket, received_data)) {
            return false;
        }
        LOG_CLIENT_DEBUG("Received Noise message 0 - " << received_data.size() << " bytes");
        
        payload_len = sizeof(payload_buf);
        err = handshake.read_message(received_data.data(), received_data.size(), payload_buf, &payload_len);
        if (err != rats::NoiseError::OK) {
            LOG_CLIENT_ERROR("Failed to read Noise message 0: " << static_cast<int>(err));
            return false;
        }
        
        // Message 1: <- e, ee, s, es
        message_len = sizeof(message_buf);
        err = handshake.write_message(nullptr, 0, message_buf, &message_len);
        if (err != rats::NoiseError::OK) {
            LOG_CLIENT_ERROR("Failed to write Noise message 1");
            return false;
        }
        
        if (!send_noise_message(socket, message_buf, message_len)) {
            return false;
        }
        LOG_CLIENT_DEBUG("Sent Noise message 1 (e, ee, s, es) - " << message_len << " bytes");
        
        // Receive message 2: -> s, se
        if (!recv_noise_message(socket, received_data)) {
            return false;
        }
        LOG_CLIENT_DEBUG("Received Noise message 2 - " << received_data.size() << " bytes");
        
        payload_len = sizeof(payload_buf);
        err = handshake.read_message(received_data.data(), received_data.size(), payload_buf, &payload_len);
        if (err != rats::NoiseError::OK) {
            LOG_CLIENT_ERROR("Failed to read Noise message 2: " << static_cast<int>(err));
            return false;
        }
    }
    
    // Handshake should be complete now
    if (!handshake.is_handshake_complete()) {
        LOG_CLIENT_ERROR("Noise handshake not complete after all messages");
        return false;
    }
    
    // Split into transport ciphers
    auto send_cipher = std::make_shared<rats::NoiseCipherState>();
    auto recv_cipher = std::make_shared<rats::NoiseCipherState>();
    
    err = handshake.split(*send_cipher, *recv_cipher);
    if (err != rats::NoiseError::OK) {
        LOG_CLIENT_ERROR("Failed to split Noise session: " << static_cast<int>(err));
        return false;
    }
    
    // Store ciphers and remote static key in peer
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        auto it = peers_.find(peer_id);
        if (it == peers_.end()) {
            // Try to find by socket
            auto sock_it = socket_to_peer_id_.find(socket);
            if (sock_it != socket_to_peer_id_.end()) {
                it = peers_.find(sock_it->second);
            }
        }
        
        if (it != peers_.end()) {
            it->second.send_cipher = std::move(send_cipher);
            it->second.recv_cipher = std::move(recv_cipher);
            it->second.noise_handshake_completed = true;
            
            // Store remote static key
            const uint8_t* remote_key = handshake.get_remote_static_public();
            if (handshake.has_remote_static()) {
                it->second.remote_static_key.assign(remote_key, remote_key + 32);
            }
            
            LOG_CLIENT_INFO("Noise handshake completed with " << it->second.peer_id);
        } else {
            LOG_CLIENT_ERROR("Peer not found after Noise handshake: " << peer_id);
            return false;
        }
    }
    
    // Reset socket timeout to infinite (0) for normal operation after handshake
#ifdef _WIN32
    DWORD no_timeout = 0;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&no_timeout), sizeof(no_timeout));
#else
    struct timeval no_timeout;
    no_timeout.tv_sec = 0;
    no_timeout.tv_usec = 0;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&no_timeout), sizeof(no_timeout));
#endif
    
    return true;
}

bool RatsClient::encrypt_and_send(socket_t socket, const std::string& peer_id, const std::vector<uint8_t>& plaintext) {
    rats::NoiseCipherState* cipher = nullptr;
    
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        auto it = peers_.find(peer_id);
        if (it == peers_.end()) {
            auto sock_it = socket_to_peer_id_.find(socket);
            if (sock_it != socket_to_peer_id_.end()) {
                it = peers_.find(sock_it->second);
            }
        }
        
        if (it != peers_.end() && it->second.send_cipher) {
            cipher = it->second.send_cipher.get();
        }
    }
    
    if (!cipher) {
        LOG_CLIENT_ERROR("No send cipher for peer: " << peer_id);
        return false;
    }
    
    // Encrypt
    std::vector<uint8_t> ciphertext(plaintext.size() + rats::NOISE_TAG_SIZE);
    size_t ct_len = cipher->encrypt_with_ad(nullptr, 0, plaintext.data(), plaintext.size(), ciphertext.data());
    if (ct_len == 0) {
        LOG_CLIENT_ERROR("Encryption failed for peer: " << peer_id);
        return false;
    }
    
    ciphertext.resize(ct_len);
    
    // Send as framed message
    return send_noise_message(socket, ciphertext.data(), ciphertext.size());
}

bool RatsClient::receive_and_decrypt(socket_t socket, const std::string& peer_id, std::vector<uint8_t>& plaintext) {
    rats::NoiseCipherState* cipher = nullptr;
    
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        auto it = peers_.find(peer_id);
        if (it == peers_.end()) {
            auto sock_it = socket_to_peer_id_.find(socket);
            if (sock_it != socket_to_peer_id_.end()) {
                it = peers_.find(sock_it->second);
            }
        }
        
        if (it != peers_.end() && it->second.recv_cipher) {
            cipher = it->second.recv_cipher.get();
        }
    }
    
    if (!cipher) {
        LOG_CLIENT_ERROR("No recv cipher for peer: " << peer_id);
        return false;
    }
    
    // Receive ciphertext
    std::vector<uint8_t> ciphertext;
    if (!recv_noise_message(socket, ciphertext)) {
        return false;
    }
    
    // Decrypt
    plaintext.resize(ciphertext.size());
    size_t pt_len = cipher->decrypt_with_ad(nullptr, 0, ciphertext.data(), ciphertext.size(), plaintext.data());
    if (pt_len == 0) {
        LOG_CLIENT_ERROR("Decryption failed for peer: " << peer_id);
        return false;
    }
    
    plaintext.resize(pt_len);
    return true;
}

} // namespace librats
