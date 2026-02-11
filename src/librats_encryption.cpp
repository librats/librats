#include "librats.h"
#include "librats_log_macros.h"

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

// =========================================================================
// Async Noise Handshake (non-blocking, driven by io_loop)
// =========================================================================

/*
 * Noise XX pattern (3 messages):
 *   Initiator: write msg0 → read msg1 → write msg2 → split
 *   Responder: read msg0 → write msg1 → read msg2 → split
 *
 * noise_step tracks where we are in this sequence:
 *   Initiator: 0 = need write, 1 = need read, 2 = need write, 3 = done
 *   Responder: 0 = need read,  1 = need write, 2 = need read,  3 = done
 *
 * start_noise_handshake_async() initialises noise_hs and writes the first
 * outgoing message (if initiator).  Subsequent messages are processed by
 * handle_noise_frame() which is called from handle_readable when
 * handshake_state == NOISE_PENDING.
 */

void RatsClient::start_noise_handshake_async(RatsPeer& peer) {
    LOG_CLIENT_INFO("Starting async Noise handshake for " << peer.peer_id 
                    << " (initiator: " << peer.is_outgoing << ")");
    
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
    
    // Allocate handshake state on the peer's IO context
    peer.io_.noise_hs = std::make_unique<rats::NoiseHandshakeState>();
    peer.io_.noise_step = 0;
    
    auto err = peer.io_.noise_hs->initialize(peer.is_outgoing, &static_keypair);
    if (err != rats::NoiseError::OK) {
        LOG_CLIENT_ERROR("Failed to initialise Noise handshake: " << static_cast<int>(err));
        peer.handshake_state = RatsPeer::HandshakeState::FAILED;
        return;
    }
    
    // Initiator sends message 0 immediately
    if (peer.is_outgoing) {
        uint8_t msg_buf[256];
        size_t msg_len = sizeof(msg_buf);
        err = peer.io_.noise_hs->write_message(nullptr, 0, msg_buf, &msg_len);
        if (err != rats::NoiseError::OK) {
            LOG_CLIENT_ERROR("Failed to write Noise msg 0: " << static_cast<int>(err));
            peer.handshake_state = RatsPeer::HandshakeState::FAILED;
            return;
        }
        
        // Enqueue as a length-prefixed frame (same framing as data messages)
        std::vector<uint8_t> payload(msg_buf, msg_buf + msg_len);
        enqueue_message_unlocked(peer, payload);
        peer.io_.noise_step = 1;  // next: need to read msg 1
        LOG_CLIENT_DEBUG("Sent Noise msg 0 (" << msg_len << " bytes) to " << peer.peer_id);
    }
    // Responder waits for msg 0 from initiator (noise_step stays 0)
}

bool RatsClient::handle_noise_frame(RatsPeer& peer) {
    // The caller (handle_readable) has already verified that a complete
    // length-prefixed frame is available in the receive buffer, but hasn't
    // consumed it yet.  We read the payload from recv_buf (skip 4-byte length).
    auto& recv_buf = peer.io_.recv_buffer;
    
    // Read payload length
    uint32_t net_len;
    memcpy(&net_len, recv_buf.data(), 4);
    uint32_t frame_len = ntohl(net_len);
    
    const uint8_t* frame_data = recv_buf.data() + 4;
    
    if (!peer.io_.noise_hs) {
        LOG_CLIENT_ERROR("Noise frame received but no handshake state for " << peer.peer_id);
        return false;
    }
    
    auto& hs = *peer.io_.noise_hs;
    bool is_initiator = peer.is_outgoing;
    rats::NoiseError err;
    uint8_t out_buf[256];
    size_t out_len;
    
    /*
     * Step table (noise_step → action):
     *   Initiator: 0=write, 1=read, 2=write, 3=done
     *   Responder: 0=read,  1=write, 2=read,  3=done
     *
     * This function is only called when we received a frame, so the current
     * step must expect a "read".
     */
    
    // ── Read the incoming Noise message ──
    out_len = sizeof(out_buf);
    err = hs.read_message(frame_data, frame_len, out_buf, &out_len);
    if (err != rats::NoiseError::OK) {
        LOG_CLIENT_ERROR("Noise read_message failed (step " << peer.io_.noise_step 
                         << "): " << static_cast<int>(err));
        return false;
    }
    LOG_CLIENT_DEBUG("Read Noise msg (step " << peer.io_.noise_step 
                     << ", " << frame_len << " bytes) from " << peer.peer_id);
    
    peer.io_.noise_step++;
    
    // ── If there's a reply to write, do it now ──
    bool need_write = false;
    if (is_initiator) {
        // Initiator writes on steps 0 and 2 → after reading (step becomes 2), write
        need_write = (peer.io_.noise_step == 2);
    } else {
        // Responder writes on step 1 → after reading (step becomes 1), write
        need_write = (peer.io_.noise_step == 1);
    }
    
    if (need_write) {
        out_len = sizeof(out_buf);
        err = hs.write_message(nullptr, 0, out_buf, &out_len);
        if (err != rats::NoiseError::OK) {
            LOG_CLIENT_ERROR("Noise write_message failed (step " << peer.io_.noise_step 
                             << "): " << static_cast<int>(err));
            return false;
        }
        
        std::vector<uint8_t> payload(out_buf, out_buf + out_len);
        enqueue_message_unlocked(peer, payload);
        LOG_CLIENT_DEBUG("Sent Noise msg (step " << peer.io_.noise_step 
                         << ", " << out_len << " bytes) to " << peer.peer_id);
        peer.io_.noise_step++;
    }
    
    // ── Check if handshake is complete ──
    if (hs.is_handshake_complete()) {
        auto send_cipher = std::make_shared<rats::NoiseCipherState>();
        auto recv_cipher = std::make_shared<rats::NoiseCipherState>();
        
        err = hs.split(*send_cipher, *recv_cipher);
        if (err != rats::NoiseError::OK) {
            LOG_CLIENT_ERROR("Noise split failed: " << static_cast<int>(err));
            return false;
        }
        
        // Store ciphers and remote static key
        peer.send_cipher = std::move(send_cipher);
        peer.recv_cipher = std::move(recv_cipher);
        peer.noise_handshake_completed = true;
        
        if (hs.has_remote_static()) {
            const uint8_t* remote_key = hs.get_remote_static_public();
            peer.remote_static_key.assign(remote_key, remote_key + 32);
        }
        
        // Free handshake state (no longer needed)
        peer.io_.noise_hs.reset();
        peer.io_.noise_step = 0;
        
        // Mark handshake completed
        peer.handshake_state = RatsPeer::HandshakeState::COMPLETED;
        validated_peer_count_.fetch_add(1, std::memory_order_relaxed);
        log_handshake_completion_unlocked(peer);
        
        LOG_CLIENT_INFO("Noise handshake completed with " << peer.peer_id);
    }
    
    return true;
}

} // namespace librats
