#include "security/noise_security.h"
#include "crypto/noise.h"
#include "util/logger.h"

namespace librats {
namespace {

// Human-readable Noise failure reason for handshake diagnostics. Kept local: the
// crypto layer deliberately exposes only the enum, and this is its sole logger.
const char* noise_error_name(librats::NoiseError e) {
    switch (e) {
        case librats::NoiseError::OK:                         return "ok";
        case librats::NoiseError::INVALID_STATE:              return "invalid-state";
        case librats::NoiseError::DECRYPT_FAILED:             return "decrypt-failed";
        case librats::NoiseError::MESSAGE_TOO_LARGE:          return "message-too-large";
        case librats::NoiseError::HANDSHAKE_NOT_COMPLETE:     return "handshake-not-complete";
        case librats::NoiseError::HANDSHAKE_ALREADY_COMPLETE: return "handshake-already-complete";
        case librats::NoiseError::INVALID_KEY:                return "invalid-key";
        case librats::NoiseError::INTERNAL_ERROR:             return "internal-error";
    }
    return "unknown";
}

/// Session backed by a completed librats::NoiseSession (owns its transport ciphers).
class NoiseSessionAdapter final : public Session {
public:
    NoiseSessionAdapter(std::unique_ptr<librats::NoiseSession> session, PeerId remote)
        : session_(std::move(session)), remote_id_(remote) {}

    bool encrypt(ByteView plain, Bytes& out) override {
        out.resize(plain.size() + librats::NOISE_TAG_SIZE);
        const size_t n = session_->encrypt(plain.data(), plain.size(), out.data());
        if (n == 0 && plain.size() != 0) return false;
        out.resize(n);
        return true;
    }

    bool decrypt(ByteView cipher, Bytes& out) override {
        if (cipher.size() < librats::NOISE_TAG_SIZE) return false;
        out.resize(cipher.size());  // plaintext is always shorter than ciphertext
        const size_t n = session_->decrypt(cipher.data(), cipher.size(), out.data());
        if (n == librats::NOISE_DECRYPT_FAILED) return false;  // 0 is a valid (empty) frame
        out.resize(n);
        return true;
    }

    const PeerId& remote_id() const override { return remote_id_; }
    bool is_secure() const override { return true; }

private:
    std::unique_ptr<librats::NoiseSession> session_;
    PeerId                              remote_id_;
};

/// Drives the Noise XX message exchange via librats::NoiseSession::handshake_step.
class NoiseHandshaker final : public Handshaker {
public:
    NoiseHandshaker(const Identity& identity, bool initiator, ByteView prologue)
        : session_(std::make_unique<librats::NoiseSession>()), initiator_(initiator) {
        session_->start(initiator, &identity.static_keypair,
                        prologue.empty() ? nullptr : prologue.data(), prologue.size());
    }

    bool start(Bytes& out) override {
        if (!initiator_) return true;     // responder waits for the first message
        return step(nullptr, 0, out);
    }

    Outcome consume(ByteView incoming, Bytes& out) override {
        Outcome oc;
        if (!step(incoming.data(), incoming.size(), out)) {
            oc.status = Outcome::Failed;
            return oc;
        }
        if (session_->is_handshake_complete()) {
            oc.remote_id = PeerId::from_public_key(session_->get_remote_static_public(),
                                                   librats::NOISE_DH_SIZE);
            oc.session   = std::make_unique<NoiseSessionAdapter>(std::move(session_), oc.remote_id);
            oc.status    = Outcome::Done;
        }
        return oc;
    }

private:
    // Run one handshake step; append the outgoing message (if any) to `out`.
    bool step(const uint8_t* received, size_t received_len, Bytes& out) {
        // A Noise transport message is capped at 65535 bytes; reject anything
        // larger before it reaches the state machine. Defense in depth: the
        // block layer admits frames up to kMaxBlockSize (64 MB), so without
        // this an oversized handshake frame would be fed straight in.
        if (received_len > librats::NOISE_MAX_MESSAGE_SIZE) {
            LOG_DEBUG("noise", "Rejecting oversized handshake message (" << received_len << " B)");
            return false;
        }

        uint8_t buffer[librats::NOISE_MAX_MESSAGE_SIZE];
        size_t  len = sizeof(buffer);
        bool    need_to_send = false;
        const auto err = session_->handshake_step(received, received_len, buffer, &len, &need_to_send);
        if (err != librats::NoiseError::OK) {
            LOG_DEBUG("noise", "Handshake step failed: " << noise_error_name(err)
                      << " (" << (initiator_ ? "initiator" : "responder") << ")");
            return false;
        }
        if (need_to_send) out.insert(out.end(), buffer, buffer + len);
        return true;
    }

    std::unique_ptr<librats::NoiseSession> session_;
    bool                                initiator_;
};

} // namespace

NoiseSecurity::NoiseSecurity(Identity identity, std::string protocol)
    : identity_(identity), prologue_(protocol_id(protocol)) {}

std::unique_ptr<Handshaker> NoiseSecurity::create(ConnRole role) {
    return std::make_unique<NoiseHandshaker>(identity_, role == ConnRole::Outbound, ByteView(prologue_));
}

} // namespace librats
