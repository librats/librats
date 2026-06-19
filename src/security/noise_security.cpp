#include "security/noise_security.h"
#include "noise.h"

namespace librats {
namespace {

/// Session backed by a completed rats::NoiseSession (owns its transport ciphers).
class NoiseSessionAdapter final : public Session {
public:
    NoiseSessionAdapter(std::unique_ptr<rats::NoiseSession> session, PeerId remote)
        : session_(std::move(session)), remote_id_(remote) {}

    bool encrypt(ByteView plain, Bytes& out) override {
        out.resize(plain.size() + rats::NOISE_TAG_SIZE);
        const size_t n = session_->encrypt(plain.data(), plain.size(), out.data());
        if (n == 0 && plain.size() != 0) return false;
        out.resize(n);
        return true;
    }

    bool decrypt(ByteView cipher, Bytes& out) override {
        if (cipher.size() < rats::NOISE_TAG_SIZE) return false;
        out.resize(cipher.size());  // plaintext is always shorter than ciphertext
        const size_t n = session_->decrypt(cipher.data(), cipher.size(), out.data());
        if (n == 0) return false;
        out.resize(n);
        return true;
    }

    const PeerId& remote_id() const override { return remote_id_; }
    bool is_secure() const override { return true; }

private:
    std::unique_ptr<rats::NoiseSession> session_;
    PeerId                              remote_id_;
};

/// Drives the Noise XX message exchange via rats::NoiseSession::handshake_step.
class NoiseHandshaker final : public Handshaker {
public:
    NoiseHandshaker(const Identity& identity, bool initiator)
        : session_(std::make_unique<rats::NoiseSession>()), initiator_(initiator) {
        session_->start(initiator, &identity.static_keypair);
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
                                                   rats::NOISE_DH_SIZE);
            oc.session   = std::make_unique<NoiseSessionAdapter>(std::move(session_), oc.remote_id);
            oc.status    = Outcome::Done;
        }
        return oc;
    }

private:
    // Run one handshake step; append the outgoing message (if any) to `out`.
    bool step(const uint8_t* received, size_t received_len, Bytes& out) {
        uint8_t buffer[rats::NOISE_MAX_MESSAGE_SIZE];
        size_t  len = sizeof(buffer);
        bool    need_to_send = false;
        const auto err = session_->handshake_step(received, received_len, buffer, &len, &need_to_send);
        if (err != rats::NoiseError::OK) return false;
        if (need_to_send) out.insert(out.end(), buffer, buffer + len);
        return true;
    }

    std::unique_ptr<rats::NoiseSession> session_;
    bool                                initiator_;
};

} // namespace

NoiseSecurity::NoiseSecurity(Identity identity) : identity_(identity) {}

std::unique_ptr<Handshaker> NoiseSecurity::create(ConnRole role) {
    return std::make_unique<NoiseHandshaker>(identity_, role == ConnRole::Outbound);
}

} // namespace librats
