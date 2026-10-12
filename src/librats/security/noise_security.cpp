#include "librats/security/noise_security.h"
#include "librats/crypto/chacha.h"
#include "librats/crypto/noise.h"
#include "librats/util/logger.h"

#include <cstring>

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

/// Label the header-protection keys are derived under, from each direction's
/// cipher key (NoiseCipherState::derive).
constexpr const char* kHeaderKeyLabel = "librats header protection";

/// Five bytes of ChaCha20 keystream for `sample`: its first eight bytes are the
/// block counter and the rest the nonce — QUIC's ChaCha20 header protection
/// (RFC 9001 §5.4.4) laid out for the 64-bit-counter ChaCha the library carries.
void chacha_mask(const uint8_t* key, const uint8_t* sample, uint8_t* mask) {
    rats_chacha_ctx ctx;
    rats_chacha_keysetup(&ctx, key, 256);
    rats_chacha_ivsetup(&ctx, sample + 8, sample);
    std::memset(mask, 0, 5);
    rats_chacha_encrypt_bytes(&ctx, mask, mask, 5);
}

/// Session over the two transport ciphers a completed Noise handshake split into.
/// The handshake state itself is dropped with its handshaker once this exists.
class NoiseSessionAdapter final : public Session {
public:
    NoiseSessionAdapter(librats::NoiseSession& done, PeerId remote) : remote_id_(remote) {
        done.take_transport(send_, recv_);
        send_.derive(kHeaderKeyLabel, send_hp_);
        recv_.derive(kHeaderKeyLabel, recv_hp_);
    }

    ~NoiseSessionAdapter() override {
        volatile uint8_t* a = send_hp_;
        volatile uint8_t* b = recv_hp_;
        for (size_t i = 0; i < sizeof(send_hp_); ++i) a[i] = b[i] = 0;
    }

    size_t overhead() const noexcept override { return librats::NOISE_TAG_SIZE; }

    void seal(uint64_t nonce, ByteView ad, uint8_t* data, size_t len) const noexcept override {
        send_.seal(nonce, ad.data(), ad.size(), data, len);
    }

    std::optional<size_t> open(uint64_t nonce, ByteView ad, uint8_t* data,
                               size_t len) const noexcept override {
        if (len < librats::NOISE_TAG_SIZE) return std::nullopt;
        const size_t n = recv_.open(nonce, ad.data(), ad.size(), data, len);
        if (n == librats::NOISE_DECRYPT_FAILED) return std::nullopt;
        return n;
    }

    void header_mask(bool outbound, const uint8_t* sample, uint8_t* mask) const noexcept override {
        chacha_mask(outbound ? send_hp_ : recv_hp_, sample, mask);
    }

    const PeerId& remote_id() const override { return remote_id_; }
    bool is_secure() const override { return true; }

private:
    librats::NoiseCipherState send_;
    librats::NoiseCipherState recv_;
    uint8_t                   send_hp_[librats::NOISE_KEY_SIZE];
    uint8_t                   recv_hp_[librats::NOISE_KEY_SIZE];
    PeerId                    remote_id_;
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
            oc.session   = std::make_unique<NoiseSessionAdapter>(*session_, oc.remote_id);
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
