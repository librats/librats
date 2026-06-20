#pragma once

/**
 * @file plaintext_security.h
 * @brief Unencrypted "secure channel": exchanges PeerIds, encrypts nothing.
 *
 * Useful for local/testing setups and as the trivial reference implementation
 * of the SecurityProvider/Handshaker/Session contract. The handshake exchanges
 * one message each way carrying the protocol id and the PeerId; the resulting
 * Session is a passthrough. Note the identity here is NOT authenticated (no key
 * proof) — that is the inherent trade-off of running without encryption.
 *
 * The protocol id is still checked (so two apps with different protocol can't
 * cross-connect even unencrypted), but unlike the Noise prologue it is not
 * cryptographically bound — a plaintext peer can claim any protocol. That is
 * acceptable for the plaintext mode's trusted/testing use cases.
 *
 * Handshake message: [proto_len:u16][protocol id][peer id: 32 bytes].
 */

#include "security/handshaker.h"
#include "security/identity.h"

#include <cstring>
#include <memory>
#include <string>

namespace librats {

/// Passthrough session: encrypt/decrypt just copy the bytes.
class PlaintextSession final : public Session {
public:
    explicit PlaintextSession(PeerId remote) : remote_id_(remote) {}
    bool encrypt(ByteView plain, Bytes& out) override { out.assign(plain.begin(), plain.end()); return true; }
    bool decrypt(ByteView cipher, Bytes& out) override { out.assign(cipher.begin(), cipher.end()); return true; }
    const PeerId& remote_id() const override { return remote_id_; }
    bool is_secure() const override { return false; }
private:
    PeerId remote_id_;
};

/// One-message-each exchange of [protocol id][PeerId].
class PlaintextHandshaker final : public Handshaker {
public:
    PlaintextHandshaker(PeerId local, bool initiator, std::string proto)
        : local_(local), proto_(std::move(proto)), initiator_(initiator) {}

    bool start(Bytes& out) override {
        if (initiator_) append_message(out);  // initiator announces first
        return true;
    }

    Outcome consume(ByteView incoming, Bytes& out) override {
        Outcome oc;
        const uint8_t* p = incoming.data();
        const size_t   n = incoming.size();
        if (n < 2) { oc.status = Outcome::Failed; return oc; }

        const size_t proto_len = (static_cast<size_t>(p[0]) << 8) | p[1];
        if (n < 2 + proto_len + PeerId::kSize) { oc.status = Outcome::Failed; return oc; }

        // Reject a peer announcing a different protocol id.
        if (proto_len != proto_.size() ||
            std::memcmp(p + 2, proto_.data(), proto_len) != 0) {
            oc.status = Outcome::Failed;
            return oc;
        }

        auto remote = PeerId::from_bytes(ByteView(p + 2 + proto_len, PeerId::kSize));
        if (!remote) { oc.status = Outcome::Failed; return oc; }

        if (!initiator_) append_message(out);  // responder replies
        oc.status    = Outcome::Done;
        oc.remote_id = *remote;
        oc.session   = std::make_unique<PlaintextSession>(*remote);
        return oc;
    }

private:
    void append_message(Bytes& out) {
        out.push_back(static_cast<uint8_t>((proto_.size() >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(proto_.size() & 0xFF));
        out.insert(out.end(), proto_.begin(), proto_.end());
        const auto& b = local_.bytes();
        out.insert(out.end(), b.begin(), b.end());
    }

    PeerId      local_;
    std::string proto_;
    bool        initiator_;
};

class PlaintextSecurity final : public SecurityProvider {
public:
    explicit PlaintextSecurity(Identity identity, std::string protocol_name = "librats",
                               std::string protocol_version = "1.0")
        : identity_(identity), proto_(protocol_id(protocol_name, protocol_version)) {}
    std::unique_ptr<Handshaker> create(ConnRole role) override {
        return std::make_unique<PlaintextHandshaker>(identity_.id, role == ConnRole::Outbound, proto_);
    }
    const PeerId& local_id() const override { return identity_.id; }
private:
    Identity    identity_;
    std::string proto_;
};

} // namespace librats
