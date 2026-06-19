#pragma once

/**
 * @file plaintext_security.h
 * @brief Unencrypted "secure channel": exchanges PeerIds, encrypts nothing.
 *
 * Useful for local/testing setups and as the trivial reference implementation
 * of the SecurityProvider/Handshaker/Session contract. The handshake is a
 * single PeerId exchange; the resulting Session is a passthrough. Note the
 * identity here is NOT authenticated (no key proof) — that is the inherent
 * trade-off of running without encryption.
 */

#include "security/handshaker.h"
#include "security/identity.h"

#include <memory>

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

/// One-message-each PeerId exchange.
class PlaintextHandshaker final : public Handshaker {
public:
    PlaintextHandshaker(PeerId local, bool initiator) : local_(local), initiator_(initiator) {}

    bool start(Bytes& out) override {
        if (initiator_) append_local_id(out);  // initiator announces first
        return true;
    }

    Outcome consume(ByteView incoming, Bytes& out) override {
        Outcome oc;
        auto remote = PeerId::from_bytes(incoming);
        if (!remote) { oc.status = Outcome::Failed; return oc; }
        if (!initiator_) append_local_id(out);  // responder replies with its id
        oc.status    = Outcome::Done;
        oc.remote_id = *remote;
        oc.session   = std::make_unique<PlaintextSession>(*remote);
        return oc;
    }

private:
    void append_local_id(Bytes& out) {
        const auto& b = local_.bytes();
        out.insert(out.end(), b.begin(), b.end());
    }

    PeerId local_;
    bool   initiator_;
};

class PlaintextSecurity final : public SecurityProvider {
public:
    explicit PlaintextSecurity(Identity identity) : identity_(identity) {}
    std::unique_ptr<Handshaker> create(ConnRole role) override {
        return std::make_unique<PlaintextHandshaker>(identity_.id, role == ConnRole::Outbound);
    }
    const PeerId& local_id() const override { return identity_.id; }
private:
    Identity identity_;
};

} // namespace librats
