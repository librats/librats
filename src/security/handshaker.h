#pragma once

/**
 * @file handshaker.h
 * @brief Secure-channel handshake driver and the provider that creates one.
 *
 * A Handshaker is fed handshake messages until it yields a Session and the
 * remote PeerId (or fails). It is transport-agnostic: the Connection frames its
 * `out` bytes as Handshake frames and feeds inbound Handshake payloads back in.
 *
 * A SecurityProvider configures the whole node (one keypair / policy) and mints
 * a fresh Handshaker per connection. Swapping NoiseSecurity ⇄ PlaintextSecurity
 * changes the entire security posture without touching the transport.
 */

#include "core/bytes.h"
#include "core/types.h"   // ConnRole
#include "peer/peer_id.h"
#include "security/session.h"

#include <memory>

namespace librats {

class Handshaker {
public:
    struct Outcome {
        enum Status { NeedMore, Done, Failed } status = NeedMore;
        std::unique_ptr<Session> session;   ///< valid iff status == Done
        PeerId                   remote_id; ///< valid iff status == Done
    };

    virtual ~Handshaker() = default;

    /// Called once when the transport is up. Appends the initial message, if
    /// any (e.g. the initiator's first Noise message), to `out`. False on error.
    virtual bool start(Bytes& out) = 0;

    /// Consume one received handshake message; append any reply to `out`.
    virtual Outcome consume(ByteView incoming, Bytes& out) = 0;
};

class SecurityProvider {
public:
    virtual ~SecurityProvider() = default;

    /// Create a handshaker for a new connection in the given role.
    virtual std::unique_ptr<Handshaker> create(ConnRole role) = 0;

    /// This node's own identity.
    virtual const PeerId& local_id() const = 0;
};

} // namespace librats
