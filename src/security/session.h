#pragma once

/**
 * @file session.h
 * @brief Post-handshake symmetric session: encrypts/decrypts transport frames.
 *
 * A Session is produced by a Handshaker once the secure channel is established.
 * The Connection holds it and runs every outbound frame through encrypt() and
 * every inbound frame through decrypt(). The plaintext mode supplies a
 * passthrough Session so the Connection code path is identical with or without
 * encryption — no `if (encrypted)` scattered through the hot path.
 */

#include "core/bytes.h"
#include "peer/peer_id.h"

namespace librats {

class Session {
public:
    virtual ~Session() = default;

    /// Encrypt `plain` into `out` (resized to fit). Returns false on failure.
    virtual bool encrypt(ByteView plain, Bytes& out) = 0;

    /// Decrypt `cipher` into `out` (resized to fit). Returns false on failure.
    virtual bool decrypt(ByteView cipher, Bytes& out) = 0;

    /// The remote peer's identity, proven during the handshake.
    virtual const PeerId& remote_id() const = 0;

    /// True if traffic is actually encrypted (false for the plaintext passthrough).
    virtual bool is_secure() const = 0;
};

} // namespace librats
