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

#include "librats/util/rats_export.h"
#include "librats/core/bytes.h"
#include "librats/peer/peer_id.h"

namespace librats {

class RATS_API Session {
public:
    virtual ~Session() = default;

    /// Encrypt `plain` into `out` (resized to fit). Returns false on failure.
    virtual bool encrypt(ByteView plain, Bytes& out) = 0;

    /// Decrypt `cipher` into `out` (resized to fit). Returns false on failure.
    virtual bool decrypt(ByteView cipher, Bytes& out) = 0;

    /// The remote peer's identity, proven during the handshake.
    virtual const PeerId& remote_id() const = 0;

    /// Bytes encrypt() adds to a plaintext of any size (an AEAD tag, typically).
    /// The send path needs the ciphertext's size *before* encrypting it, because
    /// a message it turns out it cannot frame must be refused without a nonce
    /// having been spent on it — the counters run in lockstep at both ends, so a
    /// message encrypted and then not sent would break every one after it.
    virtual size_t overhead() const noexcept = 0;

    /// True if traffic is actually encrypted (false for the plaintext passthrough).
    virtual bool is_secure() const = 0;
};

} // namespace librats
