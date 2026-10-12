#pragma once

/**
 * @file session.h
 * @brief The keys of an established secure channel: AEAD with explicit nonces.
 *
 * A Session is produced by a Handshaker once the secure channel is established,
 * and the transport above it runs every outbound message through seal() and every
 * inbound one through open(). The plaintext mode supplies a passthrough Session,
 * so the transport's code path is identical with or without encryption — no
 * `if (encrypted)` scattered through the hot path.
 *
 * The nonce belongs to the caller, not to the Session. A transport over an ordered
 * byte stream numbers its messages 0, 1, 2… at both ends; one over datagrams uses
 * the packet number, which is what lets a packet that never arrives be skipped
 * instead of breaking every one after it. Either way the one rule is that a nonce
 * is never used twice in one direction of one session.
 *
 * Both calls work in place: the transport already holds the bytes in the buffer
 * they leave from or arrived in, so encrypting into a second one would only add an
 * allocation and a copy per message.
 */

#include "librats/util/rats_export.h"
#include "librats/core/bytes.h"
#include "librats/peer/peer_id.h"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace librats {

class RATS_API Session {
public:
    virtual ~Session() = default;

    /// Bytes seal() appends to what it encrypts (an AEAD tag; 0 for plaintext).
    virtual size_t overhead() const noexcept = 0;

    /// Encrypt `data[0, len)` in place and write overhead() bytes of tag right
    /// behind it, so the buffer must have room for len + overhead(). `ad` is
    /// authenticated but not encrypted. `nonce` must never repeat for this session.
    virtual void seal(uint64_t nonce, ByteView ad, uint8_t* data, size_t len) const noexcept = 0;

    /// Authenticate and decrypt `data[0, len)` — ciphertext, then tag — in place.
    /// Returns the plaintext length (len - overhead()), or nullopt when the bytes
    /// do not authenticate under `nonce` and `ad`.
    virtual std::optional<size_t> open(uint64_t nonce, ByteView ad,
                                       uint8_t* data, size_t len) const noexcept = 0;

    /// Header protection: five bytes of mask for a packet whose ciphertext holds
    /// `sample` (16 bytes), under the key of the direction it travels in —
    /// `outbound` for one being sent, otherwise one received. A datagram transport
    /// XORs it over the parts of its header the path has no business reading (see
    /// transport/udp_wire.h). Its own key, not the AEAD's, so the mask says nothing
    /// about the keystream. All zeros for plaintext.
    virtual void header_mask(bool outbound, const uint8_t* sample, uint8_t* mask) const noexcept = 0;

    /// The remote peer's identity, proven during the handshake.
    virtual const PeerId& remote_id() const = 0;

    /// True if traffic is actually encrypted (false for the plaintext passthrough).
    virtual bool is_secure() const = 0;
};

} // namespace librats
