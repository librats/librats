#pragma once

/**
 * @file peer_id.h
 * @brief Self-certifying peer identity.
 *
 * A PeerId is the SHA-256 of a peer's static (Noise) public key. Because the
 * Noise XX handshake proves possession of that key, a completed handshake also
 * proves the remote's PeerId — identity is cryptographically bound to the key
 * and cannot be forged (libp2p uses the same self-certifying scheme).
 *
 * This is a value type: cheap to copy, hashable, and ordered, so it slots
 * straight into unordered_map / set as a key.
 */

#include "core/bytes.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace librats {

class PeerId {
public:
    static constexpr size_t kSize = 32;  ///< SHA-256 digest length

    PeerId() = default;

    /// Derive the PeerId from a raw static public key (SHA-256 of the key).
    static PeerId from_public_key(const uint8_t* key, size_t len);
    static PeerId from_public_key(ByteView key) { return from_public_key(key.data(), key.size()); }

    /// Wrap raw 32 id-bytes verbatim (NOT hashed). nullopt unless exactly kSize.
    static std::optional<PeerId> from_bytes(ByteView raw);

    /// Parse a 64-char lowercase/uppercase hex string. nullopt if malformed.
    static std::optional<PeerId> from_hex(std::string_view hex);

    std::string to_hex() const;
    std::string short_hex() const;  ///< first 8 hex chars, for logs

    const std::array<uint8_t, kSize>& bytes() const noexcept { return bytes_; }
    bool is_zero() const noexcept;

    bool operator==(const PeerId& o) const noexcept { return bytes_ == o.bytes_; }
    bool operator!=(const PeerId& o) const noexcept { return bytes_ != o.bytes_; }
    bool operator<(const PeerId& o) const noexcept { return bytes_ < o.bytes_; }

    /// Hash functor for use as an unordered_map/set key.
    struct Hash {
        size_t operator()(const PeerId& id) const noexcept;
    };

private:
    std::array<uint8_t, kSize> bytes_{};
};

} // namespace librats
