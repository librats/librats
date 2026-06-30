#pragma once

/**
 * @file types.h
 * @brief Core BitTorrent identifiers, constants and small identity helpers.
 *
 * Everything BitTorrent-specific lives in namespace librats::bittorrent. The
 * 20-byte InfoHash is intentionally the *same* std::array type as the DHT's
 * librats::InfoHash, so handing an info-hash to DhtClient::find_peers /
 * announce_peer is a zero-conversion pass-through — no glue, no copying.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace librats::bittorrent {

// ---- Sizes (bytes) ----
constexpr std::size_t kPeerIdSize   = 20;   ///< BEP 20 peer id length
constexpr std::size_t kInfoHashSize = 20;   ///< SHA-1 of the bencoded info dictionary

/// 20-byte info hash. Same underlying type as librats::InfoHash (std::array<uint8_t,20>),
/// so it passes straight into DhtClient without conversion.
using InfoHash = std::array<std::uint8_t, kInfoHashSize>;

/// 20-byte peer identifier (BEP 20).
using PeerId = std::array<std::uint8_t, kPeerIdSize>;

/// The 8 reserved bytes exchanged in the BitTorrent handshake.
using ReservedBytes = std::array<std::uint8_t, 8>;

// ---- Protocol constants ----
constexpr char          kProtocolString[]    = "BitTorrent protocol";  // 19 chars (+NUL)
constexpr std::size_t   kProtocolStringLen   = 19;
constexpr std::size_t   kHandshakeSize       = 68;          ///< 1 + 19 + 8 + 20 + 20
constexpr std::uint32_t kBlockSize           = 16 * 1024;   ///< standard request block (16 KiB)
constexpr std::uint32_t kMaxBlockSize        = 32 * 1024;   ///< largest block we will serve
constexpr std::uint32_t kDefaultPieceLength  = 256 * 1024;  ///< default for created torrents
constexpr std::uint32_t kMetadataPieceSize   = 16 * 1024;   ///< BEP 9 metadata block size
/// Largest ut_metadata (BEP 9) info dict we will accept from a peer. The size is
/// self-reported in the peer's extended handshake, so it must be capped before we
/// allocate a buffer for it — otherwise a hostile peer advertising ~4 GiB triggers
/// an out-of-memory allocation. libtorrent uses the same 4 MiB ceiling.
constexpr std::uint32_t kMaxMetadataSize     = 4 * 1024 * 1024;

// ---- Reserved-bit negotiation (handshake) ----
// Each capability is a single bit in a specific reserved byte, per the relevant BEP.
namespace reserved {
    inline void enable_dht(ReservedBytes& r)        noexcept { r[7] |= 0x01; }  // BEP 5  DHT
    inline void enable_fast(ReservedBytes& r)       noexcept { r[7] |= 0x04; }  // BEP 6  Fast
    inline void enable_extensions(ReservedBytes& r) noexcept { r[5] |= 0x10; }  // BEP 10 Extension protocol

    inline bool has_dht(const ReservedBytes& r)        noexcept { return (r[7] & 0x01) != 0; }
    inline bool has_fast(const ReservedBytes& r)       noexcept { return (r[7] & 0x04) != 0; }
    inline bool has_extensions(const ReservedBytes& r) noexcept { return (r[5] & 0x10) != 0; }
} // namespace reserved

// ---- Hex / identity helpers (defined in types.cpp) ----

/// Lowercase hex of an arbitrary byte run.
std::string to_hex(const std::uint8_t* data, std::size_t len);

/// Lowercase hex of any 20-byte id (InfoHash or PeerId — they share the type).
inline std::string to_hex(const std::array<std::uint8_t, 20>& id) {
    return to_hex(id.data(), id.size());
}

/// Parse a 40-character hex string into an InfoHash. nullopt if the length is wrong
/// or a non-hex character is present.
std::optional<InfoHash> info_hash_from_hex(const std::string& hex);

/// True when every byte is zero (an unset / invalid hash).
bool is_all_zero(const std::array<std::uint8_t, 20>& id) noexcept;

/// Generate an Azureus-style peer id: a prefix (≤8 chars, e.g. "-LR0001-" for
/// librats v0.0.0.1) followed by a random tail filling the 20 bytes.
PeerId generate_peer_id(const std::string& client_prefix = "-LR0001-");

/// Best-effort human-readable client name + version from a peer id (BEP 20).
/// Returns "Unknown [...]" for unrecognised ids.
std::string identify_client(const PeerId& id);

} // namespace librats::bittorrent
