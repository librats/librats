#pragma once

/**
 * @file byte_io.h
 * @brief Big-endian (network order) integer read/write helpers for the BitTorrent wire.
 *
 * The BitTorrent peer protocol, the BEP 15 UDP tracker protocol and extension
 * messages are all big-endian. These tiny inline helpers keep (de)serialisation
 * obvious and endianness-correct, without sprinkling htonl/ntohl or manual shifts
 * across the codebase.
 */

#include "core/bytes.h"

#include <cstddef>
#include <cstdint>

namespace librats::bittorrent {

inline std::uint16_t read_u16_be(const std::uint8_t* p) noexcept {
    return std::uint16_t(std::uint16_t(p[0]) << 8 | std::uint16_t(p[1]));
}
inline std::uint32_t read_u32_be(const std::uint8_t* p) noexcept {
    return std::uint32_t(p[0]) << 24 | std::uint32_t(p[1]) << 16
         | std::uint32_t(p[2]) << 8  | std::uint32_t(p[3]);
}
inline std::uint64_t read_u64_be(const std::uint8_t* p) noexcept {
    return std::uint64_t(read_u32_be(p)) << 32 | read_u32_be(p + 4);
}

inline void write_u16_be(std::uint8_t* p, std::uint16_t v) noexcept {
    p[0] = std::uint8_t(v >> 8);
    p[1] = std::uint8_t(v);
}
inline void write_u32_be(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = std::uint8_t(v >> 24);
    p[1] = std::uint8_t(v >> 16);
    p[2] = std::uint8_t(v >> 8);
    p[3] = std::uint8_t(v);
}
inline void write_u64_be(std::uint8_t* p, std::uint64_t v) noexcept {
    write_u32_be(p,     std::uint32_t(v >> 32));
    write_u32_be(p + 4, std::uint32_t(v));
}

// Append helpers — grow a Bytes buffer with one big-endian value.
inline void append_u8(Bytes& b, std::uint8_t v) { b.push_back(v); }
inline void append_u16_be(Bytes& b, std::uint16_t v) {
    std::uint8_t t[2]; write_u16_be(t, v); b.insert(b.end(), t, t + 2);
}
inline void append_u32_be(Bytes& b, std::uint32_t v) {
    std::uint8_t t[4]; write_u32_be(t, v); b.insert(b.end(), t, t + 4);
}
inline void append_u64_be(Bytes& b, std::uint64_t v) {
    std::uint8_t t[8]; write_u64_be(t, v); b.insert(b.end(), t, t + 8);
}

} // namespace librats::bittorrent
