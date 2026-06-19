#pragma once

/**
 * @file frame.h
 * @brief Binary wire framing for librats.
 *
 * Every message on the wire is a single length-prefixed frame:
 *
 *   ┌──────────────┬──────┬───────┬─────────┬───────────────┐
 *   │ length (u32) │ type │ flags │ channel │   payload …   │
 *   │   4 bytes    │  u8  │  u8   │  u16    │  length-4 B   │
 *   └──────────────┴──────┴───────┴─────────┴───────────────┘
 *        big-endian            big-endian
 *
 * `length` counts everything after itself (the 4-byte fixed header + payload),
 * so the total bytes on the wire are `4 + length`. The message kind lives in
 * `type` and the application sub-channel in `channel`, which means the receiver
 * demultiplexes with a single byte read — no JSON parse, no string compare.
 *
 * Decoding is zero-copy: a decoded Frame's payload is a ByteView pointing into
 * the caller's receive buffer, valid only until that buffer is consumed.
 */

#include "core/bytes.h"

#include <cstdint>

namespace librats {

/// Top-level message kind. Reserved values let subsystems share the wire
/// without colliding; application traffic rides on `App` with a `channel`.
enum class MessageType : uint8_t {
    Handshake = 0,  ///< Secure-channel handshake (security layer).
    App       = 1,  ///< Application message, addressed by `channel`.
    Control   = 2,  ///< Core control plane (peer exchange, ping…).
    Gossip    = 3,  ///< GossipSub pub/sub.
    FileChunk = 4,  ///< File-transfer binary chunk.
};

/// Per-frame metadata (the fixed header that follows the length prefix).
struct FrameHeader {
    MessageType type    = MessageType::App;
    uint8_t     flags   = 0;
    uint16_t    channel = 0;  ///< Interned application channel id (0 for non-App).
};

/// A decoded frame. `payload` is a non-owning view into the source buffer.
struct Frame {
    FrameHeader header;
    ByteView    payload;
};

namespace framer {

constexpr size_t   kLengthPrefixSize = 4;
constexpr size_t   kHeaderSize       = 4;                  ///< type+flags+channel
constexpr uint32_t kMaxFrameSize     = 64u * 1024 * 1024;  ///< body cap (length field)

/// Append a complete length-prefixed frame to `out` (grows it in place).
void encode(Bytes& out, FrameHeader header, ByteView payload);

/// Result of attempting to decode one frame from the front of a buffer.
struct Decoded {
    enum Status {
        Ok,          ///< A full frame was decoded; see `frame` and `consumed`.
        Incomplete,  ///< Not enough bytes yet; wait for more and retry.
        Error,       ///< Protocol violation (bad length); drop the connection.
    } status = Incomplete;

    size_t consumed = 0;  ///< Bytes to consume from the buffer (valid when Ok).
    Frame  frame{};       ///< Decoded frame (valid when Ok; payload views input).
};

/// Try to decode a single frame from `[data, data+size)` without copying.
Decoded try_decode(const uint8_t* data, size_t size);

} // namespace framer
} // namespace librats
