#pragma once

/**
 * @file frame.h
 * @brief Two-level wire framing: outer length-prefixed blocks, inner messages.
 *
 * The wire is a stream of length-prefixed **blocks**:
 *
 *   ┌──────────────┬───────────────────────────┐
 *   │ length (u32) │            body            │
 *   │   4 bytes    │       length bytes         │
 *   └──────────────┴───────────────────────────┘
 *
 * A block's body is opaque at this layer. The Connection uses it for two things:
 *
 *   - during the handshake, the body is a raw handshake message (Noise / id);
 *   - once established, the body is the Session-encrypted bytes of an inner
 *     **message**, which has its own fixed 4-byte header:
 *
 *       ┌──────┬───────┬─────────┬───────────────┐
 *       │ type │ flags │ channel │   payload …   │
 *       │  u8  │  u8   │   u16   │               │
 *       └──────┴───────┴─────────┴───────────────┘
 *
 * Splitting "outer block" from "inner message" keeps encryption clean: the
 * cipher wraps the whole inner message (type included), and the block layer
 * never needs to understand it. Decoding is zero-copy — views point into the
 * caller's buffer and are valid only until it is consumed.
 */

#include "core/bytes.h"

#include <cstdint>

namespace librats {

/// Inner-message kind. Application traffic uses App, addressed by `channel`.
enum class MessageType : uint8_t {
    App       = 1,
    Control   = 2,  ///< core control plane (peer exchange…)
    Gossip    = 3,
    FileChunk = 4,
    Ping      = 5,  ///< liveness / RTT (PingService)
    Storage   = 6,  ///< distributed key-value store (StorageManager)
    Typed     = 7,  ///< typed JSON message exchange (MessageJson)
    Pex       = 8,  ///< peer exchange — gossip of known peer addresses (PeerExchange)
};

/// Fixed header of an inner message.
struct FrameHeader {
    MessageType type    = MessageType::App;
    uint8_t     flags   = 0;
    uint16_t    channel = 0;  ///< interned application channel id (0 for non-App)
};

/// A decoded inner message. `payload` is a non-owning view into the source bytes.
struct Frame {
    FrameHeader header;
    ByteView    payload;
};

namespace framer {

constexpr size_t   kLengthPrefixSize = 4;
constexpr size_t   kHeaderSize       = 4;                  ///< type+flags+channel
constexpr uint32_t kMaxBlockSize     = 64u * 1024 * 1024;  ///< body cap

// ── Outer block (length-prefixed opaque body) ───────────────────────────────

/// Append `[u32 len][body]` to `out`.
void encode_block(Bytes& out, ByteView body);

struct Block {
    enum Status { Ok, Incomplete, Error } status = Incomplete;
    size_t   consumed = 0;  ///< bytes to consume from the buffer (when Ok)
    ByteView body{};        ///< the block body (when Ok); views the input
};

/// Try to take one block from the front of `[data, data+size)` without copying.
Block try_take_block(const uint8_t* data, size_t size);

// ── Inner message (fixed header + payload, no length prefix) ─────────────────

/// Append `[type][flags][channel][payload]` to `out` (no length prefix).
void encode_message(Bytes& out, FrameHeader header, ByteView payload);

struct Message {
    bool  ok = false;
    Frame frame{};
};

/// Parse an inner message from `inner` (header + payload). `ok` false if short.
Message parse_message(ByteView inner);

} // namespace framer
} // namespace librats
