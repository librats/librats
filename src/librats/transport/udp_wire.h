#pragma once

/**
 * @file udp_wire.h
 * @brief Wire format of the datagram transport (v5): packets, frames, varints.
 *
 * The shape is QUIC's (RFC 9000), cut down to what a peer-to-peer node on Noise
 * needs. It is not QUIC on the wire — there is no TLS, no version negotiation
 * and no attempt at compatibility — but every idea that makes QUIC work over a
 * hostile network is here: packets are numbered and never resent, what they
 * carry is a run of frames, each packet is sealed on its own, and the header a
 * middlebox can read is as small as it can be.
 *
 * ── Packets ──────────────────────────────────────────────────────────────────
 * The first byte says which of two forms a datagram is. Everything is big-endian.
 *
 * Long header — the handshake, and nothing after it. Never encrypted as a whole:
 * the Noise messages it carries protect themselves as far as they need to.
 *
 *      byte 0     1 1 T T 0 0 0 0      form, fixed bit, type, reserved
 *      bytes 1-4  version              kVersion; anything else is dropped unanswered
 *      bytes 5-12 destination id       the id the receiver routes by
 *      bytes 13-20 source id           the sender's own id
 *      then, by type:
 *        Initial    token length (varint), token, message length (varint), message,
 *                   zeros up to kMaxDatagram — the dialer's first Noise message,
 *                   padded so a responder may answer it with three times as much
 *                   before the dialer has proved its address (see udp_connection.h)
 *        Handshake  message number (u8), message length (varint), message — every
 *                   later handshake message, numbered from 1
 *        Retry      kTokenSize bytes: a responder under load asking the dialer to
 *                   prove its address before it spends anything on it
 *        Close      error code (varint) — a handshake refused or abandoned
 *
 * Short header — everything once the handshake is done.
 *
 *      byte 0     0 1 R R R R P P      form, fixed bit, reserved (0), PP = number length - 1
 *      bytes 1-8  destination id
 *      then       packet number, PP + 1 bytes, the low bytes of the full number
 *      then       frames, sealed by the Session: nonce = the full packet number,
 *                 associated data = the header above as it was before masking
 *
 * The low five bits of byte 0 and the packet number are then masked with five
 * bytes derived from 16 bytes of the ciphertext (Session::header_mask), as QUIC
 * does, so nothing on the path can read where a connection's numbering stands or
 * come to depend on the reserved bits. A packet is padded so those 16 bytes exist.
 *
 * Connection ids are 64-bit and come in pairs: the dialer picks an even id for
 * itself and gives the responder that id + 1 (paired_cid). One random number,
 * two ids, and a node that has forgotten a connection can still address its
 * peer's half of it — which is what a stateless reset needs.
 *
 * ── Frames ───────────────────────────────────────────────────────────────────
 * A short packet's payload is a run of frames, each a varint type and its fields.
 *
 *      PADDING      0x00
 *      PING         0x01                    ack-eliciting and nothing else
 *      ACK          0x02  largest, ack delay (kAckDelayUnit), range count,
 *                         first range, then (gap, range) pairs — RFC 9000 §19.3
 *      STREAM       0x08-0x0f  stream id, [offset], [length], data — bit 0x04 says
 *                         an offset is present (0 otherwise), 0x02 a length (the
 *                         rest of the packet otherwise); 0x01 (FIN) is never valid
 *      MAX_DATA     0x10  bytes of stream data, all streams together, the sender
 *                         will accept
 *      DATA_BLOCKED 0x14  the limit the sender is stopped at
 *      CLOSE        0x1c  error code (varint); 0 is an orderly close
 *      LIVE         0x20-0x21  message id, lifetime, [size, offset], length, data —
 *                         a live message (see udp_live.h) or a piece of one. Bit
 *                         0x01 says it is a piece: `size` is the whole message's,
 *                         `offset` where this piece begins; without it the frame
 *                         is the whole message. `lifetime` is the milliseconds the
 *                         message had left when this packet was sent.
 *      LIVE_REPAIR  0x22  message id, lifetime, size, symbol, index, then `symbol`
 *                         bytes: repair symbol `index` of a live message cut into
 *                         symbols of `symbol` bytes (udp_fec.h), from which the
 *                         receiver rebuilds pieces the path lost.
 *      RESET_TOKEN  0x30  kResetTokenSize bytes: what a stateless reset for the
 *                         sender's connection id will end with
 *
 * A stream is one lane of messages — one per MessageType, so its id is the type —
 * and each message on it is a varint length and the inner message of wire/frame.h.
 * A live message is an inner message of its own, outside every stream.
 */

#include "librats/core/bytes.h"
#include "librats/core/types.h"

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace librats {
namespace udp {

/// Wire version, in every long header. A peer that sees another one drops the
/// datagram unanswered, and a dial between the two falls back to TCP. 3: the
/// packet-numbered, frame-based protocol of this file (v1/v2 were a byte stream);
/// 4: LIVE frames, which a v3 peer would take for a protocol error; 5: LIVE_REPAIR,
/// likewise for a v4 one.
constexpr uint32_t kVersion = 5;

/// Largest datagram this transport sends, and every Initial's size. 1220 keeps it
/// inside IPv6's 1280-byte minimum MTU with room for a tunnel header, so nothing
/// ever depends on IP fragmentation — which on a datagram path turns one lost
/// fragment into a lost packet.
constexpr size_t kMaxDatagram = 1220;

using Cid = uint64_t;
constexpr size_t kCidSize = 8;

/// The other half of a connection id pair (see the file comment). The dialer's id
/// is even, the responder's the odd one above it.
constexpr Cid paired_cid(Cid cid) noexcept { return cid ^ 1; }

constexpr size_t kLongHeaderSize  = 1 + 4 + 2 * kCidSize;  ///< up to the type's own fields
constexpr size_t kShortHeaderSize = 1 + kCidSize;          ///< up to the packet number
constexpr size_t kMaxPnLength     = 4;
/// Ciphertext bytes the header mask is derived from, starting kMaxPnLength bytes
/// past where the packet number begins — so whatever the number's length, the
/// sample never overlaps it.
constexpr size_t kSampleSize = 16;
/// Smallest short packet there can be: header, the four bytes the sample skips,
/// and the sample.
constexpr size_t kMinShortPacket = kShortHeaderSize + kMaxPnLength + kSampleSize;

/// Bytes of the address-validation token a Retry hands out and an Initial hands
/// back: a keyed hash of the dialer's address and ids (see udp_mux.cpp).
constexpr size_t kTokenSize = 8;
/// Bytes of a stateless-reset token, and so of the tail that identifies a reset.
constexpr size_t kResetTokenSize = 16;

/// Largest handshake message a packet can carry: what an Initial has room for
/// once its header, a token and the length fields are in.
constexpr size_t kMaxHandshakeMessage = kMaxDatagram - kLongHeaderSize - 1 - kTokenSize - 2;

/// What a live message is on the wire: an inner message of wire/frame.h, its
/// header ([type][flags][channel], framer::kHeaderSize — not included here, where
/// `Frame` means this file's) and a payload of at most SendOptions::kMaxLivePayload.
constexpr size_t kInnerHeaderSize = 4;
constexpr size_t kMaxLiveMessage  = kInnerHeaderSize + SendOptions::kMaxLivePayload;
/// Smallest symbol a LIVE_REPAIR frame may name, unless the message is smaller
/// still (one symbol, then, the size of the message). A sender cuts nearly
/// packet-sized symbols; tiny ones would only cost the receiver bookkeeping.
constexpr size_t kMinRepairSymbol = 256;

/// Resolution of an ACK's delay field: 8 us, QUIC's default exponent of 3.
constexpr std::chrono::microseconds kAckDelayUnit{8};
/// Ranges one ACK names at most. 32 runs is a hole every ~30 packets across a
/// thousand-packet window; older ones are left out first, and earlier ACKs have
/// named them already.
constexpr size_t kMaxAckRanges = 32;

// ── Varints (RFC 9000 §16) ──────────────────────────────────────────────────

constexpr uint64_t kMaxVarint = (uint64_t{1} << 62) - 1;

/// Bytes `v` takes as a varint: 1, 2, 4 or 8. `v` must be at most kMaxVarint.
constexpr size_t varint_size(uint64_t v) noexcept {
    return v < 64 ? 1 : v < 16384 ? 2 : v < (uint64_t{1} << 30) ? 4 : 8;
}

/// Write `v` (at most kMaxVarint) and return the byte past it.
uint8_t* put_varint(uint8_t* out, uint64_t v) noexcept;

/// Bounds-checked reading over a received buffer. Every accessor returns false,
/// consuming nothing, when the buffer is too short — so a decoder is a chain of
/// calls that either all succeed or stop at the first missing byte.
class Reader {
public:
    Reader(const uint8_t* data, size_t len) noexcept : p_(data), end_(data + len) {}

    bool varint(uint64_t& v) noexcept;
    bool u8(uint8_t& v) noexcept;
    bool u32(uint32_t& v) noexcept;
    bool u64(uint64_t& v) noexcept;
    bool bytes(size_t n, ByteView& v) noexcept;
    bool skip(size_t n) noexcept;

    size_t         left() const noexcept { return static_cast<size_t>(end_ - p_); }
    bool           empty() const noexcept { return p_ == end_; }
    const uint8_t* pos() const noexcept { return p_; }

private:
    const uint8_t* p_;
    const uint8_t* end_;
};

// ── Packets ─────────────────────────────────────────────────────────────────

enum class LongType : uint8_t {
    Initial   = 0,
    Retry     = 1,
    Handshake = 2,
    Close     = 3,
};

/// Whether a datagram's first byte is a long header. Both forms carry the fixed
/// bit; a byte without it is not a packet of this protocol at all.
inline bool is_long_header(uint8_t first) noexcept { return (first & 0x80) != 0; }
inline bool has_fixed_bit(uint8_t first) noexcept { return (first & 0x40) != 0; }

/// The destination id of any packet, long or short: what the mux routes by.
bool peek_dcid(const uint8_t* data, size_t len, Cid& out) noexcept;

/// A decoded long-header packet. Views point into the datagram.
struct LongPacket {
    LongType type    = LongType::Initial;
    Cid      dcid    = 0;
    Cid      scid    = 0;
    ByteView token;        ///< Initial (may be empty), Retry
    uint8_t  number  = 0;  ///< which handshake message: 0 for an Initial's
    ByteView message;      ///< Initial, Handshake
    uint64_t error   = 0;  ///< Close
};

/// Parse a long-header packet of this version. False for anything malformed or
/// of another version; padding after an Initial's message is allowed, anything
/// after another type's last field is not.
bool decode_long(const uint8_t* data, size_t len, LongPacket& out) noexcept;

/// The encoders write into `out`, which must hold kMaxDatagram bytes, and return
/// the datagram's length. An Initial is always exactly kMaxDatagram long.
size_t encode_initial(uint8_t* out, Cid dcid, Cid scid, ByteView token, ByteView message) noexcept;
size_t encode_handshake(uint8_t* out, Cid dcid, Cid scid, uint8_t number, ByteView message) noexcept;
size_t encode_retry(uint8_t* out, Cid dcid, Cid scid, ByteView token) noexcept;
size_t encode_close(uint8_t* out, Cid dcid, Cid scid, uint64_t error) noexcept;

/// Bytes of packet number to send `pn` with, given the largest number the peer has
/// acknowledged (`have_acked` false: none yet). Enough that the receiver, decoding
/// against the highest number it has seen, cannot mistake it (RFC 9000 §17.1).
size_t pn_length(uint64_t pn, uint64_t largest_acked, bool have_acked) noexcept;

/// The full packet number whose low `len` bytes are `truncated`, closest to
/// `expected` — the number after the highest one received (RFC 9000 §A.3).
uint64_t decode_pn(uint64_t truncated, size_t len, uint64_t expected) noexcept;

// ── Frames ──────────────────────────────────────────────────────────────────

enum FrameType : uint8_t {
    kPadding     = 0x00,
    kPing        = 0x01,
    kAck         = 0x02,
    kStream      = 0x08,   ///< 0x08 to 0x0f, the low bits are flags
    kMaxData     = 0x10,
    kDataBlocked = 0x14,
    kClose       = 0x1c,
    kLive        = 0x20,   ///< 0x20 and 0x21, the low bit a flag
    kLiveRepair  = 0x22,
    kResetToken  = 0x30,
};

constexpr uint8_t kStreamOffBit = 0x04;
constexpr uint8_t kStreamLenBit = 0x02;
constexpr uint8_t kStreamFinBit = 0x01;
constexpr uint8_t kLivePieceBit = 0x01;

/// An ACK as it arrived. The ranges after the first are left encoded in `more`
/// and walked with AckRanges; the reader has already checked every one of them.
struct AckFrame {
    uint64_t largest     = 0;
    uint64_t delay       = 0;   ///< in kAckDelayUnit
    uint64_t first_range = 0;   ///< packets below `largest` in the first range
    uint64_t range_count = 0;   ///< ranges after the first
    ByteView more;
};

/// The ranges of an AckFrame, highest first, as inclusive [lo, hi].
class AckRanges {
public:
    explicit AckRanges(const AckFrame& ack) noexcept;
    bool next(uint64_t& lo, uint64_t& hi) noexcept;

private:
    Reader   r_;
    uint64_t left_;
    uint64_t lo_ = 0;
    bool     first_ = true;
    uint64_t largest_, first_range_;
};

struct StreamFrame {
    uint64_t stream = 0;
    uint64_t offset = 0;
    ByteView data;
};

/// A live message, or one piece of it. The reader has checked that the piece lies
/// within the message and that the message is not past kMaxLiveMessage.
struct LiveFrame {
    uint64_t id       = 0;
    uint64_t lifetime = 0;   ///< milliseconds left when it was sent
    uint64_t size     = 0;   ///< the whole message
    uint64_t offset   = 0;   ///< where `data` begins in it
    ByteView data;

    bool whole() const noexcept { return offset == 0 && data.size() == size; }
};

/// A repair symbol of a live message. The reader has checked the message's size
/// as for a LiveFrame, and the symbol's against it and kMinRepairSymbol.
struct LiveRepairFrame {
    uint64_t id       = 0;
    uint64_t lifetime = 0;   ///< milliseconds left when it was sent
    uint64_t size     = 0;   ///< the whole message
    uint64_t symbol   = 0;   ///< bytes of every symbol, and of `data`
    uint64_t index    = 0;   ///< which repair symbol (fec::Layout)
    ByteView data;
};

/// One decoded frame. Only the fields of its type are meaningful.
struct Frame {
    uint8_t     type = kPadding;
    AckFrame    ack;
    StreamFrame stream;
    LiveFrame   live;
    LiveRepairFrame repair;
    uint64_t    value = 0;   ///< MAX_DATA, DATA_BLOCKED, CLOSE
    ByteView    token;       ///< RESET_TOKEN
};

/// Walks a packet's frames. next() returns false at the end and on anything
/// malformed; error() tells the two apart. A run of padding is skipped whole.
class FrameReader {
public:
    FrameReader(const uint8_t* data, size_t len) noexcept : r_(data, len) {}
    bool next(Frame& out) noexcept;
    bool error() const noexcept { return error_; }

private:
    bool fail() noexcept { error_ = true; return false; }
    Reader r_;
    bool   error_ = false;
};

// Frame encoders. Each writes at `out` and returns the byte past what it wrote;
// the caller has checked the room (the *_size functions say how much).

/// Encoded size of an ACK naming `count` ranges, given as inclusive [lo, hi] pairs
/// highest first (`los`/`his`).
size_t   ack_frame_size(const uint64_t* los, const uint64_t* his, size_t count, uint64_t delay) noexcept;
uint8_t* put_ack(uint8_t* out, const uint64_t* los, const uint64_t* his, size_t count,
                 uint64_t delay) noexcept;

/// Header of a STREAM frame carrying `len` bytes at `offset`; `with_length` false
/// lets the data run to the end of the packet.
size_t   stream_header_size(uint64_t stream, uint64_t offset, size_t len, bool with_length) noexcept;
uint8_t* put_stream_header(uint8_t* out, uint64_t stream, uint64_t offset, size_t len,
                           bool with_length) noexcept;

/// Header of a LIVE frame carrying `len` bytes at `offset` of message `id`, which
/// is `size` bytes in all and has `lifetime` milliseconds left. A piece that is the
/// whole message is written without its size and offset.
size_t   live_header_size(uint64_t id, uint64_t lifetime, uint64_t size, uint64_t offset,
                          size_t len) noexcept;
uint8_t* put_live_header(uint8_t* out, uint64_t id, uint64_t lifetime, uint64_t size,
                         uint64_t offset, size_t len) noexcept;

/// Header of a LIVE_REPAIR frame: the `symbol` bytes of data follow it.
size_t   live_repair_header_size(uint64_t id, uint64_t lifetime, uint64_t size, uint64_t symbol,
                                 uint64_t index) noexcept;
uint8_t* put_live_repair_header(uint8_t* out, uint64_t id, uint64_t lifetime, uint64_t size,
                                uint64_t symbol, uint64_t index) noexcept;

uint8_t* put_value_frame(uint8_t* out, FrameType type, uint64_t value) noexcept;  ///< MAX_DATA, DATA_BLOCKED, CLOSE
uint8_t* put_reset_token(uint8_t* out, const uint8_t* token) noexcept;

} // namespace udp
} // namespace librats
