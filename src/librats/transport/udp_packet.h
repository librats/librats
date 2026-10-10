#pragma once

/**
 * @file udp_packet.h
 * @brief Wire format of the reliable-UDP transport: one fixed 16-byte header.
 *
 * A datagram is a header, an optional 4-byte selective-ack word, and (for Data)
 * a payload. Everything is big-endian, and every field is fixed-width, so decode
 * is a handful of loads with a single length check — no allocation, no parsing
 * state, and nothing a hostile datagram can make us over-reserve.
 *
 *      0               1               2               3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-------+-------+---------------+-------------------------------+
 *     |  ver  | type  |     flags     |            window             |
 *     +-------+-------+---------------+-------------------------------+
 *     |                            conn_id                            |
 *     +---------------------------------------------------------------+
 *     |                              seq                              |
 *     +---------------------------------------------------------------+
 *     |                              ack                              |
 *     +---------------------------------------------------------------+
 *     |                     sack  (only if flag Sack)                 |
 *     +---------------------------------------------------------------+
 *
 *  - conn_id : the id the *receiver* registered this stream under, so a single
 *              shared socket can demultiplex thousands of streams with one hash
 *              lookup and no per-peer socket. Each side picks its own; see
 *              udp_stream.h for how the pair is derived from the Syn.
 *  - seq     : sequence number of this packet. Syn, Data and Fin each consume
 *              one (so all three are retransmitted until acknowledged); an Ack
 *              carries the next sequence number to be used and consumes nothing,
 *              which is why a pure acknowledgement is never itself acknowledged.
 *  - ack     : the highest sequence number received *in order* — a cumulative
 *              acknowledgement, so a lost Ack costs nothing as long as a later
 *              one arrives. 0 means "nothing received yet" (sequence numbers
 *              start at 1).
 *  - sack    : a bitmap acknowledging the 32 packets after the hole at ack+1
 *              (bit i ⇒ ack+2+i arrived). This is what lets a single loss be
 *              repaired without stalling everything queued behind it.
 *  - window  : how many further packets the sender of this datagram can buffer,
 *              in packets. This is the flow-control signal; 0 stops the peer.
 *
 * ── Acknowledgement ranges ───────────────────────────────────────────────────
 * The sack word reaches only 32 packets past the first hole, and a window holds a
 * thousand. On a path that loses more than one packet per window, everything
 * past that reach is invisible to the sender until the hole in front of it fills,
 * so holes are found — and repaired — one round trip at a time. A pure Ack may
 * therefore also carry a range block (flag AckRanges):
 *
 *     [count : u8] then count x [offset : u16][length : u16]
 *
 * each entry acknowledging the `length` packets from ack+1+offset on. Ranges
 * name runs of received packets in ascending order, up to kMaxAckRanges of them.
 * They ride only on pure Acks, so a Data packet never grows past kMaxDatagram and
 * the path MTU budget behind kMaxPayload is untouched.
 *
 * A peer from before ranges existed would reject an Ack carrying them, so they
 * are only ever sent to a peer that has said it understands them: every packet
 * carries flag ExtAck ("I parse ranges"), which an older peer simply ignores.
 *
 * Only three types carry anything after the header. Data carries stream bytes.
 * Retry and Syn carry the kCookieSize address-validation cookie, or nothing —
 * a responder under load answers a Syn with a Retry rather than opening a stream,
 * and only a Syn that hands the cookie back costs it any memory (see udp_mux.h).
 * Everything else is header-only, and a datagram that pads one is rejected.
 *
 * Sequence numbers are 32-bit and wrap; compare them only with seq_less/seq_diff,
 * never with < on the raw value.
 */

#include "librats/core/bytes.h"

#include <cstdint>
#include <cstddef>

namespace librats {
namespace rudp {

/// Protocol version carried in the high nibble of byte 0. Bumped only for a
/// change no existing peer could parse; a peer that sees another version drops
/// the datagram (silently — an unauthenticated sender gets no reply).
constexpr uint8_t kVersion = 1;

enum class PacketType : uint8_t {
    Syn   = 0,  ///< open a stream (initiator → responder); consumes a sequence number
    Data  = 1,  ///< stream payload; consumes a sequence number
    Ack   = 2,  ///< pure acknowledgement / window update / keep-alive
    Fin   = 3,  ///< orderly end of the sender's stream; consumes a sequence number
    Reset = 4,  ///< abort now: the stream is gone or was never known
    Retry = 5,  ///< "prove you are at that address first" — carries a cookie, holds no state
};

enum PacketFlags : uint8_t {
    FlagNone      = 0,
    FlagSack      = 1 << 0,  ///< the 4-byte selective-ack word follows the header
    FlagExtAck    = 1 << 1,  ///< the sender understands acknowledgement ranges
    FlagAckRanges = 1 << 2,  ///< (Ack only) a range block follows the sack word
};

/// Bytes on the wire before the payload, without the selective-ack word.
constexpr size_t kHeaderSize = 16;
/// Bytes added by the selective-ack word.
constexpr size_t kSackSize = 4;
/// Packets one selective-ack word can name — the 32 that follow the hole at
/// ack+1. This is a reach as well as a width: from the word alone a sender learns
/// nothing about a packet further than this past its oldest unacknowledged one,
/// which is why a pure Ack may also carry ranges (see the file comment).
constexpr uint32_t kSackBits = 8 * static_cast<uint32_t>(kSackSize);
/// The largest a header can get. A sender that keeps this much headroom in front
/// of a payload can write the header directly ahead of the bytes it describes and
/// hand the socket one contiguous datagram — see encode_header().
constexpr size_t kMaxHeaderSize = kHeaderSize + kSackSize;

/// Bytes of the address-validation cookie a Retry hands out and a Syn hands back
/// (see udp_mux.h). Four is the width of the truncated keyed hash it carries: an
/// attacker who cannot receive at the address it is bound to gets one guess in
/// 2^32 per Syn, which is the same order of protection a TCP SYN cookie encodes
/// into a 32-bit sequence number.
constexpr size_t kCookieSize = 4;

/// Payload carried by one Data packet. 1200 keeps header+payload inside the
/// smallest MTU worth designing for (IPv6's 1280 floor, minus room for an IPv6
/// header plus a tunnel), so a stream never depends on IP fragmentation — which
/// on a datagram path turns one lost fragment into a lost packet.
constexpr size_t kMaxPayload = 1200;

/// Largest datagram this transport ever sends or expects to receive.
constexpr size_t kMaxDatagram = kHeaderSize + kSackSize + kMaxPayload;

/// Bytes one acknowledgement range occupies, and the most one Ack carries. 32
/// ranges is a hole every ~30 packets across a full window — far more than any
/// path that is still worth sending on — in a 149-byte datagram.
constexpr size_t kAckRangeSize = 4;
constexpr size_t kMaxAckRanges = 32;

/// One run of packets the receiver holds: [ack+1+offset, ack+1+offset+length).
struct AckRange {
    uint16_t offset = 0;
    uint16_t length = 0;
};

/// Packets a receiver will hold out of order, and therefore the largest window it
/// ever advertises. This is the hard ceiling on in-flight data, so it is also the
/// ceiling on throughput: a window of W packets on a path of RTT R can never
/// exceed W * kMaxPayload / R, whatever the link underneath can do.
///
/// 1024 * 1200 B ≈ 1.2 MiB, i.e. ~96 Mbit/s at 100 ms and ~48 Mbit/s at 200 ms —
/// enough that an intercontinental path is limited by the path rather than by
/// this constant. (At the previous 256 it was ~24 Mbit/s at 100 ms, well under
/// what TCP would have managed on the same path.)
///
/// It is also what bounds the memory one peer can make us hold: the reorder
/// buffer never holds more than this many packets, so ~1.2 MiB per stream in the
/// worst case. That worst case needs a window's worth of loss to reach, and both
/// the reorder map and the retransmission queue only ever grow to what is
/// actually outstanding — an idle or slow stream costs nothing near it.
constexpr uint16_t kMaxWindowPackets = 1024;
static_assert((kMaxWindowPackets & (kMaxWindowPackets - 1)) == 0 && kMaxWindowPackets % 64 == 0,
              "the receiver indexes its reorder ring by sequence number modulo the window");

struct Packet {
    PacketType type   = PacketType::Ack;
    uint8_t    flags  = FlagNone;
    uint16_t   window = 0;
    uint32_t   conn_id = 0;
    uint32_t   seq     = 0;
    uint32_t   ack     = 0;
    uint32_t   sack    = 0;   ///< meaningful only when (flags & FlagSack)
    /// The encoded range entries (kAckRangeSize bytes each, no count byte) — on
    /// decode they point into the receive buffer, on encode into the sender's.
    /// Only ever on an Ack; see ack_range().
    ByteView   ranges;
    ByteView   payload;       ///< points into the caller's receive buffer

    bool   has_sack()    const noexcept { return (flags & FlagSack) != 0; }
    bool   ext_ack()     const noexcept { return (flags & FlagExtAck) != 0; }
    size_t range_count() const noexcept { return ranges.size() / kAckRangeSize; }
};

/// The i-th range of a decoded Ack. decode() has already checked every one of them
/// is non-empty and lies inside a receive window, so no caller re-validates.
AckRange ack_range(const Packet& p, size_t i) noexcept;

/// Write one range entry (kAckRangeSize bytes) for Packet::ranges.
void encode_ack_range(const AckRange& r, uint8_t* out) noexcept;

/// Bytes `p`'s header occupies on the wire: the fixed part, plus the selective-ack
/// word when one is carried.
inline size_t header_size(const Packet& p) noexcept {
    return p.has_sack() ? kHeaderSize + kSackSize : kHeaderSize;
}

/// Serialise only `p`'s header (and its optional sack word) into `out`, which must
/// have room for kMaxHeaderSize bytes. Neither the payload nor any range block is
/// written (and the AckRanges flag is left clear) — this is the Data path.
///
/// This is the form used on the send path: a packet buffer carries kMaxHeaderSize
/// bytes of headroom in front of its payload, so the header is written directly
/// ahead of the bytes it describes and the whole datagram goes to the socket in
/// one piece — no second copy of the payload just to prefix a header to it.
/// @return the number of bytes written (kHeaderSize, or kHeaderSize + kSackSize).
size_t encode_header(const Packet& p, uint8_t* out);

/// Serialise `p` (header, optional sack word, the range block of an Ack, then
/// payload) into `out`, which must have room for kMaxDatagram bytes.
/// @return the number of bytes written.
size_t encode(const Packet& p, uint8_t* out);

/// Parse one datagram. Returns false for anything malformed: a short buffer, an
/// unknown version, an unknown type, a payload on a type that cannot carry one, or
/// a range block that is not exactly well-formed (on anything but an Ack, empty,
/// past kMaxAckRanges, or reaching outside a receive window).
/// `out.payload` points into `data` and is valid only while that buffer is.
bool decode(const uint8_t* data, size_t len, Packet& out);

// ── Wrapping sequence arithmetic ────────────────────────────────────────────
//
// Sequence numbers advance forever in a 32-bit space, so ordering is only ever
// meaningful over distances far smaller than half that space. Comparing the raw
// values would invert the moment the counter wraps; comparing the *difference* as
// a signed number is correct across the wrap and is what every window check here
// goes through.

/// Signed distance a - b, correct across the 32-bit wrap.
inline int32_t seq_diff(uint32_t a, uint32_t b) noexcept {
    return static_cast<int32_t>(a - b);
}

/// True when a precedes b.
inline bool seq_less(uint32_t a, uint32_t b) noexcept { return seq_diff(a, b) < 0; }

/// True when a precedes or equals b.
inline bool seq_le(uint32_t a, uint32_t b) noexcept { return seq_diff(a, b) <= 0; }

const char* to_string(PacketType) noexcept;

} // namespace rudp
} // namespace librats
