#pragma once

/**
 * @file udp_packet.h
 * @brief Wire format of the reliable-UDP transport: one fixed 20-byte header.
 *
 * A datagram is a header, then (for Data) a payload or (for an Ack) an optional
 * block of acknowledgement ranges. Everything is big-endian, and every field is
 * fixed-width, so decode is a handful of loads with a few length checks — no
 * allocation, no parsing state, and nothing a hostile datagram can make us
 * over-reserve.
 *
 *      0               1               2               3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-------+-------+---------------+-------------------------------+
 *     |  ver  | type  |     flags     |           ack_delay           |
 *     +-------+-------+---------------+-------------------------------+
 *     |                            conn_id                            |
 *     +---------------------------------------------------------------+
 *     |                              seq                              |
 *     +---------------------------------------------------------------+
 *     |                              ack                              |
 *     +---------------------------------------------------------------+
 *     |                             limit                             |
 *     +---------------------------------------------------------------+
 *
 *  - conn_id   : the id the *receiver* registered this stream under, so a single
 *                shared socket can demultiplex thousands of streams with one hash
 *                lookup and no per-peer socket. Each side picks its own; see
 *                udp_stream.h for how the pair is derived from the Syn.
 *  - seq       : sequence number of this packet. Syn, Data and Fin each consume
 *                one (so all three are retransmitted until acknowledged); an Ack
 *                carries the next sequence number to be used and consumes nothing,
 *                which is why a pure acknowledgement is never itself acknowledged.
 *  - ack       : the highest sequence number received *in order* — a cumulative
 *                acknowledgement, so a lost Ack costs nothing as long as a later
 *                one arrives. 0 means "nothing received yet" (sequence numbers
 *                start at 1).
 *  - limit     : the highest sequence number the sender of this datagram will
 *                accept — flow control as an absolute edge rather than a count of
 *                free slots. The edge never moves backwards, so the receiver of it
 *                simply keeps the largest one it has seen: a datagram that was
 *                reordered or duplicated on the way can never shrink a window the
 *                sender has since been given. limit == ack is a closed window.
 *  - ack_delay : how long, in kAckDelayUnit, the sender held the newest packet it
 *                acknowledges before this datagram went out (saturating). It lets
 *                the peer take a delayed acknowledgement out of its round-trip
 *                estimate, as QUIC's ACK frame does.
 *
 * ── Acknowledgement ranges ───────────────────────────────────────────────────
 * The cumulative ack says nothing about what arrived past a hole, and a window
 * holds a thousand packets. A pure Ack therefore carries the runs the receiver
 * holds past it (flag AckRanges):
 *
 *     [count : u8] then count x [offset : u16][length : u16]
 *
 * each entry acknowledging the `length` packets from ack+1+offset on. Ranges come
 * newest first — the peer's loss detection reads the newest delivery — and an Ack
 * that cannot fit them all leaves out the oldest, which earlier Acks named when
 * they were new: nothing a sender learns from a range is ever taken back, so an
 * omission costs nothing. The one exception is a run the newest arrival joined
 * (a repair landing deep in the window): it is always named, in place of the
 * oldest, the way TCP's first SACK block is (RFC 2018).
 *
 * Ranges ride only on pure Acks, so a Data packet never grows past kMaxDatagram
 * and the path MTU budget behind kMaxPayload is untouched. A receiver holding
 * anything out of order answers every packet with one, whatever Data it also has
 * to send.
 *
 * Only three types carry anything after the header. Data carries stream bytes.
 * Retry and Syn carry the kCookieSize address-validation cookie, or nothing —
 * a responder under load answers a Syn with a Retry rather than opening a stream,
 * and only a Syn that hands the cookie back costs it any memory (see udp_mux.h).
 * Everything else is header-only, and a datagram that pads one is rejected.
 *
 * Flag Blocked says the sender has data queued that the receiver's limit is
 * holding back — QUIC's DATA_BLOCKED, as one bit. It is what a receiver grows its
 * window on: the one side that can see a window is too small is the one stopped
 * by it, and a receiver with no traffic of its own to measure a round trip on has
 * no other way to know.
 *
 * Other flag bits are reserved: sent as zero, ignored on receipt.
 *
 * Sequence numbers are 32-bit and wrap; compare them only with seq_less/seq_diff,
 * never with < on the raw value.
 */

#include "librats/core/bytes.h"

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace librats {
namespace rudp {

/// Protocol version carried in the high nibble of byte 0. Bumped only for a
/// change no existing peer could parse; a peer that sees another version drops
/// the datagram (silently — an unauthenticated sender gets no reply), and a dial
/// between the two falls back to TCP. 2: the absolute receive limit, ack_delay,
/// and ranges on every Ack in place of a selective-ack word.
constexpr uint8_t kVersion = 2;

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
    FlagAckRanges = 1 << 0,  ///< (Ack only) a range block follows the header
    FlagBlocked   = 1 << 1,  ///< the sender has data waiting that the peer's limit holds back
};

/// Bytes on the wire before the payload (or the range block). Every packet has
/// exactly this much, so a sender keeping this much headroom in front of a payload
/// can write the header directly ahead of the bytes it describes and hand the
/// socket one contiguous datagram — see encode_header().
constexpr size_t kHeaderSize = 20;

/// Resolution of the ack_delay field. 8 µs (QUIC's default exponent of 3) puts
/// the field's ceiling at ~0.5 s, far beyond any delay a receiver is allowed.
constexpr std::chrono::microseconds kAckDelayUnit{8};

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
constexpr size_t kMaxDatagram = kHeaderSize + kMaxPayload;

/// Bytes one acknowledgement range occupies, and the most one Ack carries. 32
/// runs is a hole every ~30 packets across a full window — far more than any
/// path that is still worth sending on — in a 149-byte datagram, and with older
/// runs dropped first a busier window still loses nothing (see the file comment).
constexpr size_t kAckRangeSize = 4;
constexpr size_t kMaxAckRanges = 32;

/// Furthest past the cumulative ack a range can reach: what a u16 offset and
/// length can name.
constexpr size_t kMaxAckReach = 65536;

/// One run of packets the receiver holds: [ack+1+offset, ack+1+offset+length).
struct AckRange {
    uint16_t offset = 0;
    uint16_t length = 0;
};

/// Packets a receiver will buffer past its cumulative ack — out of order, or in
/// order but not yet read — when a stream starts, and so how far past the ack it
/// first sets its limit. The window grows from here while the sender says it is
/// held back by it (FlagBlocked), up to a ceiling the node configures, and it is
/// the ceiling on throughput while it lasts: a window of W packets on a path of
/// RTT R can never carry more than W * kMaxPayload / R.
///
/// 1024 * 1200 B ≈ 1.2 MiB, i.e. ~96 Mbit/s at 100 ms — enough for most peers
/// never to grow at all, which is what keeps an idle or slow stream cheap.
///
/// Purely the receiver's business: nothing on the wire depends on it, so a peer
/// with a different value interoperates.
constexpr uint32_t kInitialWindowPackets = 1024;

/// The furthest a receive window ever grows: what a range can name past the
/// cumulative ack. ~78 MB of 1200-byte packets — 6 Gbit/s at 100 ms.
constexpr uint32_t kMaxWindowPackets = kMaxAckReach - 1;
static_assert(kInitialWindowPackets <= kMaxWindowPackets, "the window starts inside its ceiling");

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

struct Packet {
    PacketType type      = PacketType::Ack;
    uint8_t    flags     = FlagNone;
    uint16_t   ack_delay = 0;   ///< in kAckDelayUnit
    uint32_t   conn_id   = 0;
    uint32_t   seq       = 0;
    uint32_t   ack       = 0;
    uint32_t   limit     = 0;
    /// The encoded range entries (kAckRangeSize bytes each, no count byte) — on
    /// decode they point into the receive buffer, on encode into the sender's.
    /// Only ever on an Ack; see ack_range().
    ByteView   ranges;
    ByteView   payload;         ///< points into the caller's receive buffer

    size_t range_count() const noexcept { return ranges.size() / kAckRangeSize; }
    /// Packets past the cumulative ack the sender will still accept (0 = closed).
    /// What `limit` says, in the shape of a classic window — for diagnostics.
    uint32_t room() const noexcept {
        const int32_t d = seq_diff(limit, ack);
        return d > 0 ? static_cast<uint32_t>(d) : 0;
    }
};

/// The i-th range of a decoded Ack. decode() has already checked every one of them
/// is non-empty and starts past ack+1, so no caller re-validates.
AckRange ack_range(const Packet& p, size_t i) noexcept;

/// Write one range entry (kAckRangeSize bytes) for Packet::ranges.
void encode_ack_range(const AckRange& r, uint8_t* out) noexcept;

/// Serialise only `p`'s header into `out`, which must have room for kHeaderSize
/// bytes. Neither the payload nor any range block is written (and the AckRanges
/// flag is left clear) — this is the Data path.
///
/// This is the form used on the send path: a packet buffer carries kHeaderSize
/// bytes of headroom in front of its payload, so the header is written directly
/// ahead of the bytes it describes and the whole datagram goes to the socket in
/// one piece — no second copy of the payload just to prefix a header to it.
/// @return kHeaderSize.
size_t encode_header(const Packet& p, uint8_t* out);

/// Serialise `p` (header, the range block of an Ack, then payload) into `out`,
/// which must have room for kMaxDatagram bytes.
/// @return the number of bytes written.
size_t encode(const Packet& p, uint8_t* out);

/// Parse one datagram. Returns false for anything malformed: a short buffer, an
/// unknown version, an unknown type, a payload on a type that cannot carry one, or
/// a range block that is not exactly well-formed (on anything but an Ack, empty,
/// past kMaxAckRanges, naming ack+1, or reaching past kMaxAckReach).
/// `out.payload` points into `data` and is valid only while that buffer is.
bool decode(const uint8_t* data, size_t len, Packet& out);

const char* to_string(PacketType) noexcept;

} // namespace rudp
} // namespace librats
