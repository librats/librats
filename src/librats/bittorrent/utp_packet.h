#pragma once

/**
 * @file utp_packet.h
 * @brief Wire format of uTP (BEP 29): one fixed 20-byte header plus a chain of
 *        optional extension records.
 *
 * uTP is the BitTorrent swarm's UDP transport. Unlike the node's own reliable-UDP
 * layer (`transport/udp_packet.h`), nothing here is ours to choose: every byte is
 * dictated by BEP 29 and by what uTorrent/libtorrent actually put on the wire, so
 * this header exists to pin that format down exactly and nothing else.
 *
 *      0       4       8               16              24              32
 *      +-------+-------+---------------+---------------+---------------+
 *      | type  | ver   | extension     | connection_id                 |
 *      +-------+-------+---------------+---------------+---------------+
 *      | timestamp_microseconds                                        |
 *      +---------------+---------------+---------------+---------------+
 *      | timestamp_difference_microseconds                             |
 *      +---------------+---------------+---------------+---------------+
 *      | wnd_size                                                      |
 *      +---------------+---------------+---------------+---------------+
 *      | seq_nr                        | ack_nr                        |
 *      +---------------+---------------+---------------+---------------+
 *
 * Note the first byte: the *type* is the high nibble and the version the low one,
 * which is the reverse of the layout a reader of the ASCII diagram in BEP 29 might
 * assume. Everything is big-endian.
 *
 *  - connection_id : the id the *receiver* of this datagram registered the stream
 *                    under, so one shared socket demultiplexes every peer with a
 *                    single hash lookup. The two ids of a connection are always
 *                    adjacent (`id` and `id + 1`) — see utp_stream.h.
 *  - timestamp_microseconds : the sender's clock when it put the datagram on the
 *                    wire. The receiver subtracts it from its own clock to get a
 *                    one-way delay sample. The two clocks are unrelated, which is
 *                    fine: only *changes* in the difference carry information.
 *  - timestamp_difference_microseconds : the last such sample the sender measured,
 *                    reflected back. This is the congestion signal LEDBAT runs on
 *                    and the whole reason uTP yields to TCP rather than competing
 *                    with it.
 *  - wnd_size      : the sender's free receive-buffer space **in bytes** (uTP is
 *                    byte-windowed, unlike our own rudp which counts packets).
 *  - seq_nr        : sequence number, in *packets*, of this datagram. ST_SYN,
 *                    ST_DATA and ST_FIN each consume one; ST_STATE consumes none,
 *                    which is why a pure ack is never itself acknowledged.
 *  - ack_nr        : the last sequence number received in order.
 *
 * Sequence numbers are 16-bit and wrap roughly every 65 536 packets — about 80 MB
 * at our payload size, i.e. several times a minute on a fast link. Never compare
 * them with `<`; use seq_less()/seq_diff(), which are correct across the wrap.
 *
 * Extensions form a linked list: the header's `extension` byte names the first
 * record's type, and each record is `[next_type:u8][len:u8][len bytes]`. Type 0
 * ends the chain. We emit only Sack (1) and skip everything else, which is what
 * lets a peer add records (uTorrent's close-reason, type 3) without breaking us.
 */

#include "librats/bittorrent/byte_io.h"
#include "librats/core/bytes.h"

#include <cstddef>
#include <cstdint>

namespace librats::bittorrent::utp {

/// The only protocol version in existence. A datagram carrying anything else is
/// dropped in silence — an unauthenticated sender is owed no answer.
constexpr std::uint8_t kVersion = 1;

/// Packet types, in BEP 29's numbering (which is *not* the order they occur in).
enum class PacketType : std::uint8_t {
    Data  = 0,  ///< stream payload; consumes a sequence number
    Fin   = 1,  ///< orderly end of the sender's stream; consumes a sequence number
    State = 2,  ///< pure acknowledgement / window update; consumes nothing
    Reset = 3,  ///< abort now: the stream is gone or was never known
    Syn   = 4,  ///< open a stream; consumes a sequence number
};
constexpr std::uint8_t kNumPacketTypes = 5;

/// Extension record types. 2 is deliberately absent: an obsolete extension in the
/// wild used it, so BEP 29 skipped it when assigning `close_reason`.
enum class ExtensionType : std::uint8_t {
    None        = 0,
    Sack        = 1,
    CloseReason = 3,
};

constexpr std::size_t kHeaderSize = 20;

/// Bytes of selective-ack bitmap we emit. BEP 29 allows any multiple of 4; 4 bytes
/// name the 32 packets after the hole, which is the same reach our own rudp gives
/// itself and comfortably more than the 3-duplicate-ack window fast retransmit
/// actually acts on.
constexpr std::size_t kSackBytes = 4;

/// Payload one Data packet carries. uTP has no path-MTU discovery here (libtorrent
/// probes; we deliberately do not — see utp_stream.h), so this is chosen to survive
/// any path without IP fragmentation: IPv6's 1280-byte floor, less a 40-byte IPv6
/// header, an 8-byte UDP header and our own 20 + 6 of uTP header and SACK, rounded
/// down. Fragmenting would turn one lost fragment into a lost packet, which on a
/// congestion-controlled stream costs far more than the bytes saved.
constexpr std::size_t kMaxPayload = 1200;

/// Largest datagram we ever send. A peer may send us more (its MTU probe may have
/// found a bigger path), so the receive path sizes its buffer independently.
constexpr std::size_t kMaxDatagram = kHeaderSize + 2 + kSackBytes + kMaxPayload;

/// Biggest datagram we will accept. Generous enough for any real peer's MTU
/// (jumbo frames included) while still bounding what one recvfrom can hand us.
constexpr std::size_t kMaxRecvDatagram = 9216;

/// The decoded fixed header. Extensions are walked separately (see parse_header),
/// because their length is only known after the fact.
struct Header {
    PacketType    type        = PacketType::Data;
    std::uint8_t  version     = 0;
    std::uint8_t  extension   = 0;   ///< type of the first extension record, 0 if none
    std::uint16_t connection_id = 0;
    std::uint32_t timestamp   = 0;   ///< microseconds, sender's clock
    std::uint32_t timestamp_diff = 0;///< microseconds, last one-way delay it measured
    std::uint32_t wnd_size    = 0;   ///< sender's free receive buffer, in bytes
    std::uint16_t seq_nr      = 0;
    std::uint16_t ack_nr      = 0;
};

/// Decode the fixed header. Returns false when the datagram is too short or names
/// a version we do not speak; the type is *not* validated here so the caller can
/// tell an unknown type from a malformed datagram.
inline bool parse_header(const std::uint8_t* data, std::size_t len, Header& out) noexcept {
    if (len < kHeaderSize) return false;
    out.version = std::uint8_t(data[0] & 0x0f);
    if (out.version != kVersion) return false;
    out.type           = PacketType(data[0] >> 4);
    out.extension      = data[1];
    out.connection_id  = read_u16_be(data + 2);
    out.timestamp      = read_u32_be(data + 4);
    out.timestamp_diff = read_u32_be(data + 8);
    out.wnd_size       = read_u32_be(data + 12);
    out.seq_nr         = read_u16_be(data + 16);
    out.ack_nr         = read_u16_be(data + 18);
    return true;
}

/// Write the fixed header into a buffer of at least kHeaderSize bytes.
inline void write_header(std::uint8_t* out, const Header& h) noexcept {
    out[0] = std::uint8_t((std::uint8_t(h.type) << 4) | (kVersion & 0x0f));
    out[1] = h.extension;
    write_u16_be(out + 2,  h.connection_id);
    write_u32_be(out + 4,  h.timestamp);
    write_u32_be(out + 8,  h.timestamp_diff);
    write_u32_be(out + 12, h.wnd_size);
    write_u16_be(out + 16, h.seq_nr);
    write_u16_be(out + 18, h.ack_nr);
}

/// One extension record found while walking the chain.
struct Extension {
    ExtensionType       type = ExtensionType::None;
    const std::uint8_t* data = nullptr;
    std::size_t         len  = 0;
};

/**
 * Walk the extension chain, calling @p fn for each record.
 *
 * @return the offset of the payload (i.e. the total header size), or 0 if the
 *         chain is malformed — a record that claims to run past the end of the
 *         datagram, which a hostile peer can trivially send. Callers must treat 0
 *         as "drop this datagram" rather than "no payload".
 */
template <class Fn>
std::size_t walk_extensions(const std::uint8_t* data, std::size_t len,
                            const Header& h, Fn&& fn) {
    std::size_t off = kHeaderSize;
    std::uint8_t next = h.extension;
    // A chain longer than this is a peer trying to make us spin, not a peer with
    // something to say: BEP 29 defines two record types in total.
    for (int guard = 0; next != 0 && guard < 16; ++guard) {
        if (off + 2 > len) return 0;
        const std::uint8_t type = next;
        next                    = data[off];
        const std::size_t rec   = data[off + 1];
        off += 2;
        if (off + rec > len) return 0;
        fn(Extension{ExtensionType(type), data + off, rec});
        off += rec;
    }
    return next == 0 ? off : 0;
}

// ---- 16-bit sequence arithmetic ----------------------------------------------
//
// Sequence numbers wrap, so "less than" means "fewer than half the space ahead".
// Both helpers are exact inverses of each other over the whole 16-bit range and
// have no undefined behaviour at the wrap point — which is the entire reason they
// exist rather than being written out at each call site.

/// True when @p a precedes @p b in sequence space.
inline bool seq_less(std::uint16_t a, std::uint16_t b) noexcept {
    return std::uint16_t(b - a) != 0 && std::uint16_t(b - a) < 0x8000;
}

/// Signed distance from @p a to @p b (positive when b is ahead).
inline int seq_diff(std::uint16_t b, std::uint16_t a) noexcept {
    return int(std::int16_t(std::uint16_t(b - a)));
}

/// The same "less than, modulo the wrap" test over the full 32-bit space. Used for
/// the microsecond timestamps, which are a truncated clock and therefore wrap just
/// like a sequence number — about every 71 minutes.
inline bool seq_less_u32(std::uint32_t a, std::uint32_t b) noexcept {
    return std::uint32_t(b - a) != 0 && std::uint32_t(b - a) < 0x80000000u;
}

} // namespace librats::bittorrent::utp
