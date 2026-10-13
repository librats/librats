#include "librats/transport/udp_wire.h"

#include <algorithm>
#include <cstring>

namespace librats {
namespace udp {

namespace {

void put_u32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

void put_u64(uint8_t* p, uint64_t v) noexcept {
    put_u32(p, static_cast<uint32_t>(v >> 32));
    put_u32(p + 4, static_cast<uint32_t>(v));
}

uint64_t get_u64(const uint8_t* p) noexcept {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

/// `bytes` at `p`; returns the end. An empty view may have no data pointer, and
/// memcpy from null is undefined even for zero bytes.
uint8_t* put_bytes(uint8_t* p, ByteView bytes) noexcept {
    if (!bytes.empty()) std::memcpy(p, bytes.data(), bytes.size());
    return p + bytes.size();
}

/// Byte 0 and the ids every long header starts with.
uint8_t* put_long_header(uint8_t* out, LongType type, Cid dcid, Cid scid) noexcept {
    out[0] = static_cast<uint8_t>(0xC0 | (static_cast<uint8_t>(type) << 4));
    put_u32(out + 1, kVersion);
    put_u64(out + 5, dcid);
    put_u64(out + 13, scid);
    return out + kLongHeaderSize;
}

} // namespace

// ── Varints ─────────────────────────────────────────────────────────────────

uint8_t* put_varint(uint8_t* out, uint64_t v) noexcept {
    switch (varint_size(v)) {
        case 1:
            out[0] = static_cast<uint8_t>(v);
            return out + 1;
        case 2:
            out[0] = static_cast<uint8_t>(0x40 | (v >> 8));
            out[1] = static_cast<uint8_t>(v);
            return out + 2;
        case 4:
            put_u32(out, static_cast<uint32_t>(v) | 0x80000000u);
            return out + 4;
        default:
            put_u64(out, v | (uint64_t{3} << 62));
            return out + 8;
    }
}

bool Reader::varint(uint64_t& v) noexcept {
    if (p_ == end_) return false;
    const size_t n = size_t{1} << (*p_ >> 6);
    if (left() < n) return false;
    uint64_t x = *p_ & 0x3F;
    for (size_t i = 1; i < n; ++i) x = (x << 8) | p_[i];
    p_ += n;
    v = x;
    return true;
}

bool Reader::u8(uint8_t& v) noexcept {
    if (p_ == end_) return false;
    v = *p_++;
    return true;
}

bool Reader::u32(uint32_t& v) noexcept {
    if (left() < 4) return false;
    v = (static_cast<uint32_t>(p_[0]) << 24) | (static_cast<uint32_t>(p_[1]) << 16) |
        (static_cast<uint32_t>(p_[2]) << 8)  |  static_cast<uint32_t>(p_[3]);
    p_ += 4;
    return true;
}

bool Reader::u64(uint64_t& v) noexcept {
    if (left() < 8) return false;
    v = get_u64(p_);
    p_ += 8;
    return true;
}

bool Reader::bytes(size_t n, ByteView& v) noexcept {
    if (left() < n) return false;
    v = ByteView(p_, n);
    p_ += n;
    return true;
}

bool Reader::skip(size_t n) noexcept {
    if (left() < n) return false;
    p_ += n;
    return true;
}

// ── Packets ─────────────────────────────────────────────────────────────────

bool peek_dcid(const uint8_t* data, size_t len, Cid& out) noexcept {
    if (len < 1 || !has_fixed_bit(data[0])) return false;
    const size_t at = is_long_header(data[0]) ? 5 : 1;
    if (len < at + kCidSize) return false;
    out = get_u64(data + at);
    return true;
}

bool decode_long(const uint8_t* data, size_t len, LongPacket& out) noexcept {
    if (len < kLongHeaderSize || (data[0] & 0xC0) != 0xC0) return false;
    if ((data[0] & 0x0F) != 0) return false;   // reserved bits: sent as zero
    Reader r(data + 1, len - 1);
    uint32_t version = 0;
    if (!r.u32(version) || version != kVersion) return false;
    if (!r.u64(out.dcid) || !r.u64(out.scid)) return false;

    out.type    = static_cast<LongType>((data[0] >> 4) & 0x03);
    out.token   = ByteView{};
    out.message = ByteView{};
    out.number  = 0;
    out.error   = 0;

    uint64_t n = 0;
    switch (out.type) {
        case LongType::Initial:
            if (!r.varint(n) || n > kTokenSize || !r.bytes(static_cast<size_t>(n), out.token)) return false;
            if (!r.varint(n) || n > kMaxHandshakeMessage || !r.bytes(static_cast<size_t>(n), out.message))
                return false;
            // The rest is padding, and padding is zeros: a datagram that carries
            // anything else there was not made by this protocol.
            for (const uint8_t* p = r.pos(); p != data + len; ++p)
                if (*p != 0) return false;
            return true;
        case LongType::Handshake:
            if (!r.u8(out.number)) return false;
            if (!r.varint(n) || n > kMaxHandshakeMessage || !r.bytes(static_cast<size_t>(n), out.message))
                return false;
            return r.empty();
        case LongType::Retry:
            return r.bytes(kTokenSize, out.token) && r.empty();
        case LongType::Close:
            return r.varint(out.error) && r.empty();
    }
    return false;
}

size_t encode_initial(uint8_t* out, Cid dcid, Cid scid, ByteView token, ByteView message) noexcept {
    uint8_t* p = put_long_header(out, LongType::Initial, dcid, scid);
    p = put_bytes(put_varint(p, token.size()), token);
    p = put_bytes(put_varint(p, message.size()), message);
    std::memset(p, 0, static_cast<size_t>(out + kMaxDatagram - p));
    return kMaxDatagram;
}

size_t encode_handshake(uint8_t* out, Cid dcid, Cid scid, uint8_t number, ByteView message) noexcept {
    uint8_t* p = put_long_header(out, LongType::Handshake, dcid, scid);
    *p++ = number;
    p = put_bytes(put_varint(p, message.size()), message);
    return static_cast<size_t>(p - out);
}

size_t encode_retry(uint8_t* out, Cid dcid, Cid scid, ByteView token) noexcept {
    uint8_t* p = put_long_header(out, LongType::Retry, dcid, scid);
    std::memcpy(p, token.data(), kTokenSize);
    return kLongHeaderSize + kTokenSize;
}

size_t encode_close(uint8_t* out, Cid dcid, Cid scid, uint64_t error) noexcept {
    uint8_t* p = put_long_header(out, LongType::Close, dcid, scid);
    return static_cast<size_t>(put_varint(p, error) - out);
}

size_t pn_length(uint64_t pn, uint64_t largest_acked, bool have_acked) noexcept {
    // Twice the distance to what the peer is known to have, so a number is never
    // read as one half the space away (RFC 9000 §A.2).
    const uint64_t unacked = have_acked ? pn - largest_acked : pn + 1;
    const uint64_t range   = 2 * unacked;
    if (range < (uint64_t{1} << 8))  return 1;
    if (range < (uint64_t{1} << 16)) return 2;
    if (range < (uint64_t{1} << 24)) return 3;
    return 4;
}

uint64_t decode_pn(uint64_t truncated, size_t len, uint64_t expected) noexcept {
    const uint64_t win  = uint64_t{1} << (8 * len);
    const uint64_t half = win / 2;
    const uint64_t mask = win - 1;
    const uint64_t candidate = (expected & ~mask) | truncated;
    if (candidate + half <= expected && candidate < (uint64_t{1} << 62) - win) return candidate + win;
    if (candidate > expected + half && candidate >= win) return candidate - win;
    return candidate;
}

// ── Frames ──────────────────────────────────────────────────────────────────

AckRanges::AckRanges(const AckFrame& ack) noexcept
    : r_(ack.more.data(), ack.more.size()), left_(ack.range_count),
      largest_(ack.largest), first_range_(ack.first_range) {}

bool AckRanges::next(uint64_t& lo, uint64_t& hi) noexcept {
    if (first_) {
        first_ = false;
        hi  = largest_;
        lo  = largest_ - first_range_;
        lo_ = lo;
        return true;
    }
    if (left_ == 0) return false;
    uint64_t gap = 0, len = 0;
    // Checked when the frame was read, so these cannot fail or underflow.
    r_.varint(gap);
    r_.varint(len);
    --left_;
    hi  = lo_ - gap - 2;
    lo  = hi - len;
    lo_ = lo;
    return true;
}

bool FrameReader::next(Frame& out) noexcept {
    for (;;) {
        if (r_.empty()) return false;
        uint64_t type = 0;
        if (!r_.varint(type)) return fail();
        if (type == kPadding) continue;   // padding runs are skipped whole

        out.type = static_cast<uint8_t>(type);
        if (type >= kStream && type <= (kStream | 0x07)) {
            if (type & kStreamFinBit) return fail();   // streams never end
            out.type = kStream;
            StreamFrame& s = out.stream;
            s.offset = 0;
            if (!r_.varint(s.stream)) return fail();
            if ((type & kStreamOffBit) && !r_.varint(s.offset)) return fail();
            uint64_t len = r_.left();
            if ((type & kStreamLenBit) && !r_.varint(len)) return fail();
            if (len > r_.left() || s.offset + len > kMaxVarint) return fail();
            r_.bytes(static_cast<size_t>(len), s.data);
            return true;
        }

        if (type == kLive || type == (kLive | kLivePieceBit)) {
            out.type = kLive;
            LiveFrame& l = out.live;
            l.offset = 0;
            uint64_t len = 0;
            if (!r_.varint(l.id) || !r_.varint(l.lifetime)) return fail();
            if ((type & kLivePieceBit) && (!r_.varint(l.size) || !r_.varint(l.offset))) return fail();
            if (!r_.varint(len) || len > r_.left()) return fail();
            if (!(type & kLivePieceBit)) l.size = len;
            // A piece names its message's size so the receiver can hold the whole of
            // it from the first piece in; one that cannot be part of such a message
            // is not a piece of anything.
            if (l.size < kInnerHeaderSize || l.size > kMaxLiveMessage || l.offset > l.size ||
                len > l.size - l.offset)
                return fail();
            r_.bytes(static_cast<size_t>(len), l.data);
            return true;
        }

        switch (type) {
            case kLiveRepair: {
                LiveRepairFrame& f = out.repair;
                if (!r_.varint(f.id) || !r_.varint(f.lifetime) || !r_.varint(f.size) ||
                    !r_.varint(f.symbol) || !r_.varint(f.index))
                    return fail();
                if (f.size < kInnerHeaderSize || f.size > kMaxLiveMessage || f.symbol > f.size ||
                    f.symbol < (std::min<uint64_t>)(f.size, kMinRepairSymbol) || f.symbol > r_.left())
                    return fail();
                r_.bytes(static_cast<size_t>(f.symbol), f.data);
                return true;
            }
            case kPing:
                return true;
            case kAck: {
                AckFrame& a = out.ack;
                if (!r_.varint(a.largest) || !r_.varint(a.delay) || !r_.varint(a.range_count) ||
                    !r_.varint(a.first_range))
                    return fail();
                if (a.first_range > a.largest || a.range_count > kMaxAckRanges * 4) return fail();
                // Walk the rest once now, so AckRanges never meets a bad one: every
                // range has to stay at or above packet 0.
                const uint8_t* begin = r_.pos();
                uint64_t lo = a.largest - a.first_range;
                for (uint64_t i = 0; i < a.range_count; ++i) {
                    uint64_t gap = 0, len = 0;
                    if (!r_.varint(gap) || !r_.varint(len)) return fail();
                    if (lo < gap + 2) return fail();
                    const uint64_t hi = lo - gap - 2;
                    if (hi < len) return fail();
                    lo = hi - len;
                }
                a.more = ByteView(begin, static_cast<size_t>(r_.pos() - begin));
                return true;
            }
            case kMaxData:
            case kDataBlocked:
            case kClose:
                return r_.varint(out.value) ? true : fail();
            case kResetToken:
                return r_.bytes(kResetTokenSize, out.token) ? true : fail();
            default:
                return fail();   // a frame this version does not know
        }
    }
}

size_t ack_frame_size(const uint64_t* los, const uint64_t* his, size_t count, uint64_t delay) noexcept {
    size_t n = 1 + varint_size(his[0]) + varint_size(delay) + varint_size(count - 1) +
               varint_size(his[0] - los[0]);
    for (size_t i = 1; i < count; ++i)
        n += varint_size(los[i - 1] - his[i] - 2) + varint_size(his[i] - los[i]);
    return n;
}

uint8_t* put_ack(uint8_t* out, const uint64_t* los, const uint64_t* his, size_t count,
                 uint64_t delay) noexcept {
    *out++ = kAck;
    out = put_varint(out, his[0]);
    out = put_varint(out, delay);
    out = put_varint(out, count - 1);
    out = put_varint(out, his[0] - los[0]);
    for (size_t i = 1; i < count; ++i) {
        out = put_varint(out, los[i - 1] - his[i] - 2);
        out = put_varint(out, his[i] - los[i]);
    }
    return out;
}

size_t stream_header_size(uint64_t stream, uint64_t offset, size_t len, bool with_length) noexcept {
    return 1 + varint_size(stream) + (offset ? varint_size(offset) : 0) +
           (with_length ? varint_size(len) : 0);
}

uint8_t* put_stream_header(uint8_t* out, uint64_t stream, uint64_t offset, size_t len,
                           bool with_length) noexcept {
    uint8_t type = kStream;
    if (offset)      type |= kStreamOffBit;
    if (with_length) type |= kStreamLenBit;
    *out++ = type;
    out = put_varint(out, stream);
    if (offset)      out = put_varint(out, offset);
    if (with_length) out = put_varint(out, len);
    return out;
}

size_t live_header_size(uint64_t id, uint64_t lifetime, uint64_t size, uint64_t offset,
                        size_t len) noexcept {
    const bool piece = offset != 0 || len != size;
    return 1 + varint_size(id) + varint_size(lifetime) +
           (piece ? varint_size(size) + varint_size(offset) : 0) + varint_size(len);
}

uint8_t* put_live_header(uint8_t* out, uint64_t id, uint64_t lifetime, uint64_t size,
                         uint64_t offset, size_t len) noexcept {
    const bool piece = offset != 0 || len != size;
    *out++ = static_cast<uint8_t>(piece ? kLive | kLivePieceBit : kLive);
    out = put_varint(out, id);
    out = put_varint(out, lifetime);
    if (piece) {
        out = put_varint(out, size);
        out = put_varint(out, offset);
    }
    return put_varint(out, len);
}

size_t live_repair_header_size(uint64_t id, uint64_t lifetime, uint64_t size, uint64_t symbol,
                               uint64_t index) noexcept {
    return 1 + varint_size(id) + varint_size(lifetime) + varint_size(size) + varint_size(symbol) +
           varint_size(index);
}

uint8_t* put_live_repair_header(uint8_t* out, uint64_t id, uint64_t lifetime, uint64_t size,
                                uint64_t symbol, uint64_t index) noexcept {
    *out++ = kLiveRepair;
    out = put_varint(out, id);
    out = put_varint(out, lifetime);
    out = put_varint(out, size);
    out = put_varint(out, symbol);
    return put_varint(out, index);
}

uint8_t* put_value_frame(uint8_t* out, FrameType type, uint64_t value) noexcept {
    *out++ = type;
    return put_varint(out, value);
}

uint8_t* put_reset_token(uint8_t* out, const uint8_t* token) noexcept {
    *out++ = kResetToken;
    std::memcpy(out, token, kResetTokenSize);
    return out + kResetTokenSize;
}

} // namespace udp
} // namespace librats
