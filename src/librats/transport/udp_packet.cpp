#include "librats/transport/udp_packet.h"

#include <cstring>

namespace librats {
namespace rudp {

namespace {

void put_u16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

void put_u32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

uint16_t get_u16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t get_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |  static_cast<uint32_t>(p[3]);
}

} // namespace

AckRange ack_range(const Packet& p, size_t i) noexcept {
    const uint8_t* e = p.ranges.data() + i * kAckRangeSize;
    return AckRange{get_u16(e), get_u16(e + 2)};
}

void encode_ack_range(const AckRange& r, uint8_t* out) noexcept {
    put_u16(out, r.offset);
    put_u16(out + 2, r.length);
}

size_t encode_header(const Packet& p, uint8_t* out) {
    out[0] = static_cast<uint8_t>((kVersion << 4) | (static_cast<uint8_t>(p.type) & 0x0F));
    out[1] = static_cast<uint8_t>(p.flags & ~FlagAckRanges);
    put_u16(out + 2,  p.ack_delay);
    put_u32(out + 4,  p.conn_id);
    put_u32(out + 8,  p.seq);
    put_u32(out + 12, p.ack);
    put_u32(out + 16, p.limit);
    return kHeaderSize;
}

size_t encode(const Packet& p, uint8_t* out) {
    size_t n = encode_header(p, out);
    const size_t count = p.range_count();
    if (p.type == PacketType::Ack && count > 0) {
        out[1] |= FlagAckRanges;
        out[n++] = static_cast<uint8_t>(count);
        std::memcpy(out + n, p.ranges.data(), count * kAckRangeSize);
        n += count * kAckRangeSize;
    }
    if (!p.payload.empty()) {
        std::memcpy(out + n, p.payload.data(), p.payload.size());
        n += p.payload.size();
    }
    return n;
}

bool decode(const uint8_t* data, size_t len, Packet& out) {
    if (len < kHeaderSize) return false;
    if ((data[0] >> 4) != kVersion) return false;

    const uint8_t type = data[0] & 0x0F;
    if (type > static_cast<uint8_t>(PacketType::Retry)) return false;

    out.type      = static_cast<PacketType>(type);
    out.flags     = data[1];
    out.ack_delay = get_u16(data + 2);
    out.conn_id   = get_u32(data + 4);
    out.seq       = get_u32(data + 8);
    out.ack       = get_u32(data + 12);
    out.limit     = get_u32(data + 16);

    size_t offset = kHeaderSize;
    out.ranges = ByteView{};
    if (out.flags & FlagAckRanges) {
        // Ranges are an acknowledgement's business only, so a Data packet can never
        // have its payload's first bytes mistaken for them (or the reverse).
        if (out.type != PacketType::Ack) return false;
        if (len < offset + 1) return false;
        const size_t count = data[offset++];
        if (count == 0 || count > kMaxAckRanges) return false;
        if (len < offset + count * kAckRangeSize) return false;
        out.ranges = ByteView(data + offset, count * kAckRangeSize);
        offset += count * kAckRangeSize;
        for (size_t i = 0; i < count; ++i) {
            const AckRange r = ack_range(out, i);
            // Offset 0 is ack+1, the packet the cumulative ack says is missing.
            if (r.length == 0 || r.offset == 0) return false;
            if (size_t{r.offset} + r.length > kMaxAckReach) return false;
        }
    }

    out.payload = ByteView(data + offset, len - offset);

    // What a type is allowed to carry after the header. Being strict here is what
    // keeps a padded or spliced datagram from ever reaching a stream as stream
    // content, and keeps the accounting ("a Data packet is worth payload.size()
    // bytes") true by construction.
    switch (out.type) {
        case PacketType::Data:
            break;  // stream bytes, any length up to kMaxPayload
        case PacketType::Syn:
        case PacketType::Retry:
            // The address-validation cookie, or nothing at all. Fixed width, so
            // there is no room to smuggle anything alongside it.
            if (!out.payload.empty() && out.payload.size() != kCookieSize) return false;
            break;
        default:
            if (!out.payload.empty()) return false;  // Ack/Fin/Reset are header-only
            break;
    }
    if (out.payload.size() > kMaxPayload) return false;

    return true;
}

const char* to_string(PacketType t) noexcept {
    switch (t) {
        case PacketType::Syn:   return "SYN";
        case PacketType::Data:  return "DATA";
        case PacketType::Ack:   return "ACK";
        case PacketType::Fin:   return "FIN";
        case PacketType::Reset: return "RESET";
        case PacketType::Retry: return "RETRY";
    }
    return "?";
}

} // namespace rudp
} // namespace librats
