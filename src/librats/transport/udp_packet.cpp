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

size_t encode(const Packet& p, uint8_t* out) {
    const uint8_t flags = p.has_sack() ? static_cast<uint8_t>(p.flags)
                                       : static_cast<uint8_t>(p.flags & ~FlagSack);

    out[0] = static_cast<uint8_t>((kVersion << 4) | (static_cast<uint8_t>(p.type) & 0x0F));
    out[1] = flags;
    put_u16(out + 2, p.window);
    put_u32(out + 4,  p.conn_id);
    put_u32(out + 8,  p.seq);
    put_u32(out + 12, p.ack);

    size_t n = kHeaderSize;
    if (flags & FlagSack) {
        put_u32(out + n, p.sack);
        n += kSackSize;
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
    if (type > static_cast<uint8_t>(PacketType::Reset)) return false;

    out.type    = static_cast<PacketType>(type);
    out.flags   = data[1];
    out.window  = get_u16(data + 2);
    out.conn_id = get_u32(data + 4);
    out.seq     = get_u32(data + 8);
    out.ack     = get_u32(data + 12);

    size_t offset = kHeaderSize;
    if (out.has_sack()) {
        if (len < offset + kSackSize) return false;
        out.sack = get_u32(data + offset);
        offset += kSackSize;
    } else {
        out.sack = 0;
    }

    out.payload = ByteView(data + offset, len - offset);

    // Only Data carries a payload. Rejecting bytes on the other types keeps a
    // padded or spliced datagram from ever reaching the stream as stream content,
    // and keeps the accounting ("a Data packet is worth payload.size() bytes")
    // true by construction.
    if (out.type != PacketType::Data && !out.payload.empty()) return false;
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
    }
    return "?";
}

} // namespace rudp
} // namespace librats
