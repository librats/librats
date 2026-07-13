#include "wire/frame.h"
#include "core/socket.h"  // htonl/htons/ntohl/ntohs (winsock or arpa/inet)

#include <cstring>

namespace librats {
namespace framer {

// ── Outer block ─────────────────────────────────────────────────────────────

void encode_block_header(uint8_t* out, size_t body_size) {
    const uint32_t net_len = htonl(static_cast<uint32_t>(body_size));
    std::memcpy(out, &net_len, kLengthPrefixSize);
}

void encode_block(Bytes& out, ByteView body) {
    const size_t at = out.size();
    out.resize(at + kLengthPrefixSize + body.size());

    uint8_t* p = out.data() + at;
    encode_block_header(p, body.size());
    if (!body.empty()) std::memcpy(p + kLengthPrefixSize, body.data(), body.size());
}

Block try_take_block(const uint8_t* data, size_t size) {
    Block out;
    if (size < kLengthPrefixSize) { out.status = Block::Incomplete; return out; }

    uint32_t net_len = 0;
    std::memcpy(&net_len, data, 4);
    const uint32_t len = ntohl(net_len);

    if (len > kMaxBlockSize) { out.status = Block::Error; return out; }

    const size_t total = kLengthPrefixSize + len;
    out.needed = total;  // the prefix is in: we now know the whole block's size
    if (size < total) { out.status = Block::Incomplete; return out; }

    out.status   = Block::Ok;
    out.consumed = total;
    out.body     = ByteView(data + kLengthPrefixSize, len);
    return out;
}

// ── Inner message ───────────────────────────────────────────────────────────

void encode_message(Bytes& out, FrameHeader header, ByteView payload) {
    const size_t at = out.size();
    out.resize(at + kHeaderSize + payload.size());

    uint8_t* p = out.data() + at;
    *p++ = static_cast<uint8_t>(header.type);
    *p++ = header.flags;
    const uint16_t net_ch = htons(header.channel);
    std::memcpy(p, &net_ch, 2);
    p += 2;
    if (!payload.empty()) std::memcpy(p, payload.data(), payload.size());
}

Message parse_message(ByteView inner) {
    Message out;
    if (inner.size() < kHeaderSize) return out;  // ok stays false

    const uint8_t* p = inner.data();
    out.frame.header.type  = static_cast<MessageType>(p[0]);
    out.frame.header.flags = p[1];
    uint16_t net_ch = 0;
    std::memcpy(&net_ch, p + 2, 2);
    out.frame.header.channel = ntohs(net_ch);
    out.frame.payload = ByteView(p + kHeaderSize, inner.size() - kHeaderSize);
    out.ok = true;
    return out;
}

} // namespace framer
} // namespace librats
