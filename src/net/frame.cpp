#include "net/frame.h"
#include "socket.h"  // htonl/htons/ntohl/ntohs (winsock or arpa/inet)

#include <cstring>

namespace librats {
namespace framer {

void encode(Bytes& out, FrameHeader header, ByteView payload) {
    const uint32_t body = static_cast<uint32_t>(kHeaderSize + payload.size());
    const size_t   at   = out.size();
    out.resize(at + kLengthPrefixSize + body);

    uint8_t* p = out.data() + at;

    const uint32_t net_len = htonl(body);
    std::memcpy(p, &net_len, 4);
    p += 4;

    *p++ = static_cast<uint8_t>(header.type);
    *p++ = header.flags;

    const uint16_t net_ch = htons(header.channel);
    std::memcpy(p, &net_ch, 2);
    p += 2;

    if (!payload.empty()) {
        std::memcpy(p, payload.data(), payload.size());
    }
}

Decoded try_decode(const uint8_t* data, size_t size) {
    Decoded out;

    if (size < kLengthPrefixSize) {
        out.status = Decoded::Incomplete;
        return out;
    }

    uint32_t net_len = 0;
    std::memcpy(&net_len, data, 4);
    const uint32_t body = ntohl(net_len);

    // The body must at least contain the fixed header, and stay within the cap.
    if (body < kHeaderSize || body > kMaxFrameSize) {
        out.status = Decoded::Error;
        return out;
    }

    const size_t total = kLengthPrefixSize + body;
    if (size < total) {
        out.status = Decoded::Incomplete;
        return out;
    }

    const uint8_t* p = data + kLengthPrefixSize;

    FrameHeader h;
    h.type  = static_cast<MessageType>(p[0]);
    h.flags = p[1];
    uint16_t net_ch = 0;
    std::memcpy(&net_ch, p + 2, 2);
    h.channel = ntohs(net_ch);

    out.status        = Decoded::Ok;
    out.consumed      = total;
    out.frame.header  = h;
    out.frame.payload = ByteView(p + kHeaderSize, body - kHeaderSize);
    return out;
}

} // namespace framer
} // namespace librats
