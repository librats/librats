#include "node/identify.h"

#include <utility>

namespace librats {

namespace {

void put_u16(Bytes& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}

void put_addr(Bytes& out, const Address& a) {
    out.push_back(static_cast<uint8_t>(a.ip.size()));
    out.insert(out.end(), a.ip.begin(), a.ip.end());
    put_u16(out, a.port);
}

bool emittable(const Address& a) {
    return !a.ip.empty() && a.ip.size() <= IdentifyMessage::kMaxIpLength;
}

/// Bounds-checked forward reader: every read is validated against the remaining
/// length, and the first short read latches `ok` false so the rest are no-ops.
struct Reader {
    const uint8_t* p;
    size_t         n;
    bool           ok = true;

    explicit Reader(ByteView v) : p(v.data()), n(v.size()) {}

    uint8_t u8() {
        if (n < 1) { ok = false; return 0; }
        const uint8_t v = *p;
        ++p; --n;
        return v;
    }
    uint16_t u16() {
        const uint8_t hi = u8();
        const uint8_t lo = u8();
        return static_cast<uint16_t>((hi << 8) | lo);
    }
    std::string str(size_t len) {
        if (n < len) { ok = false; return {}; }
        std::string s(reinterpret_cast<const char*>(p), len);
        p += len; n -= len;
        return s;
    }
};

} // namespace

Bytes IdentifyMessage::encode() const {
    Bytes out;
    out.push_back(kVersion);
    put_u16(out, listen_port);

    // Emit at most kMaxAddresses well-formed addresses; the count prefix matches.
    Bytes addr_blob;
    uint8_t emitted = 0;
    for (const Address& a : addresses) {
        if (emitted >= kMaxAddresses) break;
        if (!emittable(a) || a.port == 0) continue;
        put_addr(addr_blob, a);
        ++emitted;
    }
    out.push_back(emitted);
    out.insert(out.end(), addr_blob.begin(), addr_blob.end());

    // Observed address: an IP length of 0 means "none".
    if (observed && emittable(*observed)) {
        put_addr(out, *observed);
    } else {
        out.push_back(0);
    }
    return out;
}

std::optional<IdentifyMessage> IdentifyMessage::decode(ByteView in) {
    Reader r(in);

    const uint8_t version = r.u8();
    if (!r.ok || version != kVersion) return std::nullopt;  // unknown/old → "no identify"

    IdentifyMessage msg;
    msg.listen_port = r.u16();

    const uint8_t count = r.u8();
    if (!r.ok || count > kMaxAddresses) return std::nullopt;  // capped: never over-reserve
    msg.addresses.reserve(count);
    for (uint8_t i = 0; i < count; ++i) {
        const uint8_t ip_len = r.u8();
        if (!r.ok || ip_len == 0 || ip_len > kMaxIpLength) return std::nullopt;
        std::string ip = r.str(ip_len);
        const uint16_t port = r.u16();
        if (!r.ok) return std::nullopt;
        msg.addresses.push_back(Address{std::move(ip), port});
    }

    const uint8_t obs_len = r.u8();
    if (!r.ok) return std::nullopt;
    if (obs_len != 0) {
        if (obs_len > kMaxIpLength) return std::nullopt;
        std::string ip = r.str(obs_len);
        const uint16_t port = r.u16();
        if (!r.ok) return std::nullopt;
        msg.observed = Address{std::move(ip), port};
    }

    // Trailing bytes (e.g. a future minor extension) are tolerated and ignored.
    return msg;
}

} // namespace librats
