#include "core/ip_address.h"
#include "core/socket.h"  // brings in the platform sockaddr / inet_ntop / inet_pton

#include <cstring>

namespace librats {

IpAddress IpAddress::from_v4(const std::array<uint8_t, 4>& b) {
    IpAddress a;
    std::memcpy(a.bytes_.data(), b.data(), 4);
    a.family_ = Family::V4;
    return a;
}

IpAddress IpAddress::from_v6(const std::array<uint8_t, 16>& b) {
    IpAddress a;
    std::memcpy(a.bytes_.data(), b.data(), 16);
    a.family_ = Family::V6;
    return a;
}

std::optional<IpAddress> IpAddress::from_bytes(ByteView bytes) {
    IpAddress a;
    if (bytes.size() == 4) {
        std::memcpy(a.bytes_.data(), bytes.data(), 4);
        a.family_ = Family::V4;
    } else if (bytes.size() == 16) {
        std::memcpy(a.bytes_.data(), bytes.data(), 16);
        a.family_ = Family::V6;
    } else {
        return std::nullopt;
    }
    return a;
}

std::optional<IpAddress> IpAddress::parse(std::string_view literal) {
    // inet_pton needs a NUL-terminated string; string_view may not be terminated.
    std::string s(literal);

    std::array<uint8_t, 4> v4{};
    if (inet_pton(AF_INET, s.c_str(), v4.data()) == 1)
        return from_v4(v4);

    std::array<uint8_t, 16> v6{};
    if (inet_pton(AF_INET6, s.c_str(), v6.data()) == 1)
        return from_v6(v6);

    return std::nullopt;
}

std::optional<IpAddress> IpAddress::from_sockaddr(const sockaddr* sa) {
    if (!sa) return std::nullopt;
    if (sa->sa_family == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
        std::array<uint8_t, 4> b{};
        std::memcpy(b.data(), &in->sin_addr, 4);
        return from_v4(b);
    }
    if (sa->sa_family == AF_INET6) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
        const auto* raw = reinterpret_cast<const uint8_t*>(&in6->sin6_addr);
        // Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) into a native IPv4 so a dual-stack
        // socket's view of an IPv4 peer compares/hashes identically to a v4 one.
        static const uint8_t v4_mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        if (std::memcmp(raw, v4_mapped_prefix, 12) == 0) {
            std::array<uint8_t, 4> b{};
            std::memcpy(b.data(), raw + 12, 4);
            return from_v4(b);
        }
        std::array<uint8_t, 16> b{};
        std::memcpy(b.data(), raw, 16);
        return from_v6(b);
    }
    return std::nullopt;
}

std::string IpAddress::to_string() const {
    if (family_ == Family::V4) {
        char buf[INET_ADDRSTRLEN] = {0};
        in_addr a{};
        std::memcpy(&a, bytes_.data(), 4);
        if (inet_ntop(AF_INET, &a, buf, sizeof(buf))) return buf;
    } else if (family_ == Family::V6) {
        char buf[INET6_ADDRSTRLEN] = {0};
        in6_addr a{};
        std::memcpy(&a, bytes_.data(), 16);
        if (inet_ntop(AF_INET6, &a, buf, sizeof(buf))) return buf;
    }
    return std::string();
}

size_t IpAddress::to_sockaddr(sockaddr* sa, uint16_t port) const {
    if (family_ == Family::V4) {
        auto* in = reinterpret_cast<sockaddr_in*>(sa);
        std::memset(in, 0, sizeof(*in));
        in->sin_family = AF_INET;
        in->sin_port   = htons(port);
        std::memcpy(&in->sin_addr, bytes_.data(), 4);
        return sizeof(sockaddr_in);
    }
    if (family_ == Family::V6) {
        auto* in6 = reinterpret_cast<sockaddr_in6*>(sa);
        std::memset(in6, 0, sizeof(*in6));
        in6->sin6_family = AF_INET6;
        in6->sin6_port   = htons(port);
        std::memcpy(&in6->sin6_addr, bytes_.data(), 16);
        return sizeof(sockaddr_in6);
    }
    return 0;
}

size_t IpAddress::hash() const noexcept {
    // FNV-1a over the family tag and all 16 bytes.
    uint64_t h = 1469598103934665603ull;
    h = (h ^ static_cast<uint8_t>(family_)) * 1099511628211ull;
    for (uint8_t b : bytes_) h = (h ^ b) * 1099511628211ull;
    return static_cast<size_t>(h);
}

} // namespace librats
