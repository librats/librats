#pragma once

/**
 * @file ip_address.h
 * @brief A numeric IP address (IPv4 or IPv6) stored as raw bytes.
 *
 * The building block of a dialable endpoint. Unlike a textual "1.2.3.4" this is
 * a fixed 16-byte value + a family tag — trivially copyable, allocation-free, and
 * cheap to hash/compare (it is just its bytes). Text only appears at the edges:
 * parse() on input, to_string() for logs/serialisation. Raw bytes flow straight
 * through the hot paths (sockaddr conversion, BEP 42, the DHT compact codec).
 *
 * An IpAddress is strictly NUMERIC — it never holds a hostname. An unresolved
 * "host:port" the user typed is a HostEndpoint (core/host_endpoint.h); it becomes
 * one or more IpAddress only after the resolver runs at the network boundary.
 */

#include "core/bytes.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

struct sockaddr;

namespace librats {

class IpAddress {
public:
    enum class Family : uint8_t { None, V4, V6 };

    /// The unspecified address (is_unspecified() == true).
    IpAddress() = default;

    /// Parse a bare numeric literal — "1.2.3.4" or "2001:db8::1" (no brackets, no
    /// port). nullopt for anything that is not a valid IPv4/IPv6 literal (including
    /// hostnames — those are a HostEndpoint, not an IpAddress).
    static std::optional<IpAddress> parse(std::string_view literal);

    static IpAddress from_v4(const std::array<uint8_t, 4>& b);
    static IpAddress from_v6(const std::array<uint8_t, 16>& b);

    /// Build from raw address bytes: exactly 4 (IPv4) or 16 (IPv6). nullopt for any
    /// other length. This is the compact/wire form used by the DHT and PEX.
    static std::optional<IpAddress> from_bytes(ByteView bytes);

    /// Build from a sockaddr (AF_INET / AF_INET6). nullopt for other families.
    /// An IPv4-mapped IPv6 sockaddr (::ffff:a.b.c.d) is unwrapped to a plain IPv4.
    static std::optional<IpAddress> from_sockaddr(const sockaddr* sa);

    bool   is_v4()          const noexcept { return family_ == Family::V4; }
    bool   is_v6()          const noexcept { return family_ == Family::V6; }
    bool   is_unspecified() const noexcept { return family_ == Family::None; }
    Family family()         const noexcept { return family_; }

    /// Not a dialable endpoint: either unspecified, or the all-zero wildcard
    /// (0.0.0.0 / ::) that INADDR_ANY-style "any interface" bindings carry.
    bool is_any() const noexcept {
        if (family_ == Family::None) return true;
        for (size_t i = 0, n = size(); i < n; ++i)
            if (bytes_[i] != 0) return false;
        return true;
    }

    /// The significant address bytes: 4 for IPv4, 16 for IPv6, empty otherwise.
    /// The view is valid for the lifetime of this IpAddress.
    ByteView bytes() const noexcept { return ByteView(bytes_.data(), size()); }
    size_t   size()  const noexcept {
        return family_ == Family::V6 ? 16 : (family_ == Family::V4 ? 4 : 0);
    }

    /// Textual form via inet_ntop ("" for the unspecified address).
    std::string to_string() const;

    /// Fill *sa (must point to storage at least sizeof(sockaddr_in6)) with this
    /// address and `port`. Returns the sockaddr length written, or 0 if unspecified.
    size_t to_sockaddr(sockaddr* sa, uint16_t port) const;

    bool operator==(const IpAddress& o) const noexcept {
        return family_ == o.family_ && bytes_ == o.bytes_;
    }
    bool operator!=(const IpAddress& o) const noexcept { return !(*this == o); }
    bool operator<(const IpAddress& o) const noexcept {
        return family_ != o.family_ ? family_ < o.family_ : bytes_ < o.bytes_;
    }

    /// Hash over (family, all 16 bytes). Unused tail bytes are always zero, so this
    /// is well-defined without masking.
    size_t hash() const noexcept;

private:
    // v4 occupies the first 4 bytes (tail kept zero); v6 uses all 16.
    std::array<uint8_t, 16> bytes_{};
    Family                  family_ = Family::None;
};

} // namespace librats

namespace std {
template <>
struct hash<librats::IpAddress> {
    size_t operator()(const librats::IpAddress& a) const noexcept { return a.hash(); }
};
} // namespace std
