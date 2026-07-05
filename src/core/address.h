#pragma once

/**
 * @file address.h
 * @brief A dialable transport endpoint: a numeric IP + port.
 *
 * The single ip+port endpoint type used throughout the library — by the node
 * layer (dialing, peer info, reconnection) and by the lower-level engines (DHT,
 * BitTorrent trackers, STUN/TURN). It lives in core/ because it is a foundational
 * transport primitive that every layer above depends on.
 *
 * `ip` is an IpAddress: a strictly numeric, resolved address stored as raw bytes
 * (see core/ip_address.h) — NOT a hostname and NOT a string. An unresolved
 * "host:port" a user typed is a HostEndpoint (core/host_endpoint.h) and only
 * becomes an Address once the resolver runs. This keeps Address a small,
 * allocation-free, trivially-copyable value that hashes and compares by its bytes.
 *
 * IPv4 endpoints serialise as `host:port`; IPv6 endpoints serialise in bracketed
 * `[ip]:port` form so the colons in the address are never confused with the port
 * separator. parse() accepts both forms and is the exact inverse of to_string().
 */

#include "core/ip_address.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace librats {

struct Address {
    IpAddress ip;
    uint16_t  port = 0;

    Address() = default;
    Address(IpAddress ip, uint16_t port) : ip(ip), port(port) {}

    /// Build from a numeric IP literal + port. The literal MUST be a valid
    /// IPv4/IPv6 address (hostnames belong in a HostEndpoint); an invalid literal
    /// yields an unspecified ip (asserts in debug builds). Kept for the many call
    /// sites of the form Address{"1.2.3.4", 80}.
    Address(std::string_view numeric_ip, uint16_t port);

    /// Parse "host:port" or "[ipv6]:port". Returns nullopt if the port is
    /// missing/invalid, if the host is not a numeric IP literal, or for a bare
    /// (unbracketed) IPv6 literal whose own colons make the port ambiguous.
    /// Exact inverse of to_string().
    static std::optional<Address> parse(std::string_view text);

    /// IPv6 endpoints serialise bracketed; everything else plain. "" ip → ":port".
    std::string to_string() const;

    /// A usable dial target: a specified ip and a non-zero port.
    bool is_valid() const noexcept { return !ip.is_unspecified() && port != 0; }

    bool operator==(const Address& o) const noexcept { return port == o.port && ip == o.ip; }
    bool operator!=(const Address& o) const noexcept { return !(*this == o); }
    bool operator<(const Address& o) const noexcept {
        return ip != o.ip ? ip < o.ip : port < o.port;
    }
};

} // namespace librats

namespace std {
template <>
struct hash<librats::Address> {
    std::size_t operator()(const librats::Address& a) const noexcept {
        // Fold the port into the ip hash (FNV-style) — no temporary string.
        std::size_t h = a.ip.hash();
        h ^= (static_cast<std::size_t>(a.port) + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2));
        return h;
    }
};
} // namespace std
