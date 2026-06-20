#pragma once

/**
 * @file address.h
 * @brief A dialable transport address (ip + port).
 *
 * The single ip+port endpoint type used throughout the library — by the node
 * layer (dialing, peer info, reconnection) and by the lower-level engines (DHT,
 * BitTorrent trackers, STUN/TURN). It lives in core/ because it is a foundational
 * transport primitive that every layer above depends on.
 *
 * `ip` holds a bare IP literal or hostname (no brackets). IPv4/hostname endpoints
 * serialise as `host:port`; IPv6 endpoints serialise in bracketed `[ip]:port` form
 * so the colons in the address are never confused with the port separator. parse()
 * accepts both forms and is the exact inverse of to_string().
 */

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace librats {

struct Address {
    std::string ip;
    uint16_t    port = 0;

    Address() = default;
    Address(std::string ip, uint16_t port) : ip(std::move(ip)), port(port) {}

    /// Parse "host:port" or "[ipv6]:port". Returns nullopt if the port is
    /// missing/invalid, or for a bare (unbracketed) IPv6 literal whose own colons
    /// make the port ambiguous. Exact inverse of to_string().
    static std::optional<Address> parse(std::string_view text) {
        if (!text.empty() && text.front() == '[') {
            // Bracketed IPv6: [ip]:port
            const auto close = text.find(']');
            if (close == std::string_view::npos || close + 1 >= text.size() || text[close + 1] != ':')
                return std::nullopt;
            const auto host = text.substr(1, close - 1);
            if (host.empty()) return std::nullopt;
            const auto port = parse_port(text.substr(close + 2));
            if (!port) return std::nullopt;
            return Address{std::string(host), *port};
        }
        const auto colon = text.rfind(':');
        if (colon == std::string_view::npos || colon == 0 || colon + 1 == text.size())
            return std::nullopt;
        const auto host = text.substr(0, colon);
        // A bare IPv6 literal carries its own colons; without brackets the port is
        // ambiguous, so reject it rather than guess.
        if (host.find(':') != std::string_view::npos) return std::nullopt;
        const auto port = parse_port(text.substr(colon + 1));
        if (!port) return std::nullopt;
        return Address{std::string(host), *port};
    }

    /// IPv6 literals (any ip containing ':') serialise bracketed; everything else plain.
    std::string to_string() const {
        if (ip.find(':') != std::string::npos)
            return "[" + ip + "]:" + std::to_string(port);
        return ip + ":" + std::to_string(port);
    }

    bool operator==(const Address& o) const { return ip == o.ip && port == o.port; }
    bool operator!=(const Address& o) const { return !(*this == o); }

private:
    /// Parse a 1..65535 decimal port. nullopt on empty/non-digit/out-of-range/zero.
    static std::optional<uint16_t> parse_port(std::string_view text) {
        if (text.empty()) return std::nullopt;
        unsigned long port = 0;
        for (char c : text) {
            if (c < '0' || c > '9') return std::nullopt;
            port = port * 10 + static_cast<unsigned>(c - '0');
            if (port > 65535) return std::nullopt;
        }
        if (port == 0) return std::nullopt;
        return static_cast<uint16_t>(port);
    }
};

} // namespace librats

namespace std {
template<>
struct hash<librats::Address> {
    std::size_t operator()(const librats::Address& a) const noexcept {
        return std::hash<std::string>{}(a.ip + ":" + std::to_string(a.port));
    }
};
} // namespace std
