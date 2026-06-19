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
 * `ip` holds an IP literal or hostname. Parsing splits on the last ':';
 * IPv6 literals in `[…]:port` form are a known TODO.
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

    /// Parse "ip:port". Returns nullopt if the port is missing/invalid.
    static std::optional<Address> parse(std::string_view text) {
        const auto colon = text.rfind(':');
        if (colon == std::string_view::npos || colon == 0 || colon + 1 == text.size())
            return std::nullopt;
        const auto host = text.substr(0, colon);
        const auto port_text = text.substr(colon + 1);
        unsigned long port = 0;
        for (char c : port_text) {
            if (c < '0' || c > '9') return std::nullopt;
            port = port * 10 + static_cast<unsigned>(c - '0');
            if (port > 65535) return std::nullopt;
        }
        if (port == 0) return std::nullopt;
        return Address{std::string(host), static_cast<uint16_t>(port)};
    }

    std::string to_string() const { return ip + ":" + std::to_string(port); }

    bool operator==(const Address& o) const { return ip == o.ip && port == o.port; }
    bool operator!=(const Address& o) const { return !(*this == o); }
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
