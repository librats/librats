#pragma once

/**
 * @file address.h
 * @brief A dialable transport address (host + port).
 *
 * Deliberately minimal for now: a host string (IP or name) and a port. Parsing
 * splits on the last ':'. IPv6 literals in `[…]:port` form are a known TODO.
 */

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace librats {

struct Address {
    std::string host;
    uint16_t    port = 0;

    Address() = default;
    Address(std::string h, uint16_t p) : host(std::move(h)), port(p) {}

    /// Parse "host:port". Returns nullopt if the port is missing/invalid.
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

    std::string to_string() const { return host + ":" + std::to_string(port); }

    bool operator==(const Address& o) const { return host == o.host && port == o.port; }
};

} // namespace librats
