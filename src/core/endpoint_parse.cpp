#include "core/endpoint_parse.h"

namespace librats {

std::optional<uint16_t> parse_port(std::string_view text) {
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

std::optional<std::pair<std::string_view, uint16_t>> split_host_port(std::string_view text) {
    if (!text.empty() && text.front() == '[') {
        // Bracketed IPv6: [ip]:port
        const auto close = text.find(']');
        if (close == std::string_view::npos || close + 1 >= text.size() || text[close + 1] != ':')
            return std::nullopt;
        const auto host = text.substr(1, close - 1);
        if (host.empty()) return std::nullopt;
        const auto port = parse_port(text.substr(close + 2));
        if (!port) return std::nullopt;
        return std::make_pair(host, *port);
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
    return std::make_pair(host, *port);
}

} // namespace librats
