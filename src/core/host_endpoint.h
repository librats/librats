#pragma once

/**
 * @file host_endpoint.h
 * @brief An unresolved dial target: a host (name OR literal) plus a port.
 *
 * The textual counterpart to Address. Where Address is a strictly numeric,
 * already-resolved endpoint you can hand to a socket, a HostEndpoint is what a
 * user (or a config file) supplies: "router.bittorrent.com:6881", a STUN server,
 * a tracker host. Its `host` may be a DNS name or an IP literal; it carries no
 * bytes and does nothing but hold the two fields until the resolver turns it into
 * one or more Address at the network boundary.
 *
 * Keeping this separate is deliberate (see CLAUDE.md): it keeps hostnames — and
 * the allocation/ambiguity they bring — out of the hot-path Address, which stays
 * a small trivially-copyable value.
 */

#include "core/endpoint_parse.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace librats {

struct HostEndpoint {
    std::string host;
    uint16_t    port = 0;

    HostEndpoint() = default;
    HostEndpoint(std::string host, uint16_t port) : host(std::move(host)), port(port) {}

    /// Parse "host:port" or "[ipv6]:port". Accepts hostnames and IP literals alike;
    /// only the port is validated here (resolution happens later). Returns nullopt
    /// if the port is missing/invalid or the host is empty.
    static std::optional<HostEndpoint> parse(std::string_view text) {
        const auto hp = split_host_port(text);
        if (!hp) return std::nullopt;
        return HostEndpoint{std::string(hp->first), hp->second};
    }

    /// Bracket a host that looks like an IPv6 literal (contains ':'), else plain.
    std::string to_string() const {
        if (host.find(':') != std::string::npos)
            return "[" + host + "]:" + std::to_string(port);
        return host + ":" + std::to_string(port);
    }

    bool operator==(const HostEndpoint& o) const { return port == o.port && host == o.host; }
    bool operator!=(const HostEndpoint& o) const { return !(*this == o); }
};

} // namespace librats
