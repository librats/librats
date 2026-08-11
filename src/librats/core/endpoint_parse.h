#pragma once

/**
 * @file endpoint_parse.h
 * @brief Shared textual "host:port" parsing for Address and HostEndpoint.
 *
 * Both the numeric Address and the unresolved HostEndpoint accept exactly the same
 * surface syntax — "host:port" or bracketed "[ipv6]:port" — and reject the same
 * malformed inputs (missing/invalid port, empty host, a bare unbracketed IPv6 whose
 * own colons make the port ambiguous). The only difference is what each does with
 * the host afterwards (parse it as a numeric literal vs. keep it verbatim), so the
 * structural split lives here once instead of being copy-pasted into each parse().
 */

#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>

namespace librats {

/// Parse a 1..65535 decimal port. nullopt on empty/non-digit/out-of-range/zero.
std::optional<uint16_t> parse_port(std::string_view text);

/// Split "host:port" or "[ipv6]:port" into (host, port). Returns nullopt for a
/// missing/invalid port, an empty host, or a bare (unbracketed) IPv6 literal whose
/// colons make the port ambiguous. The returned host view points into `text` and is
/// valid for its lifetime (brackets, if any, are stripped).
std::optional<std::pair<std::string_view, uint16_t>> split_host_port(std::string_view text);

} // namespace librats
