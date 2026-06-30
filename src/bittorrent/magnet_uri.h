#pragma once

/**
 * @file magnet_uri.h
 * @brief Parsing of magnet links (BEP 9 / BEP 53 subset).
 *
 * A magnet link carries an info-hash (and optionally a name, trackers and web
 * seeds) but no metadata — the file list and piece hashes must still be fetched
 * from peers via ut_metadata. We accept the v1 `xt=urn:btih:` form with either a
 * 40-char hex or a 32-char base32 SHA-1.
 */

#include "bittorrent/types.h"

#include <optional>
#include <string>
#include <vector>

namespace librats::bittorrent {

struct MagnetUri {
    InfoHash                 info_hash{};
    std::string              display_name;   ///< dn
    std::vector<std::string> trackers;       ///< tr
    std::vector<std::string> web_seeds;      ///< ws

    bool is_valid() const noexcept { return !is_all_zero(info_hash); }

    /// Parse a "magnet:?…" URI. nullopt if it is not a magnet link or carries no
    /// valid v1 info-hash.
    static std::optional<MagnetUri> parse(const std::string& uri);
};

} // namespace librats::bittorrent
