#pragma once

/**
 * @file resume_data.h
 * @brief Fast-resume state: what a torrent needs to pick up where it left off
 *        without re-hashing every piece on disk.
 *
 * It is a small bencoded record — the have-bitfield, transfer totals, save path
 * and (optionally) the verbatim info dictionary so a magnet-started torrent can
 * resume without re-fetching metadata. On load the engine *trusts* the recorded
 * bitfield (skipping the hash check for those pieces); the verbatim info section,
 * if present, is re-hashed against the info-hash before it is believed.
 */

#include "bittorrent/bitfield.h"
#include "bittorrent/types.h"
#include "core/bytes.h"

#include <cstdint>
#include <optional>
#include <string>

namespace librats::bittorrent {

struct ResumeData {
    InfoHash      info_hash{};
    std::string   name;
    std::string   save_path;
    Bitfield      have;                  ///< pieces already on disk
    std::uint64_t total_uploaded   = 0;
    std::uint64_t total_downloaded = 0;
    Bytes         info_dict;             ///< optional verbatim info section

    /// Serialise to the on-disk bencoded form.
    Bytes encode() const;
    /// Parse it back. nullopt if it isn't a librats resume record.
    static std::optional<ResumeData> decode(const Bytes& data);
};

} // namespace librats::bittorrent
