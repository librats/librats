#pragma once

/**
 * @file torrent_info.h
 * @brief Parsed torrent metadata: file layout, piece hashes, trackers, info-hash.
 *
 * A TorrentInfo is built from a .torrent file, a bare info dictionary (received
 * via ut_metadata) or a magnet link. From a magnet it is "valid but without
 * metadata" — it knows only the info-hash until set_metadata() completes it.
 *
 * The info-hash is the SHA-1 of the *exact* bytes of the bencoded `info`
 * dictionary. We therefore keep those bytes verbatim (info_dict_bytes_) rather
 * than re-encoding the parsed structure, so re-serving them over BEP 9 and
 * re-hashing always reproduce the original hash.
 */

#include "bittorrent/file_storage.h"
#include "bittorrent/types.h"
#include "core/bytes.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace librats { class BencodeValue; }

namespace librats::bittorrent {

/// Diagnostic for a parse failure (optional out-param of the factories).
struct TorrentParseError {
    std::string message;
};

class TorrentInfo {
public:
    using TrackerTier = std::vector<std::string>;
    struct DhtNode { std::string host; std::uint16_t port = 0; };

    TorrentInfo() = default;

    // ---- Factories ----
    static std::optional<TorrentInfo> from_bytes(const Bytes& data, TorrentParseError* err = nullptr);
    static std::optional<TorrentInfo> from_file(const std::string& path, TorrentParseError* err = nullptr);
    static std::optional<TorrentInfo> from_magnet(const std::string& uri, TorrentParseError* err = nullptr);
    /// Build directly from a bencoded info dict. If @p expected is non-zero, the
    /// computed info-hash must match it.
    static std::optional<TorrentInfo> from_info_dict(const Bytes& info_dict_bytes,
                                                     const InfoHash& expected,
                                                     TorrentParseError* err = nullptr);

    /// Complete a magnet-built TorrentInfo with the info dict fetched from peers.
    /// Returns false (leaving the object unchanged) if the bytes don't hash to
    /// the expected info-hash or fail to parse.
    bool set_metadata(const Bytes& info_dict_bytes);

    // ---- Core properties ----
    bool is_valid()     const noexcept { return !is_all_zero(info_hash_); }
    bool has_metadata() const noexcept { return has_metadata_; }

    const InfoHash&   info_hash()     const noexcept { return info_hash_; }
    std::string       info_hash_hex() const           { return to_hex(info_hash_); }
    const std::string& name()         const noexcept { return name_; }
    const std::string& comment()      const noexcept { return comment_; }
    const std::string& created_by()   const noexcept { return created_by_; }
    std::int64_t       creation_date()const noexcept { return creation_date_; }
    bool               is_private()   const noexcept { return is_private_; }

    // ---- File & piece info ----
    const FileStorage& files()        const noexcept { return files_; }
    std::int64_t       total_size()   const noexcept { return files_.total_size(); }
    std::size_t        num_files()    const noexcept { return files_.num_files(); }
    std::uint32_t      piece_length() const noexcept { return files_.piece_length(); }
    std::uint32_t      num_pieces()   const noexcept { return files_.num_pieces(); }
    std::uint32_t      piece_size(std::uint32_t i) const noexcept { return files_.piece_size(i); }

    /// 20-byte SHA-1 of piece @p index (all-zero if out of range).
    std::array<std::uint8_t, 20> piece_hash(std::uint32_t index) const;
    const Bytes& piece_hashes() const noexcept { return piece_hashes_; }

    // ---- Trackers / seeds / nodes ----
    const std::string&              announce()      const noexcept { return announce_; }
    const std::vector<TrackerTier>& announce_list() const noexcept { return announce_list_; }
    std::vector<std::string>        all_trackers()  const;
    const std::vector<std::string>& web_seeds()     const noexcept { return web_seeds_; }
    const std::vector<DhtNode>&     dht_nodes()      const noexcept { return dht_nodes_; }

    // ---- Raw info dict (for BEP 9) ----
    const Bytes& info_dict_bytes() const noexcept { return info_dict_bytes_; }
    std::size_t  metadata_size()   const noexcept { return info_dict_bytes_.size(); }

    /// Build a magnet URI for this torrent.
    std::string to_magnet_uri(bool include_trackers = true) const;

private:
    /// Parse name/piece-length/pieces/files/private out of a bencoded info dict
    /// into files_ and piece_hashes_. Does not touch info_hash_/info_dict_bytes_.
    bool parse_info_dict(const librats::BencodeValue& info, TorrentParseError* err);

    InfoHash                 info_hash_{};
    std::string              name_;
    std::string              comment_;
    std::string              created_by_;
    std::int64_t             creation_date_ = 0;
    bool                     is_private_   = false;
    bool                     has_metadata_ = false;
    FileStorage              files_;
    Bytes                    piece_hashes_;
    std::string              announce_;
    std::vector<TrackerTier> announce_list_;
    std::vector<std::string> web_seeds_;
    std::vector<DhtNode>     dht_nodes_;
    Bytes                    info_dict_bytes_;
};

} // namespace librats::bittorrent
