#pragma once

/**
 * @file torrent_creator.h
 * @brief Build a .torrent from files on disk.
 *
 * Point it at a file or directory; it lays the files end-to-end, hashes every
 * piece (SHA-1), and emits both a parsed TorrentInfo and the bencoded .torrent
 * bytes. The resulting metadata is exactly what a downloader would receive, so
 * the creator can immediately seed via Client::add_torrent_for_seeding.
 */

#include "bittorrent/torrent_info.h"
#include "bittorrent/types.h"
#include "core/bytes.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace librats::bittorrent {

class TorrentCreator {
public:
    void set_piece_length(std::uint32_t length) { piece_length_ = length; }
    void set_name(std::string name)             { name_ = std::move(name); }
    void add_tracker(std::string url)           { trackers_.push_back(std::move(url)); }
    void set_private(bool is_private)           { private_ = is_private; }
    void set_comment(std::string comment)       { comment_ = std::move(comment); }
    void set_created_by(std::string creator)    { created_by_ = std::move(creator); }

    /// Hash @p path (a file or directory) and build the torrent. On success the
    /// bencoded form is available via torrent_file(). Returns nullopt (and sets
    /// @p error, if given) on I/O or layout problems.
    std::optional<TorrentInfo> create_from_path(const std::string& path, std::string* error = nullptr);

    const Bytes& torrent_file() const noexcept { return torrent_bytes_; }

private:
    std::uint32_t            piece_length_ = kDefaultPieceLength;
    std::string              name_;
    std::string              comment_;
    std::string              created_by_;
    bool                     private_ = false;
    std::vector<std::string> trackers_;
    Bytes                    torrent_bytes_;
};

} // namespace librats::bittorrent
