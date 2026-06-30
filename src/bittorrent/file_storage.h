#pragma once

/**
 * @file file_storage.h
 * @brief The file layout of a torrent and the piece <-> file mapping.
 *
 * A torrent's payload is one contiguous byte space: files are laid end-to-end
 * in order, each at a running @c offset. Pieces are fixed-size windows over that
 * space (the final piece is short). FileStorage answers the two questions the
 * disk and wire layers need: "how big is piece i?" and "which file regions does
 * a (piece, offset, length) range touch?". The latter (map_block) is O(log n)
 * via a binary search over the sorted file offsets.
 */

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace librats::bittorrent {

/// One file in the torrent. @c path is the full relative path including the
/// torrent name as its first component (so the disk layer just joins it onto
/// the save path). @c offset is the file's start in the torrent byte space.
struct FileEntry {
    std::string  path;
    std::int64_t size   = 0;
    std::int64_t offset = 0;
};

/// A contiguous region of a single file — one fragment of a mapped block.
struct FileSlice {
    std::size_t  file_index = 0;
    std::int64_t offset     = 0;  ///< byte offset within the file
    std::int64_t size       = 0;
};

class FileStorage {
public:
    void set_piece_length(std::uint32_t length) noexcept { piece_length_ = length; }
    void set_name(std::string name) { name_ = std::move(name); }
    /// Append a file (its offset is computed from the running total). Returns
    /// false and leaves the layout unchanged if @p size is negative or would
    /// overflow the int64 running total — a hostile .torrent must be rejected
    /// rather than driving signed-overflow UB and a garbage num_pieces().
    bool add_file(std::string path, std::int64_t size);
    void clear();

    const std::string&            name()         const noexcept { return name_; }
    std::uint32_t                 piece_length() const noexcept { return piece_length_; }
    std::int64_t                  total_size()   const noexcept { return total_size_; }
    std::size_t                   num_files()    const noexcept { return files_.size(); }
    const FileEntry&              file_at(std::size_t i) const { return files_[i]; }
    const std::vector<FileEntry>& files()        const noexcept { return files_; }

    /// A layout is usable once it has a piece length and at least one file.
    bool is_valid() const noexcept { return piece_length_ > 0 && !files_.empty(); }

    std::uint32_t num_pieces() const noexcept;
    /// Size of piece @p piece — piece_length except a possibly-short final piece.
    std::uint32_t piece_size(std::uint32_t piece) const noexcept;
    /// Number of 16 KiB blocks in piece @p piece (the last block may be short).
    std::uint32_t blocks_in_piece(std::uint32_t piece) const noexcept;

    /// Map a byte range within a piece to the file regions it covers. The range
    /// is clamped to the torrent's total size; zero-length files are skipped.
    std::vector<FileSlice> map_block(std::uint32_t piece, std::uint32_t offset,
                                     std::int64_t size) const;

private:
    std::vector<FileEntry> files_;
    std::string            name_;
    std::uint32_t          piece_length_ = 0;
    std::int64_t           total_size_   = 0;
};

} // namespace librats::bittorrent
