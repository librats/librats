#include "bittorrent/file_storage.h"
#include "bittorrent/types.h"  // kBlockSize

#include <algorithm>
#include <limits>

namespace librats::bittorrent {

bool FileStorage::add_file(std::string path, std::int64_t size) {
    // Reject a negative size or a running total that would overflow int64: a
    // hostile .torrent could otherwise trigger signed-overflow UB here and a
    // garbage num_pieces() downstream. Leave the layout untouched so the caller
    // can bail cleanly.
    if (size < 0 || size > std::numeric_limits<std::int64_t>::max() - total_size_)
        return false;
    files_.push_back(FileEntry{std::move(path), size, total_size_});
    total_size_ += size;
    return true;
}

void FileStorage::clear() {
    files_.clear();
    name_.clear();
    piece_length_ = 0;
    total_size_   = 0;
}

std::uint32_t FileStorage::num_pieces() const noexcept {
    if (piece_length_ == 0) return 0;
    return std::uint32_t((total_size_ + piece_length_ - 1) / piece_length_);
}

std::uint32_t FileStorage::piece_size(std::uint32_t piece) const noexcept {
    const std::uint32_t n = num_pieces();
    if (piece + 1 < n) return piece_length_;
    // Final piece: the remainder. (Also the only piece for tiny torrents.)
    const std::int64_t tail = total_size_ - std::int64_t(piece) * piece_length_;
    if (tail <= 0) return 0;
    return std::uint32_t(std::min<std::int64_t>(tail, piece_length_));
}

std::uint32_t FileStorage::blocks_in_piece(std::uint32_t piece) const noexcept {
    const std::uint32_t ps = piece_size(piece);
    return (ps + kBlockSize - 1) / kBlockSize;
}

std::vector<FileSlice> FileStorage::map_block(std::uint32_t piece, std::uint32_t offset,
                                              std::int64_t size) const {
    std::vector<FileSlice> slices;
    if (size <= 0 || files_.empty()) return slices;

    std::int64_t abs = std::int64_t(piece) * piece_length_ + offset;
    if (abs >= total_size_) return slices;
    std::int64_t remaining = (std::min)(size, total_size_ - abs);  // clamp to payload

    // Binary search: the file containing `abs` is the last one whose offset <= abs.
    // (Zero-length files share an offset with the following file; picking the last
    // such index lands on the real, non-empty file, and the loop skips empties.)
    std::size_t f = std::size_t(
        std::upper_bound(files_.begin(), files_.end(), abs,
                         [](std::int64_t a, const FileEntry& e) { return a < e.offset; })
        - files_.begin());
    if (f > 0) --f;

    while (remaining > 0 && f < files_.size()) {
        const std::int64_t file_off = abs - files_[f].offset;
        if (file_off >= files_[f].size) { ++f; continue; }  // empty / already past this file
        const std::int64_t take = (std::min)(remaining, files_[f].size - file_off);
        slices.push_back(FileSlice{f, file_off, take});
        remaining -= take;
        abs       += take;
        ++f;
    }
    return slices;
}

} // namespace librats::bittorrent
