#include "bittorrent/store_buffer.h"

#include <algorithm>

namespace librats::bittorrent {

void StoreBuffer::insert(std::uint32_t piece, std::uint32_t offset, const Bytes& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocks_[{piece, offset}] = data;
}

void StoreBuffer::erase(std::uint32_t piece, std::uint32_t offset) {
    std::lock_guard<std::mutex> lock(mutex_);
    blocks_.erase({piece, offset});
}

void StoreBuffer::overlay(std::uint32_t piece, std::uint32_t offset, Bytes& out) const {
    if (out.empty()) return;
    const std::uint64_t read_begin = offset;
    const std::uint64_t read_end   = offset + out.size();

    std::lock_guard<std::mutex> lock(mutex_);
    // Walk only this piece's entries: keys in [(piece,0), (piece+1,0)).
    auto it  = blocks_.lower_bound({piece, 0});
    auto end = (piece == UINT32_MAX) ? blocks_.end() : blocks_.lower_bound({piece + 1, 0});
    for (; it != end; ++it) {
        const std::uint64_t blk_begin = it->first.second;
        const std::uint64_t blk_end   = blk_begin + it->second.size();
        const std::uint64_t from = std::max(read_begin, blk_begin);
        const std::uint64_t to   = std::min(read_end, blk_end);
        if (from >= to) continue;  // no intersection
        std::copy(it->second.begin() + std::ptrdiff_t(from - blk_begin),
                  it->second.begin() + std::ptrdiff_t(to - blk_begin),
                  out.begin() + std::ptrdiff_t(from - read_begin));
    }
}

bool StoreBuffer::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blocks_.empty();
}

std::size_t StoreBuffer::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blocks_.size();
}

} // namespace librats::bittorrent
