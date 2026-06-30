#pragma once

/**
 * @file store_buffer.h
 * @brief In-RAM cache of blocks whose disk write is still in flight.
 *
 * When a block is handed to the disk for writing it is also parked here, keyed
 * by (piece, offset within piece). A read or hash issued before that write
 * reaches the platter is then satisfied from RAM by overlaying these bytes onto
 * whatever the disk returned — so the engine never reads stale data for a block
 * it has already accepted. The entry is dropped once the write completes.
 *
 * Thread-safe: writers insert/erase from disk-worker threads while readers
 * overlay; all access is guarded by an internal mutex.
 */

#include "core/bytes.h"

#include <cstdint>
#include <map>
#include <mutex>

namespace librats::bittorrent {

class StoreBuffer {
public:
    /// Park a pending block. Replaces any existing entry at the same key.
    void insert(std::uint32_t piece, std::uint32_t offset, const Bytes& data);

    /// Drop a block once its write has landed on disk.
    void erase(std::uint32_t piece, std::uint32_t offset);

    /// Overlay any parked bytes for @p piece that intersect
    /// [@p offset, @p offset + out.size()) onto @p out (indexed from @p offset).
    void overlay(std::uint32_t piece, std::uint32_t offset, Bytes& out) const;

    bool        empty() const;
    std::size_t size()  const;

private:
    using Key = std::pair<std::uint32_t, std::uint32_t>;  // (piece, offset)

    mutable std::mutex   mutex_;
    std::map<Key, Bytes> blocks_;
};

} // namespace librats::bittorrent
