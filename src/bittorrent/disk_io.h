#pragma once

/**
 * @file disk_io.h
 * @brief Asynchronous piece storage — the boundary between the network thread
 *        and the filesystem.
 *
 * The engine never blocks on disk: it submits async_read / async_write /
 * async_hash / async_check_files jobs and is called back with the result. DiskIo
 * is an interface so a torrent can be tested against an in-memory fake, and so
 * the threading strategy is swappable.
 *
 * Completions are delivered through a CompletionPoster — a closure the owner
 * supplies to marshal handlers onto its own thread (the reactor, in the full
 * engine). With no poster, handlers run inline on the disk-worker thread.
 *
 * Offsets passed to read/write/hash are relative to the *piece* (piece index +
 * byte offset within it); ThreadedDiskIo translates them to file regions via
 * FileStorage::map_block.
 */

#include "bittorrent/bitfield.h"
#include "bittorrent/file_storage.h"
#include "bittorrent/store_buffer.h"
#include "bittorrent/torrent_info.h"
#include "core/bytes.h"

#include <array>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace librats::bittorrent {

/// Marshals a completion closure onto the owner's thread. If empty, handlers run
/// inline on the disk-worker thread.
using CompletionPoster = std::function<void(std::function<void()>)>;

using DiskReadHandler     = std::function<void(bool ok, Bytes data)>;
using DiskWriteHandler    = std::function<void(bool ok)>;
using DiskHashHandler     = std::function<void(bool ok, std::array<std::uint8_t, 20> sha1)>;
using DiskCheckProgress   = std::function<void(std::uint32_t piece, std::uint32_t total)>;
using DiskCheckHandler    = std::function<void(Bitfield have)>;

class DiskIo {
public:
    virtual ~DiskIo() = default;

    /// Read @p length bytes at @p offset within @p piece.
    virtual void async_read(std::uint32_t piece, std::uint32_t offset, std::uint32_t length,
                            DiskReadHandler handler) = 0;

    /// Write a block at @p offset within @p piece.
    virtual void async_write(std::uint32_t piece, std::uint32_t offset, Bytes data,
                             DiskWriteHandler handler) = 0;

    /// SHA-1 the whole of @p piece (for hash verification by the caller).
    virtual void async_hash(std::uint32_t piece, DiskHashHandler handler) = 0;

    /// Verify which pieces are already complete on disk. Pieces whose bit is set
    /// in @p trusted_have are accepted without re-hashing (fast resume); the rest
    /// are read and hashed. @p progress fires per piece (may be null).
    virtual void async_check_files(Bitfield trusted_have, DiskCheckProgress progress,
                                   DiskCheckHandler handler) = 0;

    /// Stop workers and quiesce. Safe to call more than once.
    virtual void stop() = 0;
};

/// Disk subsystem backed by a small pool of worker threads.
class ThreadedDiskIo final : public DiskIo {
public:
    struct Config {
        int num_threads = 2;
    };

    ThreadedDiskIo(const TorrentInfo& info, std::string save_path,
                   CompletionPoster poster, Config config);

    // Convenience overloads (defined inline so Config{} sits in a complete-class
    // context — it cannot appear in a default argument of the primary ctor).
    explicit ThreadedDiskIo(const TorrentInfo& info, std::string save_path)
        : ThreadedDiskIo(info, std::move(save_path), CompletionPoster{}, Config{}) {}
    ThreadedDiskIo(const TorrentInfo& info, std::string save_path, CompletionPoster poster)
        : ThreadedDiskIo(info, std::move(save_path), std::move(poster), Config{}) {}

    ~ThreadedDiskIo() override;

    ThreadedDiskIo(const ThreadedDiskIo&) = delete;
    ThreadedDiskIo& operator=(const ThreadedDiskIo&) = delete;

    void async_read(std::uint32_t piece, std::uint32_t offset, std::uint32_t length,
                    DiskReadHandler handler) override;
    void async_write(std::uint32_t piece, std::uint32_t offset, Bytes data,
                     DiskWriteHandler handler) override;
    void async_hash(std::uint32_t piece, DiskHashHandler handler) override;
    void async_check_files(Bitfield trusted_have, DiskCheckProgress progress,
                           DiskCheckHandler handler) override;
    void stop() override;

private:
    void enqueue(std::function<void()> job);
    void worker_loop();
    void complete(std::function<void()> handler);

    bool ensure_file(std::size_t file_index);
    bool write_range(std::uint32_t piece, std::uint32_t offset, const Bytes& data);
    /// Read [offset, offset+length) of @p piece into @p out. With @p use_store the
    /// store-buffer is overlaid. With @p allow_short a missing/short file yields
    /// false (used by check_files) instead of being treated as an error.
    bool read_range(std::uint32_t piece, std::uint32_t offset, std::uint32_t length,
                    Bytes& out, bool use_store, bool allow_short);

    std::string file_path(std::size_t file_index) const;

    FileStorage      files_;
    Bytes            piece_hashes_;   ///< concatenated 20-byte SHA-1s
    std::string      save_path_;
    CompletionPoster poster_;
    StoreBuffer      store_;

    // File preallocation bookkeeping.
    std::mutex        ensure_mutex_;
    std::vector<char> ensured_;       ///< per-file "already sized on disk" flag

    // Worker pool + job queue.
    std::vector<std::thread>          workers_;
    std::queue<std::function<void()>> jobs_;
    std::mutex                        mutex_;
    std::condition_variable           cv_;
    bool                              stopping_ = false;
};

} // namespace librats::bittorrent
