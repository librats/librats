#include "bittorrent/disk_io.h"

#include "crypto/sha1.h"
#include "util/fs.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace librats::bittorrent {

ThreadedDiskIo::ThreadedDiskIo(const TorrentInfo& info, std::string save_path,
                               CompletionPoster poster, Config config)
    : files_(info.files())
    , piece_hashes_(info.piece_hashes())
    , save_path_(std::move(save_path))
    , poster_(std::move(poster))
    , ensured_(info.num_files(), 0) {
    const int n = std::max(1, config.num_threads);
    workers_.reserve(std::size_t(n));
    for (int i = 0; i < n; ++i) workers_.emplace_back([this] { worker_loop(); });
}

ThreadedDiskIo::~ThreadedDiskIo() {
    stop();
}

void ThreadedDiskIo::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) return;
        stopping_ = true;
    }
    cv_.notify_all();
    for (auto& t : workers_)
        if (t.joinable()) t.join();
    workers_.clear();
}

void ThreadedDiskIo::enqueue(std::function<void()> job) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) return;
        jobs_.push(std::move(job));
    }
    cv_.notify_one();
}

void ThreadedDiskIo::worker_loop() {
    for (;;) {
        std::function<void()> job;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return stopping_ || !jobs_.empty(); });
            if (stopping_ && jobs_.empty()) return;
            job = std::move(jobs_.front());
            jobs_.pop();
        }
        job();
    }
}

void ThreadedDiskIo::complete(std::function<void()> handler) {
    if (poster_) poster_(std::move(handler));
    else handler();
}

std::string ThreadedDiskIo::file_path(std::size_t file_index) const {
    return combine_paths(save_path_, files_.file_at(file_index).path);
}

bool ThreadedDiskIo::ensure_file(std::size_t file_index) {
    std::lock_guard<std::mutex> lock(ensure_mutex_);
    if (ensured_[file_index]) return true;

    const std::string   path = file_path(file_index);
    const std::int64_t  size = files_.file_at(file_index).size;

    const std::string parent = get_parent_directory(path.c_str());
    if (!parent.empty() && !directory_exists(parent.c_str())) {
        if (!create_directories(parent.c_str())) return false;
    }

    if (file_exists(path.c_str())) {
        // Extend a short (e.g. partially-downloaded) file without truncating it.
        if (size > 0 && get_file_size(path.c_str()) < size) {
            const std::uint8_t zero = 0;
            if (!write_file_chunk(path, std::uint64_t(size - 1), &zero, 1)) return false;
        }
    } else if (!create_file_with_size(path, std::uint64_t(size))) {
        return false;
    }

    ensured_[file_index] = 1;
    return true;
}

bool ThreadedDiskIo::write_range(std::uint32_t piece, std::uint32_t offset, const Bytes& data) {
    auto slices = files_.map_block(piece, offset, std::int64_t(data.size()));
    std::int64_t in_pos = 0;
    for (const auto& s : slices) {
        if (!ensure_file(s.file_index)) return false;
        if (!write_file_chunk(file_path(s.file_index), std::uint64_t(s.offset),
                              data.data() + in_pos, std::size_t(s.size))) {
            return false;
        }
        in_pos += s.size;
    }
    return in_pos == std::int64_t(data.size());
}

bool ThreadedDiskIo::read_range(std::uint32_t piece, std::uint32_t offset, std::uint32_t length,
                                Bytes& out, bool use_store, bool allow_short) {
    out.assign(length, 0);
    auto slices = files_.map_block(piece, offset, std::int64_t(length));
    std::int64_t out_pos = 0;
    for (const auto& s : slices) {
        const std::string path = file_path(s.file_index);
        // On the check path a missing/short file is expected (piece not yet on
        // disk); probe the size first so we don't trip read_file_chunk's error log.
        if (allow_short && get_file_size(path.c_str()) < s.offset + s.size) return false;
        if (!read_file_chunk(path, std::uint64_t(s.offset), out.data() + out_pos, std::size_t(s.size)))
            return false;
        out_pos += s.size;
    }
    if (use_store) store_.overlay(piece, offset, out);
    return true;
}

void ThreadedDiskIo::async_read(std::uint32_t piece, std::uint32_t offset, std::uint32_t length,
                                DiskReadHandler handler) {
    enqueue([this, piece, offset, length, handler = std::move(handler)]() mutable {
        Bytes out;
        const bool ok = read_range(piece, offset, length, out, /*use_store=*/true, /*allow_short=*/false);
        complete([handler = std::move(handler), ok, out = std::move(out)]() mutable {
            if (handler) handler(ok, std::move(out));
        });
    });
}

void ThreadedDiskIo::async_write(std::uint32_t piece, std::uint32_t offset, Bytes data,
                                 DiskWriteHandler handler) {
    // Park the block so reads/hashes see it before the write reaches disk, and
    // count it toward the pending-write total that drives backpressure (D-2).
    const std::size_t sz = data.size();
    store_.insert(piece, offset, data);
    queued_bytes_.fetch_add(sz, std::memory_order_relaxed);
    enqueue([this, piece, offset, sz, data = std::move(data), handler = std::move(handler)]() mutable {
        const bool ok = write_range(piece, offset, data);
        store_.erase(piece, offset);
        queued_bytes_.fetch_sub(sz, std::memory_order_relaxed);
        complete([handler = std::move(handler), ok]() mutable {
            if (handler) handler(ok);
        });
    });
}

void ThreadedDiskIo::async_hash(std::uint32_t piece, DiskHashHandler handler) {
    enqueue([this, piece, handler = std::move(handler)]() mutable {
        const std::uint32_t ps = files_.piece_size(piece);
        Bytes buf;
        const bool ok = read_range(piece, 0, ps, buf, /*use_store=*/true, /*allow_short=*/false);
        std::array<std::uint8_t, 20> digest{};
        if (ok) digest = SHA1::hash_raw(buf.data(), buf.size());
        complete([handler = std::move(handler), ok, digest]() mutable {
            if (handler) handler(ok, digest);
        });
    });
}

void ThreadedDiskIo::async_check_files(Bitfield trusted_have, DiskCheckProgress progress,
                                       DiskCheckHandler handler) {
    enqueue([this, trusted_have = std::move(trusted_have), progress = std::move(progress),
             handler = std::move(handler)]() mutable {
        const std::uint32_t n = files_.num_pieces();
        const bool have_trust = trusted_have.size() == n;
        Bitfield have(n, false);

        for (std::uint32_t p = 0; p < n; ++p) {
            if (have_trust && trusted_have.get(p)) {
                have.set(p);  // fast resume: trust the saved bit, skip hashing
            } else {
                Bytes buf;
                if (read_range(p, 0, files_.piece_size(p), buf, /*use_store=*/false, /*allow_short=*/true)) {
                    auto digest = SHA1::hash_raw(buf.data(), buf.size());
                    if (std::memcmp(digest.data(), piece_hashes_.data() + std::size_t(p) * 20, 20) == 0)
                        have.set(p);
                }
            }
            if (progress) {
                const std::uint32_t done = p + 1;
                complete([progress, done, n] { progress(done, n); });
            }
        }
        complete([handler = std::move(handler), have = std::move(have)]() mutable {
            if (handler) handler(std::move(have));
        });
    });
}

} // namespace librats::bittorrent
