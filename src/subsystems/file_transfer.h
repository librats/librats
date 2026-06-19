#pragma once

/**
 * @file file_transfer.h
 * @brief Stream a file or a whole directory tree to a peer, with integrity,
 *        backpressure, pause/resume/cancel, idle-timeout and crash-safe writes.
 *
 * Push model: the sender offers a file/directory; the receiver accepts (choosing
 * a destination) or rejects; the sender streams the data; the receiver verifies a
 * per-chunk CRC32 and a whole-file SHA-256 before moving each temp file into
 * place. All control + data ride on MessageType::FileChunk as compact binary
 * opcodes (no JSON). This restores the full feature set of the legacy
 * FileTransferManager onto the Node/Subsystem plugin model.
 *
 * Integrity: every chunk carries a CRC32; every file ends with its SHA-256. A
 * mismatch (or a disk-write failure) fails the whole transfer — a temp file is
 * only moved to its destination after its SHA-256 verifies.
 *
 * Backpressure: the sender keeps at most `window_bytes` un-acked; the receiver
 * acks cumulative progress at least twice per window, so the sender never stalls.
 *
 * Safety: temp file names are derived from the transfer id (never the peer's
 * name), and every peer-supplied relative path in a directory manifest is
 * validated against path traversal before use.
 *
 * Threading: a worker pool runs the blocking send loop (one transfer per worker);
 * receiving + all control handling run on the reactor thread; a maintenance
 * thread reaps idle/timed-out transfers and purges finished ones. Each transfer
 * has its own mutex+condvar; the maps are guarded by mutex_.
 *
 * Wire (MessageType::FileChunk payload, big-endian):
 *   OFFER    [1][id:u64][flags:u8][total:u64][name_len:u16][name][file_count:u32]
 *                                      { [path_len:u16][path][size:u64] } × file_count
 *   RESPONSE [2][id:u64][accept:u8]
 *   CHUNK    [3][id:u64][file_index:u32][offset:u64][crc32:u32][data]
 *   FILE_END [4][id:u64][file_index:u32][sha256:32]
 *   PROGRESS [5][id:u64][received:u64]      (cumulative across all files)
 *   COMPLETE [6][id:u64][ok:u8]
 *   CANCEL   [7][id:u64]
 *   PAUSE    [8][id:u64]
 *   RESUME   [9][id:u64]
 */

#include "node/peer_network.h"
#include "peer/peer.h"
#include "core/bytes.h"
#include "peer/peer_id.h"

extern "C" {
#include "sha256.h"
}

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace librats {

class FileTransfer final : public Subsystem {
public:
    struct Config {
        uint32_t    chunk_size           = 64 * 1024;        ///< payload bytes per chunk
        uint32_t    window_bytes         = 4 * 1024 * 1024;  ///< max un-acked bytes in flight
        uint32_t    progress_interval    = 256 * 1024;       ///< receiver acks every N bytes
        uint32_t    transfer_timeout_secs = 60;              ///< abort a transfer idle this long
        uint32_t    worker_threads       = 4;                ///< concurrent outgoing transfers
        bool        verify_integrity     = true;             ///< per-chunk CRC32 + whole-file SHA-256
        std::string temp_directory       = ".";              ///< holds in-progress downloads
    };

    enum class Status   { Pending, Active, Paused, Completed, Failed, Cancelled };
    enum class Direction { Sending, Receiving };

    /// One file inside a transfer (a single-file transfer has exactly one).
    struct FileEntry {
        std::string relative_path;  ///< POSIX path relative to the transfer root
        uint64_t    size = 0;
    };

    /// Delivered to the offer callback so the app can accept() or reject().
    struct Offer {
        PeerId                 from;
        uint64_t               id = 0;
        std::string            name;             ///< file or directory name
        uint64_t               size = 0;         ///< total size across all files
        bool                   is_directory = false;
        std::vector<FileEntry> files;            ///< full manifest
    };

    /// Snapshot passed to the progress callback (both directions).
    struct Progress {
        uint64_t   id = 0;
        PeerId     peer;
        Direction  direction = Direction::Sending;
        Status     status = Status::Pending;
        uint64_t   bytes_transferred = 0;
        uint64_t   total_bytes = 0;
        uint32_t   files_completed = 0;
        uint32_t   total_files = 0;
    };

    /// Aggregate counters.
    struct Stats {
        uint64_t bytes_sent = 0, bytes_received = 0;
        uint64_t completed = 0, failed = 0;
    };

    using OfferHandler    = std::function<void(const Offer&)>;
    using ProgressHandler = std::function<void(const Progress&)>;
    using CompleteHandler = std::function<void(uint64_t id, bool success, const std::string& path)>;

    explicit FileTransfer(std::string temp_dir = ".");
    explicit FileTransfer(Config config);
    ~FileTransfer() override;

    void on_offer(OfferHandler handler)       { offer_handler_ = std::move(handler); }
    void on_progress(ProgressHandler handler) { progress_handler_ = std::move(handler); }
    void on_complete(CompleteHandler handler) { complete_handler_ = std::move(handler); }

    /// Offer a single file. Returns the transfer id (0 if the file is unusable).
    uint64_t send_file(const PeerId& to, const std::string& path);
    /// Offer a directory tree. Returns the transfer id (0 if the dir is unusable).
    uint64_t send_directory(const PeerId& to, const std::string& dir_path);

    /// Accept an offered transfer. For a single file, dest_path is the file path;
    /// for a directory, it is the destination directory. (from, id) names the offer.
    void accept(const PeerId& from, uint64_t id, const std::string& dest_path);
    void reject(const PeerId& from, uint64_t id);

    /// Control a live transfer (works from either side); (peer, id) names it.
    bool cancel(const PeerId& peer, uint64_t id);
    bool pause(const PeerId& peer, uint64_t id);
    bool resume(const PeerId& peer, uint64_t id);

    Stats stats() const;

    /// A relative path from a peer's directory manifest is safe only if it stays
    /// inside the destination: non-empty, not absolute, no drive letter, and no
    /// "."/".." component. Public + static so it can be unit-tested directly.
    static bool is_safe_relative_path(const std::string& p);

    void attach(PeerNetwork& network) override;
    void start() override;
    void stop() override;

private:
    // ── Per-transfer state (held via shared_ptr so workers/handlers keep it
    //    alive past map removal) ──────────────────────────────────────────────
    struct Outgoing {
        uint64_t                 id = 0;
        PeerId                   peer;
        std::string              name;
        std::string              root;          ///< local source path/dir
        bool                     is_directory = false;
        std::vector<FileEntry>   files;         ///< relative_path + size
        std::vector<std::string> sources;       ///< absolute source path per file
        uint64_t                 total_bytes = 0;

        std::mutex               mtx;
        std::condition_variable  cv;
        size_t                   cur_file = 0;
        uint64_t                 cur_offset = 0;
        uint64_t                 bytes_done = 0;
        uint64_t                 acked = 0;
        uint32_t                 files_done = 0;
        Status                   status = Status::Pending;
        bool                     worker_active = false;
        bool                     finished = false;
        sha256_context_t         hash{};
        std::chrono::steady_clock::time_point last_activity{};
    };

    struct IncomingFile {
        std::string relative_path;
        uint64_t    size = 0;
        std::string final_path;
        std::string temp_path;
        uint64_t    received = 0;
        bool        temp_created = false;
        bool        sha_known = false;
        bool        finalized = false;
        uint8_t     expected_sha[SHA256_HASH_SIZE]{};
    };
    struct Incoming {
        uint64_t                   id = 0;
        PeerId                     peer;
        std::string                name;
        bool                       is_directory = false;
        std::string                dest_root;
        std::vector<IncomingFile>  files;

        std::mutex                 mtx;
        size_t                     recv_file = 0;
        uint64_t                   bytes_done = 0;
        uint64_t                   last_ack = 0;
        uint32_t                   files_done = 0;
        Status                     status = Status::Pending;
        bool                       finished = false;
        sha256_context_t           hash{};
        uint8_t                    computed_sha[SHA256_HASH_SIZE]{};
        std::chrono::steady_clock::time_point last_activity{};
    };

    // ── message handling (reactor thread) ─────────────────────────────────────
    void on_message(const Peer& peer, ByteView payload);
    void handle_offer(const PeerId& from, uint64_t id, bool is_dir, uint64_t total,
                      std::string name, std::vector<FileEntry> files);
    void handle_chunk(const PeerId& from, uint64_t id, uint32_t fidx, uint64_t offset,
                      uint32_t crc, ByteView data);
    void handle_file_end(const PeerId& from, uint64_t id, uint32_t fidx, const uint8_t* sha);

    // ── sending ──────────────────────────────────────────────────────────────
    uint64_t start_send(std::shared_ptr<Outgoing> t);
    void     queue_send(uint64_t id);
    void     worker_loop();
    void     run_send(const std::shared_ptr<Outgoing>& t);

    // ── receiving ────────────────────────────────────────────────────────────
    void try_finalize_file(const std::shared_ptr<Incoming>& t, size_t file_index);

    // ── lifecycle helpers ─────────────────────────────────────────────────────
    void maintenance_loop();
    void finish_outgoing(const std::shared_ptr<Outgoing>& t, bool success);
    void finish_incoming(const std::shared_ptr<Incoming>& t, bool success, const std::string& error);
    void emit_progress(const std::shared_ptr<Outgoing>& t);
    void emit_progress(const std::shared_ptr<Incoming>& t);

    std::shared_ptr<Outgoing> find_outgoing(uint64_t id) const;
    std::shared_ptr<Incoming> find_incoming(const PeerId& peer, uint64_t id) const;

    void send_to(const PeerId& peer, const Bytes& msg) {
        if (network_) network_->send(peer, MessageType::FileChunk, ByteView(msg));
    }
    void send_simple(const PeerId& peer, uint8_t op, uint64_t id);
    void send_complete(const PeerId& peer, uint64_t id, bool ok);

    PeerNetwork*          network_ = nullptr;
    Config                config_;
    std::atomic<uint64_t> next_id_{1};
    std::atomic<bool>     running_{false};

    OfferHandler    offer_handler_;
    ProgressHandler progress_handler_;
    CompleteHandler complete_handler_;

    mutable std::mutex mutex_;  ///< guards the two maps below
    std::unordered_map<uint64_t, std::shared_ptr<Outgoing>> outgoing_;
    std::unordered_map<PeerId, std::unordered_map<uint64_t, std::shared_ptr<Incoming>>,
                       PeerId::Hash> incoming_;

    // worker pool + send queue
    std::vector<std::thread>  workers_;
    std::mutex                queue_mutex_;
    std::condition_variable   queue_cv_;
    std::queue<uint64_t>      send_queue_;

    // maintenance (idle timeout / purge)
    std::thread               maintenance_thread_;
    std::mutex                maintenance_mutex_;
    std::condition_variable   maintenance_cv_;

    mutable std::mutex stats_mutex_;
    Stats              stats_;
};

} // namespace librats
