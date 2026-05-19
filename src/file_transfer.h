#pragma once

// =============================================================================
// File / directory transfer for librats
// =============================================================================
//
// A transfer streams one file or a whole directory tree to a connected peer
// over the reliable (and, when enabled, encrypted) RatsClient connection.
//
// Wire protocol (see file_transfer.cpp for the exact framing):
//   * Control messages travel on the named-message channel as JSON:
//       ft_offer    sender  -> receiver : manifest of files to be sent
//       ft_response receiver-> sender   : accepted / rejected
//       ft_file_end sender  -> receiver : SHA-256 of a file once fully streamed
//       ft_progress receiver-> sender   : bytes received so far (drives backpressure)
//       ft_complete receiver-> sender   : transfer finished (success / failure)
//       ft_control  either  -> either   : pause / resume / cancel
//   * File data travels on the binary channel as self-describing chunk frames.
//
// Design notes:
//   * The transport is reliable and ordered, so chunks are streamed strictly
//     sequentially - there is no per-chunk retransmission. Integrity is checked
//     with a per-chunk CRC32 and a whole-file SHA-256.
//   * Backpressure: the sender keeps at most `window_bytes` un-acknowledged and
//     waits for `ft_progress` before sending more, so memory stays bounded.
//   * Received data is written to a temp file and only moved to its final path
//     after the SHA-256 matches, so a failed transfer never leaves a bad file.
//
// =============================================================================

#include "json.hpp"

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

class RatsClient;
struct Transfer; // internal per-transfer state, defined in file_transfer.cpp

// -----------------------------------------------------------------------------
// Public enums
// -----------------------------------------------------------------------------

enum class FileTransferStatus {
    PENDING,      // incoming offer awaiting accept/reject, or outgoing offer awaiting response
    STARTING,     // accepted, about to move data
    IN_PROGRESS,  // actively transferring
    PAUSED,       // paused by either side
    COMPLETED,    // finished successfully
    FAILED,       // finished with an error
    CANCELLED,    // cancelled by either side
    RESUMING      // transient state between PAUSED and IN_PROGRESS
};

enum class FileTransferDirection {
    SENDING,
    RECEIVING
};

// Human-readable name of a status, e.g. "IN_PROGRESS". Never returns null.
const char* file_transfer_status_name(FileTransferStatus status);

// -----------------------------------------------------------------------------
// Public data structures
// -----------------------------------------------------------------------------

// One file inside a transfer. A single-file transfer has exactly one entry; a
// directory transfer has one per regular file.
struct FileInfo {
    std::string relative_path; // POSIX-style path relative to the transfer root
    uint64_t    size = 0;      // file size in bytes
};

// Description of an incoming transfer, delivered to the offer callback so the
// application can decide whether to accept() or reject() it.
struct IncomingTransferOffer {
    std::string transfer_id;
    std::string peer_id;
    std::string name;             // file name, or directory name
    bool        is_directory = false;
    uint64_t    total_size = 0;   // sum of all file sizes
    std::vector<FileInfo> files;  // full manifest
};

// Immutable snapshot of a transfer's progress. Returned by queries and passed
// to the progress callback.
struct FileTransferProgress {
    std::string transfer_id;
    std::string peer_id;
    FileTransferDirection direction = FileTransferDirection::SENDING;
    FileTransferStatus    status    = FileTransferStatus::PENDING;

    std::string filename;     // file name, or directory name
    std::string local_path;   // local source (sending) or destination (receiving)
    bool        is_directory = false;

    uint64_t bytes_transferred = 0;
    uint64_t total_bytes       = 0;
    uint32_t files_completed   = 0;
    uint32_t total_files       = 0;

    double transfer_rate_bps = 0.0; // recent throughput, bytes/second
    double average_rate_bps  = 0.0; // average throughput since start

    std::chrono::milliseconds elapsed_time{0};
    std::chrono::milliseconds estimated_time_remaining{0};

    std::string error_message; // populated when status == FAILED

    // Completion as a percentage in [0, 100].
    double get_completion_percentage() const {
        if (total_bytes == 0) {
            return status == FileTransferStatus::COMPLETED ? 100.0 : 0.0;
        }
        return (static_cast<double>(bytes_transferred) / static_cast<double>(total_bytes)) * 100.0;
    }

    std::chrono::milliseconds get_elapsed_time() const { return elapsed_time; }
};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

struct FileTransferConfig {
    uint32_t chunk_size            = 64 * 1024;        // payload bytes per network chunk
    uint32_t window_bytes          = 4 * 1024 * 1024;  // max un-acknowledged bytes in flight
    uint32_t progress_interval     = 256 * 1024;       // receiver sends an ack every N bytes
    uint32_t transfer_timeout_secs = 60;               // abort a transfer idle for this long
    uint32_t worker_threads        = 4;                // concurrent outgoing transfers
    bool     verify_integrity      = true;             // per-chunk CRC32 + whole-file SHA-256
    std::string temp_directory     = "./rats_file_transfers"; // holds in-progress downloads
};

// -----------------------------------------------------------------------------
// Callback types
// -----------------------------------------------------------------------------

// Invoked when a peer offers a transfer. The handler should eventually call
// accept()/reject() (it may do so synchronously or later, from any thread).
// If no offer callback is registered, incoming offers are auto-rejected.
using TransferOfferCallback = std::function<void(const IncomingTransferOffer&)>;

// Invoked periodically with a progress snapshot, for both directions.
using TransferProgressCallback = std::function<void(const FileTransferProgress&)>;

// Invoked once when a transfer reaches a terminal state.
using TransferCompletedCallback =
    std::function<void(const std::string& transfer_id, bool success, const std::string& error)>;

// -----------------------------------------------------------------------------
// FileTransferManager
// -----------------------------------------------------------------------------

class FileTransferManager {
public:
    explicit FileTransferManager(RatsClient& client,
                                 const FileTransferConfig& config = FileTransferConfig());
    ~FileTransferManager();

    FileTransferManager(const FileTransferManager&) = delete;
    FileTransferManager& operator=(const FileTransferManager&) = delete;

    // --- configuration ---
    void set_config(const FileTransferConfig& config);
    FileTransferConfig get_config() const;

    // --- starting transfers ---
    // Returns a transfer id, or "" on immediate failure (e.g. missing file).
    std::string send_file(const std::string& peer_id, const std::string& file_path,
                          const std::string& remote_name = "");
    std::string send_directory(const std::string& peer_id, const std::string& directory_path,
                               const std::string& remote_name = "");

    // --- responding to an incoming offer ---
    // For a single file, local_path is the destination file path.
    // For a directory, local_path is the destination directory.
    bool accept(const std::string& transfer_id, const std::string& local_path);
    bool reject(const std::string& transfer_id, const std::string& reason = "");

    // --- controlling an active transfer (works from either side) ---
    bool pause(const std::string& transfer_id);
    bool resume(const std::string& transfer_id);
    bool cancel(const std::string& transfer_id);

    // --- queries ---
    std::shared_ptr<FileTransferProgress> get_progress(const std::string& transfer_id) const;
    std::vector<std::shared_ptr<FileTransferProgress>> get_active_transfers() const;
    nlohmann::json get_statistics() const;

    // --- callbacks ---
    void set_offer_callback(TransferOfferCallback callback);
    void set_progress_callback(TransferProgressCallback callback);
    void set_completed_callback(TransferCompletedCallback callback);

    // --- hooks invoked by RatsClient (not part of the application API) ---
    // Returns true if the binary data was a file-transfer chunk frame.
    bool handle_binary_data(const std::string& peer_id, const std::vector<uint8_t>& data);
    void on_peer_disconnected(const std::string& peer_id);

    // --- utilities ---
    // Hex-encoded SHA-256 of a file, or "" if it cannot be read.
    static std::string compute_file_sha256(const std::string& path);

private:
    // --- setup / teardown ---
    void register_handlers();
    void worker_loop();
    void maintenance_loop();

    // --- sending ---
    std::string start_send(const std::string& peer_id, const std::shared_ptr<Transfer>& t,
                           const std::string& name);
    void run_send(const std::shared_ptr<Transfer>& t);
    void queue_send(const std::string& transfer_id);

    // --- control message handlers ---
    void on_offer(const std::string& peer_id, const nlohmann::json& msg);
    void on_response(const std::string& peer_id, const nlohmann::json& msg);
    void on_file_end(const std::string& peer_id, const nlohmann::json& msg);
    void on_progress(const std::string& peer_id, const nlohmann::json& msg);
    void on_complete(const std::string& peer_id, const nlohmann::json& msg);
    void on_control(const std::string& peer_id, const nlohmann::json& msg);

    // --- receiving ---
    void on_chunk(const std::string& transfer_id, const std::string& peer_id,
                  uint32_t file_index, uint64_t offset,
                  const uint8_t* data, uint32_t len, uint32_t crc);
    void try_finalize_file(const std::shared_ptr<Transfer>& t, size_t file_index);

    // --- shared helpers ---
    std::shared_ptr<Transfer> find(const std::string& transfer_id) const;
    void finish(const std::shared_ptr<Transfer>& t, bool success, const std::string& error);
    void emit_progress(const std::shared_ptr<Transfer>& t);
    FileTransferProgress snapshot(const std::shared_ptr<Transfer>& t) const; // call with t->mtx held
    void send_control(const std::shared_ptr<Transfer>& t, const std::string& action);
    void cleanup_temp_files(const std::shared_ptr<Transfer>& t);

    RatsClient& client_;

    mutable std::mutex config_mutex_;
    FileTransferConfig config_;

    // All transfers, active and recently finished, keyed by transfer id.
    mutable std::mutex transfers_mutex_;
    std::unordered_map<std::string, std::shared_ptr<Transfer>> transfers_;

    // Outgoing transfers ready to be streamed by a worker thread.
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<std::string> send_queue_;

    std::vector<std::thread> workers_;
    std::thread maintenance_thread_;
    std::mutex maintenance_mutex_;
    std::condition_variable maintenance_cv_;
    std::atomic<bool> running_{true};

    mutable std::mutex callbacks_mutex_;
    TransferOfferCallback offer_callback_;
    TransferProgressCallback progress_callback_;
    TransferCompletedCallback completed_callback_;

    // Aggregate statistics.
    mutable std::mutex stats_mutex_;
    uint64_t stat_bytes_sent_ = 0;
    uint64_t stat_bytes_received_ = 0;
    uint64_t stat_files_sent_ = 0;
    uint64_t stat_files_received_ = 0;
    uint64_t stat_completed_ = 0;
    uint64_t stat_failed_ = 0;
    std::chrono::steady_clock::time_point started_at_;
};

} // namespace librats
