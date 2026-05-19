#include "file_transfer.h"
#include "librats.h"
#include "fs.h"
#include "logger.h"
#include "crypto/sha256.h"

#include <algorithm>
#include <cstring>
#include <random>

// Logging shorthand for this module.
#define LOG_FT_INFO(msg)  LOG_INFO("filetransfer", msg)
#define LOG_FT_WARN(msg)  LOG_WARN("filetransfer", msg)
#define LOG_FT_ERROR(msg) LOG_ERROR("filetransfer", msg)
#define LOG_FT_DEBUG(msg) LOG_DEBUG("filetransfer", msg)

namespace librats {

// =============================================================================
// Wire constants
// =============================================================================

namespace {

// Named control-message types exchanged on the JSON channel.
constexpr const char* MSG_OFFER    = "ft_offer";
constexpr const char* MSG_RESPONSE = "ft_response";
constexpr const char* MSG_FILE_END = "ft_file_end";
constexpr const char* MSG_PROGRESS = "ft_progress";
constexpr const char* MSG_COMPLETE = "ft_complete";
constexpr const char* MSG_CONTROL  = "ft_control";

// Magic prefix of a binary chunk frame.
constexpr char CHUNK_MAGIC[4] = {'R', 'F', 'T', '1'};

// How long a finished transfer is kept queryable before being purged.
constexpr auto FINISHED_RETENTION = std::chrono::minutes(5);

// =============================================================================
// Small helpers
// =============================================================================

// --- big-endian serialization ---
void put_u16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v));
}
void put_u32(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back(uint8_t(v >> 24));
    b.push_back(uint8_t(v >> 16));
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v));
}
void put_u64(std::vector<uint8_t>& b, uint64_t v) {
    for (int s = 56; s >= 0; s -= 8) b.push_back(uint8_t(v >> s));
}
uint16_t get_u16(const uint8_t* p) { return uint16_t(p[0]) << 8 | p[1]; }
uint32_t get_u32(const uint8_t* p) {
    return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
}
uint64_t get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

// --- CRC32 (IEEE 802.3) for per-chunk integrity ---
struct Crc32Table {
    uint32_t t[256];
    Crc32Table() {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
    }
};
uint32_t crc32(const uint8_t* data, size_t len) {
    static const Crc32Table tbl;
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) c = tbl.t[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// --- hex encoding ---
std::string to_hex(const uint8_t* d, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s(n * 2, '0');
    for (size_t i = 0; i < n; ++i) {
        s[2 * i]     = h[d[i] >> 4];
        s[2 * i + 1] = h[d[i] & 0xF];
    }
    return s;
}

// SHA-256 of an empty input, used for zero-byte files.
std::string sha256_of_empty() {
    uint8_t digest[SHA256_HASH_SIZE];
    sha256_hash(digest, nullptr, 0);
    return to_hex(digest, SHA256_HASH_SIZE);
}

// --- random transfer id ---
std::string random_transfer_id() {
    static const char* h = "0123456789abcdef";
    std::random_device rd;
    std::mt19937 gen(rd() ^ uint32_t(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<int> dis(0, 15);
    std::string id(32, '0');
    for (char& c : id) c = h[dis(gen)];
    return id;
}

// A relative path coming from a peer must not escape the destination directory.
bool is_safe_relative_path(const std::string& p) {
    if (p.empty()) return false;
    if (p.front() == '/' || p.front() == '\\') return false;
    if (p.size() >= 2 && p[1] == ':') return false; // Windows drive letter
    size_t start = 0;
    for (size_t i = 0; i <= p.size(); ++i) {
        if (i == p.size() || p[i] == '/' || p[i] == '\\') {
            std::string comp = p.substr(start, i - start);
            if (comp.empty() || comp == "." || comp == "..") return false;
            start = i + 1;
        }
    }
    return true;
}

} // namespace

// =============================================================================
// Internal per-transfer state
// =============================================================================

// One file within a transfer.
struct TransferFile {
    std::string relative_path;   // POSIX path relative to the transfer root
    uint64_t    size = 0;

    // sender side
    std::string source_path;     // local path the data is read from

    // receiver side
    std::string temp_path;       // chunks are written here first
    std::string final_path;      // destination once verified
    uint64_t    received = 0;    // bytes written so far
    bool        temp_created = false;
    std::string expected_sha;    // from ft_file_end
    std::string computed_sha;    // hashed while receiving
    bool        sha_known = false;
    bool        finalized = false;
};

// Full state of a single transfer. Always held through a shared_ptr; `mtx`
// guards every field below `total_bytes`.
struct Transfer {
    // immutable after creation
    std::string id;
    std::string peer_id;
    FileTransferDirection direction;
    bool is_directory = false;
    std::string name;
    std::string local_root;          // sender: source path; receiver: destination
    std::vector<TransferFile> files;
    uint64_t total_bytes = 0;

    // mutable state
    std::mutex mtx;
    std::condition_variable cv;
    FileTransferStatus status = FileTransferStatus::PENDING;
    bool finished = false;           // finish() has run (fired callbacks); distinct from status
    std::string error;
    uint64_t bytes_done = 0;         // sender: streamed bytes; receiver: written bytes
    uint64_t acked_bytes = 0;        // sender: bytes confirmed by the peer
    uint32_t files_done = 0;

    // sender streaming cursor (survives pause)
    size_t   send_file = 0;
    uint64_t send_offset = 0;
    sha256_context_t send_hash;
    bool     worker_active = false;

    // receiver cursor
    size_t   recv_file = 0;
    sha256_context_t recv_hash;
    uint64_t last_ack_sent = 0;      // bytes_done at the last ft_progress emitted

    // timing
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_activity;
    std::chrono::steady_clock::time_point last_progress_cb;

    // throughput
    double rate_bps = 0.0;
    uint64_t rate_mark_bytes = 0;
    std::chrono::steady_clock::time_point rate_mark_time;

    bool is_terminal() const {
        return status == FileTransferStatus::COMPLETED ||
               status == FileTransferStatus::FAILED ||
               status == FileTransferStatus::CANCELLED;
    }
};

// =============================================================================
// Status name
// =============================================================================

const char* file_transfer_status_name(FileTransferStatus s) {
    switch (s) {
        case FileTransferStatus::PENDING:     return "PENDING";
        case FileTransferStatus::STARTING:    return "STARTING";
        case FileTransferStatus::IN_PROGRESS: return "IN_PROGRESS";
        case FileTransferStatus::PAUSED:      return "PAUSED";
        case FileTransferStatus::COMPLETED:   return "COMPLETED";
        case FileTransferStatus::FAILED:      return "FAILED";
        case FileTransferStatus::CANCELLED:   return "CANCELLED";
        case FileTransferStatus::RESUMING:    return "RESUMING";
    }
    return "UNKNOWN";
}

// =============================================================================
// Construction / destruction
// =============================================================================

FileTransferManager::FileTransferManager(RatsClient& client, const FileTransferConfig& config)
    : client_(client), config_(config) {
    started_at_ = std::chrono::steady_clock::now();
    create_directories(config_.temp_directory.c_str());
    register_handlers();

    uint32_t threads = std::max<uint32_t>(1, config_.worker_threads);
    for (uint32_t i = 0; i < threads; ++i) {
        workers_.emplace_back(&FileTransferManager::worker_loop, this);
    }
    maintenance_thread_ = std::thread(&FileTransferManager::maintenance_loop, this);

    LOG_FT_INFO("FileTransferManager started (" << threads << " workers)");
}

FileTransferManager::~FileTransferManager() {
    running_.store(false);
    queue_cv_.notify_all();
    maintenance_cv_.notify_all();

    // Wake any worker blocked on a transfer's condition variable.
    {
        std::lock_guard<std::mutex> lk(transfers_mutex_);
        for (auto& kv : transfers_) {
            std::lock_guard<std::mutex> tk(kv.second->mtx);
            kv.second->cv.notify_all();
        }
    }

    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
    if (maintenance_thread_.joinable()) maintenance_thread_.join();
    LOG_FT_INFO("FileTransferManager stopped");
}

void FileTransferManager::register_handlers() {
    client_.on(MSG_OFFER,    [this](const std::string& p, const nlohmann::json& m) { on_offer(p, m); });
    client_.on(MSG_RESPONSE, [this](const std::string& p, const nlohmann::json& m) { on_response(p, m); });
    client_.on(MSG_FILE_END, [this](const std::string& p, const nlohmann::json& m) { on_file_end(p, m); });
    client_.on(MSG_PROGRESS, [this](const std::string& p, const nlohmann::json& m) { on_progress(p, m); });
    client_.on(MSG_COMPLETE, [this](const std::string& p, const nlohmann::json& m) { on_complete(p, m); });
    client_.on(MSG_CONTROL,  [this](const std::string& p, const nlohmann::json& m) { on_control(p, m); });
}

// =============================================================================
// Configuration
// =============================================================================

void FileTransferManager::set_config(const FileTransferConfig& config) {
    std::lock_guard<std::mutex> lk(config_mutex_);
    config_ = config;
    create_directories(config_.temp_directory.c_str());
}

FileTransferConfig FileTransferManager::get_config() const {
    std::lock_guard<std::mutex> lk(config_mutex_);
    return config_;
}

// =============================================================================
// Callbacks
// =============================================================================

void FileTransferManager::set_offer_callback(TransferOfferCallback cb) {
    std::lock_guard<std::mutex> lk(callbacks_mutex_);
    offer_callback_ = std::move(cb);
}
void FileTransferManager::set_progress_callback(TransferProgressCallback cb) {
    std::lock_guard<std::mutex> lk(callbacks_mutex_);
    progress_callback_ = std::move(cb);
}
void FileTransferManager::set_completed_callback(TransferCompletedCallback cb) {
    std::lock_guard<std::mutex> lk(callbacks_mutex_);
    completed_callback_ = std::move(cb);
}

// =============================================================================
// Lookup / progress snapshot
// =============================================================================

std::shared_ptr<Transfer> FileTransferManager::find(const std::string& id) const {
    std::lock_guard<std::mutex> lk(transfers_mutex_);
    auto it = transfers_.find(id);
    return it == transfers_.end() ? nullptr : it->second;
}

// Builds a progress snapshot. Caller must hold t->mtx.
FileTransferProgress FileTransferManager::snapshot(const std::shared_ptr<Transfer>& t) const {
    FileTransferProgress p;
    p.transfer_id = t->id;
    p.peer_id = t->peer_id;
    p.direction = t->direction;
    p.status = t->status;
    p.filename = t->name;
    p.local_path = t->local_root;
    p.is_directory = t->is_directory;
    p.bytes_transferred = t->bytes_done;
    p.total_bytes = t->total_bytes;
    p.files_completed = t->files_done;
    p.total_files = static_cast<uint32_t>(t->files.size());
    p.transfer_rate_bps = t->rate_bps;
    p.error_message = t->error;

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - t->start_time);
    p.elapsed_time = elapsed;
    if (elapsed.count() > 0) {
        p.average_rate_bps = static_cast<double>(t->bytes_done) * 1000.0 / elapsed.count();
    }
    if (t->rate_bps > 1.0 && t->total_bytes > t->bytes_done) {
        double secs = static_cast<double>(t->total_bytes - t->bytes_done) / t->rate_bps;
        p.estimated_time_remaining = std::chrono::milliseconds(static_cast<int64_t>(secs * 1000.0));
    }
    return p;
}

std::shared_ptr<FileTransferProgress>
FileTransferManager::get_progress(const std::string& id) const {
    auto t = find(id);
    if (!t) return nullptr;
    std::lock_guard<std::mutex> lk(t->mtx);
    return std::make_shared<FileTransferProgress>(snapshot(t));
}

std::vector<std::shared_ptr<FileTransferProgress>>
FileTransferManager::get_active_transfers() const {
    std::vector<std::shared_ptr<Transfer>> all;
    {
        std::lock_guard<std::mutex> lk(transfers_mutex_);
        for (auto& kv : transfers_) all.push_back(kv.second);
    }
    std::vector<std::shared_ptr<FileTransferProgress>> out;
    for (auto& t : all) {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (!t->is_terminal()) {
            out.push_back(std::make_shared<FileTransferProgress>(snapshot(t)));
        }
    }
    return out;
}

nlohmann::json FileTransferManager::get_statistics() const {
    nlohmann::json j;
    {
        std::lock_guard<std::mutex> lk(stats_mutex_);
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - started_at_);
        j["uptime_seconds"] = uptime.count();
        j["total_bytes_sent"] = stat_bytes_sent_;
        j["total_bytes_received"] = stat_bytes_received_;
        j["total_files_sent"] = stat_files_sent_;
        j["total_files_received"] = stat_files_received_;
        j["completed_transfers"] = stat_completed_;
        j["failed_transfers"] = stat_failed_;
        uint64_t total = stat_completed_ + stat_failed_;
        j["success_rate"] = total ? static_cast<double>(stat_completed_) / total : 0.0;
    }
    {
        std::lock_guard<std::mutex> lk(transfers_mutex_);
        size_t active = 0;
        for (auto& kv : transfers_) {
            std::lock_guard<std::mutex> tk(kv.second->mtx);
            if (!kv.second->is_terminal()) ++active;
        }
        j["active_transfers"] = active;
    }
    return j;
}

// =============================================================================
// Progress / completion notification
// =============================================================================

void FileTransferManager::emit_progress(const std::shared_ptr<Transfer>& t) {
    FileTransferProgress snap;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        auto now = std::chrono::steady_clock::now();

        // Refresh the throughput estimate roughly twice a second.
        auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(now - t->rate_mark_time);
        if (dt.count() >= 500) {
            t->rate_bps = static_cast<double>(t->bytes_done - t->rate_mark_bytes) * 1000.0 / dt.count();
            t->rate_mark_bytes = t->bytes_done;
            t->rate_mark_time = now;
        }

        // Throttle callbacks to ~10/s unless the transfer just finished.
        auto since_cb = std::chrono::duration_cast<std::chrono::milliseconds>(now - t->last_progress_cb);
        if (!t->is_terminal() && since_cb.count() < 100) return;
        t->last_progress_cb = now;

        snap = snapshot(t);
    }
    TransferProgressCallback cb;
    {
        std::lock_guard<std::mutex> lk(callbacks_mutex_);
        cb = progress_callback_;
    }
    if (cb) cb(snap);
}

void FileTransferManager::finish(const std::shared_ptr<Transfer>& t, bool success,
                                 const std::string& error) {
    FileTransferProgress snap;
    bool is_receiver;
    size_t file_count;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->finished) return; // finish() already ran for this transfer
        t->finished = true;
        // Preserve an explicit CANCELLED status set by the cancel path.
        if (!success && t->status == FileTransferStatus::CANCELLED) {
            // keep CANCELLED
        } else {
            t->status = success ? FileTransferStatus::COMPLETED : FileTransferStatus::FAILED;
        }
        t->error = error;
        t->last_activity = std::chrono::steady_clock::now();
        t->last_progress_cb = {}; // force the final progress callback through
        is_receiver = (t->direction == FileTransferDirection::RECEIVING);
        file_count = t->files.size();
        t->cv.notify_all();
        snap = snapshot(t);
    }

    if (!success && is_receiver) {
        cleanup_temp_files(t);
    }

    {
        std::lock_guard<std::mutex> lk(stats_mutex_);
        if (success) {
            ++stat_completed_;
            if (is_receiver) stat_files_received_ += file_count;
            else             stat_files_sent_ += file_count;
        } else {
            ++stat_failed_;
        }
    }

    TransferProgressCallback pcb;
    TransferCompletedCallback ccb;
    {
        std::lock_guard<std::mutex> lk(callbacks_mutex_);
        pcb = progress_callback_;
        ccb = completed_callback_;
    }
    if (pcb) pcb(snap);
    if (ccb) ccb(t->id, success, error);

    LOG_FT_INFO("Transfer " << t->id << " " << (success ? "completed" : "ended")
                            << (error.empty() ? "" : (": " + error)));
}

void FileTransferManager::cleanup_temp_files(const std::shared_ptr<Transfer>& t) {
    std::vector<std::string> temps;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        for (auto& f : t->files) {
            if (f.temp_created && !f.finalized) temps.push_back(f.temp_path);
        }
    }
    for (auto& p : temps) {
        if (file_exists(p)) delete_file(p.c_str());
    }
}

// =============================================================================
// Sending: send_file / send_directory
// =============================================================================

namespace {
// Recursively collects regular files under `abs_dir` into `out`.
void scan_directory(const std::string& abs_dir, const std::string& rel_prefix,
                    std::vector<TransferFile>& out) {
    std::vector<DirectoryEntry> entries;
    if (!list_directory(abs_dir.c_str(), entries)) return;
    for (const auto& e : entries) {
        std::string rel = rel_prefix.empty() ? e.name : rel_prefix + "/" + e.name;
        if (e.is_directory) {
            scan_directory(e.path, rel, out);
        } else {
            TransferFile f;
            f.relative_path = rel;
            int64_t sz = get_file_size(e.path.c_str());
            f.size = sz > 0 ? static_cast<uint64_t>(sz) : 0;
            f.source_path = e.path;
            out.push_back(std::move(f));
        }
    }
}
} // namespace

std::string FileTransferManager::send_file(const std::string& peer_id, const std::string& file_path,
                                           const std::string& remote_name) {
    if (!file_exists(file_path) || is_directory(file_path.c_str())) {
        LOG_FT_ERROR("send_file: not a readable file: " << file_path);
        return "";
    }
    int64_t sz = get_file_size(file_path.c_str());
    if (sz < 0) {
        LOG_FT_ERROR("send_file: cannot stat: " << file_path);
        return "";
    }
    std::string name = remote_name.empty() ? get_filename_from_path(file_path) : remote_name;

    auto t = std::make_shared<Transfer>();
    t->id = random_transfer_id();
    t->peer_id = peer_id;
    t->direction = FileTransferDirection::SENDING;
    t->is_directory = false;
    t->name = name;
    t->local_root = file_path;
    t->total_bytes = static_cast<uint64_t>(sz);

    TransferFile f;
    f.relative_path = name;
    f.size = t->total_bytes;
    f.source_path = file_path;
    t->files.push_back(std::move(f));

    return start_send(peer_id, t, name);
}

std::string FileTransferManager::send_directory(const std::string& peer_id,
                                                const std::string& directory_path,
                                                const std::string& remote_name) {
    if (!directory_exists(directory_path)) {
        LOG_FT_ERROR("send_directory: not a directory: " << directory_path);
        return "";
    }
    std::string name = remote_name.empty() ? get_filename_from_path(directory_path) : remote_name;

    auto t = std::make_shared<Transfer>();
    t->id = random_transfer_id();
    t->peer_id = peer_id;
    t->direction = FileTransferDirection::SENDING;
    t->is_directory = true;
    t->name = name;
    t->local_root = directory_path;

    scan_directory(directory_path, "", t->files);
    for (auto& f : t->files) t->total_bytes += f.size;

    return start_send(peer_id, t, name);
}

// Registers a freshly-built sending transfer and sends its offer.
std::string FileTransferManager::start_send(const std::string& peer_id,
                                            const std::shared_ptr<Transfer>& t,
                                            const std::string& /*name*/) {
    t->status = FileTransferStatus::STARTING;
    t->start_time = std::chrono::steady_clock::now();
    t->last_activity = t->start_time;
    t->rate_mark_time = t->start_time;

    {
        std::lock_guard<std::mutex> lk(transfers_mutex_);
        transfers_[t->id] = t;
    }

    nlohmann::json offer;
    offer["transfer_id"] = t->id;
    offer["name"] = t->name;
    offer["is_directory"] = t->is_directory;
    offer["total_size"] = t->total_bytes;
    nlohmann::json files = nlohmann::json::array();
    for (const auto& f : t->files) {
        files.push_back({{"path", f.relative_path}, {"size", f.size}});
    }
    offer["files"] = files;

    client_.send(peer_id, MSG_OFFER, offer);
    LOG_FT_INFO("Offering " << (t->is_directory ? "directory '" : "file '") << t->name
                            << "' (" << t->files.size() << " file(s), " << t->total_bytes
                            << " bytes) to " << peer_id << " [" << t->id << "]");
    return t->id;
}


// =============================================================================
// Sending: streaming worker
// =============================================================================

void FileTransferManager::queue_send(const std::string& id) {
    {
        std::lock_guard<std::mutex> lk(queue_mutex_);
        send_queue_.push(id);
    }
    queue_cv_.notify_one();
}

void FileTransferManager::worker_loop() {
    while (running_.load()) {
        std::string id;
        {
            std::unique_lock<std::mutex> lk(queue_mutex_);
            queue_cv_.wait(lk, [this] { return !running_.load() || !send_queue_.empty(); });
            if (!running_.load()) return;
            id = send_queue_.front();
            send_queue_.pop();
        }
        auto t = find(id);
        if (!t) continue;

        {
            std::lock_guard<std::mutex> lk(t->mtx);
            if (t->worker_active) continue; // another worker already owns it
            t->worker_active = true;
        }
        run_send(t);
        {
            std::lock_guard<std::mutex> lk(t->mtx);
            t->worker_active = false;
        }
    }
}

void FileTransferManager::run_send(const std::shared_ptr<Transfer>& t) {
    FileTransferConfig cfg = get_config();
    std::vector<uint8_t> buf(cfg.chunk_size);

    while (running_.load()) {
        size_t   file_index;
        uint64_t offset;
        uint64_t file_size;
        std::string source_path;
        {
            std::unique_lock<std::mutex> lk(t->mtx);
            if (t->status == FileTransferStatus::RESUMING) {
                t->status = FileTransferStatus::IN_PROGRESS;
            }
            if (t->status == FileTransferStatus::PAUSED) return;       // cursor preserved
            if (t->status != FileTransferStatus::IN_PROGRESS) return;  // cancelled / failed
            if (t->send_file >= t->files.size()) break;                // all data sent

            file_index  = t->send_file;
            offset      = t->send_offset;
            file_size   = t->files[file_index].size;
            source_path = t->files[file_index].source_path;
            if (offset == 0) sha256_reset(&t->send_hash);
        }

        // Empty file: no chunks, just the end marker.
        if (file_size == 0) {
            nlohmann::json end{{"transfer_id", t->id}, {"file_index", file_index},
                               {"sha256", sha256_of_empty()}};
            client_.send(t->peer_id, MSG_FILE_END, end);
            std::lock_guard<std::mutex> lk(t->mtx);
            t->send_file++;
            t->send_offset = 0;
            t->files_done++;
            continue;
        }

        uint32_t want = static_cast<uint32_t>(std::min<uint64_t>(cfg.chunk_size, file_size - offset));
        if (!read_file_chunk(source_path, offset, buf.data(), want)) {
            nlohmann::json done{{"transfer_id", t->id}, {"success", false},
                                {"error", "sender failed to read file"}};
            client_.send(t->peer_id, MSG_COMPLETE, done);
            finish(t, false, "failed to read " + source_path);
            return;
        }

        uint32_t crc = crc32(buf.data(), want);

        // Build the chunk frame: magic | id | file_index | offset | len | crc | data.
        std::vector<uint8_t> frame;
        frame.reserve(4 + 2 + t->id.size() + 4 + 8 + 4 + 4 + want);
        frame.insert(frame.end(), CHUNK_MAGIC, CHUNK_MAGIC + 4);
        put_u16(frame, static_cast<uint16_t>(t->id.size()));
        frame.insert(frame.end(), t->id.begin(), t->id.end());
        put_u32(frame, static_cast<uint32_t>(file_index));
        put_u64(frame, offset);
        put_u32(frame, want);
        put_u32(frame, crc);
        frame.insert(frame.end(), buf.data(), buf.data() + want);

        bool sent = client_.send_binary_to_peer_id(t->peer_id, frame, MessageDataType::BINARY);
        if (!sent) {
            finish(t, false, "connection lost while sending");
            return;
        }

        bool file_done = false;
        std::string sha_hex;
        {
            std::lock_guard<std::mutex> lk(t->mtx);
            sha256_update(&t->send_hash, buf.data(), want);
            t->send_offset += want;
            t->bytes_done  += want;
            t->last_activity = std::chrono::steady_clock::now();
            if (t->send_offset >= file_size) {
                uint8_t digest[SHA256_HASH_SIZE];
                sha256_finish(&t->send_hash, digest);
                sha_hex = to_hex(digest, SHA256_HASH_SIZE);
                t->send_file++;
                t->send_offset = 0;
                t->files_done++;
                file_done = true;
            }
        }
        {
            std::lock_guard<std::mutex> lk(stats_mutex_);
            stat_bytes_sent_ += want;
        }
        if (file_done) {
            nlohmann::json end{{"transfer_id", t->id}, {"file_index", file_index},
                               {"sha256", sha_hex}};
            client_.send(t->peer_id, MSG_FILE_END, end);
        }

        emit_progress(t);

        // Backpressure: do not get more than `window_bytes` ahead of the peer.
        {
            std::unique_lock<std::mutex> lk(t->mtx);
            while (running_.load() && t->status == FileTransferStatus::IN_PROGRESS &&
                   t->bytes_done - t->acked_bytes >= cfg.window_bytes) {
                t->cv.wait_for(lk, std::chrono::milliseconds(200));
            }
        }
    }

    if (!running_.load()) return;

    // All data streamed; wait for the receiver's ft_complete.
    {
        std::unique_lock<std::mutex> lk(t->mtx);
        while (running_.load() && t->status == FileTransferStatus::IN_PROGRESS) {
            t->cv.wait_for(lk, std::chrono::milliseconds(200));
        }
    }
}

// =============================================================================
// Receiving: offer handling
// =============================================================================

void FileTransferManager::on_offer(const std::string& peer_id, const nlohmann::json& msg) {
    try {
        std::string id = msg.at("transfer_id").get<std::string>();
        if (find(id)) return; // duplicate offer

        auto t = std::make_shared<Transfer>();
        t->id = id;
        t->peer_id = peer_id;
        t->direction = FileTransferDirection::RECEIVING;
        t->is_directory = msg.value("is_directory", false);
        t->name = msg.value("name", std::string("transfer"));
        t->total_bytes = msg.value("total_size", uint64_t(0));
        t->status = FileTransferStatus::PENDING;
        t->start_time = std::chrono::steady_clock::now();
        t->last_activity = t->start_time;
        t->rate_mark_time = t->start_time;

        bool unsafe = false;
        for (const auto& fj : msg.at("files")) {
            TransferFile f;
            f.relative_path = fj.at("path").get<std::string>();
            f.size = fj.value("size", uint64_t(0));
            if (!is_safe_relative_path(f.relative_path)) unsafe = true;
            t->files.push_back(std::move(f));
        }

        if (unsafe) {
            LOG_FT_WARN("Rejecting offer " << id << " from " << peer_id << ": unsafe path in manifest");
            nlohmann::json resp{{"transfer_id", id}, {"accepted", false},
                                {"reason", "unsafe path in manifest"}};
            client_.send(peer_id, MSG_RESPONSE, resp);
            return;
        }

        {
            std::lock_guard<std::mutex> lk(transfers_mutex_);
            transfers_[id] = t;
        }

        IncomingTransferOffer offer;
        offer.transfer_id = id;
        offer.peer_id = peer_id;
        offer.name = t->name;
        offer.is_directory = t->is_directory;
        offer.total_size = t->total_bytes;
        for (const auto& f : t->files) offer.files.push_back({f.relative_path, f.size});

        LOG_FT_INFO("Incoming offer [" << id << "] '" << t->name << "' from " << peer_id
                                       << " (" << t->files.size() << " file(s), "
                                       << t->total_bytes << " bytes)");

        TransferOfferCallback cb;
        {
            std::lock_guard<std::mutex> lk(callbacks_mutex_);
            cb = offer_callback_;
        }
        if (cb) {
            cb(offer);
        } else {
            reject(id, "no offer handler configured");
        }
    } catch (const std::exception& e) {
        LOG_FT_ERROR("Malformed ft_offer from " << peer_id << ": " << e.what());
    }
}

bool FileTransferManager::accept(const std::string& transfer_id, const std::string& local_path) {
    auto t = find(transfer_id);
    if (!t || t->direction != FileTransferDirection::RECEIVING) return false;

    FileTransferConfig cfg = get_config();
    bool empty_transfer = false;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->status != FileTransferStatus::PENDING) return false;
        t->local_root = local_path;
        for (size_t i = 0; i < t->files.size(); ++i) {
            TransferFile& f = t->files[i];
            f.final_path = t->is_directory ? combine_paths(local_path, f.relative_path)
                                           : local_path;
            f.temp_path  = combine_paths(cfg.temp_directory,
                                         transfer_id + "." + std::to_string(i) + ".part");
        }
        t->status = FileTransferStatus::IN_PROGRESS;
        t->start_time = std::chrono::steady_clock::now();
        t->last_activity = t->start_time;
        t->rate_mark_time = t->start_time;
        empty_transfer = t->files.empty();
    }

    create_directories(cfg.temp_directory.c_str());
    nlohmann::json resp{{"transfer_id", transfer_id}, {"accepted", true}};
    client_.send(t->peer_id, MSG_RESPONSE, resp);
    LOG_FT_INFO("Accepted transfer [" << transfer_id << "] -> " << local_path);

    if (t->is_directory) create_directories(local_path.c_str());

    emit_progress(t);

    // A transfer with no files (e.g. an empty directory) is done immediately.
    if (empty_transfer) {
        nlohmann::json done{{"transfer_id", transfer_id}, {"success", true}};
        client_.send(t->peer_id, MSG_COMPLETE, done);
        finish(t, true, "");
    }
    return true;
}

bool FileTransferManager::reject(const std::string& transfer_id, const std::string& reason) {
    auto t = find(transfer_id);
    if (!t || t->direction != FileTransferDirection::RECEIVING) return false;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->status != FileTransferStatus::PENDING) return false;
        t->status = FileTransferStatus::CANCELLED;
    }
    nlohmann::json resp{{"transfer_id", transfer_id}, {"accepted", false}, {"reason", reason}};
    client_.send(t->peer_id, MSG_RESPONSE, resp);
    finish(t, false, reason.empty() ? "rejected" : ("rejected: " + reason));
    return true;
}

// =============================================================================
// Receiving: chunk handling
// =============================================================================

bool FileTransferManager::handle_binary_data(const std::string& peer_id,
                                             const std::vector<uint8_t>& data) {
    if (data.size() < 4 || std::memcmp(data.data(), CHUNK_MAGIC, 4) != 0) {
        return false; // not a file-transfer frame
    }
    const uint8_t* p = data.data();
    size_t n = data.size();
    size_t pos = 4;

    if (pos + 2 > n) return true;
    uint16_t id_len = get_u16(p + pos);
    pos += 2;
    if (pos + id_len > n) return true;
    std::string id(reinterpret_cast<const char*>(p + pos), id_len);
    pos += id_len;
    if (pos + 4 + 8 + 4 + 4 > n) return true;
    uint32_t file_index = get_u32(p + pos); pos += 4;
    uint64_t offset     = get_u64(p + pos); pos += 8;
    uint32_t data_len   = get_u32(p + pos); pos += 4;
    uint32_t crc        = get_u32(p + pos); pos += 4;
    if (pos + data_len != n) {
        LOG_FT_WARN("Chunk frame from " << peer_id << " has inconsistent length");
        return true;
    }
    on_chunk(id, peer_id, file_index, offset, p + pos, data_len, crc);
    return true;
}

void FileTransferManager::on_chunk(const std::string& transfer_id, const std::string& peer_id,
                                   uint32_t file_index, uint64_t offset,
                                   const uint8_t* data, uint32_t len, uint32_t crc) {
    auto t = find(transfer_id);
    if (!t || t->direction != FileTransferDirection::RECEIVING) return;
    FileTransferConfig cfg = get_config();

    // Acknowledge at least twice per window so the sender never stalls waiting
    // for a progress update it will not receive.
    uint64_t ack_interval = std::min<uint64_t>(
        cfg.progress_interval, std::max<uint32_t>(1, cfg.window_bytes / 2));

    std::string temp_path;
    uint64_t file_size = 0;
    std::string fail_error;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        // Only accept chunks while the transfer is live (PAUSED still drains
        // chunks already in flight).
        if (t->status != FileTransferStatus::IN_PROGRESS &&
            t->status != FileTransferStatus::PAUSED) {
            return;
        }
        if (file_index >= t->files.size() || file_index != t->recv_file) {
            // Strict ordering is guaranteed by the reliable transport.
            fail_error = "out-of-order file index";
        } else {
            TransferFile& f = t->files[file_index];
            if (offset != f.received) {
                fail_error = "out-of-order chunk offset";
            } else if (offset + len > f.size) {
                fail_error = "chunk exceeds declared file size";
            } else {
                temp_path = f.temp_path;
                file_size = f.size;
            }
        }
        if (!fail_error.empty()) {
            t->status = FileTransferStatus::FAILED;
            t->error = fail_error;
            t->cv.notify_all();
        }
    }
    if (!fail_error.empty()) {
        nlohmann::json done{{"transfer_id", transfer_id}, {"success", false},
                            {"error", fail_error}};
        client_.send(peer_id, MSG_COMPLETE, done);
        finish(t, false, fail_error);
        return;
    }

    if (cfg.verify_integrity && crc32(data, len) != crc) {
        nlohmann::json done{{"transfer_id", transfer_id}, {"success", false},
                            {"error", "chunk CRC mismatch"}};
        client_.send(peer_id, MSG_COMPLETE, done);
        finish(t, false, "chunk CRC mismatch");
        return;
    }

    // Create the temp file on first contact, pre-sized to the declared length.
    {
        bool need_create;
        {
            std::lock_guard<std::mutex> lk(t->mtx);
            need_create = !t->files[file_index].temp_created;
        }
        if (need_create) {
            if (!create_file_with_size(temp_path.c_str(), file_size)) {
                nlohmann::json done{{"transfer_id", transfer_id}, {"success", false},
                                    {"error", "cannot create destination temp file"}};
                client_.send(peer_id, MSG_COMPLETE, done);
                finish(t, false, "cannot create temp file");
                return;
            }
            std::lock_guard<std::mutex> lk(t->mtx);
            t->files[file_index].temp_created = true;
        }
    }

    if (!write_file_chunk(temp_path, offset, data, len)) {
        nlohmann::json done{{"transfer_id", transfer_id}, {"success", false},
                            {"error", "receiver failed to write to disk"}};
        client_.send(peer_id, MSG_COMPLETE, done);
        finish(t, false, "failed to write chunk to disk");
        return;
    }

    bool data_complete = false;
    bool send_ack = false;
    uint64_t ack_bytes = 0;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        TransferFile& f = t->files[file_index];
        if (f.received == 0) sha256_reset(&t->recv_hash);
        sha256_update(&t->recv_hash, data, len);
        f.received   += len;
        t->bytes_done += len;
        t->last_activity = std::chrono::steady_clock::now();

        if (f.received >= f.size) {
            uint8_t digest[SHA256_HASH_SIZE];
            sha256_finish(&t->recv_hash, digest);
            f.computed_sha = to_hex(digest, SHA256_HASH_SIZE);
            data_complete = true;
        }
        if (data_complete || t->bytes_done - t->last_ack_sent >= ack_interval) {
            t->last_ack_sent = t->bytes_done;
            ack_bytes = t->bytes_done;
            send_ack = true;
        }
    }
    {
        std::lock_guard<std::mutex> lk(stats_mutex_);
        stat_bytes_received_ += len;
    }

    if (send_ack) {
        nlohmann::json prog{{"transfer_id", transfer_id}, {"bytes_received", ack_bytes}};
        client_.send(peer_id, MSG_PROGRESS, prog);
    }
    emit_progress(t);

    if (data_complete) try_finalize_file(t, file_index);
}

void FileTransferManager::on_file_end(const std::string& /*peer_id*/, const nlohmann::json& msg) {
    try {
        std::string id = msg.at("transfer_id").get<std::string>();
        auto t = find(id);
        if (!t || t->direction != FileTransferDirection::RECEIVING) return;
        size_t file_index = msg.at("file_index").get<size_t>();
        std::string sha = msg.value("sha256", std::string());
        {
            std::lock_guard<std::mutex> lk(t->mtx);
            if (t->is_terminal() || file_index >= t->files.size()) return;
            TransferFile& f = t->files[file_index];
            if (f.finalized) return;
            f.expected_sha = sha;
            f.sha_known = true;
            // A zero-byte file produces no chunks, so hash it here.
            if (f.size == 0 && f.computed_sha.empty()) f.computed_sha = sha256_of_empty();
        }
        try_finalize_file(t, file_index);
    } catch (const std::exception& e) {
        LOG_FT_ERROR("Malformed ft_file_end: " << e.what());
    }
}

// Moves a fully-received, verified file to its destination. When the last file
// of the transfer is finalized, completes the whole transfer.
void FileTransferManager::try_finalize_file(const std::shared_ptr<Transfer>& t, size_t file_index) {
    FileTransferConfig cfg = get_config();
    std::string final_path, temp_path, rel_path;
    bool do_finalize = false;
    bool sha_mismatch = false;
    bool zero_byte = false;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->is_terminal() || file_index >= t->files.size()) return;
        TransferFile& f = t->files[file_index];
        if (f.finalized) return;
        if (f.received < f.size) return; // data not complete yet
        if (!f.sha_known) return;        // ft_file_end not received yet

        if (cfg.verify_integrity && f.computed_sha != f.expected_sha) {
            sha_mismatch = true;
        } else {
            do_finalize = true;
            final_path = f.final_path;
            temp_path  = f.temp_path;
            rel_path   = f.relative_path;
            zero_byte  = (f.size == 0);
        }
    }

    if (sha_mismatch) {
        nlohmann::json done{{"transfer_id", t->id}, {"success", false},
                            {"error", "SHA-256 mismatch"}};
        client_.send(t->peer_id, MSG_COMPLETE, done);
        finish(t, false, "SHA-256 mismatch for " + rel_path);
        return;
    }
    if (!do_finalize) return;

    // Place the file at its destination (parent directories created as needed).
    std::string parent = get_parent_directory(final_path.c_str());
    if (!parent.empty()) create_directories(parent.c_str());
    if (file_exists(final_path)) delete_file(final_path.c_str());

    bool ok;
    if (zero_byte) {
        ok = create_file_with_size(final_path.c_str(), 0);
        if (file_exists(temp_path)) delete_file(temp_path.c_str());
    } else {
        ok = rename_file(temp_path, final_path);
        if (!ok) {
            // rename fails across volumes; fall back to copy + delete.
            ok = copy_file(temp_path.c_str(), final_path.c_str());
            if (ok) delete_file(temp_path.c_str());
        }
    }
    if (!ok) {
        nlohmann::json done{{"transfer_id", t->id}, {"success", false},
                            {"error", "cannot write destination file"}};
        client_.send(t->peer_id, MSG_COMPLETE, done);
        finish(t, false, "cannot move file to " + final_path);
        return;
    }

    bool all_done = false;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        TransferFile& f = t->files[file_index];
        f.finalized = true;
        t->files_done++;
        if (file_index == t->recv_file) t->recv_file++;
        all_done = true;
        for (const auto& ff : t->files) {
            if (!ff.finalized) { all_done = false; break; }
        }
    }
    emit_progress(t);

    if (all_done) {
        nlohmann::json done{{"transfer_id", t->id}, {"success", true}};
        client_.send(t->peer_id, MSG_COMPLETE, done);
        finish(t, true, "");
    }
}

// =============================================================================
// Control message handlers
// =============================================================================

void FileTransferManager::on_response(const std::string& /*peer_id*/, const nlohmann::json& msg) {
    try {
        std::string id = msg.at("transfer_id").get<std::string>();
        auto t = find(id);
        if (!t || t->direction != FileTransferDirection::SENDING) return;
        bool accepted = msg.value("accepted", false);

        if (accepted) {
            {
                std::lock_guard<std::mutex> lk(t->mtx);
                if (t->status != FileTransferStatus::STARTING) return;
                t->status = FileTransferStatus::IN_PROGRESS;
                t->start_time = std::chrono::steady_clock::now();
                t->last_activity = t->start_time;
                t->rate_mark_time = t->start_time;
            }
            LOG_FT_INFO("Transfer " << id << " accepted by peer");
            queue_send(id);
        } else {
            std::string reason = msg.value("reason", std::string("rejected by peer"));
            finish(t, false, reason);
        }
    } catch (const std::exception& e) {
        LOG_FT_ERROR("Malformed ft_response: " << e.what());
    }
}

void FileTransferManager::on_progress(const std::string& /*peer_id*/, const nlohmann::json& msg) {
    try {
        std::string id = msg.at("transfer_id").get<std::string>();
        auto t = find(id);
        if (!t || t->direction != FileTransferDirection::SENDING) return;
        uint64_t acked = msg.value("bytes_received", uint64_t(0));
        {
            std::lock_guard<std::mutex> lk(t->mtx);
            if (acked > t->acked_bytes) t->acked_bytes = acked;
            t->last_activity = std::chrono::steady_clock::now();
            t->cv.notify_all(); // wake the streaming worker if it was throttled
        }
    } catch (const std::exception& e) {
        LOG_FT_ERROR("Malformed ft_progress: " << e.what());
    }
}

void FileTransferManager::on_complete(const std::string& /*peer_id*/, const nlohmann::json& msg) {
    try {
        std::string id = msg.at("transfer_id").get<std::string>();
        auto t = find(id);
        if (!t) return;
        bool success = msg.value("success", false);
        std::string error = msg.value("error", std::string());
        finish(t, success, success ? "" : (error.empty() ? "peer reported failure" : error));
    } catch (const std::exception& e) {
        LOG_FT_ERROR("Malformed ft_complete: " << e.what());
    }
}

void FileTransferManager::on_control(const std::string& /*peer_id*/, const nlohmann::json& msg) {
    try {
        std::string id = msg.at("transfer_id").get<std::string>();
        std::string action = msg.at("action").get<std::string>();
        auto t = find(id);
        if (!t) return;

        if (action == "pause") {
            std::lock_guard<std::mutex> lk(t->mtx);
            if (t->status == FileTransferStatus::IN_PROGRESS) {
                t->status = FileTransferStatus::PAUSED;
                t->cv.notify_all();
            }
        } else if (action == "resume") {
            bool requeue = false;
            {
                std::lock_guard<std::mutex> lk(t->mtx);
                if (t->status == FileTransferStatus::PAUSED) {
                    if (t->direction == FileTransferDirection::SENDING) {
                        t->status = FileTransferStatus::RESUMING;
                        requeue = true;
                    } else {
                        t->status = FileTransferStatus::IN_PROGRESS;
                    }
                    t->cv.notify_all();
                }
            }
            if (requeue) queue_send(id);
        } else if (action == "cancel") {
            {
                std::lock_guard<std::mutex> lk(t->mtx);
                if (t->is_terminal()) return;
                t->status = FileTransferStatus::CANCELLED;
                t->cv.notify_all();
            }
            finish(t, false, "cancelled by peer");
        }
    } catch (const std::exception& e) {
        LOG_FT_ERROR("Malformed ft_control: " << e.what());
    }
}

// =============================================================================
// Transfer control (local side)
// =============================================================================

void FileTransferManager::send_control(const std::shared_ptr<Transfer>& t,
                                       const std::string& action) {
    nlohmann::json ctl{{"transfer_id", t->id}, {"action", action}};
    client_.send(t->peer_id, MSG_CONTROL, ctl);
}

bool FileTransferManager::pause(const std::string& transfer_id) {
    auto t = find(transfer_id);
    if (!t) return false;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->status != FileTransferStatus::IN_PROGRESS) return false;
        t->status = FileTransferStatus::PAUSED;
        t->cv.notify_all();
    }
    send_control(t, "pause");
    emit_progress(t);
    LOG_FT_INFO("Transfer " << transfer_id << " paused");
    return true;
}

bool FileTransferManager::resume(const std::string& transfer_id) {
    auto t = find(transfer_id);
    if (!t) return false;
    bool requeue = false;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->status != FileTransferStatus::PAUSED) return false;
        if (t->direction == FileTransferDirection::SENDING) {
            t->status = FileTransferStatus::RESUMING;
            requeue = true;
        } else {
            t->status = FileTransferStatus::IN_PROGRESS;
        }
        t->last_activity = std::chrono::steady_clock::now();
        t->cv.notify_all();
    }
    send_control(t, "resume");
    if (requeue) queue_send(transfer_id);
    emit_progress(t);
    LOG_FT_INFO("Transfer " << transfer_id << " resumed");
    return true;
}

bool FileTransferManager::cancel(const std::string& transfer_id) {
    auto t = find(transfer_id);
    if (!t) return false;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->is_terminal()) return false;
        t->status = FileTransferStatus::CANCELLED;
        t->cv.notify_all();
    }
    send_control(t, "cancel");
    finish(t, false, "cancelled");
    LOG_FT_INFO("Transfer " << transfer_id << " cancelled");
    return true;
}

// =============================================================================
// Peer disconnect
// =============================================================================

void FileTransferManager::on_peer_disconnected(const std::string& peer_id) {
    std::vector<std::shared_ptr<Transfer>> affected;
    {
        std::lock_guard<std::mutex> lk(transfers_mutex_);
        for (auto& kv : transfers_) {
            if (kv.second->peer_id == peer_id) affected.push_back(kv.second);
        }
    }
    for (auto& t : affected) {
        bool active;
        {
            std::lock_guard<std::mutex> lk(t->mtx);
            active = !t->is_terminal();
            if (active) t->cv.notify_all();
        }
        if (active) finish(t, false, "peer disconnected");
    }
}

// =============================================================================
// Maintenance: timeouts and cleanup
// =============================================================================

void FileTransferManager::maintenance_loop() {
    while (running_.load()) {
        {
            std::unique_lock<std::mutex> lk(maintenance_mutex_);
            maintenance_cv_.wait_for(lk, std::chrono::seconds(2),
                                     [this] { return !running_.load(); });
        }
        if (!running_.load()) return;

        auto now = std::chrono::steady_clock::now();
        uint32_t timeout_secs = get_config().transfer_timeout_secs;

        std::vector<std::shared_ptr<Transfer>> all;
        {
            std::lock_guard<std::mutex> lk(transfers_mutex_);
            for (auto& kv : transfers_) all.push_back(kv.second);
        }

        std::vector<std::shared_ptr<Transfer>> timed_out;
        std::vector<std::string> to_purge;
        for (auto& t : all) {
            std::lock_guard<std::mutex> lk(t->mtx);
            auto idle = std::chrono::duration_cast<std::chrono::seconds>(now - t->last_activity);
            if (t->is_terminal()) {
                if (idle > FINISHED_RETENTION) to_purge.push_back(t->id);
            } else if (t->status != FileTransferStatus::PAUSED &&
                       idle.count() > timeout_secs) {
                timed_out.push_back(t);
            }
        }

        for (auto& t : timed_out) {
            LOG_FT_WARN("Transfer " << t->id << " timed out");
            nlohmann::json done{{"transfer_id", t->id}, {"success", false},
                                {"error", "timed out"}};
            client_.send(t->peer_id, MSG_COMPLETE, done);
            finish(t, false, "timed out");
        }
        if (!to_purge.empty()) {
            std::lock_guard<std::mutex> lk(transfers_mutex_);
            for (auto& id : to_purge) transfers_.erase(id);
        }
    }
}

// =============================================================================
// Utilities
// =============================================================================

std::string FileTransferManager::compute_file_sha256(const std::string& path) {
    int64_t size = get_file_size(path.c_str());
    if (size < 0) return "";
    sha256_context_t ctx;
    sha256_reset(&ctx);
    std::vector<uint8_t> buf(64 * 1024);
    uint64_t offset = 0;
    uint64_t remaining = static_cast<uint64_t>(size);
    while (remaining > 0) {
        uint32_t want = static_cast<uint32_t>(std::min<uint64_t>(buf.size(), remaining));
        if (!read_file_chunk(path, offset, buf.data(), want)) return "";
        sha256_update(&ctx, buf.data(), want);
        offset += want;
        remaining -= want;
    }
    uint8_t digest[SHA256_HASH_SIZE];
    sha256_finish(&ctx, digest);
    return to_hex(digest, SHA256_HASH_SIZE);
}

} // namespace librats
