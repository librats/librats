#include "subsystems/file_transfer.h"
#include "crc32.h"
#include "fs.h"
#include "logger.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace librats {

namespace {

enum : uint8_t {
    OP_OFFER = 1, OP_RESPONSE = 2, OP_CHUNK = 3, OP_FILE_END = 4,
    OP_PROGRESS = 5, OP_COMPLETE = 6, OP_CANCEL = 7, OP_PAUSE = 8, OP_RESUME = 9,
};

constexpr auto FINISHED_RETENTION = std::chrono::seconds(30);

void put_u16(Bytes& b, uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xFF); }
void put_u32(Bytes& b, uint32_t v) { for (int i = 3; i >= 0; --i) b.push_back((v >> (i * 8)) & 0xFF); }
void put_u64(Bytes& b, uint64_t v) { for (int i = 7; i >= 0; --i) b.push_back((v >> (i * 8)) & 0xFF); }

struct Reader {
    const uint8_t* p;
    const uint8_t* end;
    bool ok = true;
    uint8_t  u8()  { if (p >= end) { ok = false; return 0; } return *p++; }
    uint16_t u16() { if (end - p < 2) { ok = false; return 0; } uint16_t v = (uint16_t(p[0]) << 8) | p[1]; p += 2; return v; }
    uint32_t u32() { if (end - p < 4) { ok = false; return 0; } uint32_t v = 0; for (int i = 0; i < 4; ++i) v = (v << 8) | *p++; return v; }
    uint64_t u64() { if (end - p < 8) { ok = false; return 0; } uint64_t v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | *p++; return v; }
    ByteView bytes(size_t n) { if (size_t(end - p) < n) { ok = false; return {}; } ByteView v(p, n); p += n; return v; }
    ByteView rest() { ByteView v(p, size_t(end - p)); p = end; return v; }
};

// Recursively collect regular files under abs_dir, recording POSIX relative paths.
void scan_directory(const std::string& abs_dir, const std::string& rel_prefix,
                    std::vector<FileTransfer::FileEntry>& files, std::vector<std::string>& sources) {
    std::vector<DirectoryEntry> entries;
    if (!list_directory(abs_dir.c_str(), entries)) return;
    for (const auto& e : entries) {
        const std::string rel = rel_prefix.empty() ? e.name : rel_prefix + "/" + e.name;
        if (e.is_directory) {
            scan_directory(e.path, rel, files, sources);
        } else {
            const int64_t sz = get_file_size(e.path.c_str());
            files.push_back({rel, sz > 0 ? static_cast<uint64_t>(sz) : 0});
            sources.push_back(e.path);
        }
    }
}

} // namespace

// A relative path coming from a peer must not escape the destination directory.
bool FileTransfer::is_safe_relative_path(const std::string& p) {
    if (p.empty()) return false;
    if (p.front() == '/' || p.front() == '\\') return false;
    if (p.size() >= 2 && p[1] == ':') return false;  // Windows drive letter
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

FileTransfer::FileTransfer(std::string temp_dir) { config_.temp_directory = std::move(temp_dir); }
FileTransfer::FileTransfer(Config config) : config_(std::move(config)) {}
FileTransfer::~FileTransfer() { stop(); }

void FileTransfer::attach(PeerNetwork& network) {
    network_ = &network;
    network_->on_message(MessageType::FileChunk,
                         [this](const PeerHandle& peer, ByteView payload) { on_message(peer, payload); });
    network_->on_peer_disconnected([this](const PeerId& id) {
        // Fail every in-flight transfer with the departed peer and reclaim temps.
        std::vector<std::shared_ptr<Outgoing>> out;
        std::vector<std::shared_ptr<Incoming>> in;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& [tid, t] : outgoing_) if (t->peer == id) out.push_back(t);
            auto pit = incoming_.find(id);
            if (pit != incoming_.end())
                for (auto& [tid, t] : pit->second) in.push_back(t);
        }
        for (auto& t : out) finish_outgoing(t, false);
        for (auto& t : in)  finish_incoming(t, false, "peer disconnected");
    });
}

void FileTransfer::start() {
    if (running_.exchange(true)) return;
    const uint32_t n = std::max<uint32_t>(1, config_.worker_threads);
    for (uint32_t i = 0; i < n; ++i) workers_.emplace_back(&FileTransfer::worker_loop, this);
    maintenance_thread_ = std::thread(&FileTransfer::maintenance_loop, this);
}

void FileTransfer::stop() {
    if (!running_.exchange(false)) return;

    queue_cv_.notify_all();
    maintenance_cv_.notify_all();

    // Wake any worker blocked on a transfer's window/wait so run_send returns.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, t] : outgoing_) { std::lock_guard<std::mutex> lk(t->mtx); t->status = Status::Cancelled; t->cv.notify_all(); }
    }
    for (auto& w : workers_) if (w.joinable()) w.join();
    workers_.clear();
    if (maintenance_thread_.joinable()) maintenance_thread_.join();

    // Drop remaining transfers, reclaiming receiver temp files.
    std::unordered_map<PeerId, std::unordered_map<uint64_t, std::shared_ptr<Incoming>>, PeerId::Hash> in;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        outgoing_.clear();
        in.swap(incoming_);
    }
    for (auto& [peer, m] : in)
        for (auto& [id, t] : m) {
            std::lock_guard<std::mutex> lk(t->mtx);
            for (auto& f : t->files) if (f.temp_created && !f.finalized) delete_file(f.temp_path.c_str());
        }
}

FileTransfer::Stats FileTransfer::stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

// ── lookups ───────────────────────────────────────────────────────────────────

std::shared_ptr<FileTransfer::Outgoing> FileTransfer::find_outgoing(uint64_t id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = outgoing_.find(id);
    return it == outgoing_.end() ? nullptr : it->second;
}

std::shared_ptr<FileTransfer::Incoming> FileTransfer::find_incoming(const PeerId& peer, uint64_t id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto pit = incoming_.find(peer);
    if (pit == incoming_.end()) return nullptr;
    auto it = pit->second.find(id);
    return it == pit->second.end() ? nullptr : it->second;
}

// ── small senders ─────────────────────────────────────────────────────────────

void FileTransfer::send_simple(const PeerId& peer, uint8_t op, uint64_t id) {
    Bytes m; m.push_back(op); put_u64(m, id); send_to(peer, m);
}
void FileTransfer::send_complete(const PeerId& peer, uint64_t id, bool ok) {
    Bytes m; m.push_back(OP_COMPLETE); put_u64(m, id); m.push_back(ok ? 1 : 0); send_to(peer, m);
}

// ── Sender: build + offer ───────────────────────────────────────────────────

uint64_t FileTransfer::send_file(const PeerId& to, const std::string& path) {
    if (!is_file(path.c_str())) { LOG_WARN("filexfer", "send_file: not a file: " << path); return 0; }
    const int64_t size = get_file_size(path.c_str());
    if (size < 0) { LOG_WARN("filexfer", "send_file: cannot stat " << path); return 0; }

    auto t = std::make_shared<Outgoing>();
    t->peer = to;
    t->name = get_filename_from_path(path.c_str());
    t->root = path;
    t->is_directory = false;
    t->files.push_back({t->name, static_cast<uint64_t>(size)});
    t->sources.push_back(path);
    t->total_bytes = static_cast<uint64_t>(size);
    return start_send(std::move(t));
}

uint64_t FileTransfer::send_directory(const PeerId& to, const std::string& dir_path) {
    if (!is_directory(dir_path.c_str())) { LOG_WARN("filexfer", "send_directory: not a directory: " << dir_path); return 0; }

    auto t = std::make_shared<Outgoing>();
    t->name = get_filename_from_path(dir_path.c_str());
    t->root = dir_path;
    t->is_directory = true;
    scan_directory(dir_path, "", t->files, t->sources);
    for (const auto& f : t->files) t->total_bytes += f.size;
    t->peer = to;
    return start_send(std::move(t));
}

uint64_t FileTransfer::start_send(std::shared_ptr<Outgoing> t) {
    const uint64_t id = next_id_.fetch_add(1);
    t->id = id;
    t->last_activity = std::chrono::steady_clock::now();
    t->status = Status::Pending;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        outgoing_.emplace(id, t);
    }

    Bytes m;
    m.push_back(OP_OFFER);
    put_u64(m, id);
    m.push_back(t->is_directory ? 1 : 0);
    put_u64(m, t->total_bytes);
    put_u16(m, static_cast<uint16_t>(t->name.size()));
    m.insert(m.end(), t->name.begin(), t->name.end());
    put_u32(m, static_cast<uint32_t>(t->files.size()));
    for (const auto& f : t->files) {
        put_u16(m, static_cast<uint16_t>(f.relative_path.size()));
        m.insert(m.end(), f.relative_path.begin(), f.relative_path.end());
        put_u64(m, f.size);
    }
    send_to(t->peer, m);
    LOG_INFO("filexfer", "Offering " << (t->is_directory ? "directory '" : "file '") << t->name
             << "' (" << t->files.size() << " file(s), " << t->total_bytes << " B) [" << id << "]");
    return id;
}

void FileTransfer::queue_send(uint64_t id) {
    { std::lock_guard<std::mutex> lk(queue_mutex_); send_queue_.push(id); }
    queue_cv_.notify_one();
}

void FileTransfer::worker_loop() {
    while (running_.load()) {
        uint64_t id;
        {
            std::unique_lock<std::mutex> lk(queue_mutex_);
            queue_cv_.wait(lk, [this] { return !running_.load() || !send_queue_.empty(); });
            if (!running_.load()) return;
            id = send_queue_.front();
            send_queue_.pop();
        }
        auto t = find_outgoing(id);
        if (!t) continue;
        {
            std::lock_guard<std::mutex> lk(t->mtx);
            if (t->worker_active) continue;  // another worker owns it
            t->worker_active = true;
        }
        run_send(t);
        { std::lock_guard<std::mutex> lk(t->mtx); t->worker_active = false; }
    }
}

void FileTransfer::run_send(const std::shared_ptr<Outgoing>& t) {
    std::vector<uint8_t> buf(config_.chunk_size);

    while (running_.load()) {
        size_t      file_index;
        uint64_t    offset, file_size;
        std::string source;
        {
            std::unique_lock<std::mutex> lk(t->mtx);
            if (t->status != Status::Active) return;       // paused / cancelled / done
            if (t->cur_file >= t->files.size()) break;     // all data streamed
            file_index = t->cur_file;
            offset     = t->cur_offset;
            file_size  = t->files[file_index].size;
            source     = t->sources[file_index];
            if (offset == 0) sha256_reset(&t->hash);
        }

        // Empty file: no chunks, just the per-file SHA (of the empty input).
        if (file_size == 0) {
            sha256_context_t e; sha256_reset(&e);
            uint8_t digest[SHA256_HASH_SIZE]; sha256_finish(&e, digest);
            Bytes m; m.push_back(OP_FILE_END); put_u64(m, t->id);
            put_u32(m, static_cast<uint32_t>(file_index));
            m.insert(m.end(), digest, digest + SHA256_HASH_SIZE);
            send_to(t->peer, m);
            std::lock_guard<std::mutex> lk(t->mtx);
            t->cur_file++; t->cur_offset = 0; t->files_done++;
            continue;
        }

        const uint32_t want = static_cast<uint32_t>(std::min<uint64_t>(config_.chunk_size, file_size - offset));
        if (!read_file_chunk(source.c_str(), offset, buf.data(), want)) {
            LOG_ERROR("filexfer", "read error on " << source << " at " << offset);
            send_complete(t->peer, t->id, false);
            finish_outgoing(t, false);
            return;
        }
        const uint32_t crc = CRC32::calculate(buf.data(), want);

        Bytes m;
        m.reserve(1 + 8 + 4 + 8 + 4 + want);
        m.push_back(OP_CHUNK);
        put_u64(m, t->id);
        put_u32(m, static_cast<uint32_t>(file_index));
        put_u64(m, offset);
        put_u32(m, crc);
        m.insert(m.end(), buf.data(), buf.data() + want);
        send_to(t->peer, m);

        bool file_done = false;
        uint8_t digest[SHA256_HASH_SIZE];
        {
            std::lock_guard<std::mutex> lk(t->mtx);
            sha256_update(&t->hash, buf.data(), want);
            t->cur_offset += want;
            t->bytes_done += want;
            t->last_activity = std::chrono::steady_clock::now();
            if (t->cur_offset >= file_size) {
                sha256_finish(&t->hash, digest);
                t->cur_file++; t->cur_offset = 0; t->files_done++;
                file_done = true;
            }
        }
        { std::lock_guard<std::mutex> lk(stats_mutex_); stats_.bytes_sent += want; }

        if (file_done) {
            Bytes e; e.push_back(OP_FILE_END); put_u64(e, t->id);
            put_u32(e, static_cast<uint32_t>(file_index));
            e.insert(e.end(), digest, digest + SHA256_HASH_SIZE);
            send_to(t->peer, e);
        }
        emit_progress(t);

        // Backpressure: stay within `window_bytes` of the receiver's last ack.
        std::unique_lock<std::mutex> lk(t->mtx);
        while (running_.load() && t->status == Status::Active &&
               t->bytes_done - t->acked >= config_.window_bytes) {
            t->cv.wait_for(lk, std::chrono::milliseconds(200));
        }
    }
    // All data streamed; the transfer stays Active until the receiver's COMPLETE
    // arrives (handled on the reactor thread), which calls finish_outgoing().
}

void FileTransfer::finish_outgoing(const std::shared_ptr<Outgoing>& t, bool success) {
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->finished) return;
        t->finished = true;
        if (t->status != Status::Cancelled)
            t->status = success ? Status::Completed : Status::Failed;
        t->cv.notify_all();
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        outgoing_.erase(t->id);
    }
    { std::lock_guard<std::mutex> lk(stats_mutex_); success ? ++stats_.completed : ++stats_.failed; }
    emit_progress(t);
    if (complete_handler_) complete_handler_(t->id, success, t->root);
}

// ── Receiver ──────────────────────────────────────────────────────────────────

void FileTransfer::accept(const PeerId& from, uint64_t id, const std::string& dest_path) {
    auto t = find_incoming(from, id);
    if (!t) return;
    bool empty_transfer = false;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->status != Status::Pending) return;
        t->dest_root = dest_path;
        for (size_t i = 0; i < t->files.size(); ++i) {
            IncomingFile& f = t->files[i];
            f.final_path = t->is_directory ? combine_paths(dest_path, f.relative_path) : dest_path;
            f.temp_path  = combine_paths(config_.temp_directory,
                                         std::to_string(id) + "." + std::to_string(i) + ".part");
        }
        t->status = Status::Active;
        t->last_activity = std::chrono::steady_clock::now();
        empty_transfer = t->files.empty();
    }
    create_directories(config_.temp_directory.c_str());
    if (t->is_directory) create_directories(dest_path.c_str());

    Bytes m; m.push_back(OP_RESPONSE); put_u64(m, id); m.push_back(1); send_to(from, m);
    LOG_INFO("filexfer", "Accepted transfer [" << id << "] -> " << dest_path);

    if (empty_transfer) {  // e.g. an empty directory: done immediately
        send_complete(from, id, true);
        finish_incoming(t, true, "");
    }
}

void FileTransfer::reject(const PeerId& from, uint64_t id) {
    auto t = find_incoming(from, id);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto pit = incoming_.find(from);
        if (pit != incoming_.end()) pit->second.erase(id);
    }
    Bytes m; m.push_back(OP_RESPONSE); put_u64(m, id); m.push_back(0); send_to(from, m);
    if (t && complete_handler_) complete_handler_(id, false, "");
}

void FileTransfer::try_finalize_file(const std::shared_ptr<Incoming>& t, size_t file_index) {
    std::string final_path, temp_path, rel;
    bool do_finalize = false, sha_mismatch = false, zero_byte = false;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->finished || file_index >= t->files.size()) return;
        IncomingFile& f = t->files[file_index];
        if (f.finalized) return;
        if (f.received < f.size) return;  // data not complete
        if (!f.sha_known) return;         // FILE_END not received yet

        uint8_t local[SHA256_HASH_SIZE];
        if (f.size == 0) { sha256_context_t e; sha256_reset(&e); sha256_finish(&e, local); }
        else             { std::memcpy(local, t->computed_sha, SHA256_HASH_SIZE); }

        if (config_.verify_integrity && std::memcmp(local, f.expected_sha, SHA256_HASH_SIZE) != 0) {
            sha_mismatch = true;
        } else {
            do_finalize = true;
            final_path = f.final_path; temp_path = f.temp_path; rel = f.relative_path;
            zero_byte = (f.size == 0);
        }
    }

    if (sha_mismatch) {
        LOG_ERROR("filexfer", "SHA-256 mismatch for " << rel << " on transfer " << t->id);
        send_complete(t->peer, t->id, false);
        finish_incoming(t, false, "SHA-256 mismatch");
        return;
    }
    if (!do_finalize) return;

    const std::string parent = get_parent_directory(final_path.c_str());
    if (!parent.empty()) create_directories(parent.c_str());
    if (file_exists(final_path.c_str())) delete_file(final_path.c_str());

    bool ok;
    if (zero_byte) {
        ok = create_file_with_size(final_path.c_str(), 0);
        if (file_exists(temp_path.c_str())) delete_file(temp_path.c_str());
    } else {
        ok = rename_file(temp_path.c_str(), final_path.c_str());
        if (!ok) {  // rename fails across volumes; fall back to copy + delete
            ok = copy_file(temp_path.c_str(), final_path.c_str());
            if (ok) delete_file(temp_path.c_str());
        }
    }
    if (!ok) {
        LOG_ERROR("filexfer", "cannot place file " << final_path);
        send_complete(t->peer, t->id, false);
        finish_incoming(t, false, "cannot write destination file");
        return;
    }

    bool all_done = false;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        IncomingFile& f = t->files[file_index];
        f.finalized = true;
        t->files_done++;
        if (file_index == t->recv_file) t->recv_file++;
        all_done = true;
        for (const auto& ff : t->files) if (!ff.finalized) { all_done = false; break; }
    }
    emit_progress(t);

    if (all_done) {
        send_complete(t->peer, t->id, true);
        finish_incoming(t, true, "");
    }
}

void FileTransfer::finish_incoming(const std::shared_ptr<Incoming>& t, bool success, const std::string& error) {
    std::string dest;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->finished) return;
        t->finished = true;
        if (t->status != Status::Cancelled)
            t->status = success ? Status::Completed : Status::Failed;
        dest = t->dest_root;
        if (!success)  // reclaim partial temp files
            for (auto& f : t->files) if (f.temp_created && !f.finalized) delete_file(f.temp_path.c_str());
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto pit = incoming_.find(t->peer);
        if (pit != incoming_.end()) pit->second.erase(t->id);
    }
    { std::lock_guard<std::mutex> lk(stats_mutex_); success ? ++stats_.completed : ++stats_.failed; }
    emit_progress(t);
    if (!error.empty()) LOG_WARN("filexfer", "transfer " << t->id << " ended: " << error);
    if (complete_handler_) complete_handler_(t->id, success, dest);
}

// ── Message dispatch (reactor thread) ────────────────────────────────────────

void FileTransfer::on_message(const PeerHandle& peer, ByteView payload) {
    Reader r{payload.data(), payload.data() + payload.size()};
    const uint8_t op = r.u8();
    const PeerId from = peer.id();

    switch (op) {
        case OP_OFFER: {
            const uint64_t id    = r.u64();
            const bool     is_dir = r.u8() != 0;
            const uint64_t total = r.u64();
            const uint16_t nlen  = r.u16();
            ByteView nm = r.bytes(nlen);
            const uint32_t count = r.u32();
            if (!r.ok) return;
            std::string name(reinterpret_cast<const char*>(nm.data()), nm.size());
            std::vector<FileEntry> files;
            files.reserve(count);
            for (uint32_t i = 0; i < count; ++i) {
                const uint16_t plen = r.u16();
                ByteView pb = r.bytes(plen);
                const uint64_t sz = r.u64();
                if (!r.ok) return;
                files.push_back({std::string(reinterpret_cast<const char*>(pb.data()), pb.size()), sz});
            }
            handle_offer(from, id, is_dir, total, std::move(name), std::move(files));
            return;
        }
        case OP_RESPONSE: {
            const uint64_t id = r.u64();
            const uint8_t accepted = r.u8();
            if (!r.ok) return;
            auto t = find_outgoing(id);
            if (!t) return;
            if (!accepted) { finish_outgoing(t, false); return; }
            { std::lock_guard<std::mutex> lk(t->mtx); if (t->status == Status::Pending) t->status = Status::Active; t->last_activity = std::chrono::steady_clock::now(); }
            queue_send(id);
            return;
        }
        case OP_CHUNK: {
            const uint64_t id     = r.u64();
            const uint32_t fidx   = r.u32();
            const uint64_t offset = r.u64();
            const uint32_t crc    = r.u32();
            ByteView data = r.rest();
            if (!r.ok) return;
            handle_chunk(from, id, fidx, offset, crc, data);
            return;
        }
        case OP_FILE_END: {
            const uint64_t id   = r.u64();
            const uint32_t fidx = r.u32();
            ByteView sha = r.bytes(SHA256_HASH_SIZE);
            if (!r.ok) return;
            handle_file_end(from, id, fidx, sha.data());
            return;
        }
        case OP_PROGRESS: {
            const uint64_t id = r.u64();
            const uint64_t received = r.u64();
            if (!r.ok) return;
            auto t = find_outgoing(id);
            if (!t) return;
            { std::lock_guard<std::mutex> lk(t->mtx); t->acked = received; t->last_activity = std::chrono::steady_clock::now(); }
            t->cv.notify_all();
            return;
        }
        case OP_COMPLETE: {
            const uint64_t id = r.u64();
            const uint8_t ok = r.u8();
            if (!r.ok) return;
            if (auto t = find_outgoing(id)) finish_outgoing(t, ok != 0);
            return;
        }
        case OP_CANCEL: {
            const uint64_t id = r.u64();
            if (!r.ok) return;
            if (auto t = find_outgoing(id)) {
                { std::lock_guard<std::mutex> lk(t->mtx); t->status = Status::Cancelled; t->cv.notify_all(); }
                finish_outgoing(t, false);
            }
            if (auto t = find_incoming(from, id)) {
                { std::lock_guard<std::mutex> lk(t->mtx); t->status = Status::Cancelled; }
                finish_incoming(t, false, "cancelled by peer");
            }
            return;
        }
        case OP_PAUSE: {
            const uint64_t id = r.u64();
            if (!r.ok) return;
            if (auto t = find_outgoing(id)) { std::lock_guard<std::mutex> lk(t->mtx); if (t->status == Status::Active) t->status = Status::Paused; t->cv.notify_all(); }
            if (auto t = find_incoming(from, id)) { std::lock_guard<std::mutex> lk(t->mtx); if (t->status == Status::Active) t->status = Status::Paused; }
            return;
        }
        case OP_RESUME: {
            const uint64_t id = r.u64();
            if (!r.ok) return;
            if (auto t = find_outgoing(id)) {
                bool requeue = false;
                { std::lock_guard<std::mutex> lk(t->mtx); if (t->status == Status::Paused) { t->status = Status::Active; t->last_activity = std::chrono::steady_clock::now(); requeue = true; } t->cv.notify_all(); }
                if (requeue) queue_send(id);
            }
            if (auto t = find_incoming(from, id)) { std::lock_guard<std::mutex> lk(t->mtx); if (t->status == Status::Paused) { t->status = Status::Active; t->last_activity = std::chrono::steady_clock::now(); } }
            return;
        }
        default: return;
    }
}

void FileTransfer::handle_offer(const PeerId& from, uint64_t id, bool is_dir, uint64_t total,
                                std::string name, std::vector<FileEntry> files) {
    if (find_incoming(from, id)) return;  // duplicate offer

    // Validate every peer-supplied relative path in a directory manifest before
    // it can be used to build a destination path.
    if (is_dir) {
        for (const auto& f : files) {
            if (!is_safe_relative_path(f.relative_path)) {
                LOG_WARN("filexfer", "Rejecting offer " << id << " from " << from.short_hex()
                         << ": unsafe path in manifest ('" << f.relative_path << "')");
                Bytes m; m.push_back(OP_RESPONSE); put_u64(m, id); m.push_back(0); send_to(from, m);
                return;
            }
        }
    }

    auto t = std::make_shared<Incoming>();
    t->id = id; t->peer = from; t->name = std::move(name); t->is_directory = is_dir;
    t->last_activity = std::chrono::steady_clock::now();
    t->files.reserve(files.size());
    for (auto& f : files) {
        IncomingFile inf; inf.relative_path = f.relative_path; inf.size = f.size;
        t->files.push_back(std::move(inf));
    }
    Offer offer{from, id, t->name, total, is_dir, std::move(files)};
    { std::lock_guard<std::mutex> lock(mutex_); incoming_[from].emplace(id, t); }

    if (offer_handler_) offer_handler_(offer);
    else                reject(from, id);  // no handler → auto-reject
}

void FileTransfer::handle_chunk(const PeerId& from, uint64_t id, uint32_t fidx, uint64_t offset,
                                uint32_t crc, ByteView data) {
    auto t = find_incoming(from, id);
    if (!t) return;

    const uint64_t ack_interval =
        std::min<uint64_t>(config_.progress_interval, std::max<uint32_t>(1, config_.window_bytes / 2));

    std::string temp_path, fail;
    uint64_t file_size = 0;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->status != Status::Active && t->status != Status::Paused) return;
        if (fidx >= t->files.size() || fidx != t->recv_file) {
            fail = "out-of-order file index";
        } else {
            IncomingFile& f = t->files[fidx];
            if (offset != f.received)            fail = "out-of-order chunk offset";
            else if (offset + data.size() > f.size) fail = "chunk exceeds declared file size";
            else { temp_path = f.temp_path; file_size = f.size; }
        }
    }
    if (!fail.empty()) {
        LOG_ERROR("filexfer", "transfer " << id << ": " << fail);
        send_complete(from, id, false);
        finish_incoming(t, false, fail);
        return;
    }

    if (config_.verify_integrity && CRC32::calculate(data.data(), data.size()) != crc) {
        LOG_ERROR("filexfer", "transfer " << id << ": chunk CRC mismatch");
        send_complete(from, id, false);
        finish_incoming(t, false, "chunk CRC mismatch");
        return;
    }

    // Create the temp file on first contact, pre-sized to the declared length.
    {
        bool need_create;
        { std::lock_guard<std::mutex> lk(t->mtx); need_create = !t->files[fidx].temp_created; }
        if (need_create) {
            if (!create_file_with_size(temp_path.c_str(), file_size)) {
                send_complete(from, id, false);
                finish_incoming(t, false, "cannot create temp file");
                return;
            }
            std::lock_guard<std::mutex> lk(t->mtx); t->files[fidx].temp_created = true;
        }
    }

    // The disk write is checked: a failure fails the transfer (the SHA must reflect
    // bytes actually on disk, so we never report success for a corrupt file).
    if (!write_file_chunk(temp_path.c_str(), offset, data.data(), data.size())) {
        LOG_ERROR("filexfer", "transfer " << id << ": disk write failed");
        send_complete(from, id, false);
        finish_incoming(t, false, "failed to write chunk to disk");
        return;
    }

    bool data_complete = false, send_ack = false;
    uint64_t ack_bytes = 0;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        IncomingFile& f = t->files[fidx];
        if (f.received == 0) sha256_reset(&t->hash);
        sha256_update(&t->hash, data.data(), data.size());
        f.received += data.size();
        t->bytes_done += data.size();
        t->last_activity = std::chrono::steady_clock::now();
        if (f.received >= f.size) {
            sha256_finish(&t->hash, t->computed_sha);
            data_complete = true;
        }
        if (data_complete || t->bytes_done - t->last_ack >= ack_interval) {
            t->last_ack = t->bytes_done; ack_bytes = t->bytes_done; send_ack = true;
        }
    }
    { std::lock_guard<std::mutex> lk(stats_mutex_); stats_.bytes_received += data.size(); }

    if (send_ack) { Bytes m; m.push_back(OP_PROGRESS); put_u64(m, id); put_u64(m, ack_bytes); send_to(from, m); }
    emit_progress(t);

    if (data_complete) try_finalize_file(t, fidx);
}

void FileTransfer::handle_file_end(const PeerId& from, uint64_t id, uint32_t fidx, const uint8_t* sha) {
    auto t = find_incoming(from, id);
    if (!t) return;
    {
        std::lock_guard<std::mutex> lk(t->mtx);
        if (t->finished || fidx >= t->files.size()) return;
        IncomingFile& f = t->files[fidx];
        if (f.finalized) return;
        std::memcpy(f.expected_sha, sha, SHA256_HASH_SIZE);
        f.sha_known = true;
    }
    try_finalize_file(t, fidx);
}

// ── Control API (works from either side) ──────────────────────────────────────

bool FileTransfer::cancel(const PeerId& peer, uint64_t id) {
    bool acted = false;
    if (auto t = find_outgoing(id)) {
        { std::lock_guard<std::mutex> lk(t->mtx); if (!t->finished) { t->status = Status::Cancelled; t->cv.notify_all(); acted = true; } }
        if (acted) { send_simple(t->peer, OP_CANCEL, id); finish_outgoing(t, false); }
    }
    if (auto t = find_incoming(peer, id)) {
        bool a = false;
        { std::lock_guard<std::mutex> lk(t->mtx); if (!t->finished) { t->status = Status::Cancelled; a = true; } }
        if (a) { send_simple(peer, OP_CANCEL, id); finish_incoming(t, false, "cancelled"); acted = true; }
    }
    return acted;
}

bool FileTransfer::pause(const PeerId& peer, uint64_t id) {
    if (auto t = find_outgoing(id)) {
        bool ok = false;
        { std::lock_guard<std::mutex> lk(t->mtx); if (t->status == Status::Active) { t->status = Status::Paused; ok = true; t->cv.notify_all(); } }
        if (ok) { send_simple(t->peer, OP_PAUSE, id); return true; }
    }
    if (auto t = find_incoming(peer, id)) {
        bool ok = false;
        { std::lock_guard<std::mutex> lk(t->mtx); if (t->status == Status::Active) { t->status = Status::Paused; ok = true; } }
        if (ok) { send_simple(peer, OP_PAUSE, id); return true; }
    }
    return false;
}

bool FileTransfer::resume(const PeerId& peer, uint64_t id) {
    if (auto t = find_outgoing(id)) {
        bool ok = false;
        { std::lock_guard<std::mutex> lk(t->mtx); if (t->status == Status::Paused) { t->status = Status::Active; t->last_activity = std::chrono::steady_clock::now(); ok = true; t->cv.notify_all(); } }
        if (ok) { send_simple(t->peer, OP_RESUME, id); queue_send(id); return true; }
    }
    if (auto t = find_incoming(peer, id)) {
        bool ok = false;
        { std::lock_guard<std::mutex> lk(t->mtx); if (t->status == Status::Paused) { t->status = Status::Active; t->last_activity = std::chrono::steady_clock::now(); ok = true; } }
        if (ok) { send_simple(peer, OP_RESUME, id); return true; }
    }
    return false;
}

// ── Progress callbacks ────────────────────────────────────────────────────────

void FileTransfer::emit_progress(const std::shared_ptr<Outgoing>& t) {
    if (!progress_handler_) return;
    Progress p;
    { std::lock_guard<std::mutex> lk(t->mtx);
      p.id = t->id; p.peer = t->peer; p.direction = Direction::Sending; p.status = t->status;
      p.bytes_transferred = t->bytes_done; p.total_bytes = t->total_bytes;
      p.files_completed = t->files_done; p.total_files = static_cast<uint32_t>(t->files.size()); }
    progress_handler_(p);
}

void FileTransfer::emit_progress(const std::shared_ptr<Incoming>& t) {
    if (!progress_handler_) return;
    Progress p;
    { std::lock_guard<std::mutex> lk(t->mtx);
      p.id = t->id; p.peer = t->peer; p.direction = Direction::Receiving; p.status = t->status;
      p.bytes_transferred = t->bytes_done;
      uint64_t total = 0; for (auto& f : t->files) total += f.size; p.total_bytes = total;
      p.files_completed = t->files_done; p.total_files = static_cast<uint32_t>(t->files.size()); }
    progress_handler_(p);
}

// ── Maintenance: idle timeout + purge ────────────────────────────────────────

void FileTransfer::maintenance_loop() {
    while (running_.load()) {
        {
            std::unique_lock<std::mutex> lk(maintenance_mutex_);
            maintenance_cv_.wait_for(lk, std::chrono::seconds(2), [this] { return !running_.load(); });
        }
        if (!running_.load()) return;

        const auto now = std::chrono::steady_clock::now();
        const uint32_t timeout = config_.transfer_timeout_secs;

        std::vector<std::shared_ptr<Outgoing>> out;
        std::vector<std::shared_ptr<Incoming>> in;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& [id, t] : outgoing_) out.push_back(t);
            for (auto& [peer, m] : incoming_) for (auto& [id, t] : m) in.push_back(t);
        }

        for (auto& t : out) {
            bool stale = false;
            { std::lock_guard<std::mutex> lk(t->mtx);
              if (!t->finished && t->status != Status::Paused &&
                  std::chrono::duration_cast<std::chrono::seconds>(now - t->last_activity).count() > timeout)
                  stale = true; }
            if (stale) { LOG_WARN("filexfer", "outgoing transfer " << t->id << " timed out"); send_complete(t->peer, t->id, false); finish_outgoing(t, false); }
        }
        for (auto& t : in) {
            bool stale = false;
            { std::lock_guard<std::mutex> lk(t->mtx);
              if (!t->finished && t->status != Status::Paused && t->status != Status::Pending &&
                  std::chrono::duration_cast<std::chrono::seconds>(now - t->last_activity).count() > timeout)
                  stale = true; }
            if (stale) { LOG_WARN("filexfer", "incoming transfer " << t->id << " timed out"); send_complete(t->peer, t->id, false); finish_incoming(t, false, "timed out"); }
        }
    }
}

} // namespace librats
