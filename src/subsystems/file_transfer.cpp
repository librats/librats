#include "subsystems/file_transfer.h"
#include "fs.h"
#include "logger.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace librats {

namespace {

enum : uint8_t {
    OP_OFFER = 1, OP_RESPONSE = 2, OP_CHUNK = 3,
    OP_END = 4, OP_PROGRESS = 5, OP_COMPLETE = 6, OP_CANCEL = 7,
};

void put_u16(Bytes& b, uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xFF); }
void put_u64(Bytes& b, uint64_t v) { for (int i = 7; i >= 0; --i) b.push_back((v >> (i * 8)) & 0xFF); }

struct Reader {
    const uint8_t* p;
    const uint8_t* end;
    bool ok = true;
    uint8_t  u8()  { if (p >= end) { ok = false; return 0; } return *p++; }
    uint16_t u16() { if (end - p < 2) { ok = false; return 0; } uint16_t v = (uint16_t(p[0]) << 8) | p[1]; p += 2; return v; }
    uint64_t u64() { if (end - p < 8) { ok = false; return 0; } uint64_t v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | *p++; return v; }
    ByteView bytes(size_t n) { if (size_t(end - p) < n) { ok = false; return {}; } ByteView v(p, n); p += n; return v; }
    ByteView rest() { ByteView v(p, size_t(end - p)); p = end; return v; }
};

} // namespace

FileTransfer::FileTransfer(std::string temp_dir) : temp_dir_(std::move(temp_dir)) {}

FileTransfer::~FileTransfer() { stop(); }

void FileTransfer::attach(PeerNetwork& network) {
    network_ = &network;
    network_->on_message(MessageType::FileChunk,
                         [this](const PeerHandle& peer, ByteView payload) { on_message(peer, payload); });
}

void FileTransfer::stop() {
    std::unordered_map<uint64_t, std::unique_ptr<Outgoing>> outgoing;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        outgoing.swap(outgoing_);
        incoming_.clear();
    }
    for (auto& [id, t] : outgoing) {
        { std::lock_guard<std::mutex> lk(t->mutex); t->cancelled = true; }
        t->cv.notify_all();
        if (t->worker.joinable()) t->worker.join();
    }
}

// ── Sender ──────────────────────────────────────────────────────────────────

uint64_t FileTransfer::send_file(const PeerId& to, const std::string& path) {
    const int64_t size = get_file_size(path.c_str());
    if (size < 0) {
        LOG_WARN("filexfer", "send_file: cannot stat " << path);
        return 0;
    }

    const uint64_t id = next_id_.fetch_add(1);
    auto t = std::make_unique<Outgoing>();
    t->id = id; t->peer = to; t->path = path; t->size = static_cast<uint64_t>(size);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        outgoing_.emplace(id, std::move(t));
    }

    const std::string name = get_filename_from_path(path);
    Bytes m;
    m.push_back(OP_OFFER);
    put_u64(m, id);
    put_u64(m, static_cast<uint64_t>(size));
    put_u16(m, static_cast<uint16_t>(name.size()));
    m.insert(m.end(), name.begin(), name.end());
    send_to(to, m);
    return id;
}

void FileTransfer::run_send(Outgoing* t) {
    sha256_context_t ctx;
    sha256_reset(&ctx);

    std::vector<uint8_t> buf(kChunkSize);
    uint64_t offset = 0;
    while (offset < t->size) {
        {
            std::unique_lock<std::mutex> lk(t->mutex);
            t->cv.wait(lk, [&] { return t->cancelled || (offset - t->acked) < kWindowBytes; });
            if (t->cancelled) return;
        }
        const size_t n = static_cast<size_t>(std::min<uint64_t>(kChunkSize, t->size - offset));
        if (!read_file_chunk(t->path.c_str(), offset, buf.data(), n)) {
            LOG_ERROR("filexfer", "read error on " << t->path << " at " << offset);
            return;
        }
        sha256_update(&ctx, buf.data(), n);

        Bytes m;
        m.push_back(OP_CHUNK);
        put_u64(m, t->id);
        put_u64(m, offset);
        m.insert(m.end(), buf.begin(), buf.begin() + n);
        send_to(t->peer, m);
        offset += n;
    }

    uint8_t hash[SHA256_HASH_SIZE];
    sha256_finish(&ctx, hash);
    Bytes m;
    m.push_back(OP_END);
    put_u64(m, t->id);
    m.insert(m.end(), hash, hash + SHA256_HASH_SIZE);
    send_to(t->peer, m);
    // The worker exits here; COMPLETE arrives later and finishes the transfer.
}

void FileTransfer::finish_outgoing(uint64_t id, bool success) {
    std::unique_ptr<Outgoing> t;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = outgoing_.find(id);
        if (it == outgoing_.end()) return;
        t = std::move(it->second);
        outgoing_.erase(it);
    }
    { std::lock_guard<std::mutex> lk(t->mutex); t->cancelled = true; }
    t->cv.notify_all();
    if (t->worker.joinable()) t->worker.join();
    if (complete_handler_) complete_handler_(id, success, t->path);
}

// ── Receiver ────────────────────────────────────────────────────────────────

void FileTransfer::accept(const PeerId& from, uint64_t id, const std::string& dest_path) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto peer_it = incoming_.find(from);
        if (peer_it == incoming_.end()) return;
        auto it = peer_it->second.find(id);
        if (it == peer_it->second.end()) return;

        Incoming& in = *it->second;
        in.dest = dest_path;
        in.temp = combine_paths(temp_dir_, in.name + ".part-" + std::to_string(id));
        sha256_reset(&in.sha);
        in.active = true;
        in.cursor = 0;
        in.since_ack = 0;
        create_file_with_size(in.temp.c_str(), in.size);  // pre-allocate
    }
    Bytes m;
    m.push_back(OP_RESPONSE);
    put_u64(m, id);
    m.push_back(1);  // accept
    send_to(from, m);
}

void FileTransfer::reject(const PeerId& from, uint64_t id) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto peer_it = incoming_.find(from);
        if (peer_it != incoming_.end()) peer_it->second.erase(id);
    }
    Bytes m;
    m.push_back(OP_RESPONSE);
    put_u64(m, id);
    m.push_back(0);  // reject
    send_to(from, m);
}

void FileTransfer::fail_incoming(Incoming& in) {
    if (!in.temp.empty()) delete_file(in.temp.c_str());
    Bytes m;
    m.push_back(OP_COMPLETE);
    put_u64(m, in.id);
    m.push_back(0);
    send_to(in.peer, m);
    if (complete_handler_) complete_handler_(in.id, false, "");
}

// ── Message dispatch (reactor thread) ────────────────────────────────────────

void FileTransfer::on_message(const PeerHandle& peer, ByteView payload) {
    Reader r{payload.data(), payload.data() + payload.size()};
    const uint8_t op = r.u8();

    switch (op) {
        case OP_OFFER: {
            const uint64_t id = r.u64();
            const uint64_t size = r.u64();
            const uint16_t name_len = r.u16();
            ByteView name_bytes = r.bytes(name_len);
            if (!r.ok) return;
            auto in = std::make_unique<Incoming>();
            in->id = id; in->peer = peer.id(); in->size = size;
            in->name = std::string(reinterpret_cast<const char*>(name_bytes.data()), name_bytes.size());
            Offer offer{peer.id(), id, in->name, size};
            { std::lock_guard<std::mutex> lock(mutex_); incoming_[peer.id()].emplace(id, std::move(in)); }
            if (offer_handler_) offer_handler_(offer);
            return;
        }
        case OP_RESPONSE: {
            const uint64_t id = r.u64();
            const uint8_t accepted = r.u8();
            if (!r.ok) return;
            if (!accepted) { finish_outgoing(id, false); return; }
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = outgoing_.find(id);
            if (it == outgoing_.end()) return;
            Outgoing* t = it->second.get();
            if (!t->worker.joinable()) t->worker = std::thread(&FileTransfer::run_send, this, t);
            return;
        }
        case OP_CHUNK: {
            const uint64_t id = r.u64();
            const uint64_t offset = r.u64();
            ByteView data = r.rest();
            std::lock_guard<std::mutex> lock(mutex_);
            auto peer_it = incoming_.find(peer.id());
            if (peer_it == incoming_.end()) return;
            auto it = peer_it->second.find(id);
            if (it == peer_it->second.end()) return;
            Incoming& in = *it->second;
            if (!in.active) return;
            if (offset != in.cursor) {  // gap: reliable+ordered transport, so this is fatal
                LOG_ERROR("filexfer", "chunk gap on transfer " << id << " (expected " << in.cursor
                          << ", got " << offset << ")");
                fail_incoming(in);
                peer_it->second.erase(it);
                return;
            }
            write_file_chunk(in.temp.c_str(), offset, data.data(), data.size());
            sha256_update(&in.sha, data.data(), data.size());
            in.cursor += data.size();
            in.since_ack += data.size();
            if (in.since_ack >= kWindowBytes / 2) {
                in.since_ack = 0;
                Bytes m; m.push_back(OP_PROGRESS); put_u64(m, id); put_u64(m, in.cursor);
                send_to(peer.id(), m);
            }
            return;
        }
        case OP_END: {
            const uint64_t id = r.u64();
            ByteView sha = r.bytes(SHA256_HASH_SIZE);
            if (!r.ok) return;
            std::lock_guard<std::mutex> lock(mutex_);
            auto peer_it = incoming_.find(peer.id());
            if (peer_it == incoming_.end()) return;
            auto it = peer_it->second.find(id);
            if (it == peer_it->second.end()) return;
            Incoming& in = *it->second;

            uint8_t local[SHA256_HASH_SIZE];
            sha256_finish(&in.sha, local);
            const bool ok = in.cursor == in.size && std::memcmp(local, sha.data(), SHA256_HASH_SIZE) == 0;
            if (ok) {
                create_directories(get_parent_directory(in.dest).c_str());
                move_file(in.temp.c_str(), in.dest.c_str());
                Bytes m; m.push_back(OP_COMPLETE); put_u64(m, id); m.push_back(1);
                send_to(peer.id(), m);
                if (complete_handler_) complete_handler_(id, true, in.dest);
            } else {
                LOG_ERROR("filexfer", "integrity check failed on transfer " << id);
                fail_incoming(in);
            }
            peer_it->second.erase(it);
            return;
        }
        case OP_PROGRESS: {
            const uint64_t id = r.u64();
            const uint64_t received = r.u64();
            if (!r.ok) return;
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = outgoing_.find(id);
            if (it == outgoing_.end()) return;
            Outgoing* t = it->second.get();
            { std::lock_guard<std::mutex> lk(t->mutex); t->acked = received; }
            t->cv.notify_all();
            return;
        }
        case OP_COMPLETE: {
            const uint64_t id = r.u64();
            const uint8_t ok = r.u8();
            if (!r.ok) return;
            finish_outgoing(id, ok != 0);
            return;
        }
        case OP_CANCEL: {
            const uint64_t id = r.u64();
            std::lock_guard<std::mutex> lock(mutex_);
            auto peer_it = incoming_.find(peer.id());
            if (peer_it != incoming_.end()) {
                auto it = peer_it->second.find(id);
                if (it != peer_it->second.end()) {
                    if (!it->second->temp.empty()) delete_file(it->second->temp.c_str());
                    peer_it->second.erase(it);
                }
            }
            return;
        }
        default:
            return;
    }
}

} // namespace librats
