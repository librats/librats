#include "peer/peer_book.h"
#include "util/fs.h"

#include <algorithm>
#include <sstream>
#include <unordered_set>

namespace librats {

namespace {

// "best first" ordering: returns true if a ranks strictly before b.
bool better(const PeerRecord& a, const PeerRecord& b) {
    const bool ca = a.last_connected > 0, cb = b.last_connected > 0;
    if (ca != cb)                            return ca;                          // ever-connected first
    if (a.last_connected != b.last_connected) return a.last_connected > b.last_connected;
    if (a.connect_count  != b.connect_count)  return a.connect_count  > b.connect_count;
    if (a.fail_streak    != b.fail_streak)    return a.fail_streak    < b.fail_streak;
    return a.last_seen > b.last_seen;
}

bool is_stale(const PeerRecord& r, uint64_t now, uint64_t max_age_secs) {
    return max_age_secs > 0 && r.last_seen > 0 && now > r.last_seen && (now - r.last_seen) > max_age_secs;
}

} // namespace

void PeerBook::load() {
    const std::string text = read_file_text_cpp(path_);
    if (text.empty()) return;

    std::lock_guard<std::mutex> lock(mutex_);
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ls(line);
        std::string ip, idhex;
        uint16_t    port = 0;
        PeerRecord  r;
        if (!(ls >> ip >> port) || port == 0 || ip.empty()) continue;  // need at least ip + port
        r.address = Address{ip, port};
        // Remaining metadata fields are optional; absent ones keep their defaults.
        if (ls >> idhex) {
            if (idhex != "-") { if (auto id = PeerId::from_hex(idhex)) r.id = *id; }
            ls >> r.first_seen >> r.last_seen >> r.last_connected >> r.connect_count >> r.fail_streak;
        }
        records_[r.address.to_string()] = r;
    }
}

void PeerBook::save() const {
    std::string text;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        text.reserve(records_.size() * 64);
        for (const auto& [key, r] : records_) {
            text += r.address.ip;                         text += ' ';
            text += std::to_string(r.address.port);       text += ' ';
            text += (r.id.is_zero() ? "-" : r.id.to_hex());text += ' ';
            text += std::to_string(r.first_seen);         text += ' ';
            text += std::to_string(r.last_seen);          text += ' ';
            text += std::to_string(r.last_connected);     text += ' ';
            text += std::to_string(r.connect_count);      text += ' ';
            text += std::to_string(r.fail_streak);        text += '\n';
        }
    }
    create_file(path_.c_str(), text.c_str());
}

void PeerBook::note_connected(const Address& address, const PeerId& id, uint64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    PeerRecord& r = records_[address.to_string()];
    if (r.first_seen == 0) r.first_seen = now;
    r.address        = address;
    if (!id.is_zero()) r.id = id;
    r.last_seen      = now;
    r.last_connected = now;
    r.connect_count++;
    r.fail_streak    = 0;
}

void PeerBook::note_failure(const Address& address, uint64_t /*now*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = records_.find(address.to_string());
    if (it == records_.end()) return;  // only track failures for peers we already know
    // Deliberately does NOT refresh last_seen: a peer that only ever fails must
    // still age out (otherwise repeated give-ups would keep it forever "fresh").
    it->second.fail_streak++;
}

void PeerBook::note_seen(const Address& address, uint64_t now) {
    std::lock_guard<std::mutex> lock(mutex_);
    PeerRecord& r = records_[address.to_string()];
    if (r.first_seen == 0) r.first_seen = now;
    r.address   = address;
    r.last_seen = now;
}

bool PeerBook::remove(const Address& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    return records_.erase(address.to_string()) > 0;
}

std::vector<Address> PeerBook::best(size_t n, uint64_t now, uint64_t max_age_secs) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<const PeerRecord*> recs;
    recs.reserve(records_.size());
    for (const auto& [key, r] : records_)
        if (!is_stale(r, now, max_age_secs)) recs.push_back(&r);

    std::sort(recs.begin(), recs.end(),
              [](const PeerRecord* a, const PeerRecord* b) { return better(*a, *b); });

    std::vector<Address> out;
    for (const PeerRecord* r : recs) {
        if (out.size() >= n) break;
        out.push_back(r->address);
    }
    return out;
}

size_t PeerBook::prune(uint64_t now, uint64_t max_age_secs, size_t max_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    const size_t before = records_.size();

    if (max_age_secs > 0) {
        for (auto it = records_.begin(); it != records_.end();) {
            if (is_stale(it->second, now, max_age_secs)) it = records_.erase(it);
            else ++it;
        }
    }

    if (max_size > 0 && records_.size() > max_size) {
        std::vector<const PeerRecord*> recs;
        recs.reserve(records_.size());
        for (const auto& [key, r] : records_) recs.push_back(&r);
        std::sort(recs.begin(), recs.end(),
                  [](const PeerRecord* a, const PeerRecord* b) { return better(*a, *b); });
        std::unordered_set<std::string> keep;
        keep.reserve(max_size);
        for (size_t i = 0; i < max_size; ++i) keep.insert(recs[i]->address.to_string());
        for (auto it = records_.begin(); it != records_.end();) {
            if (keep.count(it->first)) ++it;
            else it = records_.erase(it);
        }
    }

    return before - records_.size();
}

std::vector<Address> PeerBook::all() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Address> out;
    out.reserve(records_.size());
    for (const auto& [key, r] : records_) out.push_back(r.address);
    return out;
}

std::vector<PeerRecord> PeerBook::records() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PeerRecord> out;
    out.reserve(records_.size());
    for (const auto& [key, r] : records_) out.push_back(r);
    return out;
}

size_t PeerBook::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return records_.size();
}

} // namespace librats
