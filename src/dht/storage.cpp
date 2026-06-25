#include "dht/storage.h"
#include "crypto/sha1.h"

#include <algorithm>
#include <random>

namespace librats {
namespace dht {

// ---- TokenManager ----------------------------------------------------------

void TokenManager::maybe_rotate(TimePointSys now) {
    if (!initialized_) {
        std::random_device rd;
        for (auto& b : secret_) b = static_cast<uint8_t>(rd());
        prev_secret_ = secret_;
        rotated_at_ = now;
        initialized_ = true;
        return;
    }
    if (now - rotated_at_ >= kRotateInterval) {
        prev_secret_ = secret_;
        std::random_device rd;
        for (auto& b : secret_) b = static_cast<uint8_t>(rd());
        rotated_at_ = now;
    }
}

std::string TokenManager::compute(const Address& querier, const InfoHash& info_hash,
                                  const std::array<uint8_t, 16>& secret) const {
    // Port is deliberately excluded — a NAT may show a different source port on the
    // follow-up announce, but the address stays the same.
    std::vector<uint8_t> data;
    data.reserve(secret.size() + querier.ip.size() + info_hash.size());
    data.insert(data.end(), secret.begin(), secret.end());
    data.insert(data.end(), querier.ip.begin(), querier.ip.end());
    data.insert(data.end(), info_hash.begin(), info_hash.end());
    return SHA1::hash_bytes(data);
}

std::string TokenManager::generate(const Address& querier, const InfoHash& info_hash, TimePointSys now) {
    maybe_rotate(now);
    return compute(querier, info_hash, secret_);
}

bool TokenManager::verify(const Address& querier, const InfoHash& info_hash,
                          const std::string& token, TimePointSys now) {
    if (token.empty()) return false;
    maybe_rotate(now);
    return token == compute(querier, info_hash, secret_)
        || token == compute(querier, info_hash, prev_secret_);
}

// ---- PeerStore -------------------------------------------------------------

void PeerStore::store(const InfoHash& info_hash, const Address& peer, TimePointSys now) {
    auto& peers = table_[info_hash];
    for (auto& e : peers) {
        if (e.peer == peer) {  // already known → just refresh its timestamp
            e.added = now;
            return;
        }
    }
    peers.push_back({peer, now});
    if (peers.size() > kMaxPeersPerHash) peers.erase(peers.begin());  // drop the oldest
}

std::vector<Address> PeerStore::get(const InfoHash& info_hash, std::size_t max) const {
    std::vector<Address> out;
    auto it = table_.find(info_hash);
    if (it == table_.end()) return out;
    for (const auto& e : it->second) {
        out.push_back(e.peer);
        if (out.size() >= max) break;
    }
    return out;
}

void PeerStore::expire(TimePointSys now) {
    for (auto it = table_.begin(); it != table_.end();) {
        auto& peers = it->second;
        peers.erase(std::remove_if(peers.begin(), peers.end(),
                        [&](const Entry& e) { return now - e.added > kPeerTtl; }),
                    peers.end());
        if (peers.empty()) it = table_.erase(it);
        else ++it;
    }
}

} // namespace dht
} // namespace librats
