#pragma once

/**
 * @file storage.h
 * @brief Server-side DHT state: announce write-tokens and the announced-peer table (BEP 5).
 *
 * Both are pure data driven by the node's incoming-query handlers, with time passed
 * in so they're deterministic and lock-free (single actor thread).
 */

#include "core/address.h"
#include "dht/id.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace librats {
namespace dht {

using TimePointSys = std::chrono::steady_clock::time_point;

// Write tokens (BEP 5). A token is handed out with every get_peers reply and must be
// presented back on announce_peer — proving the announcer can actually receive at the
// address it claims. token = SHA1(secret || querier_ip || info_hash): unforgeable
// (the secret is private) and bound to both the address and the info-hash, so it can't
// be replayed for a different peer or torrent. The secret rotates periodically; the
// previous one stays valid across a single rotation so tokens don't expire abruptly.
class TokenManager {
public:
    static constexpr std::chrono::minutes kRotateInterval{5};

    std::string generate(const Address& querier, const InfoHash& info_hash, TimePointSys now);
    bool verify(const Address& querier, const InfoHash& info_hash,
                const std::string& token, TimePointSys now);

private:
    void maybe_rotate(TimePointSys now);
    std::string compute(const Address& querier, const InfoHash& info_hash,
                        const std::array<uint8_t, 16>& secret) const;

    std::array<uint8_t, 16> secret_{};
    std::array<uint8_t, 16> prev_secret_{};
    TimePointSys rotated_at_{};
    bool initialized_ = false;
};

// The peers that announced themselves under each info-hash, so we can answer
// get_peers. Peers expire after kPeerTtl; each info-hash is capped to bound memory.
class PeerStore {
public:
    static constexpr std::chrono::minutes kPeerTtl{30};
    static constexpr std::size_t kMaxPeersPerHash = 128;

    void store(const InfoHash& info_hash, const Address& peer, TimePointSys now);
    std::vector<Address> get(const InfoHash& info_hash, std::size_t max = kMaxPeersPerHash) const;
    void expire(TimePointSys now);

    std::size_t hash_count() const noexcept { return table_.size(); }

private:
    struct Entry {
        Address      peer;
        TimePointSys added;
    };
    std::map<InfoHash, std::vector<Entry>> table_;
};

} // namespace dht
} // namespace librats
