#pragma once

/**
 * @file peer_book.h
 * @brief Persistent address book of peers worth reconnecting to.
 *
 * Records every peer we have successfully connected to (and addresses we have
 * learned), with light metadata: when we first/last saw it, when we last
 * connected, how many times, and the current consecutive-failure streak. This
 * single store backs BOTH needs the old design split across two files — the
 * "reconnect to recent peers" working set and the "remember everyone we ever
 * met" archive. Callers query best() for the most promising addresses and rely
 * on prune() to age out the long tail (replaces master's peers.rats +
 * peers_ever.rats with one ranked source of truth).
 *
 * Time is passed in (unix seconds) rather than read here, so the book stays a
 * pure, testable data structure; the wall clock lives at the call site.
 *
 * Thread-safe. Backed by a human-readable text file, one record per line:
 *   <ip> <port> <id-hex|-> <first_seen> <last_seen> <last_connected> <connects> <fails>
 */

#include "core/address.h"
#include "peer/peer_id.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace librats {

struct PeerRecord {
    Address  address;
    PeerId   id;                  ///< last known id (is_zero() if we never connected)
    uint64_t first_seen     = 0;  ///< unix seconds first added/seen
    uint64_t last_seen      = 0;  ///< unix seconds last seen (added / learned / connected)
    uint64_t last_connected = 0;  ///< unix seconds of last successful connection (0 = never)
    uint32_t connect_count  = 0;  ///< successful connections
    uint32_t fail_streak    = 0;  ///< consecutive failed dials since the last success
};

class PeerBook {
public:
    explicit PeerBook(std::string path) : path_(std::move(path)) {}

    /// Load records from the backing file (no-op if it does not exist).
    void load();
    /// Persist the current records to the backing file.
    void save() const;

    /// A successful connection: refresh timestamps, bump connect_count, clear fails.
    void note_connected(const Address& address, const PeerId& id, uint64_t now);
    /// A failed dial to a known peer: bump its failure streak. Does NOT refresh
    /// last_seen (so a peer that only ever fails still ages out). No-op if unknown.
    void note_failure(const Address& address, uint64_t now);
    /// Learned / manually added an address without (yet) connecting to it.
    void note_seen(const Address& address, uint64_t now);

    /// Remove an address entirely. Returns true if it was present.
    bool remove(const Address& address);

    /// Up to n most promising addresses (last seen within max_age_secs, or all if
    /// max_age_secs == 0), best first: ever-connected before never-connected, then
    /// most-recently-connected, then most connects, then fewest recent failures.
    std::vector<Address> best(size_t n, uint64_t now, uint64_t max_age_secs) const;

    /// Drop records last seen longer ago than max_age_secs (0 = no aging), then cap
    /// to max_size (0 = no cap) keeping the best. Returns the number removed.
    size_t prune(uint64_t now, uint64_t max_age_secs, size_t max_size);

    std::vector<Address>    all() const;
    std::vector<PeerRecord> records() const;
    size_t                  size() const;

private:
    std::string                                 path_;
    mutable std::mutex                          mutex_;
    std::unordered_map<std::string, PeerRecord> records_;  ///< keyed by address.to_string()
};

} // namespace librats
