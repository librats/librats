#pragma once

/**
 * @file peer_store.h
 * @brief Persistent set of known peer addresses (for reconnection across restarts).
 *
 * A small, thread-safe address book backed by a plain text file (one "host:port"
 * per line). Used by the ReconnectionService to remember peers worth re-dialing.
 */

#include "net/address.h"

#include <mutex>
#include <string>
#include <vector>

namespace librats {

class PeerStore {
public:
    explicit PeerStore(std::string path) : path_(std::move(path)) {}

    /// Load addresses from the backing file (no-op if it does not exist).
    void load();

    /// Persist the current address set to the backing file.
    void save() const;

    /// Add an address. Returns true if it was not already present.
    bool add(const Address& address);

    std::vector<Address> all() const;
    size_t               size() const;

private:
    std::string                  path_;
    mutable std::mutex           mutex_;
    std::vector<Address>         addresses_;
};

} // namespace librats
